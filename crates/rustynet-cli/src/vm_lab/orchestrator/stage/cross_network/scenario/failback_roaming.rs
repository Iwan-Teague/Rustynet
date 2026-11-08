//! `cross_network_failback_roaming`, ported from
//! `scripts/e2e/live_linux_cross_network_failback_roaming_test.sh` (562 ln).
//!
//! # What this proves
//!
//! Two recoveries, back to back, on a topology that starts out relayed:
//!
//! 1. **Failback** — a client exiting *through the relay* is re-pointed at the
//!    exit directly, and re-converges onto a proven direct path within an SLO,
//!    without leaking or degrading its signed state at any sample in between.
//! 2. **Endpoint roam** — the exit then moves to a *new underlay address*, fresh
//!    signed assignments are issued naming it, and the client follows: it must
//!    end up on a live direct path to the exit's NEW endpoint, with healthy
//!    signed state, and the post-roam path must still resist a server-IP bypass
//!    aimed at that new address.
//!
//! The second half is why the bypass probe is pinned to the roam alias
//! (`--probe-bind-ip`): a bypass test against the exit's *old* address would be
//! testing a path the roam was supposed to abandon.
//!
//! # Two things that look like bugs and are not
//!
//! * **The monitoring loop does not stop at the first reconvergence.** It
//!   records when the client first reached a proven direct path and then keeps
//!   sampling for the full iteration count. Leak and signed-state evidence is
//!   about the whole transition window, not the prefix before recovery, and a
//!   loop that broke early would stop looking exactly when a flapping client
//!   became interesting.
//! * **The iteration count and the SLO are separate numbers** (35 samples, 30
//!   seconds). Raising the SLO must not silently lengthen the observation
//!   window, and the shell kept them as two flags for that reason.
//!
//! # Three preserved asymmetries
//!
//! These differ from the other scenarios' spellings. Each is the shell's, kept
//! rather than harmonised, because tightening a check during a port is an
//! unreviewed behaviour change:
//!
//! * **The in-loop signed-state predicate is narrower than
//!   [`signed_state_healthy`](super::signed_state_healthy).** It checks
//!   `traversal_alarm_state` and `traversal_error=none` only — never
//!   `dns_alarm_state`. The *post-roam* check in the same scenario uses the full
//!   predicate, so both live here side by side.
//! * **Leak detection is the strict reading.** A sample leaks when any route
//!   line leaves by a device that is not the tunnel, rather than when the tunnel
//!   is unnamed. See
//!   [`route_leaves_non_tunnel_dev`](super::endpoint_switch::route_leaves_non_tunnel_dev).
//! * **Reconvergence does not require `state=ExitActive`.** The shell asked for
//!   `exit_node=<exit>`, a tunnel route, and a proven direct path — but not the
//!   daemon state field the direct scenario checks.
//!
//! # Checks the shell performed that are now structural
//!
//! The ones common to every scenario (see the module docs), plus `live_lab_init`
//! / `live_lab_push_sudo_password` on all three hosts,
//! `live_lab_resolved_target_address`, and the three-way host-distinctness
//! guard — the caller resolves client, exit and relay from distinct role slots.
//!
//! One new drop, specific to this scenario: **`--failback-recovery-slo-secs`
//! and `--failback-monitor-iterations` argument parsing** (`parse_positive_integer`).
//! Both are typed fields on [`FailbackRoamingOptions`], whose constructor
//! rejects zero for each.

use std::time::Duration;

use rustynet_control::roles::RoleCapability;

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::{self, RoamAlias, SAMPLE_INTERVAL, unix_now};
use super::host::ScenarioHost;
use super::provisioning::{
    self, AllowSpec, AssignmentsSpec, EXIT_NODE_CAPABILITIES, EnvFile, LabContext, NodeSpec, during,
};
use super::remote_exit_common::{BypassRun, run_bypass_validator, write_trust_summary};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, WIREGUARD_PORT, capture_peer_endpoints,
    path_proven_direct, route_via_rustynet, rustynet_capture_allow_failure, signed_state_healthy,
    status, wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_failback_roaming";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "relay_to_direct_failback_success",
    "endpoint_roam_recovery_success",
    "remote_exit_no_underlay_leak",
    "cross_network_topology_heuristic",
    "failback_reconnect_within_slo",
    "no_underlay_leak_while_reconnecting",
    "signed_state_valid_while_reconnecting",
];

/// The three checks `relay_to_direct_failback_success` aggregates.
const FAILBACK_CHECKS: &[&str] = &[
    "failback_reconnect_within_slo",
    "no_underlay_leak_while_reconnecting",
    "signed_state_valid_while_reconnecting",
];

/// The shell's `--failback-recovery-slo-secs` default.
pub const DEFAULT_RECOVERY_SLO_SECS: u32 = 30;
/// The shell's `--failback-monitor-iterations` default. Deliberately larger than
/// the SLO — see the module docs.
pub const DEFAULT_MONITOR_ITERATIONS: u32 = 35;

/// The `sleep 5` after both advertised routes are re-established, before
/// post-roam evidence is captured.
const POST_ADVERTISE_SETTLE: Duration = Duration::from_secs(5);

/// Capabilities the relay carries in the roam re-issuance.
///
/// The relay is enforced as `admin` for the roam (see `reissue_for_roam`), and
/// the daemon requires `anchor` in an admin node's own signed assignment
/// bundle; it consumes the final exit's traffic, so it keeps `client`. After
/// the roam nobody exits through the relay, so it needs no `exit_server`.
const ROAM_RELAY_NODE_CAPABILITIES: [RoleCapability; 2] =
    [RoleCapability::Anchor, RoleCapability::Client];

/// Remote path of the roam re-issuance env file.
const ROAM_ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_roam.env";

/// Remote path of the pre-failback re-issuance env file. Deliberately distinct
/// from [`ROAM_ISSUE_ENV_PATH`]: the two issuances happen in one stage and must
/// never collide on the guest (the file names the signing secret and is removed
/// after each issuance).
const FAILBACK_ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_failback.env";

/// Artifact basename of the composed relay baseline's report.
const BASELINE_REPORT_FILE: &str = "cross_network_failback_roaming_relay_stage_report.json";
/// Artifact basename of the composed relay baseline's log.
const BASELINE_LOG_FILE: &str = "cross_network_failback_roaming_relay_stage.log";
/// Artifact basename of the server-IP bypass validator's report.
const BYPASS_REPORT_FILE: &str = "cross_network_failback_roaming_server_ip_bypass_report.json";
/// Artifact basename of the server-IP bypass validator's log.
const BYPASS_LOG_FILE: &str = "cross_network_failback_roaming_server_ip_bypass.log";
/// Artifact basename of the per-sample failback transcript.
const MONITOR_LOG_FILE: &str = "cross_network_failback_roaming_monitor.log";
/// Artifact basename of the machine-readable SLO summary.
const SLO_SUMMARY_FILE: &str = "cross_network_failback_roaming_slo_summary.json";
/// Artifact basename of the ssh trust summary.
const TRUST_SUMMARY_FILE: &str = "cross_network_failback_roaming_ssh_trust_summary.txt";

/// The scenario's two tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailbackRoamingOptions {
    recovery_slo_secs: u32,
    monitor_iterations: u32,
}

impl Default for FailbackRoamingOptions {
    fn default() -> Self {
        Self {
            recovery_slo_secs: DEFAULT_RECOVERY_SLO_SECS,
            monitor_iterations: DEFAULT_MONITOR_ITERATIONS,
        }
    }
}

impl FailbackRoamingOptions {
    /// Both must be positive, matching the shell's `parse_positive_integer` on
    /// each flag. Zero iterations would pass both sampled checks vacuously; a
    /// zero SLO would demand instantaneous reconvergence.
    pub fn new(recovery_slo_secs: u32, monitor_iterations: u32) -> Result<Self, String> {
        if recovery_slo_secs == 0 {
            return Err("--failback-recovery-slo-secs must be a positive integer".to_owned());
        }
        if monitor_iterations == 0 {
            return Err("--failback-monitor-iterations must be a positive integer".to_owned());
        }
        Ok(Self {
            recovery_slo_secs,
            monitor_iterations,
        })
    }

    pub fn recovery_slo_secs(self) -> u32 {
        self.recovery_slo_secs
    }

    pub fn monitor_iterations(self) -> u32 {
        self.monitor_iterations
    }
}

/// Run the failback and roaming scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: FailbackRoamingOptions,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);
    let mut path_status_line = None;

    let source_artifacts = vec![
        baseline::path_arg(&lab.artifact(BASELINE_REPORT_FILE)),
        baseline::path_arg(&lab.artifact(BYPASS_REPORT_FILE)),
        baseline::path_arg(&lab.artifact(SLO_SUMMARY_FILE)),
        baseline::path_arg(&lab.artifact(TRUST_SUMMARY_FILE)),
    ];
    let log_artifacts = vec![
        baseline::path_arg(&lab.artifact(BASELINE_LOG_FILE)),
        baseline::path_arg(&lab.artifact(BYPASS_LOG_FILE)),
        baseline::path_arg(&lab.artifact(MONITOR_LOG_FILE)),
    ];

    let mut outcome = match execute(
        host,
        inputs,
        lab,
        options,
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

fn execute(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: FailbackRoamingOptions,
    checks: &mut Checks,
    path_status_line: &mut Option<String>,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;
    let relay = inputs.require_relay(SUITE)?;
    let relay_ssh_target = lab.require_relay_ssh_target(SUITE)?;
    let relay_src_dir = lab.relay_src_dir.as_deref().ok_or_else(|| {
        format!("{SUITE} requires a relay source directory but none was resolved")
    })?;

    // ── relay baseline ──
    let phase = "bootstrapping relay remote-exit path before failback";
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

    // D4 fail-fast: this baseline IS the relayed path the scenario falls back
    // FROM. If it failed, the roam below would run on an unproven path and
    // report its own unrelated breakdown (katana-xnet-1280: the relay stage
    // died on the traversal.pub misread, the scenario still roamed, `route
    // advertise` then failed against a fail-closed daemon, and the stage
    // error buried the relay cause). Stop here, restore the direct baseline
    // exactly as relay_remote_exit does, and carry the relay stage's own
    // failure_summary as this stage's error — never let a roam or a restore
    // result replace it.
    if !baseline.succeeded() {
        let relay_cause = baseline.outcome.failure_summary.clone();
        return Err(
            super::relay_remote_exit::restore_direct_baseline_after_relay_failure(
                inputs,
                lab,
                format!("relay bootstrap failed, refusing to roam off it: {relay_cause}"),
            ),
        );
    }

    // The shell did NOT gate on the baseline passing here — only on its report
    // existing, which composition makes unconditional. Its verdict is consumed
    // twice instead: as one clause of the SLO check below, and as a final gate
    // at the very end. Both are preserved.
    let baseline_ok = baseline.passed(BaselineScenario::Relay.success_check());

    let topology_distinct = during(
        phase,
        provisioning::classify_cross_network_topology(&client.address, &exit.address),
    )?;
    checks.record_bool("cross_network_topology_heuristic", topology_distinct);

    let phase = "initializing failback and roaming live-lab runtime";
    write_trust_summary(
        host,
        &lab.artifact(TRUST_SUMMARY_FILE),
        SUITE,
        &[
            ("client-host", lab.client_ssh_target.as_str()),
            ("exit-host", lab.exit_ssh_target.as_str()),
            ("relay-host", relay_ssh_target),
        ],
    )?;
    for node in [exit, relay, client] {
        during(phase, wait_for_daemon_socket(node.runner))?;
    }

    // ── 1. relay → direct failback ──
    // The coupling acts on a node whose assignment authority is the EXIT: on
    // Linux the forced local assignment refresh inside `apply-role-coupling`
    // keeps the existing bundle on such a node ("this node is not its own
    // assignment authority … the authority must issue the updated assignment",
    // katana-xnet-150 via the lan-toggle review's risk 3), so the exit
    // authority must re-issue the client's assignment for the direct-exit
    // target BEFORE the switch, or the keep arm correctly refuses to apply the
    // operator's intent and the client fail-closes on the relayed bundle.
    // Re-issuing before `switch_unix` keeps the SLO measuring the transition,
    // not the issuance.
    reissue_client_for_failback(inputs, relay)?;

    let phase = "switching client from relay exit to direct exit";
    let switch_unix = unix_now();
    during(
        phase,
        provisioning::apply_role_coupling(
            client.runner,
            "client",
            Some(&exit.node_id),
            false,
            None,
            false,
        ),
    )?;
    let failback = during(phase, monitor_failback(client, exit, lab, options))?;

    let reconvergence_secs = failback.reconvergence_secs(switch_unix);
    // Four independent clauses, all the shell's: the relay baseline proved the
    // relayed path this failback is falling back FROM, the topology really is
    // cross-network, and the measured reconvergence is both non-negative and
    // inside the SLO.
    checks.record_bool(
        "failback_reconnect_within_slo",
        baseline_ok
            && checks.passed("cross_network_topology_heuristic")
            && matches!(
                reconvergence_secs,
                Some(secs) if (0..=i64::from(options.recovery_slo_secs)).contains(&secs)
            ),
    );
    checks.record_bool(
        "no_underlay_leak_while_reconnecting",
        failback.underlay_leak_samples == 0,
    );
    checks.record_bool(
        "signed_state_valid_while_reconnecting",
        failback.signed_state_invalid_samples == 0,
    );
    checks.record_bool(
        "relay_to_direct_failback_success",
        checks.all_passed(FAILBACK_CHECKS),
    );

    during(
        phase,
        host.write_artifact(&lab.artifact(MONITOR_LOG_FILE), &failback.transcript),
    )?;
    during(
        phase,
        host.write_artifact(
            &lab.artifact(SLO_SUMMARY_FILE),
            &render_slo_summary(switch_unix, &failback, reconvergence_secs, options, checks)?,
        ),
    )?;

    // ── 2. endpoint roam ──
    let phase = "computing endpoint roam alias and issuing updated signed assignments";
    // The alias sits on the EXIT's prefix and avoids all three nodes already in
    // play: the point is to move the exit somewhere new, not onto a peer.
    let alias = during(
        phase,
        endpoint_switch::choose_alias(
            &exit.address,
            &[
                exit.address.as_str(),
                client.address.as_str(),
                relay.address.as_str(),
            ],
        ),
    )?;
    // The interface the exit reaches the CLIENT on — not its default route.
    // Adding the alias anywhere else would leave it unreachable from the client.
    let roam_iface = during(
        phase,
        endpoint_switch::route_dev_to(exit.runner, &client.address),
    )
    .map_err(|_| "failed to determine exit underlay interface for endpoint roam".to_owned())?;
    during(
        phase,
        endpoint_switch::add_alias(exit.runner, &roam_iface, &alias),
    )?;
    // The shell never removed this alias, and neither does this: the roam is the
    // scenario's end state, and tearing it down would undo the very thing the
    // post-roam evidence and the bypass probe are asserting against.

    reissue_for_roam(inputs, lab, relay, relay_src_dir, &alias)?;

    // ── post-roam evidence ──
    let phase = "capturing endpoint roam recovery evidence";
    let client_status = during(phase, status(client.runner))?;
    let client_netcheck = during(
        phase,
        rustynet_capture_allow_failure(client.runner, &["netcheck"]),
    )?;
    *path_status_line = Some(client_netcheck.clone());
    let client_route = during(
        phase,
        provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        ),
    )?;
    let client_endpoints = during(phase, capture_peer_endpoints(client.runner))?;

    // Five clauses. The last is what makes this a ROAM proof rather than a
    // reconnect proof: the client's endpoint table must name the exit's NEW
    // address, so a client still talking to the old one cannot pass.
    checks.record_bool(
        "endpoint_roam_recovery_success",
        path_proven_direct(&client_netcheck)
            && signed_state_healthy(&client_netcheck)
            && client_status.contains(&format!("exit_node={}", exit.node_id))
            && route_via_rustynet(&client_route)
            && client_endpoints.contains(&alias.wireguard_endpoint()),
    );

    // ── post-roam leak resistance ──
    let phase = "validating narrow server-IP bypass and leak resistance after endpoint roam";
    let bypass_report = lab.artifact(BYPASS_REPORT_FILE);
    let bypass_log = lab.artifact(BYPASS_LOG_FILE);
    let verdicts = run_bypass_validator(
        host,
        lab,
        &BypassRun {
            report_path: bypass_report.as_path(),
            log_path: bypass_log.as_path(),
            probe_ssh_target: lab.exit_ssh_target.as_str(),
            // Pinned to the roam alias: probing the exit's old address would
            // test a path the roam abandoned.
            probe_bind_ip: Some(alias.ip.as_str()),
            missing_evidence_summary: "server-IP bypass validator failed before emitting failback/roaming evidence",
            phase,
        },
    )?;
    // Only the leak conclusion is consumed. The shell read exactly the two
    // fields that compose it and never asked for the bypass-narrowness pair, so
    // this report carries no `remote_exit_server_ip_bypass_is_narrow` check —
    // reading the other two here and discarding them changes nothing, since
    // they feed only that unused conclusion.
    checks.record_bool("remote_exit_no_underlay_leak", verdicts.no_underlay_leak);

    // ── verdict, in the shell's order ──
    if !checks.passed("relay_to_direct_failback_success") {
        return Err(failback_failure_summary(
            checks,
            options,
            reconvergence_secs,
            baseline_ok,
        ));
    }
    if !checks.passed("endpoint_roam_recovery_success") {
        return Err("client did not recover after signed endpoint roam".to_owned());
    }
    if !checks.passed("remote_exit_no_underlay_leak") {
        return Err("post-roam path leaked or could not prove leak resistance".to_owned());
    }
    // The shell's final `[[ "$relay_rc" -eq 0 ]]`, which failed the scenario
    // when the relay baseline had failed even though every check above passed.
    // It ran AFTER `FAILURE_SUMMARY=""`, so the shell reported this case with an
    // empty summary that the report generator then replaced with a generic "is
    // not implemented yet". Preserving the gate but not that summary is a
    // deliberate, recorded deviation: the outcome is unchanged and the operator
    // now learns why.
    if !baseline_ok {
        return Err(
            "relay remote-exit baseline failed; failback cannot be claimed against a relayed \
             path that was never proven"
                .to_owned(),
        );
    }
    Ok(())
}

/// The shell's failback `if/elif` chain, in its order.
fn failback_failure_summary(
    checks: &Checks,
    options: FailbackRoamingOptions,
    reconvergence_secs: Option<i64>,
    baseline_ok: bool,
) -> String {
    if !checks.passed("failback_reconnect_within_slo") {
        // `failback_reconnect_within_slo` also folds in the relay baseline and
        // the topology heuristic (see `execute`), so it can fail with a
        // reconvergence time well inside the SLO. Reporting that as "exceeded
        // reconnect SLO (30s), measured=6s" (katana-xnet-73) is false; name the
        // clause that actually failed. The check verdicts themselves are
        // unchanged.
        let within_slo = matches!(
            reconvergence_secs,
            Some(secs) if (0..=i64::from(options.recovery_slo_secs)).contains(&secs)
        );
        if within_slo && !baseline_ok {
            return format!(
                "relay remote-exit baseline did not prove the relayed path to fail back from \
                 (reconvergence itself took {}s, within the {}s SLO)",
                reconvergence_secs.unwrap_or(NO_RECONVERGENCE_SECS),
                options.recovery_slo_secs
            );
        }
        if within_slo && !checks.passed("cross_network_topology_heuristic") {
            return format!(
                "client and exit underlay topology did not credibly prove a cross-network \
                 claim (reconvergence itself took {}s, within the {}s SLO)",
                reconvergence_secs.unwrap_or(NO_RECONVERGENCE_SECS),
                options.recovery_slo_secs
            );
        }
        return format!(
            "relay-to-direct failback exceeded reconnect SLO ({}s), measured={}s",
            options.recovery_slo_secs,
            reconvergence_secs.unwrap_or(NO_RECONVERGENCE_SECS)
        );
    }
    if !checks.passed("no_underlay_leak_while_reconnecting") {
        return "underlay leak detected while reconnecting during relay-to-direct failback"
            .to_owned();
    }
    if !checks.passed("signed_state_valid_while_reconnecting") {
        return "signed traversal state became invalid while reconnecting during relay-to-direct \
                failback"
            .to_owned();
    }
    "relay-to-direct failback did not reconverge securely".to_owned()
}

/// The shell's `reconvergence_secs=-1` sentinel, written into the typed
/// `reconvergence_secs` field of the SLO summary artifact.
const NO_RECONVERGENCE_SECS: i64 = -1;

/// What the failback monitoring loop saw.
struct FailbackObservation {
    /// Unix seconds at which the client was FIRST seen on a proven direct path.
    /// Latched once — a later flap does not move it, because the SLO measures
    /// time to first recovery.
    first_direct_unix: Option<u64>,
    underlay_leak_samples: u32,
    signed_state_invalid_samples: u32,
    transcript: String,
}

impl FailbackObservation {
    fn reconvergence_secs(&self, switch_unix: u64) -> Option<i64> {
        self.first_direct_unix.map(|at| {
            i64::try_from(at).unwrap_or(i64::MAX) - i64::try_from(switch_unix).unwrap_or(i64::MAX)
        })
    }
}

/// Sample the failback transition for the full iteration count.
///
/// Deliberately does **not** break on first reconvergence — see the module docs.
fn monitor_failback(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    options: FailbackRoamingOptions,
) -> Result<FailbackObservation, String> {
    let mut observed = FailbackObservation {
        first_direct_unix: None,
        underlay_leak_samples: 0,
        signed_state_invalid_samples: 0,
        transcript: String::new(),
    };
    let exit_selector = format!("exit_node={}", exit.node_id);

    for sample in 1..=options.monitor_iterations {
        let sampled_at = unix_now();
        let client_status = status(client.runner)?;
        let client_route = provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        )?;
        let client_endpoints = capture_peer_endpoints(client.runner)?;
        let client_netcheck = rustynet_capture_allow_failure(client.runner, &["netcheck"])?;

        if !traversal_state_valid(&client_netcheck) {
            observed.signed_state_invalid_samples += 1;
        }
        if endpoint_switch::route_leaves_non_tunnel_dev(&client_route) {
            observed.underlay_leak_samples += 1;
        }

        observed.transcript.push_str(&render_sample(
            sampled_at,
            sample,
            &[
                ("route", &client_route),
                ("status", &client_status),
                ("endpoints", &client_endpoints),
                ("netcheck", &client_netcheck),
            ],
        ));

        // Latched, not re-evaluated: the SLO measures time to FIRST recovery.
        // Note this deliberately omits `state=ExitActive` — see the module docs.
        if observed.first_direct_unix.is_none()
            && client_status.contains(&exit_selector)
            && route_via_rustynet(&client_route)
            && path_proven_direct(&client_netcheck)
        {
            observed.first_direct_unix = Some(sampled_at);
        }

        lab.sleep(SAMPLE_INTERVAL);
    }
    Ok(observed)
}

/// The in-loop signed-state predicate: `traversal_alarm_state` not in
/// {critical, error, missing}, **and** a positive `traversal_error=none`.
///
/// Narrower than [`signed_state_healthy`](super::signed_state_healthy), which
/// also rejects an unhealthy `dns_alarm_state`. That difference is the shell's
/// and is preserved deliberately: this samples a client mid-failback, where DNS
/// state is expected to be in flux, while the post-roam check in the same
/// scenario uses the full predicate against a settled path.
fn traversal_state_valid(netcheck_output: &str) -> bool {
    for state in ["critical", "error", "missing"] {
        if netcheck_output.contains(&format!("traversal_alarm_state={state}")) {
            return false;
        }
    }
    netcheck_output.contains("traversal_error=none")
}

/// The signed-assignment specs for the direct-exit topology, parameterised ONLY
/// by the address the exit is spelled at: its own address for the failback
/// re-issue, the roam alias for [`reissue_for_roam`].
///
/// One builder for both issuances so they cannot drift: the exit keeps the
/// exit-server capabilities the issuer requires ([`EXIT_NODE_CAPABILITIES`]),
/// the relay drops `exit_server` for the roam shape
/// ([`ROAM_RELAY_NODE_CAPABILITIES`]) but stays a permitted peer, all six
/// directed pairs stay allowed exactly as the shell left them, and the
/// assignments are the failback itself made durable in signed state — the
/// client exits via the EXIT directly, not through the relay.
fn direct_exit_topology_specs(
    exit: &ScenarioNode<'_>,
    relay: &ScenarioNode<'_>,
    client: &ScenarioNode<'_>,
    exit_ip: &str,
    exit_pub_hex: &str,
    relay_pub_hex: &str,
    client_pub_hex: &str,
) -> Result<(String, String, String), String> {
    let nodes = provisioning::nodes_spec(&[
        NodeSpec::new(exit.node_id.as_str(), exit_ip, WIREGUARD_PORT, exit_pub_hex)?
            .with_capabilities(&EXIT_NODE_CAPABILITIES),
        NodeSpec::new(
            relay.node_id.as_str(),
            &relay.address,
            WIREGUARD_PORT,
            relay_pub_hex,
        )?
        .with_capabilities(&ROAM_RELAY_NODE_CAPABILITIES),
        NodeSpec::new(
            client.node_id.as_str(),
            &client.address,
            WIREGUARD_PORT,
            client_pub_hex,
        )?,
    ])?;
    let allow = AllowSpec::new()
        .allow(&client.node_id, &relay.node_id)?
        .allow(&relay.node_id, &client.node_id)?
        .allow(&client.node_id, &exit.node_id)?
        .allow(&exit.node_id, &client.node_id)?
        .allow(&relay.node_id, &exit.node_id)?
        .allow(&exit.node_id, &relay.node_id)?
        .render()?;
    let assignments = AssignmentsSpec::new()
        .assign(&exit.node_id, None)?
        .assign(&relay.node_id, Some(&exit.node_id))?
        .assign(&client.node_id, Some(&exit.node_id))?
        .render()?;
    Ok((nodes, allow, assignments))
}

/// Re-issue the CLIENT's signed assignment from the EXIT authority for the
/// direct-exit target, and re-point the client's assignment-refresh env at the
/// exit, BEFORE `apply-role-coupling` switches the client off the relayed path.
///
/// Why the scenario must do this (katana-xnet-150, lan-toggle review risk 3):
/// the relay baseline issued the client's bundle from the exit authority naming
/// the RELAY as its upstream, and installed the exit authority's verifying key
/// on the client. On Linux, `ops apply-role-coupling` then forces a local
/// assignment refresh whose plan for a node that is not its own assignment
/// authority is `KeepExternalAuthority` — the bundle is deliberately KEPT and
/// the CLI itself says "the authority must issue the updated assignment". The
/// keep arm is correct product behaviour; the scenario was simply asking a
/// foreign-authority node to apply operator intent nothing had re-issued. With
/// the exit authority's fresh direct-exit bundle installed first, the coupling
/// acts on an assignment that already names the intended exit and the forced
/// refresh's convergence wait has something real to converge on.
///
/// This is [`reissue_for_roam`]'s issuance minus the alias flip (the exit is
/// spelled at its own address) and minus everything only the roam needs: only
/// the CLIENT's bundle and refresh env are installed — the exit's and relay's
/// own bundles are semantically unchanged by the failback (same nodes, same
/// allow set, the relay still exits via the exit) — and nothing restarts a
/// daemon here: `apply-role-coupling` itself restarts the daemon, and THAT
/// restart is the failback transition the SLO measures.
fn reissue_client_for_failback(
    inputs: &ScenarioInputs<'_>,
    relay: &ScenarioNode<'_>,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;
    let phase = "collecting WireGuard public keys for the failback re-issue";
    let exit_pub_hex = during(phase, provisioning::collect_pubkey_hex(exit.runner))?;
    let relay_pub_hex = during(phase, provisioning::collect_pubkey_hex(relay.runner))?;
    let client_pub_hex = during(phase, provisioning::collect_pubkey_hex(client.runner))?;

    let phase =
        "re-issuing the client assignment from the exit authority for the direct-exit target";
    let (nodes, allow, assignments) = during(
        phase,
        direct_exit_topology_specs(
            exit,
            relay,
            client,
            &exit.address,
            &exit_pub_hex,
            &relay_pub_hex,
            &client_pub_hex,
        ),
    )?;
    let issue_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", &nodes)?
            .set("ALLOW_SPEC", &allow)?
            .set("ASSIGNMENTS_SPEC", &assignments),
    )?;
    during(
        phase,
        provisioning::issue_assignment_bundles_from_env(
            exit.runner,
            &issue_env,
            FAILBACK_ISSUE_ENV_PATH,
        ),
    )?;

    let assignment_pub = during(
        phase,
        provisioning::read_remote_base64(exit.runner, &provisioning::issued_assignment_pub_path()),
    )?;
    let bundle = during(
        phase,
        provisioning::read_remote_base64(
            exit.runner,
            &provisioning::issued_assignment_path(&client.node_id)?,
        ),
    )?;
    during(
        phase,
        provisioning::install_assignment_bundle(
            client.runner,
            &client.node_id,
            &assignment_pub,
            &bundle,
        ),
    )?;
    let refresh = during(
        phase,
        provisioning::assignment_refresh_env(&client.node_id, &nodes, &allow, Some(&exit.node_id)),
    )?;
    during(
        phase,
        provisioning::install_assignment_refresh_env(client.runner, &client.node_id, &refresh),
    )
}

/// Issue and distribute the signed assignments that move the exit to `alias`,
/// then bring both advertised default routes back up.
///
/// The topology changes here as well as the address: the client's assignment now
/// names the EXIT directly rather than the relay, which is what makes the
/// post-roam path direct. The allow set is unchanged — all six directed pairs
/// stay, exactly as the shell left them, so the relay remains a permitted peer
/// even though it is no longer on the path.
fn reissue_for_roam(
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    relay: &ScenarioNode<'_>,
    relay_src_dir: &str,
    alias: &RoamAlias,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;
    let phase = "computing endpoint roam alias and issuing updated signed assignments";

    let exit_pub_hex = during(phase, provisioning::collect_pubkey_hex(exit.runner))?;
    let relay_pub_hex = during(phase, provisioning::collect_pubkey_hex(relay.runner))?;
    let client_pub_hex = during(phase, provisioning::collect_pubkey_hex(client.runner))?;

    // The exit is spelled at its ROAM ALIAS here; the other two keep their own
    // addresses. That single substitution is the whole roam — everything else
    // about the specs is the shared direct-exit shape (see
    // [`direct_exit_topology_specs`]).
    let (nodes, allow, assignments) = during(
        phase,
        direct_exit_topology_specs(
            exit,
            relay,
            client,
            &alias.ip,
            &exit_pub_hex,
            &relay_pub_hex,
            &client_pub_hex,
        ),
    )?;

    let issue_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", &nodes)?
            .set("ALLOW_SPEC", &allow)?
            .set("ASSIGNMENTS_SPEC", &assignments),
    )?;
    during(
        phase,
        provisioning::issue_assignment_bundles_from_env(
            exit.runner,
            &issue_env,
            ROAM_ISSUE_ENV_PATH,
        ),
    )?;

    let assignment_pub = during(
        phase,
        provisioning::read_remote_base64(exit.runner, &provisioning::issued_assignment_pub_path()),
    )?;
    for node in [exit, relay, client] {
        let bundle = during(
            phase,
            provisioning::read_remote_base64(
                exit.runner,
                &provisioning::issued_assignment_path(&node.node_id)?,
            ),
        )?;
        during(
            phase,
            provisioning::install_assignment_bundle(
                node.runner,
                &node.node_id,
                &assignment_pub,
                &bundle,
            ),
        )?;
    }

    for (node, upstream) in [
        (exit, None),
        (relay, Some(&exit.node_id)),
        (client, Some(&exit.node_id)),
    ] {
        let refresh = during(
            phase,
            provisioning::assignment_refresh_env(
                &node.node_id,
                &nodes,
                &allow,
                upstream.map(String::as_str),
            ),
        )?;
        during(
            phase,
            provisioning::install_assignment_refresh_env(node.runner, &node.node_id, &refresh),
        )?;
    }

    // The roam restarts every daemon through `enforce_host` below, and the
    // baseline's dns-zone bundle (300 s lifetime) is older than that by now;
    // re-issue it for the roam topology so the post-roam signed-state check
    // does not read `dns_zone_bundle_is_stale`.
    let phase = "re-issuing signed dns-zone bundles for the roam";
    during(
        phase,
        provisioning::reissue_dns_zone(
            exit.runner,
            &nodes,
            &allow,
            &[
                (exit.runner, &exit.node_id),
                (relay.runner, &relay.node_id),
                (client.runner, &client.node_id),
            ],
        ),
    )?;

    // No traversal bundle is re-issued. The shell did not re-issue one either:
    // the traversal state the relay baseline installed still names the same
    // three nodes, and the roam changes only which endpoint the ASSIGNMENT
    // advertises.
    for (node, role, src_dir) in [
        (exit, "admin", lab.exit_src_dir.as_str()),
        (relay, "admin", relay_src_dir),
        (client, "client", lab.client_src_dir.as_str()),
    ] {
        during(
            phase,
            provisioning::enforce_host(
                node.runner,
                role,
                &node.node_id,
                src_dir,
                &lab.ssh_allow_cidrs,
            ),
        )?;
    }
    for node in [exit, relay, client] {
        during(phase, wait_for_daemon_socket(node.runner))?;
    }
    during(
        phase,
        super::advertise_default_route(exit.runner, lab.pace(super::ROUTE_ADVERTISE_SLEEP)),
    )?;
    during(
        phase,
        super::advertise_default_route(relay.runner, lab.pace(super::ROUTE_ADVERTISE_SLEEP)),
    )?;
    lab.sleep(POST_ADVERTISE_SETTLE);
    Ok(())
}

/// One monitor-log line, in the shell's `printf` layout.
fn render_sample(sampled_at: u64, sample: u32, fields: &[(&str, &String)]) -> String {
    let mut line = format!("{sampled_at}|iter={sample}");
    for (name, value) in fields {
        line.push('|');
        line.push_str(name);
        line.push('=');
        line.push_str(&super::node_network_switch::squeeze(value));
    }
    line.push('\n');
    line
}

/// The SLO summary artifact, in the shell's field names and types.
///
/// The report validator does not inspect this file's contents (unlike the soak
/// scenario's monitor summary, which it does), but it does require it to exist
/// for a pass — and an operator reads it to see how long the failback actually
/// took.
fn render_slo_summary(
    switch_unix: u64,
    observed: &FailbackObservation,
    reconvergence_secs: Option<i64>,
    options: FailbackRoamingOptions,
    checks: &Checks,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "switch_unix": switch_unix,
        "first_direct_unix": observed.first_direct_unix,
        "reconvergence_secs": reconvergence_secs.unwrap_or(NO_RECONVERGENCE_SECS),
        "recovery_slo_secs": options.recovery_slo_secs,
        "monitor_iterations": options.monitor_iterations,
        "underlay_leak_samples": observed.underlay_leak_samples,
        "signed_state_invalid_samples": observed.signed_state_invalid_samples,
        "checks": {
            "failback_reconnect_within_slo":
                checks.verdict("failback_reconnect_within_slo").as_str(),
            "no_underlay_leak_while_reconnecting":
                checks.verdict("no_underlay_leak_while_reconnecting").as_str(),
            "signed_state_valid_while_reconnecting":
                checks.verdict("signed_state_valid_while_reconnecting").as_str(),
        },
    });
    serde_json::to_string_pretty(&payload)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|err| format!("failed to render failback SLO summary: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::scenario::host::recording::RecordingHost;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const EXIT_NODE_ID: &str = "exit-1";

    fn options(iterations: u32) -> FailbackRoamingOptions {
        FailbackRoamingOptions::new(DEFAULT_RECOVERY_SLO_SECS, iterations).expect("positive")
    }

    fn monitor(client: &mut MockLeafRunner, iterations: u32) -> FailbackObservation {
        // `capture_peer_endpoints` errors on an empty capture, so the script
        // must answer the endpoint probe with the exit's endpoint.
        client.stdout_by_match.push((
            "wg show rustynet0 endpoints".to_owned(),
            "peerkey\t192.168.19.40:51820".to_owned(),
        ));
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(&*client, "client-1", "192.168.18.40");
        let exit_runner = MockLeafRunner::default();
        let exit_node = ScenarioNode::new(&exit_runner, EXIT_NODE_ID, "192.168.19.40");
        monitor_failback(&client_node, &exit_node, &lab, options(iterations)).expect("monitor")
    }

    /// A client that has already failed back onto a proven direct path.
    fn recovered_client() -> MockLeafRunner {
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
                    "path_mode=direct_active path_live_proven=true traversal_error=none".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    #[test]
    fn the_loop_keeps_sampling_after_the_client_has_reconverged() {
        // Breaking early would stop looking exactly when a flapping client
        // becomes interesting, and the leak/signed-state checks are about the
        // whole window rather than the prefix before recovery.
        let mut client = recovered_client();
        let observed = monitor(&mut client, 4);
        assert_eq!(observed.transcript.lines().count(), 4);
        assert!(observed.first_direct_unix.is_some());
        assert_eq!(observed.underlay_leak_samples, 0);
        assert_eq!(observed.signed_state_invalid_samples, 0);
    }

    #[test]
    fn a_route_leaving_by_an_underlay_device_counts_as_a_leak() {
        // The strict reading: naming the tunnel is not enough if something else
        // also leaves by an underlay device.
        assert!(endpoint_switch::route_leaves_non_tunnel_dev(
            "1.1.1.1 via 192.168.18.1 dev enp0s1 src 192.168.18.40"
        ));
        assert!(!endpoint_switch::route_leaves_non_tunnel_dev(
            "1.1.1.1 dev rustynet0 src 10.42.0.2"
        ));
        // Both devices named: `route_via_rustynet` accepts this, the strict
        // reading does not, and that divergence is the point.
        let mixed = "1.1.1.1 dev rustynet0 src 10.42.0.2\n1.1.1.1 dev enp0s1 src 192.168.18.40";
        assert!(route_via_rustynet(mixed));
        assert!(endpoint_switch::route_leaves_non_tunnel_dev(mixed));
    }

    #[test]
    fn every_leaking_sample_is_counted_not_just_the_first() {
        let mut client = MockLeafRunner {
            stdout_by_match: vec![(
                "route get 1.1.1.1".to_owned(),
                "1.1.1.1 via 192.168.18.1 dev enp0s1".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let observed = monitor(&mut client, 3);
        assert_eq!(observed.underlay_leak_samples, 3);
        assert!(observed.first_direct_unix.is_none());
    }

    #[test]
    fn the_in_loop_signed_state_check_ignores_dns_alarms() {
        // Narrower than `signed_state_healthy` on purpose: DNS state is
        // expected to be in flux mid-failback. Preserved from the shell rather
        // than harmonised, because tightening it would be an unreviewed
        // behaviour change.
        let dns_degraded = "traversal_error=none dns_alarm_state=critical";
        assert!(traversal_state_valid(dns_degraded));
        assert!(
            !signed_state_healthy(dns_degraded),
            "the post-roam predicate must still reject it"
        );

        assert!(!traversal_state_valid(
            "traversal_alarm_state=error traversal_error=none"
        ));
        // Absence of the positive clause is not health, here as everywhere.
        assert!(!traversal_state_valid("path_mode=direct_active"));
    }

    #[test]
    fn reconvergence_needs_a_proven_direct_path_not_merely_the_intent() {
        let mut client = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!("exit_node={EXIT_NODE_ID}"),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0".to_owned(),
                ),
                // `path_mode` without `path_live_proven` is the daemon's intent,
                // not evidence that traffic crossed.
                (
                    "rustynet netcheck".to_owned(),
                    "path_mode=direct_active traversal_error=none".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        assert!(monitor(&mut client, 2).first_direct_unix.is_none());
    }

    #[test]
    fn reconvergence_does_not_require_the_exit_active_state_field() {
        // The shell asked for `exit_node=`, a tunnel route and a proven direct
        // path — but not `state=ExitActive`, which the direct scenario does
        // check. Preserved rather than tightened.
        let mut client = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!("exit_node={EXIT_NODE_ID} state=Connecting"),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0".to_owned(),
                ),
                (
                    "rustynet netcheck".to_owned(),
                    "path_mode=direct_active path_live_proven=true traversal_error=none".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        assert!(monitor(&mut client, 1).first_direct_unix.is_some());
    }

    #[test]
    fn both_tunables_reject_zero_and_default_to_the_shells_values() {
        assert!(FailbackRoamingOptions::new(0, 35).is_err());
        assert!(FailbackRoamingOptions::new(30, 0).is_err());
        let defaults = FailbackRoamingOptions::default();
        assert_eq!(defaults.recovery_slo_secs(), 30);
        assert_eq!(
            defaults.monitor_iterations(),
            35,
            "the observation window is deliberately longer than the SLO"
        );
    }

    #[test]
    fn the_failback_aggregate_covers_its_three_sampled_checks() {
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        for name in FAILBACK_CHECKS {
            assert!(
                CHECKS.contains(name),
                "{name} must be emitted as well as aggregated"
            );
        }
        assert!(!checks.all_passed(FAILBACK_CHECKS));
        for name in FAILBACK_CHECKS {
            checks.record_bool(name, true);
        }
        assert!(checks.all_passed(FAILBACK_CHECKS));
    }

    #[test]
    fn the_failure_summary_names_the_first_failing_failback_clause() {
        let options = FailbackRoamingOptions::default();
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        assert_eq!(
            failback_failure_summary(&checks, options, None, true),
            "relay-to-direct failback exceeded reconnect SLO (30s), measured=-1s"
        );

        checks.record_bool("failback_reconnect_within_slo", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7), true),
            "underlay leak detected while reconnecting during relay-to-direct failback"
        );

        checks.record_bool("no_underlay_leak_while_reconnecting", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7), true),
            "signed traversal state became invalid while reconnecting during relay-to-direct \
             failback"
        );

        checks.record_bool("signed_state_valid_while_reconnecting", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7), true),
            "relay-to-direct failback did not reconverge securely"
        );
    }

    /// katana-xnet-73: reconvergence took 6 s, the relay baseline failed, and the
    /// summary claimed "exceeded reconnect SLO (30s), measured=6s". The check
    /// verdict is unchanged; only the text now names the clause that failed.
    #[test]
    fn a_failed_baseline_is_not_reported_as_a_slo_miss() {
        let options = FailbackRoamingOptions::default();
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        let text = failback_failure_summary(&checks, options, Some(6), false);
        assert!(
            text.starts_with("relay remote-exit baseline did not prove"),
            "{text}"
        );
        assert!(text.contains("took 6s, within the 30s SLO"), "{text}");
        // A genuine SLO miss keeps the original wording.
        assert_eq!(
            failback_failure_summary(&checks, options, Some(31), false),
            "relay-to-direct failback exceeded reconnect SLO (30s), measured=31s"
        );
        assert_eq!(
            failback_failure_summary(&checks, options, Some(-1), true),
            "relay-to-direct failback exceeded reconnect SLO (30s), measured=-1s"
        );
        // Baseline fine, topology not credible, reconvergence in range.
        checks.record_bool("cross_network_topology_heuristic", false);
        let text = failback_failure_summary(&checks, options, Some(6), true);
        assert!(
            text.starts_with("client and exit underlay topology"),
            "{text}"
        );
        // Nothing wrong with any clause but the time was never measured.
        checks.record_bool("cross_network_topology_heuristic", true);
        assert_eq!(
            failback_failure_summary(&checks, options, None, true),
            "relay-to-direct failback exceeded reconnect SLO (30s), measured=-1s"
        );
    }

    #[test]
    fn the_slo_summary_spells_no_reconvergence_as_null_and_minus_one() {
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        let observed = FailbackObservation {
            first_direct_unix: None,
            underlay_leak_samples: 3,
            signed_state_invalid_samples: 1,
            transcript: String::new(),
        };
        let rendered = render_slo_summary(
            1700,
            &observed,
            None,
            FailbackRoamingOptions::default(),
            &checks,
        )
        .expect("render");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert!(parsed["first_direct_unix"].is_null());
        assert_eq!(parsed["reconvergence_secs"], -1);
        assert_eq!(parsed["monitor_iterations"], 35);
        assert_eq!(parsed["underlay_leak_samples"], 3);
        assert_eq!(
            parsed["checks"]["no_underlay_leak_while_reconnecting"],
            "fail"
        );
    }

    #[test]
    fn the_exit_roam_interface_is_the_one_reaching_the_client() {
        // Not the exit's default route: an alias added anywhere else would be
        // unreachable from the client.
        let exit = MockLeafRunner {
            stdout_by_match: vec![(
                "route get".to_owned(),
                "192.168.18.40 via 192.168.19.1 dev enp0s2 src 192.168.19.40".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        assert_eq!(
            endpoint_switch::route_dev_to(&exit, "192.168.18.40").expect("iface"),
            "enp0s2"
        );

        let unreachable = MockLeafRunner::default();
        assert!(endpoint_switch::route_dev_to(&unreachable, "192.168.18.40").is_err());
    }

    // ── the pre-failback authority re-issue ──

    /// 32 key bytes whose hex spelling is the ASCII of "0123456789abcdef"
    /// twice — easy to eyeball in a rendered spec.
    const PUB_B64: &str = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    const PUB_HEX: &str = "3031323334353637383961626364656630313233343536373839616263646566";

    fn key_runner() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![(
                format!("cat {}", provisioning::WG_PUB_KEY_PATH),
                PUB_B64.to_owned(),
            )],
            ..MockLeafRunner::default()
        }
    }

    fn failback_inputs<'a>(
        client: &'a MockLeafRunner,
        exit: &'a MockLeafRunner,
        relay: &'a MockLeafRunner,
    ) -> ScenarioInputs<'a> {
        use crate::vm_lab::orchestrator::stage::cross_network::substrate::NatProfileId;
        ScenarioInputs {
            client: ScenarioNode::new(client, "client-1", "192.168.18.40"),
            exit: ScenarioNode::new(exit, EXIT_NODE_ID, "192.168.19.40"),
            relay: Some(ScenarioNode::new(relay, "relay-1", "192.168.20.40")),
            probe: None,
            nat_profile: NatProfileId::parse("full_cone").expect("full_cone is known"),
            impairment_profile: "none".to_owned(),
        }
    }

    /// The decoded payload of the `write_remote_text` call that wrote
    /// `path` — the env file's contents.
    fn decoded_env_at(runner: &MockLeafRunner, path: &str) -> Option<String> {
        use base64::Engine as _;
        runner
            .recorded()
            .into_iter()
            .find(|call| {
                let joined = call.join(" ");
                joined.contains(path) && joined.contains("base64 -d")
            })
            .and_then(|call| {
                let payload = call.last()?;
                base64::engine::general_purpose::STANDARD
                    .decode(payload)
                    .ok()
                    .map(|bytes| String::from_utf8(bytes).expect("utf8 env"))
            })
    }

    /// The value of `KEY="value"` in a rendered env file, quotes stripped.
    fn env_value(env: &str, key: &str) -> Option<String> {
        env.lines().find_map(|line| {
            line.strip_prefix(key)?
                .strip_prefix('=')?
                .strip_prefix('"')?
                .strip_suffix('"')
                .map(ToOwned::to_owned)
        })
    }

    #[test]
    fn the_failback_reissue_issues_from_the_exit_authority_only() {
        // katana-xnet-150: the client's verifier key belongs to the EXIT
        // authority, so only the exit can re-issue the direct-exit bundle the
        // coupling's keep arm demands. Issuing anywhere else is the bug.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let issue = "e2e-issue-assignment-bundles-from-env";
        assert!(
            exit.recorded()
                .iter()
                .any(|call| call.join(" ").contains(issue)),
            "the exit authority must run the issuance"
        );
        for other in [&client, &relay] {
            assert!(
                !other
                    .recorded()
                    .iter()
                    .any(|call| call.join(" ").contains(issue)),
                "a non-authority node must never run the issuance"
            );
        }
    }

    #[test]
    fn the_failback_issue_env_assigns_the_client_to_the_exit_directly() {
        // The whole point: the re-issued bundle names the EXIT — not the
        // relay — as the client's upstream, or the failback fail-closes on
        // the relayed bundle.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let env = decoded_env_at(&exit, FAILBACK_ISSUE_ENV_PATH).expect("issue env written");
        assert_eq!(
            env_value(&env, "ASSIGNMENTS_SPEC").as_deref(),
            Some("exit-1|-;relay-1|exit-1;client-1|exit-1"),
            "{env}"
        );
    }

    #[test]
    fn the_failback_refresh_env_points_the_client_at_the_exit() {
        // The coupling forces a LOCAL refresh on the client; the refresh env
        // must name the exit as the upstream, or the refreshed assignment
        // regresses to the relay.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let env = decoded_env_at(&client, "/tmp/rn-assignment-refresh-client-1.env")
            .expect("client refresh env written");
        assert_eq!(
            env_value(&env, "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID").as_deref(),
            Some("client-1"),
            "{env}"
        );
        assert_eq!(
            env_value(&env, "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID").as_deref(),
            Some(EXIT_NODE_ID),
            "{env}"
        );
    }

    #[test]
    fn the_failback_issue_env_names_real_addresses_and_capabilities() {
        // The exit is spelled at its OWN address here (the alias flip is the
        // roam's, not the failback's), with the issuer-required capabilities.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let env = decoded_env_at(&exit, FAILBACK_ISSUE_ENV_PATH).expect("issue env written");
        let nodes = env_value(&env, "NODES_SPEC").expect("NODES_SPEC");
        assert_eq!(
            nodes,
            format!(
                "{EXIT_NODE_ID}|192.168.19.40:{WIREGUARD_PORT}|{PUB_HEX}|anchor,exit_server;\
                 relay-1|192.168.20.40:{WIREGUARD_PORT}|{PUB_HEX}|anchor,client;\
                 client-1|192.168.18.40:{WIREGUARD_PORT}|{PUB_HEX}"
            ),
            "{nodes}"
        );
    }

    #[test]
    fn only_the_client_gets_the_reissued_bundle_installed() {
        // The exit's and relay's own assignments are semantically unchanged
        // by the failback; re-installing them would widen the blast radius
        // of the pre-switch step for nothing.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let installed = "/var/lib/rustynet/rustynetd.assignment";
        assert!(
            client
                .recorded()
                .iter()
                .any(|call| call.join(" ").contains(installed)),
            "the client must receive the fresh bundle"
        );
        for other in [&exit, &relay] {
            assert!(
                !other
                    .recorded()
                    .iter()
                    .any(|call| call.join(" ").contains(installed)),
                "no other node may be touched"
            );
        }
    }

    #[test]
    fn the_failback_issue_env_carries_the_complete_topology() {
        // All three specs must travel in the env file: a missing ALLOW_SPEC
        // or half a node table would strand a peer after the switch.
        let client = key_runner();
        let exit = failback_exit_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        reissue_client_for_failback(&inputs, &relay_node(&relay)).expect("reissue");

        let env = decoded_env_at(&exit, FAILBACK_ISSUE_ENV_PATH).expect("issue env written");
        assert!(env_value(&env, "NODES_SPEC").is_some(), "{env}");
        assert_eq!(
            env_value(&env, "ALLOW_SPEC").as_deref(),
            Some(
                "client-1|relay-1;relay-1|client-1;client-1|exit-1;exit-1|client-1;\
                 relay-1|exit-1;exit-1|relay-1"
            ),
            "{env}"
        );
        assert!(env_value(&env, "ASSIGNMENTS_SPEC").is_some(), "{env}");
    }

    fn relay_node(relay: &MockLeafRunner) -> ScenarioNode<'_> {
        ScenarioNode::new(relay, "relay-1", "192.168.20.40")
    }

    /// An exit runner that also answers the reads of the issued pub and the
    /// CLIENT's bundle — everything the failback re-issue consumes.
    fn failback_exit_runner() -> MockLeafRunner {
        let mut exit = key_runner();
        exit.stdout_by_match.push((
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment.pub".to_owned(),
            "cHVi".to_owned(),
        ));
        exit.stdout_by_match.push((
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment-client-1.assignment"
                .to_owned(),
            "YnVuZGxl".to_owned(),
        ));
        exit
    }

    fn roam_exit_runner() -> MockLeafRunner {
        let mut exit = key_runner();
        // The roam reads the issued assignment pub, all three assignment
        // bundles, and all three dns-zone bundles off the exit.
        for needle in [
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment.pub",
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment-exit-1.assignment",
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment-relay-1.assignment",
            "base64 -w 0 /run/rustynet/assignment-issue/rn-assignment-client-1.assignment",
        ] {
            exit.stdout_by_match
                .push((needle.to_owned(), "YnVuZGxl".to_owned()));
        }
        for needle in [
            "base64 -w 0 /run/rustynet/dns-zone-issue/rn-dns-zone.pub",
            "base64 -w 0 /run/rustynet/dns-zone-issue/rn-dns-zone-exit-1.dns-zone",
            "base64 -w 0 /run/rustynet/dns-zone-issue/rn-dns-zone-relay-1.dns-zone",
            "base64 -w 0 /run/rustynet/dns-zone-issue/rn-dns-zone-client-1.dns-zone",
        ] {
            exit.stdout_by_match
                .push((needle.to_owned(), "em9uZQ==".to_owned()));
        }
        exit
    }

    #[test]
    fn the_roam_reissue_still_moves_the_exit_to_the_alias() {
        // Regression guard for the shared builder: reusing
        // `direct_exit_topology_specs` must not lose the one substitution
        // that IS the roam — the exit spelled at the alias address.
        let client = key_runner();
        let relay = key_runner();
        let exit = roam_exit_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let alias = RoamAlias {
            ip: "192.168.19.61".to_owned(),
            prefix: 32,
        };
        reissue_for_roam(
            &inputs,
            &lab,
            &relay_node(&relay),
            lab.relay_src_dir.as_deref().expect("relay src dir"),
            &alias,
        )
        .expect("roam reissue");

        let env = decoded_env_at(&exit, ROAM_ISSUE_ENV_PATH).expect("roam issue env written");
        let nodes = env_value(&env, "NODES_SPEC").expect("NODES_SPEC");
        assert!(
            nodes.contains(&format!("{EXIT_NODE_ID}|192.168.19.61:{WIREGUARD_PORT}")),
            "{nodes}"
        );
        assert!(
            !nodes.contains("192.168.19.40"),
            "the roam must abandon the exit's old address: {nodes}"
        );
    }

    #[test]
    fn failback_and_roam_specs_differ_only_in_the_exit_address() {
        // One builder for both issuances: the failback is the roam shape
        // with the exit spelled at its own address, and NOTHING else may
        // drift between them.
        let client = key_runner();
        let exit = key_runner();
        let relay = key_runner();
        let inputs = failback_inputs(&client, &exit, &relay);
        let relay = relay_node(&relay);
        let (own_nodes, own_allow, own_assignments) = direct_exit_topology_specs(
            &inputs.exit,
            &relay,
            &inputs.client,
            &inputs.exit.address,
            PUB_HEX,
            PUB_HEX,
            PUB_HEX,
        )
        .expect("own-address specs");
        let (alias_nodes, alias_allow, alias_assignments) = direct_exit_topology_specs(
            &inputs.exit,
            &relay,
            &inputs.client,
            "192.168.19.61",
            PUB_HEX,
            PUB_HEX,
            PUB_HEX,
        )
        .expect("alias specs");

        assert_ne!(own_nodes, alias_nodes, "the exit address must differ");
        let own_exit_line = own_nodes.split(';').next().expect("exit entry");
        let alias_exit_line = alias_nodes.split(';').next().expect("exit entry");
        assert_eq!(
            own_exit_line.replace("192.168.19.40", "192.168.19.61"),
            alias_exit_line,
            "only the exit's address may differ in the node table"
        );
        assert_eq!(
            own_nodes.split(';').skip(1).collect::<Vec<_>>(),
            alias_nodes.split(';').skip(1).collect::<Vec<_>>(),
            "relay and client entries must be byte-identical"
        );
        assert_eq!(own_allow, alias_allow);
        assert_eq!(own_assignments, alias_assignments);
    }

    // ── D4 fail-fast: a failed relay baseline stops the scenario ──

    /// REAL (katana-xnet-1280, cross_network_failback_roaming.log:22): the
    /// relay guest's `ip -o -4 addr show` answer carrying the 198.18/15
    /// transport alias (`valid_lft` tail elided — the parser reads the inet
    /// field, not the lease).
    const REAL_RELAY_ADDR_SHOW: &str =
        "677: rustynet-vx0    inet 198.18.10.4/16 scope global rustynet-vx0";

    /// REAL (katana-xnet-1280, cross_network_relay_remote_exit.log:188-190):
    /// the base64 TRANSPORT `base64 -w 0 /etc/rustynet/traversal.pub` returns
    /// — the string that refused the deploy ("traversal verifying key is not
    /// 64 hex characters (got 88 characters)",
    /// logs/cross_network_relay_remote_exit.log:2).
    const REAL_TRAVERSAL_PUB_TRANSPORT: &str =
        "NGRkNDI2ZGQ2NTE5MDIxNzljMjdlMmZmM2RkMjJkZGVjZmU5MjI0MDkxZDU2NWQyMDFmY2E0Y2RjNzY4MTY0Mwo=";

    /// A relay runner that fails the composed relay stage exactly the way the
    /// real katana-xnet-1280 relay did: healthy pubkey and transport alias,
    /// then the traversal.pub read returns the base64 TRANSPORT, which the
    /// hex check refuses.
    fn d4_relay_runner() -> MockLeafRunner {
        let mut relay = key_runner();
        relay.stdout_by_match.push((
            "ip -o -4 addr show".to_owned(),
            REAL_RELAY_ADDR_SHOW.to_owned(),
        ));
        relay.stdout_by_match.push((
            "cat /etc/rustynet/traversal.pub".to_owned(),
            REAL_TRAVERSAL_PUB_TRANSPORT.to_owned(),
        ));
        relay
    }

    fn wg_pub_reads(runner: &MockLeafRunner) -> usize {
        let needle = format!("cat {}", provisioning::WG_PUB_KEY_PATH);
        runner
            .recorded()
            .iter()
            .filter(|call| call.join(" ").contains(&needle))
            .count()
    }

    /// The exit answers every read the relay baseline's distribution makes
    /// with base64-shaped bytes the way the real `base64 -w 0` does — the
    /// traversal pub with the REAL katana-xnet-1280 transport.
    fn d4_exit_runner() -> MockLeafRunner {
        let mut exit = roam_exit_runner();
        exit.stdout_by_match.push((
            "base64 -w 0 /run/rustynet/traversal-issue/rn-traversal.pub".to_owned(),
            REAL_TRAVERSAL_PUB_TRANSPORT.to_owned(),
        ));
        for node in ["exit-1", "relay-1", "client-1"] {
            exit.stdout_by_match.push((
                format!("base64 -w 0 /run/rustynet/traversal-issue/rn-traversal-{node}.traversal"),
                "dHJhdg==".to_owned(),
            ));
        }
        exit
    }

    /// Stage-level: when the composed relay baseline fails (here: the REAL D4
    /// misread), the scenario must NOT roam — no role coupling on the client,
    /// no dns-zone re-issue on the exit — must restore the direct baseline
    /// (the direct provisioning runs again on both nodes) and must report the
    /// relay stage's own failure_summary, not a roam breakdown.
    #[test]
    fn a_failed_relay_baseline_stops_the_roam_restores_and_carries_the_relay_cause() {
        let host = RecordingHost::default();
        let lab = super::super::node_network_switch::test_support::lab(
            "/tmp/rustynet-cn3-tests-failback-d4",
        );
        let client = key_runner();
        let exit = d4_exit_runner();
        let relay = d4_relay_runner();
        let inputs = failback_inputs(&client, &exit, &relay);

        let outcome = run(&host, &inputs, &lab, FailbackRoamingOptions::default());

        assert!(
            !outcome.is_pass(),
            "a failed relay baseline fails the stage"
        );
        assert!(
            outcome
                .failure_summary
                .contains("traversal verifying key is not 64 hex characters (got 88 characters)"),
            "the relay cause must survive into the stage error: {}",
            outcome.failure_summary
        );
        assert!(
            outcome.failure_summary.contains("refusing to roam off it"),
            "{}",
            outcome.failure_summary
        );
        assert!(
            outcome
                .failure_summary
                .contains("direct remote-exit baseline restored"),
            "the restore must be part of the reported failure: {}",
            outcome.failure_summary
        );
        let client_cmds: Vec<String> = client
            .recorded()
            .iter()
            .map(|call| call.join(" "))
            .collect();
        assert!(
            !client_cmds
                .iter()
                .any(|c| c.contains("apply-role-coupling")),
            "no roam may be issued on a failed relay baseline: {client_cmds:?}"
        );
        let exit_cmds: Vec<String> = exit.recorded().iter().map(|call| call.join(" ")).collect();
        assert!(
            !exit_cmds.iter().any(|c| c.contains("apply-role-coupling")),
            "no roam may be issued on a failed relay baseline: {exit_cmds:?}"
        );
        // Restore proof: the direct provisioning collects the exit pubkey once
        // per provision pass — the relay baseline (1), the relay stage's own
        // D2 restore (2) and the composing scenario's restore (3).
        assert!(
            wg_pub_reads(&exit) >= 3,
            "the direct baseline provisioning must have run again after the relay failure"
        );
    }

    /// The old behaviour is red here: without the fail-fast the scenario
    /// carried on into the roam (katana-xnet-1280) and the stage error was
    /// the roam's own `route advertise` breakdown.
    #[test]
    fn the_roam_never_starts_when_the_relay_baseline_did_not_pass() {
        let host = RecordingHost::default();
        let lab = super::super::node_network_switch::test_support::lab(
            "/tmp/rustynet-cn3-tests-failback-d4b",
        );
        let client = key_runner();
        let exit = d4_exit_runner();
        let relay = d4_relay_runner();
        let inputs = failback_inputs(&client, &exit, &relay);

        let outcome = run(&host, &inputs, &lab, FailbackRoamingOptions::default());

        assert!(!outcome.is_pass());
        let client_cmds: Vec<String> = client
            .recorded()
            .iter()
            .map(|call| call.join(" "))
            .collect();
        // The roam's first guest-side acts: the coupling switch and the
        // monitor's endpoint probes. Neither may run on a failed baseline.
        assert!(
            !client_cmds
                .iter()
                .any(|c| c.contains("apply-role-coupling")),
            "{client_cmds:?}"
        );
        assert!(
            !client_cmds
                .iter()
                .any(|c| c.contains("wg show rustynet0 endpoints")),
            "{client_cmds:?}"
        );
    }
}
