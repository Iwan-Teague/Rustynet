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

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::{self, RoamAlias, SAMPLE_INTERVAL, unix_now};
use super::host::ScenarioHost;
use super::provisioning::{
    self, AllowSpec, AssignmentsSpec, EnvFile, LabContext, NodeSpec, during,
};
use super::remote_exit_common::{BypassRun, run_bypass_validator, write_trust_summary};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, WIREGUARD_PORT,
    capture_root_allow_failure, path_proven_direct, route_via_rustynet,
    rustynet_capture_allow_failure, signed_state_healthy, status, wait_for_daemon_socket,
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

/// Remote path of the roam re-issuance env file.
const ROAM_ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_roam.env";

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
    let client_endpoints = during(
        phase,
        capture_root_allow_failure(client.runner, &["wg", "show", "rustynet0", "endpoints"]),
    )?;

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
) -> String {
    if !checks.passed("failback_reconnect_within_slo") {
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
        let client_endpoints =
            capture_root_allow_failure(client.runner, &["wg", "show", "rustynet0", "endpoints"])?;
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
    // addresses. That single substitution is the whole roam.
    let nodes = during(
        phase,
        provisioning::nodes_spec(&[
            NodeSpec::new(
                exit.node_id.as_str(),
                &alias.ip,
                WIREGUARD_PORT,
                exit_pub_hex,
            )?,
            NodeSpec::new(
                relay.node_id.as_str(),
                &relay.address,
                WIREGUARD_PORT,
                relay_pub_hex,
            )?,
            NodeSpec::new(
                client.node_id.as_str(),
                &client.address,
                WIREGUARD_PORT,
                client_pub_hex,
            )?,
        ]),
    )?;
    let allow = during(
        phase,
        AllowSpec::new()
            .allow(&client.node_id, &relay.node_id)?
            .allow(&relay.node_id, &client.node_id)?
            .allow(&client.node_id, &exit.node_id)?
            .allow(&exit.node_id, &client.node_id)?
            .allow(&relay.node_id, &exit.node_id)?
            .allow(&exit.node_id, &relay.node_id)?
            .render(),
    )?;
    // Both the relay AND the client now exit via the final exit — the client no
    // longer chains through the relay. This is the failback made durable in
    // signed state.
    let assignments = during(
        phase,
        AssignmentsSpec::new()
            .assign(&exit.node_id, None)?
            .assign(&relay.node_id, Some(&exit.node_id))?
            .assign(&client.node_id, Some(&exit.node_id))?
            .render(),
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
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const EXIT_NODE_ID: &str = "exit-1";

    fn options(iterations: u32) -> FailbackRoamingOptions {
        FailbackRoamingOptions::new(DEFAULT_RECOVERY_SLO_SECS, iterations).expect("positive")
    }

    fn monitor(client: &MockLeafRunner, iterations: u32) -> FailbackObservation {
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(client, "client-1", "192.168.18.40");
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
        let client = recovered_client();
        let observed = monitor(&client, 4);
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
        let client = MockLeafRunner {
            stdout_by_match: vec![(
                "route get 1.1.1.1".to_owned(),
                "1.1.1.1 via 192.168.18.1 dev enp0s1".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let observed = monitor(&client, 3);
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
        let client = MockLeafRunner {
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
        assert!(monitor(&client, 2).first_direct_unix.is_none());
    }

    #[test]
    fn reconvergence_does_not_require_the_exit_active_state_field() {
        // The shell asked for `exit_node=`, a tunnel route and a proven direct
        // path — but not `state=ExitActive`, which the direct scenario does
        // check. Preserved rather than tightened.
        let client = MockLeafRunner {
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
        assert!(monitor(&client, 1).first_direct_unix.is_some());
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
            failback_failure_summary(&checks, options, None),
            "relay-to-direct failback exceeded reconnect SLO (30s), measured=-1s"
        );

        checks.record_bool("failback_reconnect_within_slo", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7)),
            "underlay leak detected while reconnecting during relay-to-direct failback"
        );

        checks.record_bool("no_underlay_leak_while_reconnecting", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7)),
            "signed traversal state became invalid while reconnecting during relay-to-direct \
             failback"
        );

        checks.record_bool("signed_state_valid_while_reconnecting", true);
        assert_eq!(
            failback_failure_summary(&checks, options, Some(7)),
            "relay-to-direct failback did not reconverge securely"
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
}
