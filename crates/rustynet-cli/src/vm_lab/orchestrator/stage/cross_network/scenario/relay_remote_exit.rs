//! `cross_network_relay_remote_exit`, ported from
//! `scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh`.
//!
//! # What this proves
//!
//! A client reaches the internet through *two* hops on distinct underlay
//! prefixes: it selects the relay as its exit, and the relay in turn selects the
//! final exit. That chain is what makes this different from the direct
//! scenario, and it is why the evidence is asymmetric — the client must name the
//! RELAY as `exit_node`, while the relay must name the FINAL EXIT as its own,
//! and both intermediate hops must report `serving_exit_node=true`.
//!
//! A single node reporting `ExitActive` proves nothing about a chain, so the
//! aggregate additionally requires `relay_peer_visibility`: the relay's
//! WireGuard endpoint table must name BOTH the client's and the final exit's
//! real underlay endpoints. A relay that has one but not the other is a
//! half-built chain that could still satisfy every per-node status check.
//!
//! # Checks the shell performed that are now structural
//!
//! The four common to every scenario (see the module docs), plus `live_lab_init`
//! / `live_lab_push_sudo_password` and `live_lab_resolved_target_address` — for
//! the same reasons the direct scenario drops them, and additionally the
//! `--relay-host` distinctness guards, since the caller resolves the relay from
//! its own role slot.

use std::time::Duration;

use super::host::ScenarioHost;
use super::provisioning::{
    self, AllowSpec, AssignmentsSpec, EnvFile, LabContext, NodeSpec, during,
};
use super::remote_exit_common::{BypassRun, run_bypass_validator, write_trust_summary};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, WIREGUARD_PORT,
    capture_root_allow_failure, exit_serving_route, netcheck, no_plaintext_passphrase_check,
    path_proven_relay, relay_session_live, route_via_rustynet, signed_state_healthy, status,
    wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_relay_remote_exit";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "relay_remote_exit_success",
    "remote_exit_no_underlay_leak",
    "remote_exit_server_ip_bypass_is_narrow",
    "cross_network_topology_heuristic",
    "client_exit_is_relay",
    "relay_exit_is_final",
    "relay_serves_exit",
    "final_exit_serves",
    "client_route_via_rustynet0",
    "relay_peer_visibility",
    "no_plaintext_passphrase_files",
];

/// The steady-state checks `relay_remote_exit_success` aggregates. Named once so
/// the aggregate cannot drift from the list the shell spelled inline.
const STEADY_STATE_CHECKS: &[&str] = &[
    "client_exit_is_relay",
    "relay_exit_is_final",
    "relay_serves_exit",
    "final_exit_serves",
    "client_route_via_rustynet0",
    "relay_peer_visibility",
    "no_plaintext_passphrase_files",
    "cross_network_topology_heuristic",
];

/// The `sleep 5` that lets both advertised routes converge before evidence is
/// captured. Sampling before it turns slow convergence into a false failure.
const POST_ADVERTISE_SETTLE: Duration = Duration::from_secs(5);

/// Remote path of the assignment issuance env file.
const ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_relay.env";
/// Remote path of the traversal issuance env file.
const TRAVERSAL_ENV_PATH: &str = "/tmp/rn_issue_cross_network_relay_traversal.env";

/// Artifact basename of the server-IP bypass validator's report.
const BYPASS_REPORT_FILE: &str = "cross_network_relay_remote_exit_server_ip_bypass_report.json";
/// Artifact basename of the server-IP bypass validator's log.
const BYPASS_LOG_FILE: &str = "cross_network_relay_remote_exit_server_ip_bypass.log";
/// Artifact basename of the ssh trust summary.
const TRUST_SUMMARY_FILE: &str = "cross_network_relay_remote_exit_ssh_trust_summary.txt";

/// Run the relay remote-exit scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);
    let mut path_status_line = None;
    let mut artifacts = Artifacts::default();

    match execute(
        host,
        inputs,
        lab,
        &mut checks,
        &mut path_status_line,
        &mut artifacts,
    ) {
        Ok(()) => finish(ScenarioOutcome::passed(checks), path_status_line, artifacts),
        Err(summary) => finish(
            ScenarioOutcome::failed(checks, summary),
            path_status_line,
            artifacts,
        ),
    }
}

#[derive(Default)]
struct Artifacts {
    source: Vec<String>,
    logs: Vec<String>,
}

fn finish(
    mut outcome: ScenarioOutcome,
    path_status_line: Option<String>,
    artifacts: Artifacts,
) -> ScenarioOutcome {
    if let Some(line) = path_status_line {
        outcome = outcome.with_path_status_line(line);
    }
    outcome.source_artifacts = artifacts.source;
    outcome.log_artifacts = artifacts.logs;
    outcome
}

fn execute(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    checks: &mut Checks,
    path_status_line: &mut Option<String>,
    artifacts: &mut Artifacts,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;
    let relay = inputs.require_relay(SUITE)?;
    let relay_ssh_target = lab.require_relay_ssh_target(SUITE)?;
    let relay_src_dir = lab.relay_src_dir.as_deref().ok_or_else(|| {
        format!("{SUITE} requires a relay source directory but none was resolved")
    })?;

    // Declared before they exist, as the shell did, so a report written from a
    // failure path still names its evidence.
    artifacts
        .source
        .push(provisioning::path_arg(&lab.artifact(BYPASS_REPORT_FILE)));
    artifacts
        .source
        .push(provisioning::path_arg(&lab.artifact(TRUST_SUMMARY_FILE)));
    artifacts
        .logs
        .push(provisioning::path_arg(&lab.artifact(BYPASS_LOG_FILE)));

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

    provision(inputs, lab, relay, relay_src_dir)?;

    // ── steady-state evidence ──
    let phase = "capturing relay remote-exit steady-state evidence";
    let client_status = during(phase, status(client.runner))?;
    let client_netcheck = during(phase, netcheck(client.runner))?;
    *path_status_line = Some(client_netcheck.clone());
    let relay_status = during(phase, status(relay.runner))?;
    let exit_status = during(phase, status(exit.runner))?;

    let client_route = during(
        phase,
        provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        ),
    )?;
    let relay_endpoints = during(
        phase,
        capture_root_allow_failure(relay.runner, &["wg", "show", "rustynet0", "endpoints"]),
    )?;
    let client_plaintext_ok = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let relay_plaintext_ok = during(phase, no_plaintext_passphrase_check(relay.runner))?;
    let exit_plaintext_ok = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    let signed_state_ok = signed_state_healthy(&client_netcheck);

    // The client's own view: a LIVE relayed path, and the relay named as its
    // exit. All three netcheck clauses are required — `relay_session_state=live`
    // is what separates a relay session that exists from one carrying traffic.
    checks.record_bool(
        "client_exit_is_relay",
        path_proven_relay(&client_netcheck)
            && relay_session_live(&client_netcheck)
            && super::client_exit_selected(&client_status, &relay.node_id),
    );
    // The relay's own view: it routes onward to the FINAL exit. The shell
    // checked only `exit_node=`, not `state=ExitActive`, on this hop; that is
    // preserved rather than tightened, because tightening it here would be an
    // unreviewed behaviour change in a port.
    checks.record_bool(
        "relay_exit_is_final",
        relay_status.contains(&format!("exit_node={}", exit.node_id)),
    );
    checks.record_bool("relay_serves_exit", exit_serving_route(&relay_status));
    checks.record_bool("final_exit_serves", exit_serving_route(&exit_status));
    checks.record_bool(
        "client_route_via_rustynet0",
        route_via_rustynet(&client_route),
    );
    // Both endpoints, not either: a relay that can see only one end is a
    // half-built chain that every per-node status check would still accept.
    checks.record_bool(
        "relay_peer_visibility",
        relay_endpoints.contains(&client.wireguard_endpoint())
            && relay_endpoints.contains(&exit.wireguard_endpoint()),
    );
    checks.record_bool(
        "no_plaintext_passphrase_files",
        client_plaintext_ok && relay_plaintext_ok && exit_plaintext_ok,
    );

    // The topology heuristic compares the client against the FINAL exit, not
    // the relay: the claim being made is that traffic crossed networks
    // end-to-end, which a client and relay on one prefix would not establish.
    let topology_distinct = during(
        phase,
        provisioning::classify_cross_network_topology(&client.address, &exit.address),
    )?;
    checks.record_bool("cross_network_topology_heuristic", topology_distinct);

    checks.record_bool(
        "relay_remote_exit_success",
        checks.all_passed(STEADY_STATE_CHECKS) && signed_state_ok,
    );

    // ── leak resistance and bypass narrowness ──
    record_bypass_verdicts(host, lab, checks)?;

    if !checks.passed("relay_remote_exit_success") {
        if !checks.passed("cross_network_topology_heuristic") {
            return Err(
                "client and final-exit underlay addresses share the same local prefix; \
                        refusing to claim cross-network relay remote exit on same-subnet \
                        topology"
                    .to_owned(),
            );
        }
        return Err("relay remote-exit steady-state checks did not all pass".to_owned());
    }
    if !checks.passed("remote_exit_no_underlay_leak") {
        return Err("relay remote-exit path leaked or could not prove leak resistance".to_owned());
    }
    if !checks.passed("remote_exit_server_ip_bypass_is_narrow") {
        return Err(
            "server-IP bypass on the relay remote-exit path was broader than allowed".to_owned(),
        );
    }
    Ok(())
}

/// Issue, distribute and enforce the signed state for the three-node chain,
/// then bring both advertised default routes up.
fn provision(
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    relay: &ScenarioNode<'_>,
    relay_src_dir: &str,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    let phase = "collecting WireGuard public keys";
    let exit_pub_hex = during(phase, provisioning::collect_pubkey_hex(exit.runner))?;
    let relay_pub_hex = during(phase, provisioning::collect_pubkey_hex(relay.runner))?;
    let client_pub_hex = during(phase, provisioning::collect_pubkey_hex(client.runner))?;

    let phase = "building signed assignment specs";
    // Exit, then relay, then client — the shell's order, preserved because the
    // spec is positional text the issuer parses.
    let nodes = during(
        phase,
        provisioning::nodes_spec(&[
            NodeSpec::new(
                exit.node_id.as_str(),
                &exit.address,
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
    // Every pair in the chain is allowed in both directions. The client↔exit
    // pair is present even though traffic goes via the relay: the shell allowed
    // it and removing it here would change what the topology permits.
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
    // The chain itself: the client exits via the relay, the relay via the final
    // exit, and the final exit has none of its own.
    let assignments = during(
        phase,
        AssignmentsSpec::new()
            .assign(&exit.node_id, None)?
            .assign(&relay.node_id, Some(&exit.node_id))?
            .assign(&client.node_id, Some(&relay.node_id))?
            .render(),
    )?;

    let phase = "issuing signed relay remote-exit assignments";
    let issue_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", &nodes)?
            .set("ALLOW_SPEC", &allow)?
            .set("ASSIGNMENTS_SPEC", &assignments),
    )?;
    during(
        phase,
        provisioning::issue_assignment_bundles_from_env(exit.runner, &issue_env, ISSUE_ENV_PATH),
    )?;

    let phase = "distributing signed assignments";
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
        (client, Some(&relay.node_id)),
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

    let phase = "issuing signed traversal bundles for relay remote-exit topology";
    let traversal_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", &nodes)?
            .set("ALLOW_SPEC", &allow),
    )?;
    during(
        phase,
        provisioning::issue_traversal_bundles_from_env(
            exit.runner,
            &traversal_env,
            TRAVERSAL_ENV_PATH,
        ),
    )?;

    let phase = "distributing signed traversal bundles";
    let traversal_pub = during(
        phase,
        provisioning::read_remote_base64(exit.runner, &provisioning::issued_traversal_pub_path()),
    )?;
    for node in [exit, relay, client] {
        let bundle = during(
            phase,
            provisioning::read_remote_base64(
                exit.runner,
                &provisioning::issued_traversal_path(&node.node_id)?,
            ),
        )?;
        during(
            phase,
            provisioning::install_traversal_bundle(node.runner, &traversal_pub, &bundle),
        )?;
    }

    // The relay runs as `admin`, not a distinct relay role: the shell enforced
    // `admin` on both the relay and the final exit, and only the client as
    // `client`.
    let phase = "enforcing runtime roles";
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

    // Both intermediate hops advertise a default route: the final exit for the
    // relay, and the relay for the client. Advertising on only one leaves the
    // chain half-formed.
    let phase = "advertising default route on relay and final exit";
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

/// Run the server-IP bypass validator and fold its verdicts in.
fn record_bypass_verdicts(
    host: &dyn ScenarioHost,
    lab: &LabContext,
    checks: &mut Checks,
) -> Result<(), String> {
    let report_path = lab.artifact(BYPASS_REPORT_FILE);
    let log_path = lab.artifact(BYPASS_LOG_FILE);
    let verdicts = run_bypass_validator(
        host,
        lab,
        &BypassRun {
            report_path: &report_path,
            log_path: &log_path,
            // The FINAL exit is the probe, not the relay: the question is
            // whether the client can reach the far end of the chain without
            // traversing it.
            probe_ssh_target: lab.exit_ssh_target.as_str(),
            probe_bind_ip: None,
            missing_evidence_summary: "server-IP bypass validator failed before emitting relay evidence",
            phase: "validating narrow server-IP bypass and leak resistance on relay \
                    remote-exit path",
        },
    )?;
    checks.record_bool("remote_exit_no_underlay_leak", verdicts.no_underlay_leak);
    checks.record_bool(
        "remote_exit_server_ip_bypass_is_narrow",
        verdicts.bypass_is_narrow,
    );
    Ok(())
}
