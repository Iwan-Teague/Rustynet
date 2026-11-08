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

use rustynet_control::roles::RoleCapability;

use super::host::ScenarioHost;
use super::provisioning::{
    self, AllowSpec, AssignmentsSpec, EnvFile, LabContext, NodeSpec, RELAY_ID_LABEL,
    RELAY_TOKEN_ISSUE_ENV_PATH, deploy_relay_service, during, install_relay_token_spool,
    issue_relay_session_tokens_from_env, parse_relay_token_name, prepare_relay_token_spool,
    read_issued_relay_token_files,
};
use super::remote_exit_common::{BypassRun, run_bypass_validator, write_trust_summary};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, WIREGUARD_PORT, capture_peer_endpoints,
    exit_serving_route, netcheck, no_plaintext_passphrase_check, path_proven_relay,
    relay_session_live, route_via_rustynet, signed_state_healthy, status, wait_for_daemon_socket,
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

/// Capabilities the FINAL exit must carry in `NODES_SPEC`.
///
/// It provides exit service to the relay, so `exit_server` is mandatory or
/// `validate_assignment_exit_provider` refuses the relay's bundle; and it is
/// enforced as `admin`, which the daemon requires `anchor` for.
pub const CHAIN_EXIT_NODE_CAPABILITIES: [RoleCapability; 2] =
    [RoleCapability::Anchor, RoleCapability::ExitServer];

/// Capabilities the RELAY must carry in `NODES_SPEC`.
///
/// This chain is the one case where a node that is not the final exit is itself
/// an exit provider: the client's bundle names the relay as its `exit_node`, so
/// the relay needs `exit_server` for the same reason the final exit does. It
/// also consumes the final exit's traffic, so it keeps `client`, and it is
/// enforced as `admin`, so it needs `anchor`. These are the sets
/// `live_linux_two_hop_test` already signs for a two-hop chain.
pub const CHAIN_RELAY_NODE_CAPABILITIES: [RoleCapability; 3] = [
    RoleCapability::Anchor,
    RoleCapability::Client,
    RoleCapability::ExitServer,
];

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

    let (nodes, allow) = provision(inputs, lab, relay, relay_src_dir)?;

    // Relay session tokens live at most 120 s, so a generation minted during
    // provisioning may be near expiry by the time evidence is captured. Mint a
    // fresh generation (superseding the previous one) before the steady-state
    // captures. The standing ~90 s top-up loop is the wait-loop stage's job,
    // not this scenario's.
    // Mutating (issues on the exit, installs spools on client+exit), so the
    // same direct-baseline restore wraps it as provisioning.
    during(
        "refreshing relay session tokens",
        reissue_relay_token_spools(exit, client, &nodes, &allow),
    )
    .map_err(|failure| restore_direct_baseline_after_relay_failure(inputs, lab, failure))?;

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
    let relay_endpoints = during(phase, capture_peer_endpoints(relay.runner))?;
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
/// then bring both advertised default routes up. Returns the `NODES_SPEC` and
/// `ALLOW_SPEC` strings so the caller can mint further relay-token generations
/// against the same signed topology.
fn provision(
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    relay: &ScenarioNode<'_>,
    relay_src_dir: &str,
) -> Result<(String, String), String> {
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
            )?
            .with_capabilities(&CHAIN_EXIT_NODE_CAPABILITIES),
            NodeSpec::new(
                relay.node_id.as_str(),
                &relay.address,
                WIREGUARD_PORT,
                relay_pub_hex,
            )?
            .with_capabilities(&CHAIN_RELAY_NODE_CAPABILITIES),
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

    // The relay transport address must be resolved BEFORE any guest is
    // mutated (D2): a relay guest missing its 198.18/15 transit alias then
    // fails the stage while every node still holds its previous signed
    // state, instead of after half of the chain was already installed.
    // RELAY_SPEC (DESIGN-XNET-RELAY S2) is baked into every peer's traversal
    // bundle so the daemon accepts `type=relay` candidates pointing at the
    // relay's 198.18/15 transport address.
    let phase = "resolving the relay transport endpoint";
    let transport_endpoint = during(phase, provisioning::relay_transport_endpoint(relay.runner))?;
    let relay_spec = format!(
        "{}|{}|{}",
        relay.node_id, RELAY_ID_LABEL, transport_endpoint
    );

    // Every step from here on mutates guests. A failure at ANY of them must
    // leave the lab on the direct remote-exit baseline the composing
    // scenarios (failback_roaming, controller_switch) and the following
    // stages expect (D3): restore by re-running the direct scenario's own
    // provisioning — the same helper remote_exit_dns composes — never a
    // second restore path.
    let topology = RelayTopology {
        nodes: &nodes,
        allow: &allow,
        assignments: &assignments,
        relay_spec: &relay_spec,
        transport_endpoint: &transport_endpoint,
    };
    apply_signed_topology(inputs, lab, relay, relay_src_dir, &topology)
        .map_err(|failure| restore_direct_baseline_after_relay_failure(inputs, lab, failure))?;

    Ok((nodes, allow))
}

/// The pure-built signed-state inputs `apply_signed_topology` installs.
struct RelayTopology<'a> {
    nodes: &'a str,
    allow: &'a str,
    assignments: &'a str,
    relay_spec: &'a str,
    transport_endpoint: &'a str,
}

/// The mutating half of relay provisioning: issue, distribute and enforce
/// the signed state for the three-node chain, deploy the relay service, then
/// bring both advertised default routes up. Every step in here runs after
/// the first guest mutation, so the caller wraps the whole function in the
/// direct-baseline restore.
fn apply_signed_topology(
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    relay: &ScenarioNode<'_>,
    relay_src_dir: &str,
    topology: &RelayTopology<'_>,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    let phase = "issuing signed relay remote-exit assignments";
    let issue_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", topology.nodes)?
            .set("ALLOW_SPEC", topology.allow)?
            .set("ASSIGNMENTS_SPEC", topology.assignments),
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
                topology.nodes,
                topology.allow,
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
            .set("NODES_SPEC", topology.nodes)?
            .set("ALLOW_SPEC", topology.allow)?
            .set("TRAVERSAL_TTL_SECS", "86400")?
            .set("RELAY_SPEC", topology.relay_spec),
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

    // The relay guest now holds /etc/rustynet/traversal.pub (installed with
    // its traversal bundle), which is the token verifier key the relay service
    // requires. Deploy the service bound to the transport endpoint minted into
    // RELAY_SPEC so in-guest candidates and the actual listener agree.
    let phase = "deploying the relay service";
    during(
        phase,
        deploy_relay_service(
            relay.runner,
            relay_src_dir,
            topology.transport_endpoint,
            RELAY_ID_LABEL,
        ),
    )?;

    let phase = "re-issuing signed dns-zone bundles";
    during(
        phase,
        provisioning::reissue_dns_zone(
            exit.runner,
            topology.nodes,
            topology.allow,
            &[
                (exit.runner, &exit.node_id),
                (relay.runner, &relay.node_id),
                (client.runner, &client.node_id),
            ],
        ),
    )?;

    // The spool drop-in must be in place BEFORE `enforce_host` (re)starts the
    // daemon: a daemon that starts without RUSTYNET_RELAY_SESSION_TOKEN_SPOOL_DIR
    // set will never read the spool, and the relay session then has no local
    // token source (DESIGN-XNET-RELAY S3).
    let phase = "preparing relay token spools on client and final exit";
    during(phase, prepare_relay_token_spool(client.runner))?;
    during(phase, prepare_relay_token_spool(exit.runner))?;
    during(
        phase,
        reissue_relay_token_spools(exit, client, topology.nodes, topology.allow),
    )?;

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

/// Restore the direct remote-exit baseline after a relay-stage failure that
/// already mutated guests, appending the restore outcome to the failure text
/// (a restore failure must never be swallowed). Reuses the direct scenario's
/// own provisioning — the same helper `remote_exit_dns` composes — so there
/// is exactly one restore path, not a second one.
///
/// Also the D2 restore for the scenarios that compose this one as their relay
/// baseline (`failback_roaming`, `controller_switch`): when that baseline
/// fails they stop and call this same helper, so the lab is left on the
/// direct baseline and the original failure is always the one reported.
pub(super) fn restore_direct_baseline_after_relay_failure(
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    failure: String,
) -> String {
    match super::direct_remote_exit::restore_direct_baseline(inputs, lab) {
        Ok(()) => {
            format!("{failure}; direct remote-exit baseline restored after the relay-stage failure")
        }
        Err(restore_failure) => format!(
            "{failure}; restoring the direct remote-exit baseline ALSO failed: {restore_failure}"
        ),
    }
}

/// Mint one generation of relay session tokens on the final exit and install
/// it into the per-peer spools on the client and the exit.
///
/// `RELAY_TOKEN_PAIRS` is written client-first (`client|relay;exit|relay`) so
/// the mint's pair index doubles as the routing key: every `…-00-….relay-token`
/// file belongs to the client's spool and every `…-01-…` file to the exit's.
/// Each install supersedes the previous generation (≤128 files, expired files
/// purged before the new batch lands).
fn reissue_relay_token_spools(
    exit: &ScenarioNode<'_>,
    client: &ScenarioNode<'_>,
    nodes: &str,
    allow: &str,
) -> Result<(), String> {
    let phase = "minting relay session tokens";
    let mint_env = during(
        phase,
        EnvFile::new()
            .set("NODES_SPEC", nodes)?
            .set("ALLOW_SPEC", allow)?
            .set("RELAY_ID", RELAY_ID_LABEL)?
            .set(
                "RELAY_TOKEN_PAIRS",
                &format!(
                    "{}|{};{}|{}",
                    client.node_id, RELAY_ID_LABEL, exit.node_id, RELAY_ID_LABEL
                ),
            )?
            .set("RELAY_TOKENS_PER_PAIR", "2")?
            .set("RELAY_TOKEN_TTL_SECS", "120"),
    )?;
    during(
        phase,
        issue_relay_session_tokens_from_env(exit.runner, &mint_env, RELAY_TOKEN_ISSUE_ENV_PATH),
    )?;
    let issued = during(phase, read_issued_relay_token_files(exit.runner))?;

    let phase = "installing relay session tokens into peer spools";
    let mut client_batch = Vec::new();
    let mut exit_batch = Vec::new();
    for file in issued {
        match parse_relay_token_name(&file.name) {
            Some((_, 0, _)) => client_batch.push(file),
            Some((_, 1, _)) => exit_batch.push(file),
            _ => {
                return Err(format!(
                    "relay token {} does not route to a known peer pair",
                    file.name
                ));
            }
        }
    }
    during(
        phase,
        install_relay_token_spool(client.runner, &client_batch),
    )?;
    during(phase, install_relay_token_spool(exit.runner, &exit_batch))?;
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

#[cfg(test)]
mod provision_order_tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::NatProfileId;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    /// Substrings that appear in argv ONLY when a guest is being mutated. The
    /// read-only phases (`collect_pubkey_hex`, `relay_transport_endpoint`) use
    /// none of them, so a transcript free of these proves the failure happened
    /// BEFORE the first mutation — which is the whole point of G1/D2.
    const MUTATION_MARKERS: &[&str] = &[
        "e2e-issue",
        "e2e-enforce-host",
        "e2e-install",
        "install ",
        "groupadd",
        "sh -c",
        "rm -f",
        "systemctl",
        "test -S",
        "route advertise",
        "rn_issue_",
    ];

    /// `ip -o -4 addr show` output in the real line format the run 1271 relay
    /// guest produced — with NO 198.18.0.0/15 address anywhere.
    const ADDR_SHOW_WITHOUT_TRANSIT_ALIAS: &str = concat!(
        "1: lo    inet 127.0.0.1/8 scope host lo\n",
        "2: ens3    inet 192.168.122.57/24 brd 192.168.122.255 scope global ens3\n",
        "646: rustynet-vx0    inet 172.20.10.4/16 brd 172.20.255.255 scope global rustynet-vx0\n",
        "647: rustynet0    inet 100.95.194.56/32 scope global rustynet0\n",
    );

    /// The same guest AFTER G3: exactly one 198.18.0.0/15 secondary alias on
    /// rustynet-vx0.
    const ADDR_SHOW_WITH_TRANSIT_ALIAS: &str = concat!(
        "1: lo    inet 127.0.0.1/8 scope host lo\n",
        "2: ens3    inet 192.168.122.57/24 brd 192.168.122.255 scope global ens3\n",
        "646: rustynet-vx0    inet 172.20.10.4/16 brd 172.20.255.255 scope global rustynet-vx0\n",
        "646: rustynet-vx0    inet 198.18.10.4/16 brd 198.18.255.255 scope global secondary rustynet-vx0\n",
        "647: rustynet0    inet 100.95.194.56/32 scope global rustynet0\n",
    );

    /// Two DIFFERENT 198.18.0.0/15 addresses — the ambiguity
    /// `unique_ipv4_in_benchmark_prefix` must refuse.
    const ADDR_SHOW_WITH_TWO_TRANSIT_ALIASES: &str = concat!(
        "646: rustynet-vx0    inet 198.18.10.4/16 brd 198.18.255.255 scope global secondary rustynet-vx0\n",
        "647: rustynet-vx0    inet 198.18.10.5/16 brd 198.18.255.255 scope global secondary rustynet-vx0\n",
    );

    /// A stdout that `collect_pubkey_hex` accepts: standard base64 decoding to
    /// exactly 32 bytes.
    fn pubkey_stdout() -> String {
        format!("{}=", "A".repeat(43))
    }

    /// A runner whose only scripted answer is its WireGuard public key.
    fn pubkey_runner() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![(provisioning::WG_PUB_KEY_PATH.to_owned(), pubkey_stdout())],
            ..MockLeafRunner::default()
        }
    }

    /// The issuer (exit) runner for the fail-injection tests: public key plus
    /// a base64 blob for every `base64 -w 0` bundle read, failing at the
    /// scripted call indexes.
    fn issuer_runner(fail_on: Vec<usize>, failure_stderr: &str) -> MockLeafRunner {
        MockLeafRunner {
            fail_on,
            failure_stderr: failure_stderr.to_owned(),
            stdout_by_match: vec![
                (provisioning::WG_PUB_KEY_PATH.to_owned(), pubkey_stdout()),
                ("base64 -w 0".to_owned(), "QUFB".to_owned()),
            ],
            ..MockLeafRunner::default()
        }
    }

    /// The relay runner: public key plus the scripted `addr show` output.
    fn relay_runner(addr_show: &str, transport_error_on: Vec<usize>) -> MockLeafRunner {
        MockLeafRunner {
            transport_error_on,
            stdout_by_match: vec![
                (provisioning::WG_PUB_KEY_PATH.to_owned(), pubkey_stdout()),
                ("addr show".to_owned(), addr_show.to_owned()),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn lab_context() -> LabContext {
        LabContext {
            ssh_identity_file: std::path::PathBuf::from("/tmp/rn-test-id_ed25519"),
            ssh_allow_cidrs: "192.168.122.0/24".to_owned(),
            artifact_dir: std::path::PathBuf::from("/tmp/rn-test-artifacts"),
            client_ssh_target: "user@client".to_owned(),
            exit_ssh_target: "user@exit".to_owned(),
            relay_ssh_target: Some("user@relay".to_owned()),
            probe_ssh_target: None,
            client_network_id: "net-client".to_owned(),
            exit_network_id: "net-exit".to_owned(),
            relay_network_id: Some("net-relay".to_owned()),
            client_src_dir: "/srv/rustynet-client".to_owned(),
            exit_src_dir: "/srv/rustynet-exit".to_owned(),
            relay_src_dir: Some("/srv/rustynet-relay".to_owned()),
            time_scale: provisioning::TimeScale::Collapsed,
        }
    }

    fn inputs_for<'a>(
        client: &'a MockLeafRunner,
        exit: &'a MockLeafRunner,
        relay: &'a MockLeafRunner,
    ) -> ScenarioInputs<'a> {
        ScenarioInputs {
            client: ScenarioNode::new(client, "katana-client-1", "192.168.64.10"),
            exit: ScenarioNode::new(exit, "katana-exit-1", "192.168.122.57"),
            relay: Some(ScenarioNode::new(relay, "katana-relay-1", "192.168.122.99")),
            probe: None,
            nat_profile: NatProfileId::parse("baseline_lan").expect("known profile"),
            impairment_profile: String::new(),
        }
    }

    /// Assert a runner's transcript holds only read-only argv.
    fn assert_no_mutations(runner: &MockLeafRunner, label: &str) {
        for call in runner.recorded() {
            let joined = call.join(" ");
            for marker in MUTATION_MARKERS {
                assert!(
                    !joined.contains(marker),
                    "{label} transcript holds a mutation ({marker}): {joined}"
                );
            }
        }
    }

    /// Assert some recorded argv contains every one of `needles`.
    fn assert_recorded_once_containing(runner: &MockLeafRunner, needles: &[&str], label: &str) {
        let hits = runner
            .recorded()
            .iter()
            .filter(|call| {
                let joined = call.join(" ");
                needles.iter().all(|needle| joined.contains(needle))
            })
            .count();
        assert!(
            hits >= 1,
            "{label} transcript holds no argv containing {needles:?}"
        );
    }

    /// D2, red-first: a relay guest with no 198.18.0.0/15 address fails the
    /// stage at endpoint resolution, and NO guest was mutated — the failure
    /// the run 1271 transcript paid for only AFTER installing half the chain.
    #[test]
    fn missing_transit_alias_fails_at_endpoint_resolution_before_any_mutation() {
        let client = pubkey_runner();
        let exit = pubkey_runner();
        let relay = relay_runner(ADDR_SHOW_WITHOUT_TRANSIT_ALIAS, Vec::new());
        let inputs = inputs_for(&client, &exit, &relay);
        let relay_node = inputs.require_relay(SUITE).expect("relay present");

        let err = provision(&inputs, &lab_context(), relay_node, "/srv/rustynet-relay")
            .expect_err("provision must fail without a 198.18/15 alias");

        assert!(
            err.contains("resolving the relay transport endpoint"),
            "phase missing: {err}"
        );
        assert!(
            err.contains("no 198.18.0.0/15 address found on the relay guest"),
            "cause missing: {err}"
        );
        // The relay was asked for its keys and its addresses — nothing else.
        assert_eq!(relay.recorded().len(), 2, "{:?}", relay.recorded());
        assert_no_mutations(&client, "client");
        assert_no_mutations(&exit, "exit");
        assert_no_mutations(&relay, "relay");
    }

    /// A transport failure while READING the addresses also fails closed
    /// before any mutation: not being able to ask is not an empty answer.
    #[test]
    fn addr_show_transport_failure_fails_closed_before_any_mutation() {
        let client = pubkey_runner();
        let exit = pubkey_runner();
        // call 0 = `cat` public key, call 1 = `ip -o -4 addr show`.
        let relay = relay_runner(ADDR_SHOW_WITHOUT_TRANSIT_ALIAS, vec![1]);
        let inputs = inputs_for(&client, &exit, &relay);
        let relay_node = inputs.require_relay(SUITE).expect("relay present");

        let err = provision(&inputs, &lab_context(), relay_node, "/srv/rustynet-relay")
            .expect_err("transport failure must fail closed");

        assert!(
            err.contains("resolving the relay transport endpoint"),
            "phase missing: {err}"
        );
        assert!(err.contains("transport failure"), "cause missing: {err}");
        assert_no_mutations(&client, "client");
        assert_no_mutations(&exit, "exit");
        assert_no_mutations(&relay, "relay");
    }

    /// Two distinct 198.18.0.0/15 addresses are refused — deploying the relay
    /// on a guessed address would mint bundles no peer can use — and again
    /// BEFORE any mutation.
    #[test]
    fn ambiguous_transit_alias_fails_closed_before_any_mutation() {
        let client = pubkey_runner();
        let exit = pubkey_runner();
        let relay = relay_runner(ADDR_SHOW_WITH_TWO_TRANSIT_ALIASES, Vec::new());
        let inputs = inputs_for(&client, &exit, &relay);
        let relay_node = inputs.require_relay(SUITE).expect("relay present");

        let err = provision(&inputs, &lab_context(), relay_node, "/srv/rustynet-relay")
            .expect_err("two aliases must be refused");

        assert!(
            err.contains("multiple 198.18.0.0/15 addresses on the relay guest"),
            "cause missing: {err}"
        );
        assert_no_mutations(&client, "client");
        assert_no_mutations(&exit, "exit");
        assert_no_mutations(&relay, "relay");
    }

    /// D3 fail-injection: the issuer refusing the RELAY assignment issuance
    /// (the first guest mutation) reports the original failure AND restores
    /// the direct remote-exit baseline — the direct issuance argv appears on
    /// the exit runner, the client is re-enforced, and the relay guest is
    /// left untouched by the restore.
    #[test]
    fn relay_issuance_failure_restores_the_direct_baseline() {
        let client = pubkey_runner();
        // exit calls: 0 = cat pubkey, 1 = sh -c env write (relay env),
        // 2 = rustynet ops e2e-issue-assignment-bundles-from-env → FAIL,
        // 3 = rm -f env cleanup, then the restore runs to completion.
        let exit = issuer_runner(vec![2], "issuer refused: signing quota exceeded");
        let relay = relay_runner(ADDR_SHOW_WITH_TRANSIT_ALIAS, Vec::new());
        let inputs = inputs_for(&client, &exit, &relay);
        let relay_node = inputs.require_relay(SUITE).expect("relay present");

        let err = provision(&inputs, &lab_context(), relay_node, "/srv/rustynet-relay")
            .expect_err("issuer refusal must fail the stage");

        assert!(
            err.contains("issuing signed relay remote-exit assignments"),
            "phase missing: {err}"
        );
        assert!(
            err.contains("issuer refused: signing quota exceeded"),
            "cause missing: {err}"
        );
        assert!(
            err.contains("direct remote-exit baseline restored after the relay-stage failure"),
            "restore outcome missing: {err}"
        );
        // The restore re-ran the DIRECT provisioning: the direct env file's
        // issuance argv is on the exit runner, and the client guest was
        // re-enforced by it.
        assert_recorded_once_containing(
            &exit,
            &[
                "e2e-issue-assignment-bundles-from-env",
                "/tmp/rn_issue_cross_network_direct.env",
            ],
            "exit",
        );
        assert_recorded_once_containing(&client, &["e2e-enforce-host"], "client");
        // The relay guest took no part in the restore.
        assert_no_mutations(&relay, "relay");
    }

    /// A restore that itself fails must never be swallowed: the error names
    /// BOTH the relay failure and the direct-baseline restore failure.
    #[test]
    fn restore_failure_is_surfaced_not_swallowed() {
        let client = pubkey_runner();
        // 2 = relay issuance fails; 6 = the RESTORE's direct issuance fails
        // (4 = cat, 5 = env write sit between).
        let exit = issuer_runner(vec![2, 6], "issuer refused: signing quota exceeded");
        let relay = relay_runner(ADDR_SHOW_WITH_TRANSIT_ALIAS, Vec::new());
        let inputs = inputs_for(&client, &exit, &relay);
        let relay_node = inputs.require_relay(SUITE).expect("relay present");

        let err = provision(&inputs, &lab_context(), relay_node, "/srv/rustynet-relay")
            .expect_err("double issuance failure must fail the stage");

        assert!(
            err.contains("issuing signed relay remote-exit assignments"),
            "relay phase missing: {err}"
        );
        assert!(
            err.contains("; restoring the direct remote-exit baseline ALSO failed:"),
            "restore failure missing: {err}"
        );
        assert!(
            err.contains("issuing signed direct remote-exit assignments"),
            "restore phase missing: {err}"
        );
    }
}
