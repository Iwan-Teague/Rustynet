//! `cross_network_direct_remote_exit`, ported from
//! `scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh`.
//!
//! # What this proves
//!
//! A client on one underlay prefix reaches the internet through an exit node on
//! a *different* prefix, over a path the daemon proved live and direct — and
//! the underlay does not leak around the tunnel while it does. The proof is
//! four independent observations that have to agree: the client's own view
//! (`exit_node=…`, `state=ExitActive`, `path_mode=direct_active`,
//! `path_live_proven=true`), the exit's view (`serving_exit_node=true`), the
//! kernel's view on both ends (`ip route get` leaves via `rustynet0`; the exit's
//! nftables ruleset carries a masquerade rule; `wg show … endpoints` names the
//! exit's real underlay endpoint), and a separate leak-resistance validator.
//!
//! Any one of those alone is cheap to satisfy without a working tunnel, which
//! is why the aggregate `direct_remote_exit_success` requires all of them plus
//! `signed_state_healthy` — the daemon may have selected an exit while its
//! signed traversal state was already degraded, and that is not a pass.
//!
//! # Checks the shell performed that are now structural
//!
//! Beyond the four common to every scenario (see the module docs), this one
//! drops:
//!
//! * **`live_lab_init` / `live_lab_push_sudo_password`.** Establishing the ssh
//!   identity, pinned host keys and passwordless sudo is the transport's job:
//!   commands reach the guest through a [`NetLeafRunner`] composed with
//!   [`SudoRunner`](super::super::netns::SudoRunner), which emits `sudo -n` and
//!   fails closed if it is not available. There is no separate priming step
//!   that could succeed while the transport is unusable.
//! * **`live_lab_resolved_target_address`.** The caller resolved each node's
//!   underlay address (applying any `--*-underlay-ip` override) before building
//!   [`ScenarioNode`], so there is no second resolution that could disagree
//!   with the first.
//!
//! One artifact is deliberately not reproduced: `live_lab_write_ssh_trust_summary`
//! wrote a text summary of the pinned host keys into the report's source
//! artifacts. It described the shell's own ad-hoc ssh setup, which no longer
//! exists here; the orchestrator owns host-key pinning for every stage.

use std::time::Duration;

use super::host::ScenarioHost;
use super::provisioning::{
    self, AllowSpec, AssignmentsSpec, EnvFile, LabContext, NodeSpec, during,
};
use super::remote_exit_common::{BypassRun, run_bypass_validator, write_trust_summary};
use super::{
    Checks, ScenarioInputs, ScenarioOutcome, WIREGUARD_PORT, capture_root_allow_failure,
    client_exit_selected, exit_masquerade_present, exit_serving_route, netcheck,
    no_plaintext_passphrase_check, path_proven_direct, route_via_rustynet, signed_state_healthy,
    status, wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_direct_remote_exit";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "direct_remote_exit_success",
    "remote_exit_no_underlay_leak",
    "remote_exit_server_ip_bypass_is_narrow",
    "cross_network_topology_heuristic",
    "client_exit_selected",
    "exit_serving_route",
    "client_route_via_rustynet0",
    "exit_endpoint_visible",
    "exit_masquerade_present",
    "no_plaintext_passphrase_files",
];

/// The steady-state checks `direct_remote_exit_success` aggregates. Named once
/// so the aggregate cannot drift from the list the shell spelled inline.
const STEADY_STATE_CHECKS: &[&str] = &[
    "client_exit_selected",
    "exit_serving_route",
    "client_route_via_rustynet0",
    "exit_endpoint_visible",
    "exit_masquerade_present",
    "no_plaintext_passphrase_files",
    "cross_network_topology_heuristic",
];

/// The `sleep 5` that lets the advertised route converge before evidence is
/// captured. Sampling before it turns a slow convergence into a false failure.
pub(crate) const POST_ADVERTISE_SETTLE: Duration = Duration::from_secs(5);

/// Remote path of the assignment issuance env file.
const ISSUE_ENV_PATH: &str = "/tmp/rn_issue_cross_network_direct.env";
/// Remote path of the traversal issuance env file.
const TRAVERSAL_ENV_PATH: &str = "/tmp/rn_issue_cross_network_direct_traversal.env";

/// Artifact basename of the server-IP bypass validator's report.
const BYPASS_REPORT_FILE: &str = "cross_network_direct_remote_exit_server_ip_bypass_report.json";
/// Artifact basename of the server-IP bypass validator's log.
const BYPASS_LOG_FILE: &str = "cross_network_direct_remote_exit_server_ip_bypass.log";
/// Artifact basename of the ssh trust summary.
const TRUST_SUMMARY_FILE: &str = "cross_network_direct_remote_exit_ssh_trust_summary.txt";

/// Run the direct remote-exit scenario.
///
/// Four other scenarios compose this one; they call it directly and read the
/// returned [`ScenarioOutcome`], rather than round-tripping through a report
/// file as the shell had to.
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

    // The shell declared both source artifacts and the log artifact at the top
    // of `main`, before any of them existed, so a report written from a failure
    // path still named them. Declaring them here has the same effect, and doing
    // it once fixes their order.
    artifacts
        .source
        .push(provisioning::path_arg(&lab.artifact(BYPASS_REPORT_FILE)));
    artifacts
        .source
        .push(provisioning::path_arg(&lab.artifact(TRUST_SUMMARY_FILE)));
    artifacts
        .logs
        .push(provisioning::path_arg(&lab.artifact(BYPASS_LOG_FILE)));

    // The shell wrote its trust summary before doing any work, and the report
    // spec requires that artifact to exist for a pass, so it is written first
    // here too: a scenario that cannot write its own evidence must fail before
    // it starts making claims, not after.
    write_trust_summary(
        host,
        &lab.artifact(TRUST_SUMMARY_FILE),
        SUITE,
        &[
            ("client-host", lab.client_ssh_target.as_str()),
            ("exit-host", lab.exit_ssh_target.as_str()),
        ],
    )?;

    provision(inputs, lab)?;

    // ── steady-state evidence ──
    let phase = "capturing direct remote-exit steady-state evidence";
    let client_status = during(phase, status(client.runner))?;
    let client_netcheck = during(phase, netcheck(client.runner))?;
    let exit_status = during(phase, status(exit.runner))?;
    *path_status_line = Some(client_netcheck.clone());

    // `ip -4 route get 1.1.1.1 || true` — no output is itself the evidence that
    // there is no route, so a non-zero exit is not an error here.
    let client_internet_route = during(
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
    let exit_nft = during(
        phase,
        capture_root_allow_failure(exit.runner, &["nft", "list", "ruleset"]),
    )?;
    let client_plaintext_ok = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_ok = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    let signed_state_ok = signed_state_healthy(&client_netcheck);

    checks.record_bool(
        "client_exit_selected",
        path_proven_direct(&client_netcheck) && client_exit_selected(&client_status, &exit.node_id),
    );
    checks.record_bool("exit_serving_route", exit_serving_route(&exit_status));
    checks.record_bool(
        "client_route_via_rustynet0",
        route_via_rustynet(&client_internet_route),
    );
    checks.record_bool(
        "exit_endpoint_visible",
        client_endpoints.contains(&exit.wireguard_endpoint()),
    );
    checks.record_bool(
        "exit_masquerade_present",
        exit_masquerade_present(&exit_nft),
    );
    checks.record_bool(
        "no_plaintext_passphrase_files",
        client_plaintext_ok && exit_plaintext_ok,
    );

    let topology_distinct = during(
        phase,
        provisioning::classify_cross_network_topology(&client.address, &exit.address),
    )?;
    checks.record_bool("cross_network_topology_heuristic", topology_distinct);

    checks.record_bool(
        "direct_remote_exit_success",
        checks.all_passed(STEADY_STATE_CHECKS) && signed_state_ok,
    );

    // ── leak resistance and bypass narrowness ──
    record_bypass_verdicts(host, lab, checks)?;

    if !checks.passed("direct_remote_exit_success") {
        if !checks.passed("cross_network_topology_heuristic") {
            return Err(
                "client and exit underlay addresses share the same local prefix; \
                        refusing to claim cross-network direct remote exit on same-subnet \
                        topology"
                    .to_owned(),
            );
        }
        return Err("direct remote-exit steady-state checks did not all pass".to_owned());
    }
    if !checks.passed("remote_exit_no_underlay_leak") {
        return Err("direct remote-exit path leaked or could not prove leak resistance".to_owned());
    }
    if !checks.passed("remote_exit_server_ip_bypass_is_narrow") {
        return Err(
            "server-IP bypass on the direct remote-exit path was broader than \
                    allowed"
                .to_owned(),
        );
    }
    Ok(())
}

/// Issue, distribute and enforce the signed state the scenario measures
/// against, then bring the exit's default route up.
fn provision(inputs: &ScenarioInputs<'_>, lab: &LabContext) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    let phase = "collecting WireGuard public keys";
    let exit_pub_hex = during(phase, provisioning::collect_pubkey_hex(exit.runner))?;
    let client_pub_hex = during(phase, provisioning::collect_pubkey_hex(client.runner))?;

    let phase = "building signed assignment specs";
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
            .allow(&client.node_id, &exit.node_id)?
            .allow(&exit.node_id, &client.node_id)?
            .render(),
    )?;
    let assignments = during(
        phase,
        AssignmentsSpec::new()
            .assign(&exit.node_id, None)?
            .assign(&client.node_id, Some(&exit.node_id))?
            .render(),
    )?;

    let phase = "issuing signed direct remote-exit assignments";
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
    let exit_assignment = during(
        phase,
        provisioning::read_remote_base64(
            exit.runner,
            &provisioning::issued_assignment_path(&exit.node_id)?,
        ),
    )?;
    let client_assignment = during(
        phase,
        provisioning::read_remote_base64(
            exit.runner,
            &provisioning::issued_assignment_path(&client.node_id)?,
        ),
    )?;
    during(
        phase,
        provisioning::install_assignment_bundle(
            exit.runner,
            &exit.node_id,
            &assignment_pub,
            &exit_assignment,
        ),
    )?;
    during(
        phase,
        provisioning::install_assignment_bundle(
            client.runner,
            &client.node_id,
            &assignment_pub,
            &client_assignment,
        ),
    )?;

    let exit_refresh = during(
        phase,
        provisioning::assignment_refresh_env(&exit.node_id, &nodes, &allow, None),
    )?;
    let client_refresh = during(
        phase,
        provisioning::assignment_refresh_env(&client.node_id, &nodes, &allow, Some(&exit.node_id)),
    )?;
    during(
        phase,
        provisioning::install_assignment_refresh_env(exit.runner, &exit.node_id, &exit_refresh),
    )?;
    during(
        phase,
        provisioning::install_assignment_refresh_env(
            client.runner,
            &client.node_id,
            &client_refresh,
        ),
    )?;

    let phase = "issuing signed traversal bundles for direct remote-exit topology";
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
    let exit_traversal = during(
        phase,
        provisioning::read_remote_base64(
            exit.runner,
            &provisioning::issued_traversal_path(&exit.node_id)?,
        ),
    )?;
    let client_traversal = during(
        phase,
        provisioning::read_remote_base64(
            exit.runner,
            &provisioning::issued_traversal_path(&client.node_id)?,
        ),
    )?;
    during(
        phase,
        provisioning::install_traversal_bundle(exit.runner, &traversal_pub, &exit_traversal),
    )?;
    during(
        phase,
        provisioning::install_traversal_bundle(client.runner, &traversal_pub, &client_traversal),
    )?;

    let phase = "enforcing runtime roles";
    during(
        phase,
        provisioning::enforce_host(
            exit.runner,
            "admin",
            &exit.node_id,
            &lab.exit_src_dir,
            &lab.ssh_allow_cidrs,
        ),
    )?;
    during(
        phase,
        provisioning::enforce_host(
            client.runner,
            "client",
            &client.node_id,
            &lab.client_src_dir,
            &lab.ssh_allow_cidrs,
        ),
    )?;
    during(phase, wait_for_daemon_socket(exit.runner))?;
    during(phase, wait_for_daemon_socket(client.runner))?;

    let phase = "advertising default route on remote exit";
    during(
        phase,
        super::advertise_default_route(exit.runner, lab.pace(super::ROUTE_ADVERTISE_SLEEP)),
    )?;
    lab.sleep(POST_ADVERTISE_SETTLE);
    Ok(())
}

/// Run the server-IP bypass validator and fold its verdicts in.
///
/// Reproduces the shell's two-step conclusion exactly. `no_underlay_leak`
/// requires the client's internet route to run through `rustynet0` *and* the
/// probe's service to be unreachable from the client; `bypass_is_narrow`
/// requires that same service block plus the endpoint's own route staying
/// direct and no unexpected bypass routes existing. The overlap on
/// `probe_service_blocked_from_client` is intentional: it is the observation
/// that separates "the tunnel carries traffic" from "the tunnel is the only
/// thing that carries traffic".
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
            // The exit node is the bypass validator's *probe*: the scenario asks
            // whether the client can still reach a service on the exit's
            // underlay address without going through the tunnel.
            probe_ssh_target: lab.exit_ssh_target.as_str(),
            probe_bind_ip: None,
            missing_evidence_summary: "server-IP bypass validator failed before emitting evidence",
            phase: "validating narrow server-IP bypass and leak resistance on direct \
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
