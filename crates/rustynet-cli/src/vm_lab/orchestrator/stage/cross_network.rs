#![allow(dead_code)]
pub mod netns;
pub mod scenario;
pub mod slirp;
pub mod substrate;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_PROFILE: &str = "baseline_lan";
const DEFAULT_IMPAIRMENT_PROFILE: &str = "none";

/// The default NAT profile as the validated type. `DEFAULT_PROFILE` is one of
/// `KNOWN_NAT_PROFILES`, which the
/// [`default_nat_profile_is_in_the_closed_vocabulary`] test pins, so this
/// cannot become an unrepresentable default without a failing test.
fn default_nat_profile() -> substrate::NatProfileId {
    substrate::NatProfileId::parse(DEFAULT_PROFILE)
        .unwrap_or_else(|err| unreachable!("the default NAT profile must be known: {err}"))
}
// The netns NAT gates used to be three bash scripts scp'd to the exit guest
// and run under `sudo -n bash`. They are now the typed in-process
// `netns::run_nat_gates` (CN-2), so nothing is copied to the guest but the
// `rustynet-netns-probe` binary the gate builds there. The evidence file this
// stage writes.
const NAT_GATE_REPORT_FILE: &str = "cross_network_nat_gates.txt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossNetworkOptions {
    pub enable_suite: bool,
    /// The requested NAT profiles, as validated [`substrate::NatProfileId`]s.
    ///
    /// CN-4 tightened these from free strings onto the closed §D5.1 vocabulary
    /// (owner-approved, `OwnerDecisionDigest_2026-08-27.md` §16): an unknown
    /// name is now a parse-time error naming the five valid profiles, instead
    /// of a shape-validated string that reached a substrate which could only
    /// answer "I do not know that profile" much later, on a guest.
    pub nat_profiles: Vec<substrate::NatProfileId>,
    pub required_nat_profiles: Vec<substrate::NatProfileId>,
    /// NOT a NAT profile: the netem impairment name, whose vocabulary lives in
    /// [`netns::NetnsImpairment`]. It keeps shape-only validation here because
    /// the impairment is applied by a substrate that may not be netns.
    pub impairment_profile: String,
    pub substrate: CrossNetworkSubstrate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrossNetworkSubstrate {
    Netns,
    Vxlan,
    Slirp,
}

impl CrossNetworkSubstrate {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "netns" => Ok(Self::Netns),
            "vxlan" => Ok(Self::Vxlan),
            "slirp" => Ok(Self::Slirp),
            other => Err(format!(
                "invalid --cross-network-substrate {other:?}; expected netns|vxlan|slirp"
            )),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Netns => "netns",
            Self::Vxlan => "vxlan",
            Self::Slirp => "slirp",
        }
    }
}

impl CrossNetworkOptions {
    pub fn disabled() -> Self {
        Self {
            enable_suite: false,
            ..Self::default()
        }
    }

    pub fn from_cli(
        enable_suite: bool,
        nat_profiles: Option<&str>,
        required_nat_profiles: Option<&str>,
        impairment_profile: Option<&str>,
        substrate: Option<&str>,
    ) -> Result<Self, String> {
        let nat_profiles = match nat_profiles {
            Some(value) => parse_profile_csv(value, "--cross-network-nat-profiles")?,
            None => vec![default_nat_profile()],
        };
        let required_nat_profiles = match required_nat_profiles {
            Some(value) => parse_profile_csv(value, "--cross-network-required-nat-profiles")?,
            None if nat_profiles.len() == 1 && nat_profiles[0] == default_nat_profile() => {
                vec![default_nat_profile()]
            }
            None => nat_profiles.clone(),
        };
        let impairment_profile = match impairment_profile {
            Some(value) => parse_profile_value(value, "--cross-network-impairment-profile")?,
            None => DEFAULT_IMPAIRMENT_PROFILE.to_owned(),
        };
        let substrate = match substrate {
            Some(value) => CrossNetworkSubstrate::parse(value)?,
            None => CrossNetworkSubstrate::Netns,
        };
        let options = Self {
            enable_suite,
            nat_profiles,
            required_nat_profiles,
            impairment_profile,
            substrate,
        };
        validate_cross_network_options(&options)?;
        Ok(options)
    }
}

impl Default for CrossNetworkOptions {
    fn default() -> Self {
        Self {
            enable_suite: true,
            nat_profiles: vec![default_nat_profile()],
            required_nat_profiles: vec![default_nat_profile()],
            impairment_profile: DEFAULT_IMPAIRMENT_PROFILE.to_owned(),
            substrate: CrossNetworkSubstrate::Netns,
        }
    }
}

#[derive(Clone, Copy)]
enum CrossNetworkStageKind {
    Preflight,
    DirectRemoteExit,
    NodeNetworkSwitch,
    RelayRemoteExit,
    FailbackRoaming,
    ControllerSwitch,
    TraversalAdversarial,
    RemoteExitDns,
    RemoteExitSoak,
    NatClassification,
    NatMatrix,
}

struct CrossNetworkStageSpec {
    id: StageId,
    name: &'static str,
    kind: CrossNetworkStageKind,
}

macro_rules! cross_network_stage {
    ($type_name:ident, $id:ident, $name:literal, $kind:ident) => {
        pub struct $type_name {
            options: CrossNetworkOptions,
        }

        impl $type_name {
            pub fn new(options: CrossNetworkOptions) -> Self {
                Self { options }
            }

            const SPEC: CrossNetworkStageSpec = CrossNetworkStageSpec {
                id: StageId::$id,
                name: $name,
                kind: CrossNetworkStageKind::$kind,
            };
        }

        impl OrchestrationStage for $type_name {
            fn id(&self) -> StageId {
                Self::SPEC.id.clone()
            }

            fn name(&self) -> &str {
                Self::SPEC.name
            }

            fn dependencies(&self) -> &[StageId] {
                &[StageId::LiveMixedTopologyValidation]
            }

            fn applies_to_roles(&self) -> &[NodeRole] {
                &[]
            }

            fn fanout(&self) -> StageFanout {
                StageFanout::Once
            }

            fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
                run_cross_network_stage(ctx, &self.options, &Self::SPEC)
            }
        }
    };
}

cross_network_stage!(
    CrossNetworkPreflightStage,
    CrossNetworkPreflight,
    "cross_network_preflight",
    Preflight
);
cross_network_stage!(
    CrossNetworkDirectRemoteExitStage,
    CrossNetworkDirectRemoteExit,
    "cross_network_direct_remote_exit",
    DirectRemoteExit
);
cross_network_stage!(
    CrossNetworkNodeNetworkSwitchStage,
    CrossNetworkNodeNetworkSwitch,
    "cross_network_node_network_switch",
    NodeNetworkSwitch
);
cross_network_stage!(
    CrossNetworkRelayRemoteExitStage,
    CrossNetworkRelayRemoteExit,
    "cross_network_relay_remote_exit",
    RelayRemoteExit
);
cross_network_stage!(
    CrossNetworkFailbackRoamingStage,
    CrossNetworkFailbackRoaming,
    "cross_network_failback_roaming",
    FailbackRoaming
);
cross_network_stage!(
    CrossNetworkControllerSwitchStage,
    CrossNetworkControllerSwitch,
    "cross_network_controller_switch",
    ControllerSwitch
);
cross_network_stage!(
    CrossNetworkTraversalAdversarialStage,
    CrossNetworkTraversalAdversarial,
    "cross_network_traversal_adversarial",
    TraversalAdversarial
);
cross_network_stage!(
    CrossNetworkRemoteExitDnsStage,
    CrossNetworkRemoteExitDns,
    "cross_network_remote_exit_dns",
    RemoteExitDns
);
cross_network_stage!(
    CrossNetworkRemoteExitSoakStage,
    CrossNetworkRemoteExitSoak,
    "cross_network_remote_exit_soak",
    RemoteExitSoak
);
cross_network_stage!(
    CrossNetworkNatClassificationStage,
    CrossNetworkNatClassification,
    "cross_network_nat_classification",
    NatClassification
);
cross_network_stage!(
    CrossNetworkNatMatrixStage,
    CrossNetworkNatMatrix,
    "cross_network_nat_matrix",
    NatMatrix
);

fn run_cross_network_stage(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
    spec: &CrossNetworkStageSpec,
) -> StageOutcome {
    if !options.enable_suite {
        return StageOutcome::Skipped(
            "the cross-network suite is not enabled for this run".to_owned(),
        );
    }
    if options.nat_profiles.is_empty() || options.required_nat_profiles.is_empty() {
        return StageOutcome::Failed(
            "cross-network NAT profile lists must not be empty".to_owned(),
        );
    }
    if let Err(err) = validate_cross_network_options(options) {
        return StageOutcome::Failed(err);
    }

    match spec.kind {
        CrossNetworkStageKind::Preflight => run_preflight(ctx, spec.name),
        CrossNetworkStageKind::NatClassification => run_nat_classification(ctx, options),
        CrossNetworkStageKind::NatMatrix => run_nat_matrix(ctx, options),
        // CN-3: ported scenarios run in-process; the rest still go through the
        // `cargo run --bin` fan below until their own port lands.
        CrossNetworkStageKind::DirectRemoteExit | CrossNetworkStageKind::RelayRemoteExit => {
            run_ported_scenario_stage(ctx, options, spec)
        }
        CrossNetworkStageKind::NodeNetworkSwitch
        | CrossNetworkStageKind::FailbackRoaming
        | CrossNetworkStageKind::ControllerSwitch
        | CrossNetworkStageKind::TraversalAdversarial
        | CrossNetworkStageKind::RemoteExitDns
        | CrossNetworkStageKind::RemoteExitSoak => run_script_stage(ctx, options, spec),
    }
}

fn run_preflight(ctx: &OrchestrationContext, stage_name: &str) -> StageOutcome {
    let stage_dir = ctx.report_dir.join(stage_name);
    if let Err(err) = fs::create_dir_all(stage_dir.as_path()) {
        return StageOutcome::Failed(format!("create {stage_name} dir failed: {err}"));
    }
    let nodes_tsv = stage_dir.join("nodes.tsv");
    if let Err(err) = write_nodes_tsv(ctx, nodes_tsv.as_path()) {
        return StageOutcome::Failed(err);
    }
    let reference_unix = unix_now().to_string();
    let output = stage_dir.join("cross_network_preflight_report.json");
    let mut cmd = cargo_ops_command("write-cross-network-preflight-report");
    cmd.arg("--nodes-tsv")
        .arg(&nodes_tsv)
        .arg("--stage-dir")
        .arg(&stage_dir)
        .arg("--output")
        .arg(&output)
        .arg("--reference-unix")
        .arg(reference_unix)
        .arg("--max-clock-skew-secs")
        .arg("300")
        .arg("--discovery-max-age-secs")
        .arg("86400")
        .arg("--signed-artifact-max-age-secs")
        .arg("86400");
    run_command(cmd, "write-cross-network-preflight-report")
}

fn run_nat_classification(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
) -> StageOutcome {
    if options.substrate != CrossNetworkSubstrate::Netns {
        return StageOutcome::Skipped(
            "this stage requires the netns cross-network substrate".to_owned(),
        );
    }
    let (alias, host) = match alias_and_remote_host_for_role(ctx, "exit") {
        Ok(pair) => pair,
        Err(err) => return StageOutcome::Failed(err),
    };
    let stage_dir = ctx.report_dir.join("cross_network_nat_classification");
    if let Err(err) = fs::create_dir_all(stage_dir.as_path()) {
        return StageOutcome::Failed(format!(
            "create cross_network_nat_classification dir failed: {err}"
        ));
    }
    let log_path = stage_dir.join("cross_network_nat_classification.log");

    // No python3 requirement any more — the netns probes are the Rust
    // `rustynet-netns-probe` binary. `nft` and `ip` do the topology work and
    // `systemd-run` runs the STUN responders as transient units, so all three
    // are hard prerequisites.
    let dependency_check = "sudo -n bash -lc 'nft --version >/dev/null 2>&1 && ip -V >/dev/null 2>&1 && systemd-run --version >/dev/null 2>&1'";
    if let Some(outcome) =
        run_ssh_checked(&host, dependency_check, &log_path, "netns dependency check")
    {
        return outcome;
    }

    // Build the Rust netns probe on-guest (std-only → offline, no new cargo-cache
    // entries) from the deployed source, then stage it at the path the gate
    // invokes (`/tmp/rustynet-netns-probe`). Runs as the SSH user (cargo is on
    // the user PATH from bootstrap); `chmod +x` keeps it executable by the
    // root-run probes.
    let build_probe = "bash -lc 'cd \"$HOME/Rustynet\" && cargo build --release -p rustynet-netns-probe && install -m 0755 target/release/rustynet-netns-probe /tmp/rustynet-netns-probe'";
    if let Some(outcome) = run_ssh_checked(
        &host,
        build_probe,
        &log_path,
        "build+stage rustynet-netns-probe",
    ) {
        return outcome;
    }

    // The simulator is built entirely inside the guest, so the guest's own
    // address is evidence only — but it must be a literal, because a handle
    // that cannot name the host it provisioned cannot report where residue is.
    let host_ip: Ipv4Addr = match host.host.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return StageOutcome::Failed(format!(
                "cross_network_nat_classification: exit node '{alias}' management host {:?} is \
                 not an IPv4 literal",
                host.host
            ));
        }
    };
    let runner = substrate::RemoteShellRunner::new(host, log_path.clone(), alias.clone());
    let sleep = |duration: std::time::Duration| std::thread::sleep(duration);
    let gate_ctx = netns::NatGateContext {
        host_alias: alias.as_str(),
        host_ip,
        sleep: &sleep,
    };
    match netns::run_nat_gates(&runner, &gate_ctx) {
        // Err = the gate could not RUN (topology would not build, guest
        // unreachable). That is a stage failure, and it is deliberately NOT
        // the same thing as a NAT that misbehaved.
        Err(err) => {
            write_nat_gate_report(&stage_dir, &[], Some(err.as_str()));
            StageOutcome::Failed(format!("netns NAT gate could not run: {err}"))
        }
        Ok(checks) => {
            write_nat_gate_report(&stage_dir, &checks, None);
            let failed: Vec<String> = checks
                .iter()
                .filter(|check| !check.passed)
                .map(|check| {
                    format!(
                        "{}/{}/{} expected={} observed={}",
                        check.gate, check.profile, check.scenario, check.expected, check.observed
                    )
                })
                .collect();
            if failed.is_empty() {
                StageOutcome::Passed
            } else {
                StageOutcome::Failed(format!(
                    "{} of {} netns NAT checks misbehaved: {}",
                    failed.len(),
                    checks.len(),
                    failed.join("; ")
                ))
            }
        }
    }
}

/// Write every gate row, pass or fail, so the evidence says WHICH profile
/// misbehaved rather than only that one did. Best-effort: a report we could
/// not write must not turn a green gate red, and the stage outcome already
/// carries the verdict.
fn write_nat_gate_report(stage_dir: &Path, checks: &[netns::GateCheck], error: Option<&str>) {
    let mut body = String::from("== netns NAT mapping + filtering gates ==\n");
    for check in checks {
        body.push_str(&check.render());
        body.push('\n');
    }
    if let Some(error) = error {
        body.push_str(&format!("GATE COULD NOT RUN: {error}\n"));
    }
    let _ = fs::write(stage_dir.join(NAT_GATE_REPORT_FILE), body);
}

fn run_nat_matrix(ctx: &OrchestrationContext, options: &CrossNetworkOptions) -> StageOutcome {
    if options.substrate != CrossNetworkSubstrate::Vxlan {
        return StageOutcome::Skipped(
            "this stage requires a cross-network substrate that supports the NAT matrix".to_owned(),
        );
    }
    let mut cmd = cargo_ops_command("validate-cross-network-nat-matrix");
    cmd.arg("--artifact-dir")
        .arg(&ctx.report_dir)
        .arg("--required-nat-profiles")
        .arg(
            options
                .required_nat_profiles
                .iter()
                .map(substrate::NatProfileId::as_str)
                .collect::<Vec<_>>()
                .join(","),
        )
        .arg("--require-pass-status")
        .arg("--output")
        .arg(
            ctx.report_dir
                .join("cross_network_nat_matrix_validation.md"),
        );
    if let Ok(commit) = git_head_commit() {
        cmd.arg("--expected-git-commit").arg(commit);
    }
    run_command(cmd, "validate-cross-network-nat-matrix")
}

/// The topology guards and stage directory every cross-network scenario stage
/// needs, resolved once. Factored out of [`run_script_stage`] so the ported
/// (in-process) and unported (`cargo run --bin`) paths cannot drift on which
/// topologies they refuse to run against.
fn prepare_scenario_stage(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
    spec: &CrossNetworkStageSpec,
) -> Result<(CrossNetworkTopology, PathBuf), StageOutcome> {
    if options.substrate != CrossNetworkSubstrate::Vxlan {
        return Err(StageOutcome::Skipped(
            "this stage requires the vxlan cross-network substrate".to_owned(),
        ));
    }
    let topology = match CrossNetworkTopology::resolve(ctx) {
        Ok(topology) => topology,
        Err(TopologyError::MissingRole(())) => {
            return Err(StageOutcome::Skipped(
                "cross-network topology requires a role that no node in this topology is assigned"
                    .to_owned(),
            ));
        }
        Err(TopologyError::Message(err)) => return Err(StageOutcome::Failed(err)),
    };
    if !topology.distinct_underlay_prefixes() {
        return Err(StageOutcome::Skipped(
            "cross-network requires the nodes to sit on distinct underlay prefixes; this \
             topology puts them on one"
                .to_owned(),
        ));
    }

    let stage_dir = ctx.report_dir.join(spec.name);
    if let Err(err) = fs::create_dir_all(stage_dir.as_path()) {
        return Err(StageOutcome::Failed(format!(
            "create {} dir failed: {err}",
            spec.name
        )));
    }
    Ok((topology, stage_dir))
}

/// CN-3: run `cross_network_direct_remote_exit` in process.
///
/// The three process boundaries the old path carried — orchestrator → `cargo
/// run` → bin shim → bash — are gone. The scenario is a function call, every
/// remote command is an argv vector on a [`substrate::NetLeafRunner`], and the
/// report is written here from the single [`scenario::ScenarioOutcome`] the
/// scenario returns, so the report cannot disagree with what the scenario
/// proved.
fn run_ported_scenario_stage(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
    spec: &CrossNetworkStageSpec,
) -> StageOutcome {
    let (topology, stage_dir) = match prepare_scenario_stage(ctx, options, spec) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };

    for (idx, profile) in options.nat_profiles.iter().enumerate() {
        // The path helpers are shared with the unported `cargo run --bin` fan
        // and still key directories off the profile NAME, so the string is
        // borrowed here and nowhere else; the profile itself stays typed all
        // the way into the scenario.
        let report_path = stage_report_path_for_idx(&stage_dir, spec.name, profile.as_str(), idx);
        let log_path = stage_log_path_for_idx(&stage_dir, spec.name, profile.as_str(), idx);
        let outcome = run_ported_scenario_profile(
            ctx,
            &topology,
            options,
            spec.kind,
            profile,
            report_path.as_path(),
            log_path.as_path(),
        );
        if !matches!(outcome, StageOutcome::Passed) {
            return outcome;
        }
    }
    StageOutcome::Passed
}

/// One NAT profile's run of a ported scenario.
fn run_ported_scenario_profile(
    ctx: &OrchestrationContext,
    topology: &CrossNetworkTopology,
    options: &CrossNetworkOptions,
    kind: CrossNetworkStageKind,
    nat_profile: &substrate::NatProfileId,
    report_path: &Path,
    log_path: &Path,
) -> StageOutcome {
    // Only the relay scenarios resolve a relay. Building one unconditionally
    // would open an ssh transport to a node the direct scenario never touches.
    let needs_relay = matches!(kind, CrossNetworkStageKind::RelayRemoteExit);
    let client_remote = match remote_host_for_role(ctx, "client") {
        Ok(host) => host,
        Err(err) => return StageOutcome::Failed(err),
    };
    let exit_remote = match remote_host_for_role(ctx, "exit") {
        Ok(host) => host,
        Err(err) => return StageOutcome::Failed(err),
    };
    let client_src_dir = match scenario_src_dir(&topology.client) {
        Ok(dir) => dir,
        Err(err) => return StageOutcome::Failed(err),
    };
    let exit_src_dir = match scenario_src_dir(&topology.exit) {
        Ok(dir) => dir,
        Err(err) => return StageOutcome::Failed(err),
    };
    let relay_remote = if needs_relay {
        match remote_host_for_any_role(ctx, &["entry", "aux"]) {
            Ok(host) => Some(host),
            Err(err) => return StageOutcome::Failed(err),
        }
    } else {
        None
    };
    let relay_src_dir = if needs_relay {
        match scenario_src_dir(&topology.relay) {
            Ok(dir) => Some(dir),
            Err(err) => return StageOutcome::Failed(err),
        }
    } else {
        None
    };
    let artifact_dir = match report_path.parent() {
        Some(dir) => dir.to_path_buf(),
        None => {
            return StageOutcome::Failed(format!(
                "cross-network report path has no parent directory: {}",
                report_path.display()
            ));
        }
    };

    let client_runner = substrate::RemoteShellRunner::new(
        client_remote,
        log_path.to_path_buf(),
        "client".to_owned(),
    );
    let exit_runner =
        substrate::RemoteShellRunner::new(exit_remote, log_path.to_path_buf(), "exit".to_owned());
    let relay_runner = relay_remote.map(|remote| {
        substrate::RemoteShellRunner::new(remote, log_path.to_path_buf(), "relay".to_owned())
    });

    let inputs = scenario::ScenarioInputs {
        // The underlay address is the resolved management host, which is what
        // the shell's `live_lab_resolved_target_address` produced; resolving it
        // once in the topology means the peer spec and the endpoint assertion
        // cannot disagree about which address the exit is dialled on.
        client: scenario::ScenarioNode::new(
            &client_runner,
            topology.client.node_id.as_str(),
            topology.client.host.as_str(),
        ),
        exit: scenario::ScenarioNode::new(
            &exit_runner,
            topology.exit.node_id.as_str(),
            topology.exit.host.as_str(),
        ),
        relay: relay_runner.as_ref().map(|runner| {
            scenario::ScenarioNode::new(
                runner,
                topology.relay.node_id.as_str(),
                topology.relay.host.as_str(),
            )
        }),
        probe: None,
        nat_profile: nat_profile.clone(),
        impairment_profile: options.impairment_profile.clone(),
    };

    let lab = scenario::provisioning::LabContext {
        ssh_identity_file: topology.client.identity_file.clone(),
        ssh_allow_cidrs: ctx.ssh_allow_cidrs.clone(),
        artifact_dir,
        client_ssh_target: topology.client.target.clone(),
        exit_ssh_target: topology.exit.target.clone(),
        relay_ssh_target: needs_relay.then(|| topology.relay.target.clone()),
        probe_ssh_target: None,
        client_src_dir,
        exit_src_dir,
        relay_src_dir,
        time_scale: scenario::provisioning::TimeScale::Real,
    };

    // `RUSTYNET_EXPECTED_GIT_COMMIT` is deliberately not set here: the old path
    // did not set it either, so the sibling validator keeps inheriting whatever
    // the orchestrator process was given. Overriding it here would let this
    // stage stamp a commit the run was not actually pinned to.
    let host = scenario::host::LocalScenarioHost::new(repo_root())
        .with_known_hosts_file(Some(topology.client.known_hosts.clone()));

    let (suite, outcome) = match kind {
        CrossNetworkStageKind::DirectRemoteExit => (
            "cross_network_direct_remote_exit",
            scenario::direct_remote_exit::run(&host, &inputs, &lab),
        ),
        CrossNetworkStageKind::RelayRemoteExit => (
            scenario::relay_remote_exit::SUITE,
            scenario::relay_remote_exit::run(&host, &inputs, &lab),
        ),
        other => {
            return StageOutcome::Failed(format!(
                "{} is not a ported cross-network scenario",
                bin_name(other)
            ));
        }
    };
    write_cross_network_scenario_report(
        suite,
        &outcome,
        topology,
        options,
        nat_profile,
        report_path,
        log_path,
    )
}

/// `live_lab_remote_src_dir` for a resolved role, derived from its ssh user.
fn scenario_src_dir(params: &ResolvedParams) -> Result<String, String> {
    let user = params
        .target
        .split('@')
        .next()
        .filter(|user| !user.is_empty())
        .ok_or_else(|| format!("ssh target names no user: {}", params.target))?;
    scenario::provisioning::remote_src_dir(user)
}

/// Write the one report a scenario's [`scenario::ScenarioOutcome`] describes.
///
/// The shell wrote its report from an `EXIT` trap reconciling four mutable
/// globals, so a validator that died early could leave a report disagreeing
/// with what it had proved. Here the outcome *is* the report's content, and it
/// is written on every path including failure — which is what keeps a failing
/// scenario assertable rather than merely absent.
fn write_cross_network_scenario_report(
    suite: &str,
    outcome: &scenario::ScenarioOutcome,
    topology: &CrossNetworkTopology,
    options: &CrossNetworkOptions,
    nat_profile: &substrate::NatProfileId,
    report_path: &Path,
    log_path: &Path,
) -> StageOutcome {
    let mut source_artifacts: Vec<PathBuf> = vec![repo_root().join(SCENARIO_SOURCE_ARTIFACT)];
    source_artifacts.extend(outcome.source_artifacts.iter().map(PathBuf::from));
    let config = crate::ops_cross_network_reports::GenerateCrossNetworkRemoteExitReportConfig {
        suite: suite.to_owned(),
        report_path: report_path.to_path_buf(),
        log_path: log_path.to_path_buf(),
        status: outcome.status.as_str().to_owned(),
        failure_summary: outcome.failure_summary.clone(),
        environment: "live_linux_skeleton".to_owned(),
        implementation_state: "live_measured_validator".to_owned(),
        source_artifacts,
        log_artifacts: outcome.log_artifacts.iter().map(PathBuf::from).collect(),
        client_host: Some(topology.client.target.clone()),
        exit_host: Some(topology.exit.target.clone()),
        relay_host: None,
        probe_host: None,
        client_network_id: Some(topology.client_network_id.clone()),
        exit_network_id: Some(topology.exit_network_id.clone()),
        relay_network_id: None,
        // The report schema is a JSON document with a string field; this is the
        // one place the typed profile is rendered back to text.
        nat_profile: nat_profile.as_str().to_owned(),
        impairment_profile: options.impairment_profile.clone(),
        check_overrides: outcome.checks.as_report_args(),
        path_status_line: outcome.path_status_line.clone(),
        path_evidence_report: None,
    };
    if let Err(err) =
        crate::ops_cross_network_reports::execute_ops_generate_cross_network_remote_exit_report(
            config,
        )
    {
        return StageOutcome::Failed(format!("writing {suite} report failed: {err}"));
    }
    if outcome.is_pass() {
        StageOutcome::Passed
    } else {
        StageOutcome::Failed(format!(
            "{suite} failed: {}",
            outcome.failure_summary.as_str()
        ))
    }
}

/// The validator's own source, recorded as report provenance. The shell named
/// its own `.sh` file here; the Rust scenario names the module that replaced it.
const SCENARIO_SOURCE_ARTIFACT: &str =
    "crates/rustynet-cli/src/vm_lab/orchestrator/stage/cross_network/scenario/mod.rs";

fn run_script_stage(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
    spec: &CrossNetworkStageSpec,
) -> StageOutcome {
    let (topology, stage_dir) = match prepare_scenario_stage(ctx, options, spec) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };

    for (idx, profile) in options.nat_profiles.iter().enumerate() {
        let profile = profile.as_str();
        let mut cmd = Command::new("cargo");
        cmd.current_dir(repo_root())
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--features",
                "vm-lab",
                "--bin",
                bin_name(spec.kind),
                "--",
            ])
            .env(
                "LIVE_LAB_PINNED_KNOWN_HOSTS_FILE",
                &topology.client.known_hosts,
            )
            .arg("--ssh-identity-file")
            .arg(&topology.client.identity_file)
            .arg("--nat-profile")
            .arg(profile)
            .arg("--impairment-profile")
            .arg(&options.impairment_profile)
            .arg("--report-path")
            .arg(stage_report_path_for_idx(
                &stage_dir, spec.name, profile, idx,
            ))
            .arg("--log-path")
            .arg(stage_log_path_for_idx(&stage_dir, spec.name, profile, idx));
        add_common_hosts(&mut cmd, &topology, spec.kind);
        let outcome = run_command(cmd, bin_name(spec.kind));
        if !matches!(outcome, StageOutcome::Passed) {
            return outcome;
        }
    }
    StageOutcome::Passed
}

fn add_common_hosts(
    cmd: &mut Command,
    topology: &CrossNetworkTopology,
    kind: CrossNetworkStageKind,
) {
    cmd.arg("--client-host")
        .arg(&topology.client.target)
        .arg("--exit-host")
        .arg(&topology.exit.target)
        .arg("--client-network-id")
        .arg(&topology.client_network_id)
        .arg("--exit-network-id")
        .arg(&topology.exit_network_id);

    if !matches!(kind, CrossNetworkStageKind::TraversalAdversarial) {
        cmd.arg("--client-node-id")
            .arg(&topology.client.node_id)
            .arg("--exit-node-id")
            .arg(&topology.exit.node_id)
            .arg("--known-hosts-file")
            .arg(&topology.client.known_hosts);
    }

    if matches!(
        kind,
        CrossNetworkStageKind::RelayRemoteExit
            | CrossNetworkStageKind::FailbackRoaming
            | CrossNetworkStageKind::ControllerSwitch
    ) {
        cmd.arg("--relay-host")
            .arg(&topology.relay.target)
            .arg("--relay-node-id")
            .arg(&topology.relay.node_id)
            .arg("--relay-network-id")
            .arg(&topology.relay_network_id);
    }

    if matches!(kind, CrossNetworkStageKind::TraversalAdversarial) {
        cmd.arg("--probe-host").arg(&topology.probe.target);
    }
}

fn bin_name(kind: CrossNetworkStageKind) -> &'static str {
    match kind {
        CrossNetworkStageKind::NodeNetworkSwitch => {
            "live_linux_cross_network_node_network_switch_test"
        }
        CrossNetworkStageKind::FailbackRoaming => "live_linux_cross_network_failback_roaming_test",
        CrossNetworkStageKind::ControllerSwitch => {
            "live_linux_cross_network_controller_switch_test"
        }
        CrossNetworkStageKind::TraversalAdversarial => {
            "live_linux_cross_network_traversal_adversarial_test"
        }
        CrossNetworkStageKind::RemoteExitDns => "live_linux_cross_network_remote_exit_dns_test",
        CrossNetworkStageKind::RemoteExitSoak => "live_linux_cross_network_remote_exit_soak_test",
        // `DirectRemoteExit` joins these: CN-3 ported it, so it is dispatched
        // in process by `run_direct_remote_exit_stage` and never reaches the
        // `cargo run --bin` fan. Its bin shim is deleted, so naming it here
        // would name a binary that does not exist.
        CrossNetworkStageKind::DirectRemoteExit
        | CrossNetworkStageKind::RelayRemoteExit
        | CrossNetworkStageKind::Preflight
        | CrossNetworkStageKind::NatClassification
        | CrossNetworkStageKind::NatMatrix => unreachable!("no script for this stage kind"),
    }
}

#[derive(Debug)]
enum TopologyError {
    MissingRole(()),
    Message(String),
}

struct CrossNetworkTopology {
    client: ResolvedParams,
    exit: ResolvedParams,
    relay: ResolvedParams,
    probe: ResolvedParams,
    client_network_id: String,
    exit_network_id: String,
    relay_network_id: String,
}

impl CrossNetworkTopology {
    fn resolve(ctx: &OrchestrationContext) -> Result<Self, TopologyError> {
        let client = ssh_params_for_role(ctx, "client").map_err(TopologyError::Message)?;
        let exit = ssh_params_for_role(ctx, "exit").map_err(TopologyError::Message)?;
        let relay = ssh_params_for_any_role(ctx, &["entry", "aux"])
            .map_err(|_| TopologyError::MissingRole(()))?;
        let probe = ssh_params_for_any_role(ctx, &["aux", "entry"])
            .map_err(|_| TopologyError::MissingRole(()))?;
        Ok(Self {
            client,
            exit,
            relay,
            probe,
            client_network_id: format!("{}-client", ctx.network_id),
            exit_network_id: format!("{}-exit", ctx.network_id),
            relay_network_id: format!("{}-relay", ctx.network_id),
        })
    }

    fn distinct_underlay_prefixes(&self) -> bool {
        match (self.client.host_ip(), self.exit.host_ip()) {
            (Some(client), Some(exit)) => !same_ipv4_prefix(client, exit, 24),
            _ => false,
        }
    }
}

struct ResolvedParams {
    target: String,
    host: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
    platform: VmGuestPlatform,
    node_id: String,
}

impl ResolvedParams {
    fn host_ip(&self) -> Option<Ipv4Addr> {
        self.host.parse().ok()
    }
}

pub(crate) struct RemoteHost {
    host: String,
    port: u16,
    user: Option<String>,
    identity_file: PathBuf,
    known_hosts: PathBuf,
}

fn ssh_params_for_any_role(
    ctx: &OrchestrationContext,
    labels: &[&str],
) -> Result<ResolvedParams, String> {
    for label in labels {
        if let Ok(params) = ssh_params_for_role(ctx, label) {
            return Ok(params);
        }
    }
    Err(format!(
        "no node assigned to any of roles {}",
        labels.join(", ")
    ))
}

/// As [`remote_host_for_role`], but keyed by node alias — the substrate
/// lifecycle stages operate on every assigned node, not a single role slot.
fn remote_host_for_alias(ctx: &OrchestrationContext, alias: &str) -> Result<RemoteHost, String> {
    let adapter = ctx
        .adapters
        .get(alias)
        .ok_or_else(|| format!("no adapter for {alias}"))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{alias}: no SSH params available"))?;
    Ok(RemoteHost {
        host: strip_ssh_host(params.host.as_str()),
        port: params.port,
        user: Some(
            params
                .user
                .unwrap_or_else(|| default_ssh_user(adapter.platform()).to_owned()),
        ),
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
}

/// As [`remote_host_for_role`], but also returns the node's alias — the netns
/// gate needs it to key its leaf runner and to name the guest any residue
/// would be on.
fn alias_and_remote_host_for_role(
    ctx: &OrchestrationContext,
    label: &str,
) -> Result<(String, RemoteHost), String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to role {label}"))?;
    let alias = assignment.alias.clone();
    let host = remote_host_for_alias(ctx, &alias)?;
    Ok((alias, host))
}

/// The first of `labels` that has a node assigned. Mirrors
/// [`ssh_params_for_any_role`], which `CrossNetworkTopology::resolve` already
/// uses for the relay slot, so the runner and the resolved params cannot end up
/// pointing at different nodes.
fn remote_host_for_any_role(
    ctx: &OrchestrationContext,
    labels: &[&str],
) -> Result<RemoteHost, String> {
    for label in labels {
        if let Ok(host) = remote_host_for_role(ctx, label) {
            return Ok(host);
        }
    }
    Err(format!(
        "no node assigned to any of roles {}",
        labels.join(", ")
    ))
}

fn remote_host_for_role(ctx: &OrchestrationContext, label: &str) -> Result<RemoteHost, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to role {label}"))?;
    let adapter = ctx
        .adapters
        .get(assignment.alias.as_str())
        .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{} ({label}): no SSH params available", assignment.alias))?;
    Ok(RemoteHost {
        host: strip_ssh_host(params.host.as_str()),
        port: params.port,
        user: Some(
            params
                .user
                .unwrap_or_else(|| default_ssh_user(adapter.platform()).to_owned()),
        ),
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to role {label}"))?;
    let adapter = ctx
        .adapters
        .get(assignment.alias.as_str())
        .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{} ({label}): no SSH params available", assignment.alias))?;
    let platform = adapter.platform();
    let user = params
        .user
        .unwrap_or_else(|| default_ssh_user(platform).to_owned());
    let host = strip_ssh_host(params.host.as_str());
    let node_id = ctx
        .node_ids
        .get(assignment.alias.as_str())
        .cloned()
        .unwrap_or_else(|| format!("{}-{}", ctx.network_id, label));
    Ok(ResolvedParams {
        target: format!("{user}@{}", params.host),
        host,
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
        platform,
        node_id,
    })
}

fn strip_ssh_host(host: &str) -> String {
    let without_user = host.split('@').next_back().unwrap_or(host);
    if without_user.starts_with('[')
        && let Some(end) = without_user.find(']')
    {
        return without_user[1..end].to_owned();
    }
    let mut parts = without_user.rsplitn(2, ':');
    let last = parts.next().unwrap_or(without_user);
    let first = parts.next();
    match first {
        Some(prefix) if last.chars().all(|c| c.is_ascii_digit()) => prefix.to_owned(),
        _ => without_user.to_owned(),
    }
}

fn same_ipv4_prefix(a: Ipv4Addr, b: Ipv4Addr, bits: u32) -> bool {
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits.min(32))
    };
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

fn write_nodes_tsv(ctx: &OrchestrationContext, path: &Path) -> Result<(), String> {
    let mut body = String::new();
    for assignment in &ctx.assignments {
        let params = ssh_params_for_role(ctx, assignment.role.as_str())?;
        body.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            assignment.alias,
            params.target,
            params.node_id,
            assignment.role.as_str()
        ));
    }
    fs::write(path, body).map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn validate_cross_network_options(options: &CrossNetworkOptions) -> Result<(), String> {
    // NAT profiles are `NatProfileId`s now, so emptiness and control characters
    // are unrepresentable by construction; only the impairment name still
    // carries free-form shape.
    let impairment = options.impairment_profile.as_str();
    if impairment.trim().is_empty() {
        return Err("cross-network profile values must not be empty".to_owned());
    }
    if impairment.chars().any(char::is_control) {
        return Err("cross-network profile values must not contain control chars".to_owned());
    }
    let profiles: HashSet<&str> = options
        .nat_profiles
        .iter()
        .map(substrate::NatProfileId::as_str)
        .collect();
    for required in &options.required_nat_profiles {
        if !profiles.contains(required.as_str()) {
            return Err(format!(
                "required NAT profile {required} is not present in cross-network NAT profiles"
            ));
        }
    }
    Ok(())
}

/// Parse a comma-separated NAT-profile list onto the closed §D5.1 vocabulary.
///
/// CN-4 behavioural change (owner-approved): a name outside
/// `substrate::KNOWN_NAT_PROFILES` is a parse-time error naming the whole
/// vocabulary. Before this, any `[A-Za-z0-9._-]+` string parsed and travelled
/// as far as a substrate before anything could object.
fn parse_profile_csv(value: &str, flag: &str) -> Result<Vec<substrate::NatProfileId>, String> {
    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    for raw in value.split(',') {
        // Keep the shape check first so a control character or an
        // option-shaped token is reported as a malformed flag value rather
        // than as an unknown profile.
        let candidate = parse_profile_value(raw, flag)?;
        let profile =
            substrate::NatProfileId::parse(&candidate).map_err(|err| format!("{flag}: {err}"))?;
        if seen.insert(profile.clone()) {
            profiles.push(profile);
        }
    }
    if profiles.is_empty() {
        return Err(format!("{flag} must contain at least one profile"));
    }
    Ok(profiles)
}

fn parse_profile_value(value: &str, flag: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("{flag} contains an empty profile"));
    }
    if trimmed.chars().any(char::is_control) {
        return Err(format!("{flag} values must not contain control chars"));
    }
    if !trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(format!(
            "{flag} values must contain only ASCII letters, digits, '.', '_' or '-'"
        ));
    }
    Ok(trimmed.to_owned())
}

fn build_ssh_command(host: &RemoteHost, remote_script: &str) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-n",
        "-F",
        "/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "IdentitiesOnly=yes",
        "-p",
        &host.port.to_string(),
    ])
    .arg("-i")
    .arg(&host.identity_file)
    .arg("-o")
    .arg(format!("UserKnownHostsFile={}", host.known_hosts.display()));
    if let Some(user) = &host.user {
        cmd.arg("-l").arg(user);
    }
    cmd.arg("--").arg(&host.host).arg(remote_script);
    cmd
}

fn run_ssh_checked(
    host: &RemoteHost,
    remote_script: &str,
    log_path: &Path,
    label: &str,
) -> Option<StageOutcome> {
    let mut cmd = build_ssh_command(host, remote_script);
    command_failure_outcome(&mut cmd, log_path, label)
}

fn command_failure_outcome(
    cmd: &mut Command,
    log_path: &Path,
    label: &str,
) -> Option<StageOutcome> {
    match cmd.output() {
        Ok(output) => {
            append_command_output(log_path, label, &output.stdout, &output.stderr);
            if output.status.success() {
                None
            } else {
                Some(StageOutcome::Failed(format!(
                    "{label} exited with {}: {}",
                    output.status,
                    stderr_snippet(&output.stderr)
                )))
            }
        }
        Err(err) => Some(StageOutcome::Failed(format!(
            "failed to run {label}: {err}"
        ))),
    }
}

fn append_command_output(log_path: &Path, label: &str, stdout: &[u8], stderr: &[u8]) {
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
    {
        let _ = writeln!(file, "\n== {label} ==");
        if !stdout.is_empty() {
            let _ = writeln!(file, "-- stdout --");
            let _ = file.write_all(stdout);
            let _ = writeln!(file);
        }
        if !stderr.is_empty() {
            let _ = writeln!(file, "-- stderr --");
            let _ = file.write_all(stderr);
            let _ = writeln!(file);
        }
    }
}

fn stage_report_path(stage_dir: &Path, stage_name: &str, profile: &str) -> PathBuf {
    stage_dir.join(format!("{stage_name}_{profile}_report.json"))
}

fn stage_report_path_for_idx(
    stage_dir: &Path,
    stage_name: &str,
    profile: &str,
    idx: usize,
) -> PathBuf {
    if idx == 0 {
        stage_dir.join(format!("{stage_name}_report.json"))
    } else {
        stage_report_path(stage_dir, stage_name, profile)
    }
}

fn stage_log_path_for_idx(
    stage_dir: &Path,
    stage_name: &str,
    profile: &str,
    idx: usize,
) -> PathBuf {
    if idx == 0 {
        stage_dir.join(format!("{stage_name}.log"))
    } else {
        stage_dir.join(format!("{stage_name}_{profile}.log"))
    }
}

fn cargo_ops_command(subcommand: &str) -> Command {
    // `--features vm-lab` is REQUIRED. Every `ops` verb driven through here is
    // `#[cfg(feature = "vm-lab")]`-gated, so without it cargo builds a
    // default-feature binary that lacks them and the call dies with
    // `unknown ops subcommand` — which surfaces as exit 64 (bad_args) and
    // reads like a caller argument error rather than a missing build feature.
    // That is exactly how `cross_network_preflight` recorded a FALSE RED.
    let mut cmd = Command::new("cargo");
    cmd.current_dir(repo_root()).args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--features",
        "vm-lab",
        "--",
        "ops",
        subcommand,
    ]);
    cmd
}

fn run_command(mut cmd: Command, label: &str) -> StageOutcome {
    match cmd.output() {
        Ok(output) if output.status.success() => StageOutcome::Passed,
        Ok(output) => StageOutcome::Failed(format!(
            "{label} exited with {}: {}",
            output.status,
            stderr_snippet(&output.stderr)
        )),
        Err(err) => StageOutcome::Failed(format!("failed to run {label}: {err}")),
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn git_head_commit() -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo_root())
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("git rev-parse HEAD failed to start: {err}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".to_owned());
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD returned non-UTF-8 output: {err}"))?;
    let trimmed = commit.trim();
    if trimmed.is_empty() {
        Err("git rev-parse HEAD returned empty output".to_owned())
    } else {
        Ok(trimmed.to_owned())
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn default_ssh_user(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Windows => "administrator",
        VmGuestPlatform::Macos => "admin",
        _ => "debian",
    }
}

fn stderr_snippet(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .take(500)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile names as plain strings, so assertions stay readable now
    /// that the flags parse onto `NatProfileId`.
    fn names(profiles: &[substrate::NatProfileId]) -> Vec<&str> {
        profiles
            .iter()
            .map(substrate::NatProfileId::as_str)
            .collect()
    }

    #[test]
    fn cross_network_options_default_to_baseline_lan() {
        let options = CrossNetworkOptions::default();
        assert!(options.enable_suite);
        assert_eq!(names(&options.nat_profiles), ["baseline_lan"]);
        assert_eq!(names(&options.required_nat_profiles), ["baseline_lan"]);
        assert_eq!(options.impairment_profile, "none");
        assert_eq!(options.substrate, CrossNetworkSubstrate::Netns);
    }

    #[test]
    fn cross_network_options_from_cli_dedupes_and_requires_requested_profiles() {
        let options = CrossNetworkOptions::from_cli(
            true,
            Some("baseline_lan, full_cone,baseline_lan"),
            None,
            Some("netem_100ms"),
            Some("vxlan"),
        )
        .expect("cross-network CLI options should parse");
        assert_eq!(names(&options.nat_profiles), ["baseline_lan", "full_cone"]);
        assert_eq!(
            names(&options.required_nat_profiles),
            ["baseline_lan", "full_cone"]
        );
        assert_eq!(options.impairment_profile, "netem_100ms");
        assert_eq!(options.substrate, CrossNetworkSubstrate::Vxlan);
    }

    /// CN-4, owner-approved (`OwnerDecisionDigest_2026-08-27.md` §16): the
    /// flags parse onto the CLOSED §D5.1 vocabulary. Every one of these strings
    /// PARSED before this change and reached a substrate as a free string.
    #[test]
    fn cross_network_nat_profile_flags_reject_names_outside_the_closed_vocabulary() {
        for bad in [
            "full-cone",
            "FULL_CONE",
            "baseline_lan_v2",
            "cone",
            "port_restricted",
            "1.2.3",
        ] {
            let err = CrossNetworkOptions::from_cli(true, Some(bad), None, None, None)
                .expect_err("an unknown NAT profile must fail at parse time");
            assert!(
                err.contains("--cross-network-nat-profiles")
                    && err.contains("unknown NAT profile")
                    // The error must NAME the vocabulary, not just refuse.
                    && err.contains("baseline_lan")
                    && err.contains("double_nat_cgnat"),
                "{bad:?}: {err}"
            );
        }
        // The same tightening applies to the `--required` half.
        let err =
            CrossNetworkOptions::from_cli(true, Some("full_cone"), Some("full-cone"), None, None)
                .expect_err("the required-profile flag is tightened too");
        assert!(
            err.contains("--cross-network-required-nat-profiles"),
            "{err}"
        );
        // One bad name in a list of good ones still fails the whole flag.
        assert!(
            CrossNetworkOptions::from_cli(
                true,
                Some("full_cone,typo_cone,symmetric"),
                None,
                None,
                None,
            )
            .is_err()
        );
    }

    #[test]
    fn every_known_nat_profile_parses_through_the_flag() {
        for known in substrate::KNOWN_NAT_PROFILES {
            let options = CrossNetworkOptions::from_cli(true, Some(known), None, None, None)
                .unwrap_or_else(|err| panic!("{known} must parse: {err}"));
            assert_eq!(names(&options.nat_profiles), [*known]);
        }
    }

    /// The default must stay inside the closed vocabulary, or
    /// `default_nat_profile()` would be an unreachable panic waiting to happen.
    #[test]
    fn default_nat_profile_is_in_the_closed_vocabulary() {
        assert!(substrate::KNOWN_NAT_PROFILES.contains(&DEFAULT_PROFILE));
        assert_eq!(default_nat_profile().as_str(), DEFAULT_PROFILE);
    }

    #[test]
    fn cross_network_options_reject_missing_required_profile() {
        let err = CrossNetworkOptions::from_cli(
            true,
            Some("baseline_lan"),
            Some("symmetric"),
            None,
            None,
        )
        .expect_err("required profile outside profile set must fail closed");
        assert!(err.contains("required NAT profile symmetric"));
    }

    #[test]
    fn cross_network_options_reject_control_chars() {
        let err =
            CrossNetworkOptions::from_cli(true, Some("baseline_lan\nfull_cone"), None, None, None)
                .expect_err("control char in profile must fail closed");
        assert!(err.contains("control chars"));
    }

    #[test]
    fn cross_network_options_reject_bad_profile_chars() {
        let err = CrossNetworkOptions::from_cli(true, Some("baseline_lan;rm"), None, None, None)
            .expect_err("shell punctuation in profile must fail closed");
        assert!(err.contains("ASCII letters"));
    }

    #[test]
    fn cross_network_options_reject_bad_substrate() {
        let err = CrossNetworkOptions::from_cli(true, None, None, None, Some("raw"))
            .expect_err("unknown substrate must fail closed");
        assert!(err.contains("invalid --cross-network-substrate"));
    }

    #[test]
    fn cross_network_command_start_failure_is_failed_outcome() {
        let outcome = run_command(
            Command::new("__rustynet_missing_cross_network_command__"),
            "missing-cross-network-command",
        );
        assert!(matches!(outcome, StageOutcome::Failed(_)));
    }

    #[test]
    fn strip_ssh_host_removes_user_and_port() {
        assert_eq!(strip_ssh_host("debian@192.168.64.10"), "192.168.64.10");
        assert_eq!(strip_ssh_host("192.168.64.10:2222"), "192.168.64.10");
        assert_eq!(strip_ssh_host("debian@[fe80::1]:2222"), "fe80::1");
    }

    #[test]
    fn same_ipv4_prefix_detects_same_slash_24() {
        assert!(same_ipv4_prefix(
            "192.168.64.10".parse().unwrap(),
            "192.168.64.99".parse().unwrap(),
            24
        ));
        assert!(!same_ipv4_prefix(
            "192.168.64.10".parse().unwrap(),
            "192.168.65.10".parse().unwrap(),
            24
        ));
    }
}
