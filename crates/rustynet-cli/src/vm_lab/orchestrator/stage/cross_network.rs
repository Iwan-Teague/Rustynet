#![allow(dead_code)]
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
const NETNS_CLASSIFICATION_TOOLS: &[&str] = &[
    "netns_internet_sim.sh",
    "netns_nat_classify.sh",
    "netns_nat_filter.sh",
    "stun_responder.py",
    "nat_probe.py",
    "nat_filter_probe.py",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossNetworkOptions {
    pub enable_suite: bool,
    pub nat_profiles: Vec<String>,
    pub required_nat_profiles: Vec<String>,
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
            None => vec![DEFAULT_PROFILE.to_owned()],
        };
        let required_nat_profiles = match required_nat_profiles {
            Some(value) => parse_profile_csv(value, "--cross-network-required-nat-profiles")?,
            None if nat_profiles.len() == 1 && nat_profiles[0] == DEFAULT_PROFILE => {
                vec![DEFAULT_PROFILE.to_owned()]
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
            nat_profiles: vec![DEFAULT_PROFILE.to_owned()],
            required_nat_profiles: vec![DEFAULT_PROFILE.to_owned()],
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
        return StageOutcome::Skipped;
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
        CrossNetworkStageKind::DirectRemoteExit
        | CrossNetworkStageKind::NodeNetworkSwitch
        | CrossNetworkStageKind::RelayRemoteExit
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
        return StageOutcome::Skipped;
    }
    let host = match remote_host_for_role(ctx, "exit") {
        Ok(host) => host,
        Err(err) => return StageOutcome::Failed(err),
    };
    let stage_dir = ctx.report_dir.join("cross_network_nat_classification");
    if let Err(err) = fs::create_dir_all(stage_dir.as_path()) {
        return StageOutcome::Failed(format!(
            "create cross_network_nat_classification dir failed: {err}"
        ));
    }
    let log_path = stage_dir.join("cross_network_nat_classification.log");

    let dependency_check = "sudo -n bash -lc 'python3 --version >/dev/null 2>&1 && nft --version >/dev/null 2>&1 && ip -V >/dev/null 2>&1'";
    if let Some(outcome) =
        run_ssh_checked(&host, dependency_check, &log_path, "netns dependency check")
    {
        return outcome;
    }

    for tool in NETNS_CLASSIFICATION_TOOLS {
        let local_path = repo_root().join("scripts/vm_lab").join(tool);
        if !local_path.is_file() {
            return StageOutcome::Failed(format!(
                "cross_network_nat_classification missing tool {}",
                local_path.display()
            ));
        }
        if let Some(outcome) = scp_to_remote(
            &host,
            local_path.as_path(),
            &format!("/tmp/{tool}"),
            &log_path,
        ) {
            return outcome;
        }
    }

    for (label, remote_script) in [
        (
            "netns NAT mapping classification",
            "sudo -n bash /tmp/netns_nat_classify.sh",
        ),
        (
            "netns NAT filtering classification",
            "sudo -n bash /tmp/netns_nat_filter.sh",
        ),
    ] {
        if let Some(outcome) = run_ssh_checked(&host, remote_script, &log_path, label) {
            return outcome;
        }
    }
    StageOutcome::Passed
}

fn run_nat_matrix(ctx: &OrchestrationContext, options: &CrossNetworkOptions) -> StageOutcome {
    if options.substrate != CrossNetworkSubstrate::Vxlan {
        return StageOutcome::Skipped;
    }
    let mut cmd = cargo_ops_command("validate-cross-network-nat-matrix");
    cmd.arg("--artifact-dir")
        .arg(&ctx.report_dir)
        .arg("--required-nat-profiles")
        .arg(options.required_nat_profiles.join(","))
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

fn run_script_stage(
    ctx: &OrchestrationContext,
    options: &CrossNetworkOptions,
    spec: &CrossNetworkStageSpec,
) -> StageOutcome {
    if options.substrate != CrossNetworkSubstrate::Vxlan {
        return StageOutcome::Skipped;
    }
    let topology = match CrossNetworkTopology::resolve(ctx) {
        Ok(topology) => topology,
        Err(TopologyError::MissingRole(_)) => return StageOutcome::Skipped,
        Err(TopologyError::Message(err)) => return StageOutcome::Failed(err),
    };
    if !topology.distinct_underlay_prefixes() {
        return StageOutcome::Skipped;
    }

    let stage_dir = ctx.report_dir.join(spec.name);
    if let Err(err) = fs::create_dir_all(stage_dir.as_path()) {
        return StageOutcome::Failed(format!("create {} dir failed: {err}", spec.name));
    }

    for (idx, profile) in options.nat_profiles.iter().enumerate() {
        let mut cmd = Command::new("cargo");
        cmd.current_dir(repo_root())
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
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
        CrossNetworkStageKind::DirectRemoteExit => {
            "live_linux_cross_network_direct_remote_exit_test"
        }
        CrossNetworkStageKind::NodeNetworkSwitch => {
            "live_linux_cross_network_node_network_switch_test"
        }
        CrossNetworkStageKind::RelayRemoteExit => "live_linux_cross_network_relay_remote_exit_test",
        CrossNetworkStageKind::FailbackRoaming => "live_linux_cross_network_failback_roaming_test",
        CrossNetworkStageKind::ControllerSwitch => {
            "live_linux_cross_network_controller_switch_test"
        }
        CrossNetworkStageKind::TraversalAdversarial => {
            "live_linux_cross_network_traversal_adversarial_test"
        }
        CrossNetworkStageKind::RemoteExitDns => "live_linux_cross_network_remote_exit_dns_test",
        CrossNetworkStageKind::RemoteExitSoak => "live_linux_cross_network_remote_exit_soak_test",
        CrossNetworkStageKind::Preflight
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

struct RemoteHost {
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
    for value in options
        .nat_profiles
        .iter()
        .chain(options.required_nat_profiles.iter())
        .chain(std::iter::once(&options.impairment_profile))
    {
        if value.trim().is_empty() {
            return Err("cross-network profile values must not be empty".to_owned());
        }
        if value.chars().any(char::is_control) {
            return Err("cross-network profile values must not contain control chars".to_owned());
        }
    }
    let profiles: HashSet<&str> = options.nat_profiles.iter().map(String::as_str).collect();
    for required in &options.required_nat_profiles {
        if !profiles.contains(required.as_str()) {
            return Err(format!(
                "required NAT profile {required} is not present in cross-network NAT profiles"
            ));
        }
    }
    Ok(())
}

fn parse_profile_csv(value: &str, flag: &str) -> Result<Vec<String>, String> {
    let mut profiles = Vec::new();
    let mut seen = HashSet::new();
    for raw in value.split(',') {
        let profile = parse_profile_value(raw, flag)?;
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

fn build_scp_to_command(host: &RemoteHost, local_path: &Path, remote_path: &str) -> Command {
    let mut cmd = Command::new("scp");
    cmd.args([
        "-q",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "IdentitiesOnly=yes",
        "-P",
        &host.port.to_string(),
    ])
    .arg("-i")
    .arg(&host.identity_file)
    .arg("-o")
    .arg(format!("UserKnownHostsFile={}", host.known_hosts.display()));
    if let Some(user) = &host.user {
        cmd.arg("-o").arg(format!("User={user}"));
    }
    cmd.arg("--")
        .arg(local_path)
        .arg(format!("{}:{remote_path}", host.host));
    cmd
}

fn scp_to_remote(
    host: &RemoteHost,
    local_path: &Path,
    remote_path: &str,
    log_path: &Path,
) -> Option<StageOutcome> {
    let mut cmd = build_scp_to_command(host, local_path, remote_path);
    command_failure_outcome(&mut cmd, log_path, "scp cross-network netns tool")
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
    let mut cmd = Command::new("cargo");
    cmd.current_dir(repo_root()).args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
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

    #[test]
    fn cross_network_options_default_to_baseline_lan() {
        let options = CrossNetworkOptions::default();
        assert!(options.enable_suite);
        assert_eq!(options.nat_profiles, ["baseline_lan"]);
        assert_eq!(options.required_nat_profiles, ["baseline_lan"]);
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
        assert_eq!(options.nat_profiles, ["baseline_lan", "full_cone"]);
        assert_eq!(options.required_nat_profiles, ["baseline_lan", "full_cone"]);
        assert_eq!(options.impairment_profile, "netem_100ms");
        assert_eq!(options.substrate, CrossNetworkSubstrate::Vxlan);
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
