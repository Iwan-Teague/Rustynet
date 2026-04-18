#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::privileged_helper::{
    PrivilegedCommandClient, PrivilegedCommandOutput, PrivilegedCommandProgram,
};
use crate::traversal::{
    CoordinationSchedule, SimultaneousOpenRuntime, SimultaneousOpenWaiter,
    TraversalCandidate as ProbeTraversalCandidate, TraversalDecision, TraversalDecisionReason,
    TraversalEngine, TraversalEngineConfig, TraversalError,
};
use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendError, BackendErrorKind,
    ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint, TunnelBackend,
};
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicySet, Decision, MembershipDirectory, MembershipStatus,
    Protocol, TrafficContext,
};

struct Phase10PeerRuntime<'a, B: TunnelBackend, S: DataplaneSystem> {
    controller: &'a mut Phase10Controller<B, S>,
    node_id: NodeId,
}

impl<'a, B: TunnelBackend, S: DataplaneSystem> SimultaneousOpenRuntime
    for Phase10PeerRuntime<'a, B, S>
{
    fn send_probe(&mut self, endpoint: SocketEndpoint, round: u8) -> Result<(), TraversalError> {
        // When probing, we treat it as a Direct path attempt.
        // If the candidate was a relay, it wouldn't be in the direct_candidates list
        // passed to execute_simultaneous_open.
        self.controller
            .reconfigure_managed_peer(&self.node_id, endpoint, PathMode::Direct)
            .map_err(|_| TraversalError::InvalidConfig("phase10 direct probe send failed"))?;
        self.controller
            .backend
            .initiate_peer_handshake(&self.node_id, round > 0)
            .map_err(|_| TraversalError::InvalidConfig("phase10 direct probe send failed"))
    }

    fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
        self.controller
            .backend
            .peer_latest_handshake_unix(&self.node_id)
            .map_err(|_| TraversalError::InvalidConfig("phase10 handshake read failed"))
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Phase10PeerWaiter;

impl SimultaneousOpenWaiter for Phase10PeerWaiter {
    fn wait(&mut self, duration: Duration) {
        if !duration.is_zero() {
            std::thread::sleep(duration);
        }
    }
}

const IP_BINARY_PATH_ENV: &str = "RUSTYNET_IP_BINARY_PATH";
const NFT_BINARY_PATH_ENV: &str = "RUSTYNET_NFT_BINARY_PATH";
const WG_BINARY_PATH_ENV: &str = "RUSTYNET_WG_BINARY_PATH";
const SYSCTL_BINARY_PATH_ENV: &str = "RUSTYNET_SYSCTL_BINARY_PATH";
const IFCONFIG_BINARY_PATH_ENV: &str = "RUSTYNET_IFCONFIG_BINARY_PATH";
const ROUTE_BINARY_PATH_ENV: &str = "RUSTYNET_ROUTE_BINARY_PATH";
const PFCTL_BINARY_PATH_ENV: &str = "RUSTYNET_PFCTL_BINARY_PATH";
const WIREGUARD_GO_BINARY_PATH_ENV: &str = "RUSTYNET_WIREGUARD_GO_BINARY_PATH";
const KILL_BINARY_PATH_ENV: &str = "RUSTYNET_KILL_BINARY_PATH";
const WINDOWS_NETSH_BINARY_PATH_ENV: &str = "RUSTYNET_NETSH_BINARY_PATH";
const DEFAULT_IP_BINARY_PATH: &str = "/usr/sbin/ip";
const DEFAULT_NFT_BINARY_PATH: &str = "/usr/sbin/nft";
const DEFAULT_WG_BINARY_PATH: &str = "/usr/bin/wg";
const DEFAULT_SYSCTL_BINARY_PATH: &str = "/usr/sbin/sysctl";
const DEFAULT_IFCONFIG_BINARY_PATH: &str = "/sbin/ifconfig";
const DEFAULT_ROUTE_BINARY_PATH: &str = "/sbin/route";
const DEFAULT_PFCTL_BINARY_PATH: &str = "/sbin/pfctl";
const DEFAULT_WIREGUARD_GO_BINARY_PATH: &str = "/usr/local/bin/wireguard-go";
const DEFAULT_KILL_BINARY_PATH: &str = "/bin/kill";
const DEFAULT_WINDOWS_NETSH_BINARY_PATH: &str = r"C:\Windows\System32\netsh.exe";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManagementCidr {
    address: IpAddr,
    prefix: u8,
}

impl ManagementCidr {
    fn nft_family(self) -> &'static str {
        match self.address {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        }
    }

    fn pf_family(self) -> &'static str {
        match self.address {
            IpAddr::V4(_) => "inet",
            IpAddr::V6(_) => "inet6",
        }
    }

    fn is_ipv6(self) -> bool {
        matches!(self.address, IpAddr::V6(_))
    }
}

impl std::fmt::Display for ManagementCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

impl std::str::FromStr for ManagementCidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (base, prefix_raw) = value
            .split_once('/')
            .ok_or_else(|| format!("invalid management cidr: {value}"))?;
        let prefix = prefix_raw
            .parse::<u8>()
            .map_err(|_| format!("invalid management cidr prefix: {value}"))?;
        let address = base
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid management cidr address: {value}"))?;
        let max_prefix = match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max_prefix {
            return Err(format!("invalid management cidr prefix: {value}"));
        }
        Ok(Self { address, prefix })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataplaneState {
    Init,
    ControlTrusted,
    DataplaneApplied,
    ExitActive,
    FailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalProbeDecision {
    Direct,
    Relay,
}

impl TraversalProbeDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            TraversalProbeDecision::Direct => "direct",
            TraversalProbeDecision::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalProbeReason {
    ExistingFreshHandshake,
    FreshHandshakeObserved,
    DirectProbeExhaustedUnprovenDirect,
    NoDirectCandidatesRelayArmed,
    CoordinationRequiredRelayArmed,
    DirectProbeExhaustedRelayArmed,
}

impl TraversalProbeReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TraversalProbeReason::ExistingFreshHandshake => "existing_fresh_handshake",
            TraversalProbeReason::FreshHandshakeObserved => "fresh_handshake_observed",
            TraversalProbeReason::DirectProbeExhaustedUnprovenDirect => {
                "direct_probe_exhausted_unproven_direct"
            }
            TraversalProbeReason::NoDirectCandidatesRelayArmed => {
                "no_direct_candidates_relay_armed"
            }
            TraversalProbeReason::CoordinationRequiredRelayArmed => {
                "coordination_required_relay_armed"
            }
            TraversalProbeReason::DirectProbeExhaustedRelayArmed => {
                "direct_probe_exhausted_relay_armed"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalProbeReport {
    pub decision: TraversalProbeDecision,
    pub reason: TraversalProbeReason,
    pub attempts: usize,
    pub selected_endpoint: SocketEndpoint,
    pub latest_handshake_unix: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct TraversalProbeEvaluation<'a> {
    pub local_candidates: &'a [ProbeTraversalCandidate],
    pub direct_candidates: &'a [ProbeTraversalCandidate],
    pub relay_endpoint: Option<SocketEndpoint>,
    pub now_unix: u64,
    pub engine_config: TraversalEngineConfig,
    pub handshake_freshness_secs: u64,
    pub coordination_schedule: Option<CoordinationSchedule>,
    pub coordination_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionEvent {
    pub from_state: DataplaneState,
    pub to_state: DataplaneState,
    pub reason: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustEvidence {
    pub tls13_valid: bool,
    pub signed_control_valid: bool,
    pub signed_data_age_secs: u64,
    pub clock_skew_secs: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustPolicy {
    pub max_signed_data_age_secs: u64,
    pub max_clock_skew_secs: u64,
}

impl Default for TrustPolicy {
    fn default() -> Self {
        Self {
            max_signed_data_age_secs: 300,
            max_clock_skew_secs: 90,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOptions {
    pub protected_dns: bool,
    pub ipv6_parity_supported: bool,
    pub exit_mode: ExitMode,
    pub serve_exit_node: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            protected_dns: true,
            ipv6_parity_supported: false,
            exit_mode: ExitMode::Off,
            serve_exit_node: false,
        }
    }
}

#[derive(Debug, Clone)]
struct ManagedPeer {
    configured: PeerConfig,
    direct_endpoint: SocketEndpoint,
    relay_endpoint: Option<SocketEndpoint>,
    path: PathMode,
    /// Candidate path mode awaiting stability window confirmation.
    pending_path_mode: Option<PathMode>,
    /// When the current pending candidate was first observed.
    pending_since: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteGrantRequest {
    pub user: String,
    pub cidr: String,
    pub protocol: Protocol,
    pub context: TrafficContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemError {
    PrerequisiteCheckFailed(String),
    RouteApplyFailed(String),
    FirewallApplyFailed(String),
    NatApplyFailed(String),
    DnsApplyFailed(String),
    KillSwitchAssertionFailed(String),
    BlockEgressFailed(String),
    RollbackFailed(String),
    Io(String),
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SystemError::PrerequisiteCheckFailed(message) => {
                write!(f, "prerequisite check failed: {message}")
            }
            SystemError::RouteApplyFailed(message) => write!(f, "route apply failed: {message}"),
            SystemError::FirewallApplyFailed(message) => {
                write!(f, "firewall apply failed: {message}")
            }
            SystemError::NatApplyFailed(message) => write!(f, "nat apply failed: {message}"),
            SystemError::DnsApplyFailed(message) => write!(f, "dns apply failed: {message}"),
            SystemError::KillSwitchAssertionFailed(message) => {
                write!(f, "killswitch assertion failed: {message}")
            }
            SystemError::BlockEgressFailed(message) => {
                write!(f, "block egress failed: {message}")
            }
            SystemError::RollbackFailed(message) => write!(f, "rollback failed: {message}"),
            SystemError::Io(message) => write!(f, "i/o failed: {message}"),
        }
    }
}

impl std::error::Error for SystemError {}

#[derive(Debug, PartialEq, Eq)]
pub enum Phase10Error {
    InvalidTransition(&'static str),
    TrustRejected(&'static str),
    Backend(BackendError),
    System(SystemError),
    TraversalProbeFailed(String),
    PolicyDenied,
    ExitNotSelected,
    LanAccessDenied,
    PeerNotManaged,
    RelayPathUnavailable,
    NotStarted,
    MembershipRevoked(String),
    MembershipNotFound(String),
}

impl fmt::Display for Phase10Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Phase10Error::InvalidTransition(msg) => write!(f, "invalid transition: {msg}"),
            Phase10Error::TrustRejected(msg) => write!(f, "trust rejected: {msg}"),
            Phase10Error::Backend(err) => write!(f, "backend error: {err}"),
            Phase10Error::System(err) => write!(f, "system error: {err}"),
            Phase10Error::TraversalProbeFailed(err) => {
                write!(f, "traversal probe failed: {err}")
            }
            Phase10Error::PolicyDenied => f.write_str("policy denied"),
            Phase10Error::ExitNotSelected => f.write_str("exit node not selected"),
            Phase10Error::LanAccessDenied => f.write_str("lan access denied"),
            Phase10Error::PeerNotManaged => f.write_str("peer is not managed by phase10"),
            Phase10Error::RelayPathUnavailable => {
                f.write_str("relay path unavailable for managed peer")
            }
            Phase10Error::NotStarted => f.write_str("phase10 controller not started"),
            Phase10Error::MembershipRevoked(id) => {
                write!(f, "peer {id} membership is revoked: provisioning denied")
            }
            Phase10Error::MembershipNotFound(id) => {
                write!(f, "peer {id} not found in membership: provisioning denied")
            }
        }
    }
}

impl std::error::Error for Phase10Error {}

impl From<BackendError> for Phase10Error {
    fn from(value: BackendError) -> Self {
        Phase10Error::Backend(value)
    }
}

impl From<SystemError> for Phase10Error {
    fn from(value: SystemError) -> Self {
        Phase10Error::System(value)
    }
}

pub trait DataplaneSystem {
    fn set_generation(&mut self, _generation: u64) {}
    fn set_relay_forwarding(&mut self, _enabled: bool) {}
    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn check_prerequisites(&mut self) -> Result<(), SystemError>;
    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        _peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        Ok(())
    }
    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError>;
    fn rollback_routes(&mut self) -> Result<(), SystemError>;
    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError>;
    fn rollback_firewall(&mut self) -> Result<(), SystemError>;
    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError>;
    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError>;
    fn apply_dns_protection(&mut self) -> Result<(), SystemError>;
    fn rollback_dns_protection(&mut self) -> Result<(), SystemError>;
    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError>;
    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn assert_killswitch(&mut self) -> Result<(), SystemError>;
    fn assert_exit_policy(&mut self, _exit_mode: ExitMode) -> Result<(), SystemError> {
        self.assert_killswitch()
    }
    fn block_all_egress(&mut self) -> Result<(), SystemError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMarker {
    BackendStarted,
    PeerApplied,
    EndpointBypassApplied,
    BackendRoutesApplied,
    SystemRoutesApplied,
    FirewallApplied,
    NatApplied,
    DnsApplied,
    ExitModeApplied,
    Ipv6Blocked,
}

#[derive(Debug, Default)]
pub struct DryRunSystem {
    pub operations: Vec<String>,
    fail_operation: Option<String>,
    generation: u64,
    relay_forwarding_enabled: bool,
}

impl DryRunSystem {
    pub fn fail_on(mut self, operation: &str) -> Self {
        self.fail_operation = Some(operation.to_string());
        self
    }

    fn step(&mut self, operation: &str) -> Result<(), SystemError> {
        self.operations.push(operation.to_string());
        if self
            .fail_operation
            .as_ref()
            .map(|candidate| candidate == operation)
            .unwrap_or(false)
        {
            return Err(SystemError::RollbackFailed(operation.to_string()));
        }
        Ok(())
    }
}

impl DataplaneSystem for DryRunSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
        self.operations.push(format!("set_generation:{generation}"));
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        self.relay_forwarding_enabled = enabled;
        self.operations
            .push(format!("set_relay_forwarding:{enabled}"));
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        self.step("prune_owned_tables")
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        self.step("check_prerequisites")
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        _peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        self.step("apply_peer_endpoint_bypass_routes")
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        self.step("apply_routes")
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        self.step("rollback_routes")
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        self.step("apply_firewall_killswitch")
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        self.step("rollback_firewall")
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.step("apply_nat_forwarding")
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.step("rollback_nat_forwarding")
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("apply_dns_protection")
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("rollback_dns_protection")
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.step("hard_disable_ipv6_egress")
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.step("rollback_ipv6_egress")
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        self.step("assert_killswitch")
    }

    fn assert_exit_policy(&mut self, exit_mode: ExitMode) -> Result<(), SystemError> {
        match exit_mode {
            ExitMode::Off => self.step("assert_exit_policy:off")?,
            ExitMode::FullTunnel => self.step("assert_exit_policy:full_tunnel")?,
        }
        self.assert_killswitch()
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        self.step("block_all_egress")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxCommandSystem {
    interface_name: String,
    egress_interface: String,
    mode: LinuxDataplaneMode,
    privileged_client: Option<PrivilegedCommandClient>,
    generation: u64,
    fail_closed_ssh_allow: bool,
    fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    firewall_table: Option<String>,
    nat_table: Option<String>,
    prior_ipv4_forwarding: Option<bool>,
    prior_ipv6_disabled: Option<bool>,
    allow_tunnel_relay_forward: bool,
    traversal_bootstrap_allow_endpoints: Vec<SocketAddr>,
    dns_protected: bool,
    expected_management_bypass_routes: BTreeSet<ExpectedBypassRoute>,
    expected_peer_endpoint_bypass_routes: BTreeSet<ExpectedBypassRoute>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDataplaneMode {
    Shell,
    HybridNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum RouteTableFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExpectedBypassRoute {
    destination: String,
    interface_name: String,
    family: RouteTableFamily,
}

impl LinuxCommandSystem {
    pub fn new(
        interface_name: impl Into<String>,
        egress_interface: impl Into<String>,
        mode: LinuxDataplaneMode,
        privileged_client: Option<PrivilegedCommandClient>,
        fail_closed_ssh_allow: bool,
        fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    ) -> Result<Self, SystemError> {
        let interface_name = interface_name.into();
        let egress_interface = egress_interface.into();
        validate_net_device_name(&interface_name)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided"
                    .to_string(),
            ));
        }

        Ok(Self {
            interface_name,
            egress_interface,
            mode,
            privileged_client,
            generation: 0,
            fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs,
            firewall_table: None,
            nat_table: None,
            prior_ipv4_forwarding: None,
            prior_ipv6_disabled: None,
            allow_tunnel_relay_forward: false,
            traversal_bootstrap_allow_endpoints: Vec::new(),
            dns_protected: false,
            expected_management_bypass_routes: BTreeSet::new(),
            expected_peer_endpoint_bypass_routes: BTreeSet::new(),
        })
    }

    pub fn with_traversal_bootstrap_allow_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.traversal_bootstrap_allow_endpoints = dedupe_socket_addrs(endpoints);
        self
    }

    fn run(&self, program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), SystemError> {
        let output = self.run_capture(program, args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "{} exited unsuccessfully: status={} stderr={}",
            program.as_str(),
            output.status,
            output.stderr
        )))
    }

    fn run_allow_failure(&self, program: PrivilegedCommandProgram, args: &[&str]) {
        let _ = self.run_capture(program, args);
    }

    fn run_capture(
        &self,
        program: PrivilegedCommandProgram,
        args: &[&str],
    ) -> Result<PrivilegedCommandOutput, SystemError> {
        if let Some(client) = self.privileged_client.as_ref() {
            return client.run_capture(program, args).map_err(SystemError::Io);
        }

        let binary = resolve_binary_path_for_program(program).map_err(|err| {
            SystemError::Io(format!(
                "{} binary resolution failed: {err}",
                program.as_str()
            ))
        })?;
        let output = Command::new(&binary).args(args).output().map_err(|err| {
            SystemError::Io(format!(
                "{} spawn failed ({}): {err}",
                program.as_str(),
                binary.display()
            ))
        })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn apply_fail_closed_management_allow_rules(&self, table: &str) -> Result<(), SystemError> {
        if !self.fail_closed_ssh_allow {
            return Ok(());
        }
        for cidr in &self.fail_closed_ssh_allow_cidrs {
            let cidr_text = cidr.to_string();
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table,
                    "killswitch",
                    cidr.nft_family(),
                    "daddr",
                    cidr_text.as_str(),
                    "tcp",
                    "dport",
                    "22",
                    "accept",
                ],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "management ssh fail-closed allow rule failed for {cidr_text}: {err}"
                ))
            })?;
            // The killswitch only filters outbound traffic. Allowing destination
            // port 22 preserves node-initiated SSH, but inbound management SSH
            // also needs sshd reply packets (source port 22) to escape the
            // host under fail-closed policy.
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table,
                    "killswitch",
                    cidr.nft_family(),
                    "daddr",
                    cidr_text.as_str(),
                    "tcp",
                    "sport",
                    "22",
                    "accept",
                ],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "management ssh reply fail-closed allow rule failed for {cidr_text}: {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn apply_traversal_bootstrap_allow_rules(&self, table: &str) -> Result<(), SystemError> {
        for endpoint in &self.traversal_bootstrap_allow_endpoints {
            let args = Self::traversal_bootstrap_allow_rule_args(
                table,
                self.egress_interface.as_str(),
                *endpoint,
            );
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            self.run(PrivilegedCommandProgram::Nft, &arg_refs)
                .map_err(|err| {
                    SystemError::FirewallApplyFailed(format!(
                        "traversal bootstrap allow rule failed for {endpoint}: {err}"
                    ))
                })?;
        }
        Ok(())
    }

    fn apply_fail_closed_management_bypass_routes(&mut self) -> Result<(), SystemError> {
        self.expected_management_bypass_routes.clear();
        if !self.fail_closed_ssh_allow {
            return Ok(());
        }
        for cidr in &self.fail_closed_ssh_allow_cidrs {
            // Management SSH must stay on the underlay interface. Resolving the
            // current FIB here can return the tunnel once exit-mode policy
            // routing is already active, which black-holes the control plane.
            let args = Self::management_bypass_route_args(cidr, self.egress_interface.as_str());
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            let result = self.run(PrivilegedCommandProgram::Ip, &arg_refs);
            result.map_err(|err| {
                SystemError::RouteApplyFailed(format!(
                    "management ssh bypass route failed for {cidr}: {err}"
                ))
            })?;
            self.expected_management_bypass_routes
                .insert(Self::expected_bypass_route(
                    cidr.to_string(),
                    self.egress_interface.clone(),
                ));
        }
        Ok(())
    }

    fn resolve_route_interface_for_ip(&self, target_ip: IpAddr) -> Result<String, SystemError> {
        let mut args = Vec::with_capacity(4);
        if matches!(target_ip, IpAddr::V6(_)) {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push("get".to_string());
        args.push(target_ip.to_string());
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self.run_capture(PrivilegedCommandProgram::Ip, &arg_refs)?;
        if !output.success() {
            return Err(SystemError::RouteApplyFailed(format!(
                "route interface resolution failed for {target_ip}: status={} stderr={}",
                output.status,
                output.stderr.trim()
            )));
        }
        let tokens = output.stdout.split_whitespace().collect::<Vec<_>>();
        for (index, token) in tokens.iter().enumerate() {
            if *token == "dev" {
                let Some(interface) = tokens.get(index + 1) else {
                    break;
                };
                validate_net_device_name(interface).map_err(|message| {
                    SystemError::RouteApplyFailed(format!(
                        "route interface resolution returned invalid interface for {target_ip}: {message}"
                    ))
                })?;
                return Ok((*interface).to_string());
            }
        }
        Err(SystemError::RouteApplyFailed(format!(
            "route interface resolution failed for {target_ip}: missing dev in output={}",
            output.stdout.trim()
        )))
    }

    fn route_table_output(&self, family: RouteTableFamily) -> Result<String, SystemError> {
        let args = match family {
            RouteTableFamily::V4 => ["-4", "route", "show", "table", "51820"],
            RouteTableFamily::V6 => ["-6", "route", "show", "table", "51820"],
        };
        let output = self.run_capture(PrivilegedCommandProgram::Ip, &args)?;
        if output.success() {
            return Ok(output.stdout);
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "{} failed: status={} stderr={}",
            args.join(" "),
            output.status,
            output.stderr.trim()
        )))
    }

    fn nft_table_output(
        &self,
        family: &str,
        table: &str,
        context: &str,
    ) -> Result<String, SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Nft,
            &["list", "table", family, table],
        )?;
        if output.success() {
            return Ok(output.stdout);
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "{context} failed: status={} stderr={}",
            output.status,
            output.stderr.trim()
        )))
    }

    fn normalize_ruleset_line(line: &str) -> String {
        line.replace('"', "")
    }

    fn nft_chain_lines(ruleset: &str, chain_name: &str) -> Option<Vec<String>> {
        let mut in_chain = false;
        let mut depth = 0usize;
        let mut lines = Vec::new();

        for raw_line in ruleset.lines() {
            let normalized = Self::normalize_ruleset_line(raw_line);
            let trimmed = normalized.trim();
            if !in_chain {
                if trimmed.starts_with(&format!("chain {chain_name}")) {
                    in_chain = true;
                    depth = depth
                        .saturating_add(trimmed.matches('{').count())
                        .saturating_sub(trimmed.matches('}').count());
                }
                continue;
            }

            depth = depth
                .saturating_add(trimmed.matches('{').count())
                .saturating_sub(trimmed.matches('}').count());
            if trimmed != "}" {
                lines.push(trimmed.to_string());
            }
            if depth == 0 {
                return Some(lines);
            }
        }

        None
    }

    fn chain_contains_all_tokens(lines: &[String], tokens: &[&str]) -> bool {
        lines
            .iter()
            .any(|line| tokens.iter().all(|token| line.contains(token)))
    }

    fn assert_chain_contains(
        &self,
        chain_lines: &[String],
        tokens: &[&str],
        message: &str,
    ) -> Result<(), SystemError> {
        if Self::chain_contains_all_tokens(chain_lines, tokens) {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "{message}: missing tokens={} chain_lines={}",
            tokens.join(" "),
            chain_lines.join(" | ")
        )))
    }

    fn expected_bypass_route(addr_or_cidr: String, interface_name: String) -> ExpectedBypassRoute {
        let family = if addr_or_cidr.contains(':') {
            RouteTableFamily::V6
        } else {
            RouteTableFamily::V4
        };
        ExpectedBypassRoute {
            destination: addr_or_cidr,
            interface_name,
            family,
        }
    }

    fn route_destination_matches_rendered(expected: &str, rendered: &str) -> bool {
        if rendered == expected {
            return true;
        }
        let Some((address, prefix)) = expected.split_once('/') else {
            return false;
        };
        let host_prefix = if address.contains(':') { "128" } else { "32" };
        prefix == host_prefix && rendered == address
    }

    fn line_matches_expected_bypass_route(line: &str, route: &ExpectedBypassRoute) -> bool {
        let mut tokens = line.split_whitespace();
        let Some(destination) = tokens.next() else {
            return false;
        };
        if !Self::route_destination_matches_rendered(route.destination.as_str(), destination) {
            return false;
        }
        let token_vec: Vec<_> = line.split_whitespace().collect();
        token_vec
            .windows(2)
            .any(|window| window[0] == "dev" && window[1] == route.interface_name.as_str())
    }

    fn assert_expected_bypass_routes(&self) -> Result<(), SystemError> {
        let mut table_v4: Option<String> = None;
        let mut table_v6: Option<String> = None;
        for route in self
            .expected_management_bypass_routes
            .iter()
            .chain(self.expected_peer_endpoint_bypass_routes.iter())
        {
            let table_output = match route.family {
                RouteTableFamily::V4 => {
                    if table_v4.is_none() {
                        table_v4 = Some(self.route_table_output(RouteTableFamily::V4)?);
                    }
                    table_v4.as_deref().ok_or_else(|| {
                        SystemError::KillSwitchAssertionFailed(
                            "missing cached ipv4 route table output".to_string(),
                        )
                    })?
                }
                RouteTableFamily::V6 => {
                    if table_v6.is_none() {
                        table_v6 = Some(self.route_table_output(RouteTableFamily::V6)?);
                    }
                    table_v6.as_deref().ok_or_else(|| {
                        SystemError::KillSwitchAssertionFailed(
                            "missing cached ipv6 route table output".to_string(),
                        )
                    })?
                }
            };
            if table_output
                .lines()
                .any(|line| Self::line_matches_expected_bypass_route(line, route))
            {
                continue;
            }
            let expected = format!("{} dev {}", route.destination, route.interface_name);
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "missing owned bypass route in table 51820: expected={} output={}",
                expected,
                table_output.trim()
            )));
        }
        Ok(())
    }

    fn assert_default_route_absent_from_tunnel(
        &self,
        route_table_output: &str,
    ) -> Result<(), SystemError> {
        let forbidden = format!("default dev {}", self.interface_name);
        if !route_table_output.contains(forbidden.as_str()) {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "unexpected full-tunnel default route remains in table 51820 while exit mode is off: forbidden={} output={}",
            forbidden,
            route_table_output.trim()
        )))
    }

    fn assert_nat_forwarding(&self) -> Result<(), SystemError> {
        let Some(table) = self.nat_table.as_deref() else {
            return Ok(());
        };
        let ruleset = self.nft_table_output("ip", table, "nft list nat table")?;
        let postrouting = Self::nft_chain_lines(&ruleset, "postrouting").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("nat postrouting chain missing".to_string())
        })?;
        self.assert_chain_contains(
            &postrouting,
            &["oifname", self.egress_interface.as_str(), "masquerade"],
            "egress masquerade rule missing",
        )?;
        if self.allow_tunnel_relay_forward {
            self.assert_chain_contains(
                &postrouting,
                &[
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "masquerade",
                ],
                "relay-with-upstream masquerade rule missing",
            )?;
        }
        let forwarding_enabled =
            Self::read_sysctl_bool("/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward")?;
        if forwarding_enabled {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(
            "ipv4 forwarding is disabled while nat forwarding is active".to_string(),
        ))
    }

    fn assert_firewall_ruleset(&self) -> Result<(), SystemError> {
        let table = self.firewall_table.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("killswitch table missing".to_string())
        })?;
        let ruleset = self.nft_table_output("inet", table.as_str(), "nft list killswitch table")?;
        let killswitch = Self::nft_chain_lines(&ruleset, "killswitch").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("killswitch chain missing".to_string())
        })?;
        let forward = Self::nft_chain_lines(&ruleset, "forward").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("forward chain missing".to_string())
        })?;
        self.assert_chain_contains(
            &killswitch,
            &["oifname", "lo", "accept"],
            "loopback killswitch allow rule missing",
        )?;
        self.assert_chain_contains(
            &killswitch,
            &["ct state established,related", "accept"],
            "established/related killswitch allow rule missing",
        )?;
        self.assert_chain_contains(
            &killswitch,
            &["oifname", self.interface_name.as_str(), "accept"],
            "tunnel-interface killswitch allow rule missing",
        )?;
        self.assert_chain_contains(
            &forward,
            &["ct state established,related", "accept"],
            "forward established/related allow rule missing",
        )?;
        self.assert_chain_contains(
            &forward,
            &[
                "iifname",
                self.interface_name.as_str(),
                "oifname",
                self.egress_interface.as_str(),
                "accept",
            ],
            "forwarding allow rule to underlay egress missing",
        )?;
        if self.allow_tunnel_relay_forward {
            self.assert_chain_contains(
                &forward,
                &[
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "accept",
                ],
                "relay-with-upstream forwarding allow rule missing",
            )?;
        }
        if self.nat_table.is_some() {
            self.assert_chain_contains(
                &killswitch,
                &["oifname", self.egress_interface.as_str(), "accept"],
                "egress-interface killswitch allow rule missing while nat forwarding is active",
            )?;
        }
        if self.dns_protected {
            self.assert_chain_contains(
                &killswitch,
                &[
                    "udp",
                    "dport",
                    "53",
                    "oifname",
                    "!=",
                    self.interface_name.as_str(),
                    "drop",
                ],
                "dns udp fail-closed rule missing",
            )?;
            self.assert_chain_contains(
                &killswitch,
                &[
                    "tcp",
                    "dport",
                    "53",
                    "oifname",
                    "!=",
                    self.interface_name.as_str(),
                    "drop",
                ],
                "dns tcp fail-closed rule missing",
            )?;
            self.assert_chain_contains(
                &killswitch,
                &["udp", "dport", "53", "accept"],
                "dns udp allow rule missing",
            )?;
            self.assert_chain_contains(
                &killswitch,
                &["tcp", "dport", "53", "accept"],
                "dns tcp allow rule missing",
            )?;
        }
        Ok(())
    }

    fn assert_rule_lookup_51820(&self, expected: bool) -> Result<(), SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Ip, &["rule", "show"])?;
        if !output.success() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "ip rule show failed: status={} stderr={}",
                output.status,
                output.stderr.trim()
            )));
        }
        let present = output
            .stdout
            .lines()
            .any(|line| line.contains("lookup 51820"));
        if present == expected {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "unexpected policy-rule state for table 51820: expected_present={} output={}",
            expected,
            output.stdout.trim()
        )))
    }

    fn assert_default_route_via_tunnel(&self, route_table_output: &str) -> Result<(), SystemError> {
        let expected = format!("default dev {}", self.interface_name);
        if route_table_output.contains(expected.as_str()) {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "missing full-tunnel default route in table 51820: expected={} output={}",
            expected,
            route_table_output.trim()
        )))
    }

    fn assert_probe_route_uses_interface(
        &self,
        expected_interface: &str,
    ) -> Result<(), SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Ip,
            &["-4", "route", "get", "1.1.1.1"],
        )?;
        if !output.success() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "ip -4 route get 1.1.1.1 failed: status={} stderr={}",
                output.status,
                output.stderr.trim()
            )));
        }
        let expected = format!("dev {expected_interface}");
        if output.stdout.contains(expected.as_str()) {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "route probe does not use expected interface: expected={} output={}",
            expected,
            output.stdout.trim()
        )))
    }

    fn assert_probe_route_avoids_interface(
        &self,
        forbidden_interface: &str,
    ) -> Result<(), SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Ip,
            &["-4", "route", "get", "1.1.1.1"],
        )?;
        if !output.success() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "ip -4 route get 1.1.1.1 failed: status={} stderr={}",
                output.status,
                output.stderr.trim()
            )));
        }
        let forbidden = format!("dev {forbidden_interface}");
        if !output.stdout.contains(forbidden.as_str()) {
            return Ok(());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "route probe unexpectedly uses tunnel interface while exit mode is off: forbidden={} output={}",
            forbidden,
            output.stdout.trim()
        )))
    }

    fn management_bypass_route_args(cidr: &ManagementCidr, route_interface: &str) -> Vec<String> {
        let mut args = Vec::with_capacity(9);
        if cidr.is_ipv6() {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push("replace".to_string());
        args.push(cidr.to_string());
        args.push("dev".to_string());
        args.push(route_interface.to_string());
        args.push("table".to_string());
        args.push("51820".to_string());
        args
    }

    fn peer_endpoint_bypass_route_args(addr: IpAddr, route_interface: &str) -> Vec<String> {
        let endpoint_cidr = match addr {
            IpAddr::V4(value) => format!("{value}/32"),
            IpAddr::V6(value) => format!("{value}/128"),
        };
        let mut args = Vec::with_capacity(9);
        if matches!(addr, IpAddr::V6(_)) {
            args.push("-6".to_string());
        }
        args.push("route".to_string());
        args.push("replace".to_string());
        args.push(endpoint_cidr);
        args.push("dev".to_string());
        args.push(route_interface.to_string());
        args.push("table".to_string());
        args.push("51820".to_string());
        args
    }

    fn traversal_bootstrap_allow_rule_args(
        table: &str,
        egress_interface: &str,
        endpoint: SocketAddr,
    ) -> Vec<String> {
        vec![
            "add".to_string(),
            "rule".to_string(),
            "inet".to_string(),
            table.to_string(),
            "killswitch".to_string(),
            "oifname".to_string(),
            egress_interface.to_string(),
            nft_family_for_ip(endpoint.ip()).to_string(),
            "daddr".to_string(),
            endpoint.ip().to_string(),
            "udp".to_string(),
            "dport".to_string(),
            endpoint.port().to_string(),
            "accept".to_string(),
            "comment".to_string(),
            "rustynet_traversal_bootstrap".to_string(),
        ]
    }

    fn set_ipv4_forwarding(&self, enabled: bool) -> Result<(), SystemError> {
        let use_native_write = matches!(self.mode, LinuxDataplaneMode::HybridNative)
            && self.privileged_client.is_none();
        if use_native_write {
            return fs::write(
                "/proc/sys/net/ipv4/ip_forward",
                if enabled { "1\n" } else { "0\n" },
            )
            .map_err(|err| SystemError::Io(format!("native ip_forward write failed: {err}")));
        }
        self.run(
            PrivilegedCommandProgram::Sysctl,
            &[
                "-w",
                if enabled {
                    "net.ipv4.ip_forward=1"
                } else {
                    "net.ipv4.ip_forward=0"
                },
            ],
        )
    }

    fn set_ipv6_disabled(&self, disabled: bool) -> Result<(), SystemError> {
        let use_native_write = matches!(self.mode, LinuxDataplaneMode::HybridNative)
            && self.privileged_client.is_none();
        if use_native_write {
            return fs::write(
                "/proc/sys/net/ipv6/conf/all/disable_ipv6",
                if disabled { "1\n" } else { "0\n" },
            )
            .map_err(|err| SystemError::Io(format!("native ipv6 disable write failed: {err}")));
        }
        self.run(
            PrivilegedCommandProgram::Sysctl,
            &[
                "-w",
                if disabled {
                    "net.ipv6.conf.all.disable_ipv6=1"
                } else {
                    "net.ipv6.conf.all.disable_ipv6=0"
                },
            ],
        )
    }

    fn firewall_table_name(&self) -> String {
        format!("rustynet_g{}", self.generation)
    }

    fn nat_table_name(&self) -> String {
        format!("rustynet_nat_g{}", self.generation)
    }

    fn ensure_failclosed_table(&mut self) -> Result<String, SystemError> {
        let target_table = self.firewall_table_name();
        if let Some(table) = self.firewall_table.clone()
            && table == target_table
        {
            if self.killswitch_chain_exists(table.as_str())? {
                return Ok(table);
            }
            // The expected generation table exists in state but is missing its
            // fail-closed chain on host. Recreate this generation table.
            self.firewall_table = None;
        }

        let table = target_table;
        self.run_allow_failure(
            PrivilegedCommandProgram::Nft,
            &["delete", "table", "inet", table.as_str()],
        );
        self.run(
            PrivilegedCommandProgram::Nft,
            &["add", "table", "inet", table.as_str()],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "inet",
                table.as_str(),
                "killswitch",
                "{",
                "type",
                "filter",
                "hook",
                "output",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.apply_fail_closed_management_allow_rules(table.as_str())?;
        self.apply_traversal_bootstrap_allow_rules(table.as_str())?;
        self.firewall_table = Some(table.clone());
        Ok(table)
    }

    fn read_sysctl_bool(path: &str, key: &str) -> Result<bool, SystemError> {
        let raw = fs::read_to_string(path)
            .map_err(|err| SystemError::Io(format!("read {key} failed: {err}")))?;
        let value = raw.trim();
        match value {
            "0" => Ok(false),
            "1" => Ok(true),
            _ => Err(SystemError::Io(format!("unexpected {key} value: {value}"))),
        }
    }

    fn restore_ipv4_forwarding(&mut self) -> Result<(), SystemError> {
        if let Some(previous) = self.prior_ipv4_forwarding.take() {
            self.set_ipv4_forwarding(previous)
                .map_err(|err| SystemError::RollbackFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn list_tables(&self) -> Result<Vec<(String, String)>, SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Nft, &["list", "tables"])?;
        if !output.success() {
            return Err(SystemError::Io(format!(
                "nft list tables exited unsuccessfully: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        let mut tables = Vec::new();
        for line in output.stdout.lines() {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() == 3 && parts[0] == "table" {
                tables.push((parts[1].to_string(), parts[2].to_string()));
            }
        }
        Ok(tables)
    }

    fn has_fail_closed_drop_rule(&self, table: &str) -> Result<bool, SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Nft,
            &["list", "chain", "inet", table, "killswitch"],
        )?;
        if !output.success() {
            if Self::is_nft_missing_object_error(output.stderr.as_str()) {
                return Ok(false);
            }
            return Err(SystemError::BlockEgressFailed(format!(
                "nft list chain exited unsuccessfully: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        Ok(output
            .stdout
            .contains("comment \"rustynet_fail_closed_drop\""))
    }

    fn killswitch_chain_exists(&self, table: &str) -> Result<bool, SystemError> {
        let output = self.run_capture(
            PrivilegedCommandProgram::Nft,
            &["list", "chain", "inet", table, "killswitch"],
        )?;
        if output.success() {
            return Ok(true);
        }
        if Self::is_nft_missing_object_error(output.stderr.as_str()) {
            return Ok(false);
        }
        Err(SystemError::Io(format!(
            "nft list chain exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn is_nft_missing_object_error(stderr: &str) -> bool {
        stderr
            .to_ascii_lowercase()
            .contains("no such file or directory")
    }
}

impl DataplaneSystem for LinuxCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        self.allow_tunnel_relay_forward = enabled;
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        let keep_firewall_target = self.firewall_table_name();
        let keep_nat_target = self.nat_table_name();
        let keep_firewall_active = self.firewall_table.clone();
        let keep_nat_active = self.nat_table.clone();
        for (family, table) in self.list_tables()? {
            let is_owned = (family == "inet" && table.starts_with("rustynet_g"))
                || (family == "ip" && table.starts_with("rustynet_nat_g"));
            if !is_owned {
                continue;
            }
            if family == "inet"
                && (table == keep_firewall_target
                    || keep_firewall_active
                        .as_deref()
                        .map(|active| active == table.as_str())
                        .unwrap_or(false))
            {
                continue;
            }
            if family == "ip"
                && (table == keep_nat_target
                    || keep_nat_active
                        .as_deref()
                        .map(|active| active == table.as_str())
                        .unwrap_or(false))
            {
                continue;
            }
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", family.as_str(), table.as_str()],
            );
        }
        Ok(())
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        #[cfg(target_os = "linux")]
        {
            self.run(PrivilegedCommandProgram::Ip, &["-V"])?;
            self.run(PrivilegedCommandProgram::Nft, &["--version"])?;
            self.run(PrivilegedCommandProgram::Wg, &["--version"])?;
            self.run(PrivilegedCommandProgram::Sysctl, &["--version"])?;
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(SystemError::PrerequisiteCheckFailed(
            "linux command system is only supported on linux".to_string(),
        ))
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        let mut endpoints = BTreeSet::new();
        self.expected_peer_endpoint_bypass_routes.clear();
        for peer in peers {
            endpoints.insert(peer.endpoint.addr);
        }
        for endpoint in endpoints {
            let route_interface = self.resolve_route_interface_for_ip(endpoint)?;
            let args = Self::peer_endpoint_bypass_route_args(endpoint, route_interface.as_str());
            let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
            self.run(PrivilegedCommandProgram::Ip, &arg_refs)
                .map_err(|err| {
                    SystemError::RouteApplyFailed(format!(
                        "peer endpoint bypass route failed for {endpoint}: {err}"
                    ))
                })?;
            self.expected_peer_endpoint_bypass_routes
                .insert(Self::expected_bypass_route(
                    match endpoint {
                        IpAddr::V4(value) => format!("{value}/32"),
                        IpAddr::V6(value) => format!("{value}/128"),
                    },
                    route_interface,
                ));
        }
        Ok(())
    }

    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError> {
        self.apply_fail_closed_management_bypass_routes()?;
        for route in routes {
            self.run(
                PrivilegedCommandProgram::Ip,
                &[
                    "route",
                    "replace",
                    route.destination_cidr.as_str(),
                    "dev",
                    self.interface_name.as_str(),
                    "table",
                    "51820",
                ],
            )
            .map_err(|err| SystemError::RouteApplyFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        // `ip route flush table 51820` exits non-zero when the table is absent,
        // which is an acceptable rollback outcome on a fresh host.
        self.run_allow_failure(
            PrivilegedCommandProgram::Ip,
            &["route", "flush", "table", "51820"],
        );
        self.run_allow_failure(
            PrivilegedCommandProgram::Ip,
            &["-6", "route", "flush", "table", "51820"],
        );
        self.expected_management_bypass_routes.clear();
        self.expected_peer_endpoint_bypass_routes.clear();
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        let previous_table = self.firewall_table.clone();
        let table = self.ensure_failclosed_table()?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "inet",
                table.as_str(),
                "forward",
                "{",
                "type",
                "filter",
                "hook",
                "forward",
                "priority",
                "0",
                ";",
                "policy",
                "drop",
                ";",
                "}",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "oifname",
                "lo",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "oifname",
                self.interface_name.as_str(),
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "forward",
                "ct",
                "state",
                "established,related",
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "forward",
                "iifname",
                self.interface_name.as_str(),
                "oifname",
                self.egress_interface.as_str(),
                "accept",
            ],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        if self.allow_tunnel_relay_forward {
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table.as_str(),
                    "forward",
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "accept",
                ],
            )
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        }
        if let Some(previous) = previous_table
            && previous != table
        {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "inet", previous.as_str()],
            );
        }
        Ok(())
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        if let Some(table) = self.firewall_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "inet", table.as_str()],
            );
        }
        Ok(())
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.prior_ipv4_forwarding = Some(Self::read_sysctl_bool(
            "/proc/sys/net/ipv4/ip_forward",
            "net.ipv4.ip_forward",
        )?);
        self.set_ipv4_forwarding(true)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))?;

        if let Some(previous) = self.nat_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", previous.as_str()],
            );
        }
        let nat_table = self.nat_table_name();
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &["add", "table", "ip", nat_table.as_str()],
        ) {
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "chain",
                "ip",
                nat_table.as_str(),
                "postrouting",
                "{",
                "type",
                "nat",
                "hook",
                "postrouting",
                "priority",
                "100",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ) {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", nat_table.as_str()],
            );
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if let Err(err) = self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "ip",
                nat_table.as_str(),
                "postrouting",
                "oifname",
                self.egress_interface.as_str(),
                "masquerade",
            ],
        ) {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", nat_table.as_str()],
            );
            let _ = self.restore_ipv4_forwarding();
            return Err(SystemError::NatApplyFailed(err.to_string()));
        }
        if self.allow_tunnel_relay_forward {
            match self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "ip",
                    nat_table.as_str(),
                    "postrouting",
                    "iifname",
                    self.interface_name.as_str(),
                    "oifname",
                    self.interface_name.as_str(),
                    "masquerade",
                ],
            ) {
                Ok(()) => {}
                Err(err) => {
                    self.run_allow_failure(
                        PrivilegedCommandProgram::Nft,
                        &["delete", "table", "ip", nat_table.as_str()],
                    );
                    let _ = self.restore_ipv4_forwarding();
                    return Err(SystemError::NatApplyFailed(err.to_string()));
                }
            }
        }
        // Collect firewall table name and egress interface before moving nat_table.
        let egress_allow = self
            .firewall_table
            .as_ref()
            .map(|fw| (fw.clone(), self.egress_interface.clone()));

        self.nat_table = Some(nat_table);

        // Allow the exit node device's own outbound traffic via the egress interface.
        // The killswitch chain has policy drop on the OUTPUT hook; without this rule
        // the exit node device itself cannot open new connections to the internet
        // while acting as an exit node.
        if let Some((fw_table, egress_iface)) = egress_allow {
            let nat_name = self.nat_table.as_deref().unwrap_or("").to_string();
            if let Err(err) = self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    fw_table.as_str(),
                    "killswitch",
                    "oifname",
                    egress_iface.as_str(),
                    "accept",
                ],
            ) {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Nft,
                    &["delete", "table", "ip", nat_name.as_str()],
                );
                self.nat_table = None;
                let _ = self.restore_ipv4_forwarding();
                return Err(SystemError::NatApplyFailed(format!(
                    "egress access rule failed: {err}"
                )));
            }
        }

        Ok(())
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        if let Some(table) = self.nat_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", table.as_str()],
            );
        }
        self.restore_ipv4_forwarding()
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        let table = self
            .firewall_table
            .clone()
            .ok_or_else(|| SystemError::DnsApplyFailed("killswitch table missing".to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "udp",
                "dport",
                "53",
                "oifname",
                "!=",
                self.interface_name.as_str(),
                "drop",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "tcp",
                "dport",
                "53",
                "oifname",
                "!=",
                self.interface_name.as_str(),
                "drop",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "udp",
                "dport",
                "53",
                "accept",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "tcp",
                "dport",
                "53",
                "accept",
            ],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.dns_protected = true;
        Ok(())
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = false;
        Ok(())
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.prior_ipv6_disabled = Some(Self::read_sysctl_bool(
            "/proc/sys/net/ipv6/conf/all/disable_ipv6",
            "net.ipv6.conf.all.disable_ipv6",
        )?);
        self.set_ipv6_disabled(true)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        if let Some(previous) = self.prior_ipv6_disabled.take() {
            self.set_ipv6_disabled(previous)
                .map_err(|err| SystemError::RollbackFailed(err.to_string()))?;
        }
        Ok(())
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        self.assert_firewall_ruleset()
    }

    fn assert_exit_policy(&mut self, exit_mode: ExitMode) -> Result<(), SystemError> {
        self.assert_killswitch()?;
        self.assert_nat_forwarding()?;
        self.assert_expected_bypass_routes()?;
        let route_table_v4 = self.route_table_output(RouteTableFamily::V4)?;
        match exit_mode {
            ExitMode::Off => {
                self.assert_rule_lookup_51820(false)?;
                self.assert_default_route_absent_from_tunnel(route_table_v4.as_str())?;
                self.assert_probe_route_avoids_interface(self.interface_name.as_str())?;
            }
            ExitMode::FullTunnel => {
                self.assert_rule_lookup_51820(true)?;
                self.assert_default_route_via_tunnel(route_table_v4.as_str())?;
                self.assert_probe_route_uses_interface(self.interface_name.as_str())?;
            }
        }
        Ok(())
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        let table = self.ensure_failclosed_table()?;
        if self.has_fail_closed_drop_rule(table.as_str())? {
            return Ok(());
        }
        self.run(
            PrivilegedCommandProgram::Nft,
            &[
                "add",
                "rule",
                "inet",
                table.as_str(),
                "killswitch",
                "counter",
                "drop",
                "comment",
                "rustynet_fail_closed_drop",
            ],
        )
        .map_err(|err| SystemError::BlockEgressFailed(err.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosCommandSystem {
    interface_name: String,
    egress_interface: String,
    privileged_client: Option<PrivilegedCommandClient>,
    generation: u64,
    fail_closed_ssh_allow: bool,
    fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    anchor_name: Option<String>,
    allow_egress_interface: bool,
    ipv6_blocked: bool,
    dns_protected: bool,
    traversal_bootstrap_allow_endpoints: Vec<SocketAddr>,
}

impl MacosCommandSystem {
    pub fn new(
        interface_name: impl Into<String>,
        egress_interface: impl Into<String>,
        privileged_client: Option<PrivilegedCommandClient>,
        fail_closed_ssh_allow: bool,
        fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    ) -> Result<Self, SystemError> {
        let interface_name = interface_name.into();
        let egress_interface = egress_interface.into();
        validate_net_device_name(&interface_name)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided"
                    .to_string(),
            ));
        }
        Ok(Self {
            interface_name,
            egress_interface,
            privileged_client,
            generation: 0,
            fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs,
            anchor_name: None,
            allow_egress_interface: false,
            ipv6_blocked: false,
            dns_protected: false,
            traversal_bootstrap_allow_endpoints: Vec::new(),
        })
    }

    pub fn with_traversal_bootstrap_allow_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.traversal_bootstrap_allow_endpoints = dedupe_socket_addrs(endpoints);
        self
    }

    fn run(&self, program: PrivilegedCommandProgram, args: &[&str]) -> Result<(), SystemError> {
        let output = self.run_capture(program, args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "{} exited unsuccessfully: status={} stderr={}",
            program.as_str(),
            output.status,
            output.stderr
        )))
    }

    fn run_allow_failure(&self, program: PrivilegedCommandProgram, args: &[&str]) {
        let _ = self.run_capture(program, args);
    }

    fn run_capture(
        &self,
        program: PrivilegedCommandProgram,
        args: &[&str],
    ) -> Result<PrivilegedCommandOutput, SystemError> {
        if let Some(client) = self.privileged_client.as_ref() {
            return client.run_capture(program, args).map_err(SystemError::Io);
        }

        let binary = resolve_binary_path_for_program(program).map_err(|err| {
            SystemError::Io(format!(
                "{} binary resolution failed: {err}",
                program.as_str()
            ))
        })?;
        let output = Command::new(&binary).args(args).output().map_err(|err| {
            SystemError::Io(format!(
                "{} spawn failed ({}): {err}",
                program.as_str(),
                binary.display()
            ))
        })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn current_anchor_name(&self) -> String {
        format!("com.apple/rustynet_g{}", self.generation)
    }

    fn ensure_pf_enabled(&self) -> Result<(), SystemError> {
        let info = self.run_capture(PrivilegedCommandProgram::Pfctl, &["-s", "info"])?;
        if info.success() && info.stdout.contains("Status: Enabled") {
            return Ok(());
        }
        self.run(PrivilegedCommandProgram::Pfctl, &["-E"])
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn render_pf_rules(&self, strict_fail_closed: bool) -> Result<String, SystemError> {
        let mut rules = String::new();
        rules.push_str("set block-policy drop\n");
        if !strict_fail_closed {
            rules.push_str("pass out quick inet on lo0 all keep state\n");
            if self.dns_protected {
                rules.push_str(&format!(
                    "pass out quick inet proto udp on {} to any port 53 keep state\n",
                    self.interface_name
                ));
                rules.push_str(&format!(
                    "pass out quick inet proto tcp on {} to any port 53 keep state\n",
                    self.interface_name
                ));
                rules.push_str("block drop out quick inet proto udp to any port 53\n");
                rules.push_str("block drop out quick inet proto tcp to any port 53\n");
            }
            rules.push_str(&format!(
                "pass out quick inet on {} all keep state\n",
                self.interface_name
            ));
            if self.allow_egress_interface {
                rules.push_str(&format!(
                    "pass out quick inet on {} all keep state\n",
                    self.egress_interface
                ));
            }
        }
        if self.fail_closed_ssh_allow {
            for cidr in &self.fail_closed_ssh_allow_cidrs {
                rules.push_str(&format!(
                    "pass out quick {} proto tcp from any to {} port 22 keep state\n",
                    cidr.pf_family(),
                    cidr
                ));
                rules.push_str(&format!(
                    "pass out quick {} proto tcp from any port 22 to {} keep state\n",
                    cidr.pf_family(),
                    cidr
                ));
            }
        }
        for endpoint in &self.traversal_bootstrap_allow_endpoints {
            rules.push_str(&format!(
                "pass out quick {} proto udp on {} to {} port {} keep state\n",
                pf_family_for_ip(endpoint.ip()),
                self.egress_interface,
                endpoint.ip(),
                endpoint.port()
            ));
        }
        if self.ipv6_blocked {
            rules.push_str("block drop out quick inet6 all\n");
        }
        rules.push_str("block drop out quick all\n");
        Ok(rules)
    }

    fn ruleset_contains_dns_rule(
        rules: &str,
        action_token: &str,
        proto: &str,
        interface: Option<&str>,
    ) -> bool {
        let action = action_token.to_ascii_lowercase();
        let proto_token = format!("proto {proto}");
        let interface_token = interface.map(|value| format!("on {}", value.to_ascii_lowercase()));
        rules.lines().any(|line| {
            let normalized = line.trim().to_ascii_lowercase();
            if !normalized.contains(&action) {
                return false;
            }
            if !normalized.contains("inet") {
                return false;
            }
            if !normalized.contains(&proto_token) {
                return false;
            }
            match interface_token.as_ref() {
                Some(token) if !normalized.contains(token) => {
                    return false;
                }
                _ => {}
            }
            normalized.contains("port 53") || normalized.contains("port = domain")
        })
    }

    fn apply_pf_rules(&mut self, strict_fail_closed: bool) -> Result<(), SystemError> {
        self.ensure_pf_enabled()?;
        let next_anchor = self.current_anchor_name();
        match self.anchor_name.as_ref() {
            Some(previous) if previous != &next_anchor => {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Pfctl,
                    &["-a", previous.as_str(), "-F", "all"],
                );
            }
            _ => {}
        }

        let tmp_path = std::env::temp_dir().join(format!(
            "rustynet-pf-rules-{}-{}.conf",
            std::process::id(),
            self.generation
        ));
        let rules = self.render_pf_rules(strict_fail_closed)?;
        fs::write(&tmp_path, rules)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        let tmp = tmp_path
            .to_str()
            .ok_or_else(|| SystemError::FirewallApplyFailed("pf temp path utf8".to_string()))?;
        let apply_result = self.run(
            PrivilegedCommandProgram::Pfctl,
            &["-a", next_anchor.as_str(), "-f", tmp],
        );
        let _ = fs::remove_file(&tmp_path);
        apply_result.map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.anchor_name = Some(next_anchor);
        Ok(())
    }

    fn owned_anchor_names_from_output(stdout: &str) -> Vec<String> {
        stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && line.starts_with("com.apple/rustynet_g"))
            .map(ToOwned::to_owned)
            .collect()
    }

    fn list_owned_anchors(&self) -> Result<Vec<String>, SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Pfctl, &["-s", "Anchors"])?;
        if output.success() {
            return Ok(Self::owned_anchor_names_from_output(&output.stdout));
        }
        let stderr = output.stderr.to_ascii_lowercase();
        if stderr.contains("pf not enabled") {
            return Ok(Vec::new());
        }
        Err(SystemError::Io(format!(
            "pfctl anchor query failed: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn flush_anchor(&mut self) {
        if let Some(anchor) = self.anchor_name.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
    }
}

impl DataplaneSystem for MacosCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        for anchor in self.list_owned_anchors()? {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
        self.anchor_name = None;
        Ok(())
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        #[cfg(target_os = "macos")]
        {
            resolve_binary_path_for_program(PrivilegedCommandProgram::Wg)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::WireguardGo)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Ifconfig)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Route)?;
            resolve_binary_path_for_program(PrivilegedCommandProgram::Pfctl)?;
            self.run(PrivilegedCommandProgram::Ifconfig, &["-l"])?;
            self.run(PrivilegedCommandProgram::Route, &["-n", "get", "default"])?;
            return Ok(());
        }
        #[allow(unreachable_code)]
        Err(SystemError::PrerequisiteCheckFailed(
            "macos command system is only supported on macos".to_string(),
        ))
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        self.flush_anchor();
        Ok(())
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = true;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = true;
        if let Err(err) = self.apply_pf_rules(false) {
            self.dns_protected = false;
            return Err(SystemError::DnsApplyFailed(err.to_string()));
        }
        Ok(())
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.ipv6_blocked = true;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.ipv6_blocked = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        let anchor = self.anchor_name.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("pf anchor missing".to_string())
        })?;
        let output = self.run_capture(
            PrivilegedCommandProgram::Pfctl,
            &["-a", anchor.as_str(), "-s", "rules"],
        )?;
        if !output.success() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "pfctl rules query failed: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        if !output.stdout.contains("block drop out quick all") {
            return Err(SystemError::KillSwitchAssertionFailed(
                "pf killswitch rule missing".to_string(),
            ));
        }
        if self.dns_protected {
            if !Self::ruleset_contains_dns_rule(
                &output.stdout,
                "pass out quick",
                "udp",
                Some(self.interface_name.as_str()),
            ) {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns udp allow rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(
                &output.stdout,
                "pass out quick",
                "tcp",
                Some(self.interface_name.as_str()),
            ) {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp allow rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "udp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns udp block rule missing".to_string(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "tcp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp block rule missing".to_string(),
                ));
            }
        }
        Ok(())
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        self.apply_pf_rules(true)
            .map_err(|err| SystemError::BlockEgressFailed(err.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsCommandSystem {
    interface_name: String,
    egress_interface: String,
    dns_resolver_bind_addr: SocketAddr,
    generation: u64,
    dns_protected: bool,
}

impl WindowsCommandSystem {
    pub fn new(
        interface_name: impl Into<String>,
        egress_interface: impl Into<String>,
        dns_resolver_bind_addr: SocketAddr,
    ) -> Result<Self, SystemError> {
        let interface_name = interface_name.into();
        let egress_interface = egress_interface.into();
        validate_windows_interface_alias(interface_name.as_str())
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        validate_windows_interface_alias(egress_interface.as_str())
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_string()))?;
        if !dns_resolver_bind_addr.ip().is_loopback() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "Windows DNS resolver bind addr must stay on loopback".to_string(),
            ));
        }
        Ok(Self {
            interface_name,
            egress_interface,
            dns_resolver_bind_addr,
            generation: 0,
            dns_protected: false,
        })
    }

    fn resolve_netsh_binary() -> Result<PathBuf, SystemError> {
        let configured = std::env::var(WINDOWS_NETSH_BINARY_PATH_ENV).ok();
        let raw = configured
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_WINDOWS_NETSH_BINARY_PATH);
        validate_windows_binary_path(raw, "netsh")?;
        Ok(PathBuf::from(raw))
    }

    fn run_netsh(&self, args: &[String]) -> Result<PrivilegedCommandOutput, SystemError> {
        let binary = Self::resolve_netsh_binary()?;
        let output = Command::new(&binary).args(args).output().map_err(|err| {
            SystemError::Io(format!("netsh spawn failed ({}): {err}", binary.display()))
        })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn run_netsh_success(&self, args: &[String]) -> Result<(), SystemError> {
        let output = self.run_netsh(args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "netsh exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn apply_dns_loopback(&mut self) -> Result<(), SystemError> {
        validate_windows_dns_bind_addr(self.dns_resolver_bind_addr)?;
        let args = windows_dns_set_args(
            self.interface_name.as_str(),
            self.dns_resolver_bind_addr.ip(),
        )?;
        self.run_netsh_success(&args)
            .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        self.dns_protected = true;
        Ok(())
    }

    fn clear_dns_loopback(&mut self) -> Result<(), SystemError> {
        let args = windows_dns_clear_args(self.interface_name.as_str());
        self.run_netsh_success(&args)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))?;
        self.dns_protected = false;
        Ok(())
    }

    fn firewall_blocker(&self, operation: &str) -> String {
        format!(
            "windows fail-closed firewall operation '{operation}' is not yet reviewed; windows-wireguard-nt stays security-first and must block before claiming a protected Windows dataplane"
        )
    }

    fn nat_blocker(&self) -> String {
        "windows exit-node NAT/forwarding is not yet reviewed; Windows must fail closed instead of advertising unsupported exit-serving behavior".to_string()
    }
}

impl DataplaneSystem for WindowsCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        let _ = Self::resolve_netsh_binary()?;
        let _ = &self.egress_interface;
        Ok(())
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        Err(SystemError::FirewallApplyFailed(
            self.firewall_blocker("apply_firewall_killswitch"),
        ))
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        Err(SystemError::NatApplyFailed(self.nat_blocker()))
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.apply_dns_loopback()
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        if !self.dns_protected {
            return Ok(());
        }
        self.clear_dns_loopback()
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        Err(SystemError::FirewallApplyFailed(
            self.firewall_blocker("hard_disable_ipv6_egress"),
        ))
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        Err(SystemError::KillSwitchAssertionFailed(
            self.firewall_blocker("assert_killswitch"),
        ))
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        Err(SystemError::BlockEgressFailed(
            self.firewall_blocker("block_all_egress"),
        ))
    }
}

#[derive(Debug)]
pub enum RuntimeSystem {
    DryRun(DryRunSystem),
    Linux(LinuxCommandSystem),
    Macos(MacosCommandSystem),
    Windows(WindowsCommandSystem),
}

impl DataplaneSystem for RuntimeSystem {
    fn set_generation(&mut self, generation: u64) {
        match self {
            RuntimeSystem::DryRun(system) => system.set_generation(generation),
            RuntimeSystem::Linux(system) => system.set_generation(generation),
            RuntimeSystem::Macos(system) => system.set_generation(generation),
            RuntimeSystem::Windows(system) => system.set_generation(generation),
        }
    }

    fn set_relay_forwarding(&mut self, enabled: bool) {
        match self {
            RuntimeSystem::DryRun(system) => system.set_relay_forwarding(enabled),
            RuntimeSystem::Linux(system) => system.set_relay_forwarding(enabled),
            RuntimeSystem::Macos(system) => system.set_relay_forwarding(enabled),
            RuntimeSystem::Windows(system) => system.set_relay_forwarding(enabled),
        }
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.prune_owned_tables(),
            RuntimeSystem::Linux(system) => system.prune_owned_tables(),
            RuntimeSystem::Macos(system) => system.prune_owned_tables(),
            RuntimeSystem::Windows(system) => system.prune_owned_tables(),
        }
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.check_prerequisites(),
            RuntimeSystem::Linux(system) => system.check_prerequisites(),
            RuntimeSystem::Macos(system) => system.check_prerequisites(),
            RuntimeSystem::Windows(system) => system.check_prerequisites(),
        }
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_peer_endpoint_bypass_routes(peers),
            RuntimeSystem::Linux(system) => system.apply_peer_endpoint_bypass_routes(peers),
            RuntimeSystem::Macos(system) => system.apply_peer_endpoint_bypass_routes(peers),
            RuntimeSystem::Windows(system) => system.apply_peer_endpoint_bypass_routes(peers),
        }
    }

    fn apply_routes(&mut self, routes: &[Route]) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_routes(routes),
            RuntimeSystem::Linux(system) => system.apply_routes(routes),
            RuntimeSystem::Macos(system) => system.apply_routes(routes),
            RuntimeSystem::Windows(system) => system.apply_routes(routes),
        }
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_routes(),
            RuntimeSystem::Linux(system) => system.rollback_routes(),
            RuntimeSystem::Macos(system) => system.rollback_routes(),
            RuntimeSystem::Windows(system) => system.rollback_routes(),
        }
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_firewall_killswitch(),
            RuntimeSystem::Linux(system) => system.apply_firewall_killswitch(),
            RuntimeSystem::Macos(system) => system.apply_firewall_killswitch(),
            RuntimeSystem::Windows(system) => system.apply_firewall_killswitch(),
        }
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_firewall(),
            RuntimeSystem::Linux(system) => system.rollback_firewall(),
            RuntimeSystem::Macos(system) => system.rollback_firewall(),
            RuntimeSystem::Windows(system) => system.rollback_firewall(),
        }
    }

    fn apply_nat_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_nat_forwarding(),
            RuntimeSystem::Linux(system) => system.apply_nat_forwarding(),
            RuntimeSystem::Macos(system) => system.apply_nat_forwarding(),
            RuntimeSystem::Windows(system) => system.apply_nat_forwarding(),
        }
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_nat_forwarding(),
            RuntimeSystem::Linux(system) => system.rollback_nat_forwarding(),
            RuntimeSystem::Macos(system) => system.rollback_nat_forwarding(),
            RuntimeSystem::Windows(system) => system.rollback_nat_forwarding(),
        }
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_dns_protection(),
            RuntimeSystem::Linux(system) => system.apply_dns_protection(),
            RuntimeSystem::Macos(system) => system.apply_dns_protection(),
            RuntimeSystem::Windows(system) => system.apply_dns_protection(),
        }
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_dns_protection(),
            RuntimeSystem::Linux(system) => system.rollback_dns_protection(),
            RuntimeSystem::Macos(system) => system.rollback_dns_protection(),
            RuntimeSystem::Windows(system) => system.rollback_dns_protection(),
        }
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.hard_disable_ipv6_egress(),
            RuntimeSystem::Linux(system) => system.hard_disable_ipv6_egress(),
            RuntimeSystem::Macos(system) => system.hard_disable_ipv6_egress(),
            RuntimeSystem::Windows(system) => system.hard_disable_ipv6_egress(),
        }
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.rollback_ipv6_egress(),
            RuntimeSystem::Linux(system) => system.rollback_ipv6_egress(),
            RuntimeSystem::Macos(system) => system.rollback_ipv6_egress(),
            RuntimeSystem::Windows(system) => system.rollback_ipv6_egress(),
        }
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.assert_killswitch(),
            RuntimeSystem::Linux(system) => system.assert_killswitch(),
            RuntimeSystem::Macos(system) => system.assert_killswitch(),
            RuntimeSystem::Windows(system) => system.assert_killswitch(),
        }
    }

    fn assert_exit_policy(&mut self, exit_mode: ExitMode) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.assert_exit_policy(exit_mode),
            RuntimeSystem::Linux(system) => system.assert_exit_policy(exit_mode),
            RuntimeSystem::Macos(system) => system.assert_exit_policy(exit_mode),
            RuntimeSystem::Windows(system) => system.assert_exit_policy(exit_mode),
        }
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.block_all_egress(),
            RuntimeSystem::Linux(system) => system.block_all_egress(),
            RuntimeSystem::Macos(system) => system.block_all_egress(),
            RuntimeSystem::Windows(system) => system.block_all_egress(),
        }
    }
}

fn dedupe_socket_addrs(endpoints: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();
    for endpoint in endpoints {
        if seen.insert(endpoint) {
            deduped.push(endpoint);
        }
    }
    deduped
}

fn nft_family_for_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ip",
        IpAddr::V6(_) => "ip6",
    }
}

fn pf_family_for_ip(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "inet",
        IpAddr::V6(_) => "inet6",
    }
}

pub struct Phase10Controller<B: TunnelBackend, S: DataplaneSystem> {
    backend: B,
    system: S,
    policy: ContextualPolicySet,
    trust_policy: TrustPolicy,
    state: DataplaneState,
    generation: u64,
    last_safe_generation: u64,
    transitions: Vec<TransitionEvent>,
    selected_exit_node: Option<NodeId>,
    lan_access_enabled: bool,
    advertised_lan_routes: HashMap<NodeId, BTreeSet<String>>,
    lan_route_acl: HashMap<(String, String), bool>,
    managed_peers: BTreeMap<NodeId, ManagedPeer>,
    current_routes: Vec<Route>,
    current_exit_mode: ExitMode,
    /// How long a Direct candidate must be continuously observed before committing (ms).
    pub direct_stability_window_ms: u64,
    /// How long a Relay candidate must be continuously observed before committing (ms).
    pub relay_stability_window_ms: u64,
    /// Membership directory used to gate peer provisioning and ACL evaluation.
    membership: MembershipDirectory,
}

impl<B: TunnelBackend, S: DataplaneSystem> Phase10Controller<B, S> {
    pub fn new(
        backend: B,
        system: S,
        policy: ContextualPolicySet,
        trust_policy: TrustPolicy,
    ) -> Self {
        Self {
            backend,
            system,
            policy,
            trust_policy,
            state: DataplaneState::Init,
            generation: 0,
            last_safe_generation: 0,
            transitions: Vec::new(),
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_lan_routes: HashMap::new(),
            lan_route_acl: HashMap::new(),
            managed_peers: BTreeMap::new(),
            current_routes: Vec::new(),
            current_exit_mode: ExitMode::Off,
            direct_stability_window_ms: 3_000,
            relay_stability_window_ms: 5_000,
            membership: MembershipDirectory::default(),
        }
    }

    /// Replace the membership directory used for peer provisioning and ACL evaluation.
    pub fn set_membership(&mut self, membership: MembershipDirectory) {
        self.membership = membership;
    }

    pub fn state(&self) -> DataplaneState {
        self.state
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn last_safe_generation(&self) -> u64 {
        self.last_safe_generation
    }

    pub fn transition_audit(&self) -> &[TransitionEvent] {
        &self.transitions
    }

    pub fn selected_exit_node(&self) -> Option<NodeId> {
        self.selected_exit_node.clone()
    }

    pub fn current_exit_mode(&self) -> ExitMode {
        self.current_exit_mode
    }

    pub fn lan_access_enabled(&self) -> bool {
        self.lan_access_enabled
    }

    pub fn establish_control_trust(&mut self, evidence: TrustEvidence) -> Result<(), Phase10Error> {
        validate_trust(&self.trust_policy, evidence)?;
        self.system.check_prerequisites()?;
        self.transition_to(DataplaneState::ControlTrusted, "control_trust_established");
        Ok(())
    }

    pub fn apply_dataplane_generation(
        &mut self,
        evidence: TrustEvidence,
        context: RuntimeContext,
        peers: Vec<PeerConfig>,
        routes: Vec<Route>,
        options: ApplyOptions,
    ) -> Result<(), Phase10Error> {
        validate_trust(&self.trust_policy, evidence)?;
        let target_generation = self.generation.saturating_add(1);
        self.system.set_generation(target_generation);

        if self.state == DataplaneState::Init {
            self.establish_control_trust(evidence)?;
        }
        if !matches!(
            self.state,
            DataplaneState::ControlTrusted
                | DataplaneState::DataplaneApplied
                | DataplaneState::ExitActive
                | DataplaneState::FailClosed
        ) {
            return Err(Phase10Error::InvalidTransition(
                "dataplane apply requires trusted/fail-closed recovery state",
            ));
        }

        self.system.prune_owned_tables()?;

        let mut applied_stages = Vec::new();
        match self.backend.start(context) {
            Ok(()) => applied_stages.push(StageMarker::BackendStarted),
            Err(err) if err.kind == BackendErrorKind::AlreadyRunning => {}
            Err(err) => {
                self.force_fail_closed("backend_start_failed")?;
                return Err(err.into());
            }
        }

        let result = self.apply_generation_stages(peers, routes, options, &mut applied_stages);

        if let Err(err) = result {
            self.rollback_generation(applied_stages)?;
            self.force_fail_closed("apply_failed")?;
            return Err(err);
        }

        self.generation = self.generation.saturating_add(1);
        self.last_safe_generation = self.generation;

        if options.exit_mode == ExitMode::FullTunnel || options.serve_exit_node {
            self.transition_to(
                DataplaneState::ExitActive,
                "dataplane_apply_commit_exit_active",
            );
        } else {
            self.transition_to(DataplaneState::DataplaneApplied, "dataplane_apply_commit");
        }

        Ok(())
    }

    fn apply_generation_stages(
        &mut self,
        peers: Vec<PeerConfig>,
        routes: Vec<Route>,
        options: ApplyOptions,
        applied_stages: &mut Vec<StageMarker>,
    ) -> Result<(), Phase10Error> {
        for peer in &peers {
            check_peer_membership_active(&peer.node_id, &self.membership)?;
            self.backend.configure_peer(peer.clone())?;
            self.managed_peers.insert(
                peer.node_id.clone(),
                ManagedPeer {
                    configured: peer.clone(),
                    direct_endpoint: peer.endpoint,
                    relay_endpoint: None,
                    path: PathMode::Direct,
                    pending_path_mode: None,
                    pending_since: None,
                },
            );
            applied_stages.push(StageMarker::PeerApplied);
        }

        self.system.rollback_routes()?;
        self.system.apply_peer_endpoint_bypass_routes(&peers)?;
        applied_stages.push(StageMarker::EndpointBypassApplied);

        self.backend.apply_routes(routes.clone())?;
        self.current_routes = routes.clone();
        applied_stages.push(StageMarker::BackendRoutesApplied);

        self.system.apply_routes(&routes)?;
        applied_stages.push(StageMarker::SystemRoutesApplied);

        let relay_with_upstream =
            options.exit_mode == ExitMode::FullTunnel && options.serve_exit_node;
        self.system.set_relay_forwarding(relay_with_upstream);
        self.system.apply_firewall_killswitch()?;
        applied_stages.push(StageMarker::FirewallApplied);

        if options.exit_mode == ExitMode::FullTunnel || options.serve_exit_node {
            self.system.apply_nat_forwarding()?;
            applied_stages.push(StageMarker::NatApplied);
        }

        if options.protected_dns {
            self.system.apply_dns_protection()?;
            applied_stages.push(StageMarker::DnsApplied);
        }

        if !options.ipv6_parity_supported {
            self.system.hard_disable_ipv6_egress()?;
            applied_stages.push(StageMarker::Ipv6Blocked);
        }

        self.backend.set_exit_mode(options.exit_mode)?;
        applied_stages.push(StageMarker::ExitModeApplied);

        self.system.assert_exit_policy(options.exit_mode)?;
        self.current_exit_mode = options.exit_mode;

        Ok(())
    }

    fn rollback_generation(
        &mut self,
        applied_stages: Vec<StageMarker>,
    ) -> Result<(), Phase10Error> {
        for stage in applied_stages.into_iter().rev() {
            match stage {
                StageMarker::ExitModeApplied => {
                    let _ = self.backend.set_exit_mode(ExitMode::Off);
                    self.current_exit_mode = ExitMode::Off;
                }
                StageMarker::Ipv6Blocked => {
                    self.system.rollback_ipv6_egress()?;
                }
                StageMarker::DnsApplied => {
                    self.system.rollback_dns_protection()?;
                }
                StageMarker::NatApplied => {
                    self.system.rollback_nat_forwarding()?;
                }
                StageMarker::FirewallApplied => {
                    self.system.rollback_firewall()?;
                }
                StageMarker::EndpointBypassApplied => {
                    self.system.rollback_routes()?;
                }
                StageMarker::SystemRoutesApplied => {
                    self.system.rollback_routes()?;
                }
                StageMarker::BackendRoutesApplied => {
                    self.backend.apply_routes(Vec::new())?;
                    self.current_routes.clear();
                }
                StageMarker::PeerApplied => {
                    if let Some(node_id) = self.managed_peers.keys().next().cloned() {
                        self.backend.remove_peer(&node_id)?;
                        self.managed_peers.remove(&node_id);
                    }
                }
                StageMarker::BackendStarted => {
                    let _ = self.backend.shutdown();
                }
            }
        }

        Ok(())
    }

    pub fn force_fail_closed(&mut self, reason: &str) -> Result<(), Phase10Error> {
        self.system.block_all_egress()?;
        self.current_exit_mode = ExitMode::Off;
        self.transition_to(DataplaneState::FailClosed, reason);
        Ok(())
    }

    pub fn set_exit_node(
        &mut self,
        node_id: NodeId,
        requester: &str,
        protocol: Protocol,
    ) -> Result<(), Phase10Error> {
        self.ensure_started()?;

        let decision = self.policy.evaluate(&ContextualAccessRequest {
            src: requester.to_string(),
            dst: format!("node:{}", node_id.as_str()),
            protocol,
            context: TrafficContext::SharedExit,
        });
        if decision != Decision::Allow {
            return Err(Phase10Error::PolicyDenied);
        }

        self.backend.set_exit_mode(ExitMode::FullTunnel)?;
        self.system.assert_exit_policy(ExitMode::FullTunnel)?;
        self.current_exit_mode = ExitMode::FullTunnel;
        self.selected_exit_node = Some(node_id);
        self.transition_to(DataplaneState::ExitActive, "exit_node_selected");
        Ok(())
    }

    pub fn clear_exit_node(&mut self) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        self.backend.set_exit_mode(ExitMode::Off)?;
        self.system.assert_exit_policy(ExitMode::Off)?;
        self.current_exit_mode = ExitMode::Off;
        self.selected_exit_node = None;
        self.transition_to(DataplaneState::DataplaneApplied, "exit_node_cleared");
        Ok(())
    }

    pub fn set_lan_access(&mut self, enabled: bool) {
        self.lan_access_enabled = enabled;
    }

    pub fn advertise_lan_route(&mut self, node_id: NodeId, cidr: &str) {
        self.advertised_lan_routes
            .entry(node_id)
            .or_default()
            .insert(cidr.to_string());
    }

    pub fn set_lan_route_acl(&mut self, user: &str, cidr: &str, allowed: bool) {
        self.lan_route_acl
            .insert((user.to_string(), cidr.to_string()), allowed);
    }

    pub fn ensure_lan_route_allowed(&self, request: RouteGrantRequest) -> Result<(), Phase10Error> {
        if !self.lan_access_enabled {
            return Err(Phase10Error::LanAccessDenied);
        }

        let Some(exit_node) = &self.selected_exit_node else {
            return Err(Phase10Error::ExitNotSelected);
        };

        let advertised = self
            .advertised_lan_routes
            .get(exit_node)
            .map(|routes| routes.contains(&request.cidr))
            .unwrap_or(false);
        if !advertised {
            return Err(Phase10Error::LanAccessDenied);
        }

        let acl_allowed = self
            .lan_route_acl
            .get(&(request.user.clone(), request.cidr.clone()))
            .copied()
            .unwrap_or(false);
        if !acl_allowed {
            return Err(Phase10Error::LanAccessDenied);
        }

        let decision = self.policy.evaluate(&ContextualAccessRequest {
            src: request.user,
            dst: request.cidr,
            protocol: request.protocol,
            context: request.context,
        });
        if decision != Decision::Allow {
            return Err(Phase10Error::PolicyDenied);
        }

        Ok(())
    }

    pub fn mark_direct_failed(&mut self, node_id: &NodeId) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        // Verify relay endpoint is available before entering hysteresis window.
        self.managed_peers
            .get(node_id)
            .ok_or(Phase10Error::PeerNotManaged)?
            .relay_endpoint
            .ok_or(Phase10Error::RelayPathUnavailable)?;
        self.consider_path_change_for_peer(node_id, PathMode::Relay)
    }

    pub fn mark_direct_recovered(&mut self, node_id: &NodeId) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        self.consider_path_change_for_peer(node_id, PathMode::Direct)
    }

    /// Evaluate a candidate path mode for a peer under hysteresis policy.
    ///
    /// The candidate must be observed continuously for the applicable stability
    /// window before `commit_path_change_for_peer` is invoked.  If the
    /// candidate matches the currently committed path, any pending candidate is
    /// cleared (flap reset).  Returns `Ok(())` in all cases — callers should
    /// not interpret "no immediate switch" as an error.
    pub fn consider_path_change_for_peer(
        &mut self,
        node_id: &NodeId,
        candidate: PathMode,
    ) -> Result<(), Phase10Error> {
        let peer = self
            .managed_peers
            .get_mut(node_id)
            .ok_or(Phase10Error::PeerNotManaged)?;

        if peer.path == candidate {
            // Already on the desired path; reset any pending candidate.
            peer.pending_path_mode = None;
            peer.pending_since = None;
            return Ok(());
        }

        if peer.pending_path_mode != Some(candidate) {
            // New candidate observed — start stability window.
            peer.pending_path_mode = Some(candidate);
            peer.pending_since = Some(Instant::now());
            return Ok(());
        }

        // Same candidate as before — check whether the stability window elapsed.
        let elapsed = peer
            .pending_since
            .map(|t| t.elapsed())
            .unwrap_or(Duration::ZERO);
        let required = match candidate {
            PathMode::Direct => Duration::from_millis(self.direct_stability_window_ms),
            PathMode::Relay => Duration::from_millis(self.relay_stability_window_ms),
        };
        if elapsed >= required {
            // Stability window elapsed — commit the path change.
            let _ = peer; // release mutable borrow before calling commit
            self.commit_path_change_for_peer(node_id, candidate)?;
        }
        Ok(())
    }

    /// Commit a path change for a peer. This is the **single hardened apply
    /// path** for peer endpoint updates. It updates the backend, refreshes
    /// routes, asserts the measured exit policy, clears hysteresis state, and
    /// logs the transition.
    fn commit_path_change_for_peer(
        &mut self,
        node_id: &NodeId,
        path: PathMode,
    ) -> Result<(), Phase10Error> {
        let endpoint = {
            let peer = self
                .managed_peers
                .get(node_id)
                .ok_or(Phase10Error::PeerNotManaged)?;
            match path {
                PathMode::Direct => peer.direct_endpoint,
                PathMode::Relay => peer
                    .relay_endpoint
                    .ok_or(Phase10Error::RelayPathUnavailable)?,
            }
        };
        self.reconfigure_managed_peer(node_id, endpoint, path)?;
        // Clear hysteresis state after successful commit.
        if let Some(peer) = self.managed_peers.get_mut(node_id) {
            peer.pending_path_mode = None;
            peer.pending_since = None;
        }
        log::info!(
            "peer {}: committed path change to {:?}",
            node_id.as_str(),
            path
        );
        Ok(())
    }

    fn commit_verified_traversal_path_for_peer(
        &mut self,
        node_id: &NodeId,
        path: PathMode,
    ) -> Result<(), Phase10Error> {
        self.ensure_started()?;
        if self.peer_path(node_id) == Some(path) {
            if let Some(peer) = self.managed_peers.get_mut(node_id) {
                peer.pending_path_mode = None;
                peer.pending_since = None;
            }
            return Ok(());
        }
        self.commit_path_change_for_peer(node_id, path)
    }

    /// Apply a peer revocation immediately: remove from backend and dataplane.
    /// Does not wait for the next generation cycle.
    pub fn apply_revocation(&mut self, node_id: &NodeId) -> Result<(), Phase10Error> {
        self.backend.remove_peer(node_id)?;
        self.managed_peers.remove(node_id);
        self.refresh_peer_endpoint_routes_and_attest()?;
        log::info!(
            "peer {} revoked and removed from dataplane",
            node_id.as_str()
        );
        Ok(())
    }

    /// Set the stability windows used by `consider_path_change_for_peer`.
    pub fn set_stability_windows(
        &mut self,
        direct_stability_window_ms: u64,
        relay_stability_window_ms: u64,
    ) {
        self.direct_stability_window_ms = direct_stability_window_ms;
        self.relay_stability_window_ms = relay_stability_window_ms;
    }

    /// For testing: back-date a peer's `pending_since` by `elapsed` so tests
    /// can simulate time passing without sleeping.
    #[cfg(test)]
    pub fn backdate_pending_since_for_test(&mut self, node_id: &NodeId, elapsed: Duration) {
        if let Some(peer) = self.managed_peers.get_mut(node_id)
            && let Some(since) = peer.pending_since
        {
            peer.pending_since = Some(since - elapsed);
        }
    }

    pub fn configure_traversal_paths(
        &mut self,
        node_id: &NodeId,
        direct_endpoint: Option<SocketEndpoint>,
        relay_endpoint: Option<SocketEndpoint>,
    ) -> Result<(), Phase10Error> {
        self.ensure_started()?;

        let managed = self
            .managed_peers
            .get_mut(node_id)
            .ok_or(Phase10Error::PeerNotManaged)?;
        let current_path = managed.path;
        let current_endpoint = managed.configured.endpoint;
        if let Some(endpoint) = direct_endpoint {
            managed.direct_endpoint = endpoint;
        }
        managed.relay_endpoint = relay_endpoint;

        let reconfigure_endpoint = match current_path {
            PathMode::Direct => Some(managed.direct_endpoint),
            PathMode::Relay => managed.relay_endpoint,
        };
        if let Some(endpoint) = reconfigure_endpoint {
            let needs_update = current_endpoint != endpoint;
            if needs_update {
                let _ = managed;
                self.reconfigure_managed_peer(node_id, endpoint, current_path)?;
            }
        }
        Ok(())
    }

    pub fn peer_path(&self, node_id: &NodeId) -> Option<PathMode> {
        self.managed_peers.get(node_id).map(|peer| peer.path)
    }

    pub fn managed_peer_endpoint(&self, node_id: &NodeId) -> Option<SocketEndpoint> {
        self.managed_peers
            .get(node_id)
            .map(|peer| peer.configured.endpoint)
    }

    pub fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, Phase10Error> {
        if !self.managed_peers.contains_key(node_id) {
            return Err(Phase10Error::PeerNotManaged);
        }
        Ok(self.backend.current_peer_endpoint(node_id)?)
    }

    pub fn current_peer_endpoints(
        &self,
    ) -> Result<Vec<(NodeId, Option<SocketEndpoint>)>, Phase10Error> {
        let mut endpoints = Vec::with_capacity(self.managed_peers.len());
        for node_id in self.managed_peers.keys() {
            endpoints.push((
                node_id.clone(),
                self.backend.current_peer_endpoint(node_id)?,
            ));
        }
        Ok(endpoints)
    }

    pub fn managed_peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, Phase10Error> {
        self.ensure_started()?;
        if !self.managed_peers.contains_key(node_id) {
            return Err(Phase10Error::PeerNotManaged);
        }
        Ok(self.backend.peer_latest_handshake_unix(node_id)?)
    }

    pub fn evaluate_traversal_probes(
        &mut self,
        node_id: &NodeId,
        evaluation: TraversalProbeEvaluation<'_>,
    ) -> Result<TraversalProbeReport, Phase10Error> {
        self.ensure_started()?;
        if evaluation.handshake_freshness_secs == 0 {
            return Err(Phase10Error::TraversalProbeFailed(
                "handshake freshness window must be greater than zero".to_string(),
            ));
        }
        if !self.managed_peers.contains_key(node_id) {
            return Err(Phase10Error::PeerNotManaged);
        }

        if let Some(relay_endpoint) = evaluation.relay_endpoint {
            self.configure_traversal_paths(node_id, None, Some(relay_endpoint))?;
        }

        let current_endpoint = self
            .backend
            .current_peer_endpoint(node_id)?
            .ok_or(Phase10Error::PeerNotManaged)?;
        let current_handshake = self.backend.peer_latest_handshake_unix(node_id)?;
        if evaluation
            .direct_candidates
            .iter()
            .any(|candidate| candidate.endpoint == current_endpoint)
            && handshake_is_fresh(
                current_handshake,
                evaluation.now_unix,
                evaluation.handshake_freshness_secs,
            )
        {
            return Ok(TraversalProbeReport {
                decision: TraversalProbeDecision::Direct,
                reason: TraversalProbeReason::ExistingFreshHandshake,
                attempts: 0,
                selected_endpoint: current_endpoint,
                latest_handshake_unix: current_handshake,
            });
        }

        if evaluation.direct_candidates.is_empty() {
            let relay_endpoint = evaluation.relay_endpoint.ok_or_else(|| {
                Phase10Error::TraversalProbeFailed(
                    "traversal failed closed: no direct candidates and no relay endpoint"
                        .to_string(),
                )
            })?;
            self.commit_verified_traversal_path_for_peer(node_id, PathMode::Relay)?;
            self.configure_traversal_paths(node_id, None, Some(relay_endpoint))?;
            self.reconfigure_managed_peer(node_id, relay_endpoint, PathMode::Relay)?;
            return Ok(TraversalProbeReport {
                decision: TraversalProbeDecision::Relay,
                reason: TraversalProbeReason::NoDirectCandidatesRelayArmed,
                attempts: 0,
                selected_endpoint: relay_endpoint,
                latest_handshake_unix: current_handshake,
            });
        }

        let schedule = match evaluation.coordination_schedule {
            Some(schedule) => schedule,
            None => {
                if let Some(relay_endpoint) = evaluation.relay_endpoint {
                    self.commit_verified_traversal_path_for_peer(node_id, PathMode::Relay)?;
                    self.configure_traversal_paths(node_id, None, Some(relay_endpoint))?;
                    self.reconfigure_managed_peer(node_id, relay_endpoint, PathMode::Relay)?;
                    return Ok(TraversalProbeReport {
                        decision: TraversalProbeDecision::Relay,
                        reason: TraversalProbeReason::CoordinationRequiredRelayArmed,
                        attempts: 0,
                        selected_endpoint: relay_endpoint,
                        latest_handshake_unix: current_handshake,
                    });
                }
                let detail = evaluation.coordination_error.unwrap_or_else(|| {
                    "validated signed traversal coordination required for direct probe".to_string()
                });
                return Err(Phase10Error::TraversalProbeFailed(format!(
                    "traversal failed closed: {detail}"
                )));
            }
        };

        let engine = TraversalEngine::new(evaluation.engine_config).map_err(|err| {
            Phase10Error::TraversalProbeFailed(format!("invalid traversal engine config: {err}"))
        })?;

        let result = {
            let mut runtime = Phase10PeerRuntime {
                controller: self,
                node_id: node_id.clone(),
            };
            let mut waiter = Phase10PeerWaiter;

            engine
                .execute_simultaneous_open(
                    &mut runtime,
                    &mut waiter,
                    schedule,
                    evaluation.local_candidates,
                    evaluation.direct_candidates,
                    evaluation.relay_endpoint,
                    evaluation.now_unix,
                    evaluation.handshake_freshness_secs,
                )
                .map_err(|err| Phase10Error::TraversalProbeFailed(err.to_string()))?
        };

        match result.decision {
            TraversalDecision::Direct {
                endpoint,
                reason: _,
            } => {
                self.commit_verified_traversal_path_for_peer(node_id, PathMode::Direct)?;
                self.configure_traversal_paths(node_id, Some(endpoint), evaluation.relay_endpoint)?;
                self.reconfigure_managed_peer(node_id, endpoint, PathMode::Direct)?;

                Ok(TraversalProbeReport {
                    decision: TraversalProbeDecision::Direct,
                    reason: TraversalProbeReason::FreshHandshakeObserved,
                    attempts: result.attempts,
                    selected_endpoint: endpoint,
                    latest_handshake_unix: result.latest_handshake_unix,
                })
            }
            TraversalDecision::Relay {
                endpoint, reason, ..
            } => {
                self.commit_verified_traversal_path_for_peer(node_id, PathMode::Relay)?;
                self.configure_traversal_paths(node_id, None, Some(endpoint))?;
                self.reconfigure_managed_peer(node_id, endpoint, PathMode::Relay)?;

                let reason = match reason {
                    TraversalDecisionReason::NoDirectCandidatesRelayArmed => {
                        TraversalProbeReason::NoDirectCandidatesRelayArmed
                    }
                    _ => TraversalProbeReason::DirectProbeExhaustedRelayArmed,
                };

                Ok(TraversalProbeReport {
                    decision: TraversalProbeDecision::Relay,
                    reason,
                    attempts: result.attempts,
                    selected_endpoint: endpoint,
                    latest_handshake_unix: result.latest_handshake_unix,
                })
            }
            TraversalDecision::FailClosed { reason, .. } => {
                let endpoint = evaluation
                    .direct_candidates
                    .iter()
                    .max_by_key(|candidate| candidate.priority)
                    .map(|candidate| candidate.endpoint)
                    .ok_or_else(|| {
                        Phase10Error::TraversalProbeFailed(format!(
                            "traversal failed closed: {reason:?}"
                        ))
                    })?;
                self.commit_verified_traversal_path_for_peer(node_id, PathMode::Direct)?;
                self.configure_traversal_paths(node_id, Some(endpoint), None)?;
                self.reconfigure_managed_peer(node_id, endpoint, PathMode::Direct)?;

                Ok(TraversalProbeReport {
                    decision: TraversalProbeDecision::Direct,
                    reason: TraversalProbeReason::DirectProbeExhaustedUnprovenDirect,
                    attempts: result.attempts,
                    selected_endpoint: endpoint,
                    latest_handshake_unix: result.latest_handshake_unix,
                })
            }
        }
    }

    pub fn relay_path_armed(&self, node_id: &NodeId) -> bool {
        self.managed_peers
            .get(node_id)
            .and_then(|peer| peer.relay_endpoint)
            .is_some()
    }

    pub fn has_armed_relay_path(&self) -> bool {
        self.managed_peers
            .values()
            .any(|peer| peer.relay_endpoint.is_some())
    }

    pub fn has_active_relay_path(&self) -> bool {
        self.managed_peers
            .values()
            .any(|peer| peer.path == PathMode::Relay)
    }

    pub fn managed_peer_ids(&self) -> Vec<NodeId> {
        self.managed_peers.keys().cloned().collect()
    }

    pub fn authoritative_transport_identity(&self) -> Option<AuthoritativeTransportIdentity> {
        self.backend.authoritative_transport_identity()
    }

    pub fn authoritative_transport_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, Phase10Error> {
        Ok(self
            .backend
            .authoritative_transport_round_trip(remote_addr, payload, timeout)?)
    }

    pub fn authoritative_transport_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<AuthoritativeTransportIdentity, Phase10Error> {
        Ok(self
            .backend
            .authoritative_transport_send(remote_addr, payload)?)
    }

    #[cfg(test)]
    pub fn backend_mut_for_test(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn shutdown(&mut self) -> Result<(), Phase10Error> {
        let _ = self.backend.set_exit_mode(ExitMode::Off);
        self.backend.shutdown()?;
        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.managed_peers.clear();
        self.current_routes.clear();
        self.current_exit_mode = ExitMode::Off;
        self.transition_to(DataplaneState::Init, "shutdown");
        Ok(())
    }

    fn reconfigure_managed_peer(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
        path: PathMode,
    ) -> Result<(), Phase10Error> {
        let mut peer = self
            .managed_peers
            .get(node_id)
            .cloned()
            .ok_or(Phase10Error::PeerNotManaged)?;
        peer.configured.endpoint = endpoint;
        peer.path = path;
        let current_endpoint = self.backend.current_peer_endpoint(node_id)?;
        if current_endpoint == Some(endpoint) {
            self.managed_peers.insert(node_id.clone(), peer);
            return Ok(());
        }
        self.backend.update_peer_endpoint(node_id, endpoint)?;
        self.refresh_peer_endpoint_routes_and_attest()?;
        self.managed_peers.insert(node_id.clone(), peer);
        Ok(())
    }

    fn refresh_peer_endpoint_routes_and_attest(&mut self) -> Result<(), Phase10Error> {
        self.system.rollback_routes()?;
        let peers = self
            .managed_peers
            .values()
            .map(|peer| peer.configured.clone())
            .collect::<Vec<_>>();
        self.system.apply_peer_endpoint_bypass_routes(&peers)?;
        self.system.apply_routes(&self.current_routes)?;
        self.system.assert_exit_policy(self.current_exit_mode)?;
        Ok(())
    }

    fn transition_to(&mut self, target: DataplaneState, reason: &str) {
        let event = TransitionEvent {
            from_state: self.state,
            to_state: target,
            reason: reason.to_string(),
            generation: self.generation,
        };
        self.transitions.push(event);
        self.state = target;
    }

    fn ensure_started(&self) -> Result<(), Phase10Error> {
        if matches!(
            self.state,
            DataplaneState::DataplaneApplied | DataplaneState::ExitActive
        ) {
            return Ok(());
        }
        Err(Phase10Error::NotStarted)
    }
}

fn handshake_is_fresh(value: Option<u64>, now_unix: u64, freshness_secs: u64) -> bool {
    value
        .map(|timestamp| now_unix.saturating_sub(timestamp) <= freshness_secs)
        .unwrap_or(false)
}

/// Gate peer provisioning on membership status (M4).
///
/// A node that is not positively confirmed `Active` in the membership
/// directory is denied provisioning (default-deny).
///
/// When the directory is unpopulated (no entries have been registered) the
/// check is skipped so that deployments that have not yet adopted quorum
/// membership governance are not broken.
fn check_peer_membership_active(
    node_id: &NodeId,
    membership: &MembershipDirectory,
) -> Result<(), Phase10Error> {
    if !membership.is_populated() {
        // Membership governance not yet active — skip the gate.
        return Ok(());
    }
    match membership.node_status(node_id.as_str()) {
        MembershipStatus::Active => Ok(()),
        MembershipStatus::Revoked => Err(Phase10Error::MembershipRevoked(
            node_id.as_str().to_string(),
        )),
        MembershipStatus::Unknown => Err(Phase10Error::MembershipNotFound(
            node_id.as_str().to_string(),
        )),
    }
}

fn validate_trust(policy: &TrustPolicy, evidence: TrustEvidence) -> Result<(), Phase10Error> {
    if !evidence.tls13_valid {
        return Err(Phase10Error::TrustRejected("tls13_not_valid"));
    }
    if !evidence.signed_control_valid {
        return Err(Phase10Error::TrustRejected("signed_control_invalid"));
    }
    if evidence.signed_data_age_secs > policy.max_signed_data_age_secs {
        return Err(Phase10Error::TrustRejected("signed_data_stale"));
    }
    if evidence.clock_skew_secs > policy.max_clock_skew_secs {
        return Err(Phase10Error::TrustRejected("clock_skew_exceeded"));
    }
    Ok(())
}

fn resolve_binary_path(
    env_var: &str,
    default: &str,
    program: PrivilegedCommandProgram,
) -> Result<PathBuf, SystemError> {
    let configured = std::env::var(env_var).ok();
    let raw = configured
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default);
    validate_binary_path(raw, program)?;
    Ok(PathBuf::from(raw))
}

fn resolve_binary_path_for_program(
    program: PrivilegedCommandProgram,
) -> Result<PathBuf, SystemError> {
    match program {
        PrivilegedCommandProgram::Ip => resolve_binary_path(
            IP_BINARY_PATH_ENV,
            DEFAULT_IP_BINARY_PATH,
            PrivilegedCommandProgram::Ip,
        ),
        PrivilegedCommandProgram::Nft => resolve_binary_path(
            NFT_BINARY_PATH_ENV,
            DEFAULT_NFT_BINARY_PATH,
            PrivilegedCommandProgram::Nft,
        ),
        PrivilegedCommandProgram::Wg => resolve_binary_path(
            WG_BINARY_PATH_ENV,
            DEFAULT_WG_BINARY_PATH,
            PrivilegedCommandProgram::Wg,
        ),
        PrivilegedCommandProgram::Sysctl => resolve_binary_path(
            SYSCTL_BINARY_PATH_ENV,
            DEFAULT_SYSCTL_BINARY_PATH,
            PrivilegedCommandProgram::Sysctl,
        ),
        PrivilegedCommandProgram::Ifconfig => resolve_binary_path(
            IFCONFIG_BINARY_PATH_ENV,
            DEFAULT_IFCONFIG_BINARY_PATH,
            PrivilegedCommandProgram::Ifconfig,
        ),
        PrivilegedCommandProgram::Route => resolve_binary_path(
            ROUTE_BINARY_PATH_ENV,
            DEFAULT_ROUTE_BINARY_PATH,
            PrivilegedCommandProgram::Route,
        ),
        PrivilegedCommandProgram::Pfctl => resolve_binary_path(
            PFCTL_BINARY_PATH_ENV,
            DEFAULT_PFCTL_BINARY_PATH,
            PrivilegedCommandProgram::Pfctl,
        ),
        PrivilegedCommandProgram::WireguardGo => resolve_binary_path(
            WIREGUARD_GO_BINARY_PATH_ENV,
            DEFAULT_WIREGUARD_GO_BINARY_PATH,
            PrivilegedCommandProgram::WireguardGo,
        ),
        PrivilegedCommandProgram::Kill => resolve_binary_path(
            KILL_BINARY_PATH_ENV,
            DEFAULT_KILL_BINARY_PATH,
            PrivilegedCommandProgram::Kill,
        ),
    }
}

fn validate_binary_path(raw: &str, program: PrivilegedCommandProgram) -> Result<(), SystemError> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{} binary path must be absolute: {raw}",
            program.as_str()
        )));
    }
    let canonical = fs::canonicalize(path).map_err(|err| {
        SystemError::PrerequisiteCheckFailed(format!(
            "{} binary canonicalization failed for {}: {err}",
            program.as_str(),
            path.display()
        ))
    })?;
    let metadata = fs::metadata(&canonical).map_err(|err| {
        SystemError::PrerequisiteCheckFailed(format!(
            "{} binary metadata read failed for {}: {err}",
            program.as_str(),
            canonical.display()
        ))
    })?;
    if !metadata.file_type().is_file() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{} binary path must be a regular file: {}",
            program.as_str(),
            canonical.display()
        )));
    }
    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode & 0o111 == 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary is not executable: {} ({:03o})",
                program.as_str(),
                canonical.display(),
                mode
            )));
        }
        if mode & 0o022 != 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary must not be group/other writable: {} ({:03o})",
                program.as_str(),
                canonical.display(),
                mode
            )));
        }
        let owner_uid = metadata.uid();
        if owner_uid != 0 {
            return Err(SystemError::PrerequisiteCheckFailed(format!(
                "{} binary must be root-owned: {} (uid={owner_uid})",
                program.as_str(),
                canonical.display()
            )));
        }
    }
    Ok(())
}

fn validate_net_device_name(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 15 {
        return Err("device name length must be between 1 and 15 characters");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err("device name contains invalid characters");
    }
    Ok(())
}

fn validate_windows_interface_alias(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || value.len() > 32 {
        return Err("Windows interface alias length must be between 1 and 32 characters");
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '+' | '='))
    {
        return Err("Windows interface alias contains invalid characters");
    }
    Ok(())
}

fn validate_windows_binary_path(raw: &str, label: &str) -> Result<(), SystemError> {
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must be absolute: {raw}"
        )));
    }
    Ok(())
}

fn validate_windows_dns_bind_addr(addr: SocketAddr) -> Result<(), SystemError> {
    if !addr.ip().is_loopback() {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection requires a loopback resolver bind address".to_string(),
        ));
    }
    if addr.port() != 53 {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection requires rustynetd to bind the reviewed local resolver on 127.0.0.1:53 because Windows interface DNS settings cannot encode a non-default port".to_string(),
        ));
    }
    Ok(())
}

fn windows_dns_set_args(
    interface_name: &str,
    dns_server: IpAddr,
) -> Result<Vec<String>, SystemError> {
    if !dns_server.is_loopback() {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection only supports reviewed loopback resolvers".to_string(),
        ));
    }
    Ok(vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "set".to_string(),
        "dnsservers".to_string(),
        format!("name={interface_name}"),
        "source=static".to_string(),
        format!("address={dns_server}"),
        "validate=no".to_string(),
    ])
}

fn windows_dns_clear_args(interface_name: &str) -> Vec<String> {
    vec![
        "interface".to_string(),
        "ipv4".to_string(),
        "delete".to_string(),
        "dnsservers".to_string(),
        format!("name={interface_name}"),
        "all".to_string(),
    ]
}

pub fn write_state_transition_audit(
    path: impl AsRef<Path>,
    transitions: &[TransitionEvent],
) -> Result<(), SystemError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| SystemError::Io(err.to_string()))?;
    }

    let mut output = String::new();
    for transition in transitions {
        output.push_str(&format!(
            "generation={} from={:?} to={:?} reason={}\n",
            transition.generation, transition.from_state, transition.to_state, transition.reason
        ));
    }

    fs::write(path, output).map_err(|err| SystemError::Io(err.to_string()))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PerfMetric {
    pub name: &'static str,
    pub value: f64,
    pub threshold: &'static str,
    pub status: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Phase10PerfMeasurement {
    pub soak_test_hours: u64,
    pub idle_cpu_percent: f64,
    pub idle_rss_mb: f64,
    pub reconnect_seconds: f64,
    pub route_apply_p95_seconds: f64,
    pub throughput_overhead_percent: f64,
}

impl Phase10PerfMeasurement {
    fn validate(self) -> Result<(), SystemError> {
        if self.soak_test_hours == 0 {
            return Err(SystemError::PrerequisiteCheckFailed(
                "soak_test_hours must be greater than zero".to_string(),
            ));
        }
        for (name, value) in [
            ("idle_cpu_percent", self.idle_cpu_percent),
            ("idle_rss_mb", self.idle_rss_mb),
            ("reconnect_seconds", self.reconnect_seconds),
            ("route_apply_p95_seconds", self.route_apply_p95_seconds),
            (
                "throughput_overhead_percent",
                self.throughput_overhead_percent,
            ),
        ] {
            if !value.is_finite() || value < 0.0 {
                return Err(SystemError::PrerequisiteCheckFailed(format!(
                    "{name} must be a finite non-negative number"
                )));
            }
        }
        Ok(())
    }
}

fn metric_status(value: f64, threshold_max: f64) -> &'static str {
    if value <= threshold_max {
        "pass"
    } else {
        "fail"
    }
}

pub fn write_phase10_perf_report(
    path: impl AsRef<Path>,
    measurements: Phase10PerfMeasurement,
    environment: &str,
) -> Result<(), SystemError> {
    measurements.validate()?;
    if environment.trim().is_empty() {
        return Err(SystemError::PrerequisiteCheckFailed(
            "environment must not be empty".to_string(),
        ));
    }

    let metrics = [
        PerfMetric {
            name: "idle_cpu_percent",
            value: measurements.idle_cpu_percent,
            threshold: "<=2",
            status: metric_status(measurements.idle_cpu_percent, 2.0),
        },
        PerfMetric {
            name: "idle_rss_mb",
            value: measurements.idle_rss_mb,
            threshold: "<=120",
            status: metric_status(measurements.idle_rss_mb, 120.0),
        },
        PerfMetric {
            name: "reconnect_seconds",
            value: measurements.reconnect_seconds,
            threshold: "<=5",
            status: metric_status(measurements.reconnect_seconds, 5.0),
        },
        PerfMetric {
            name: "route_apply_p95_seconds",
            value: measurements.route_apply_p95_seconds,
            threshold: "<=2",
            status: metric_status(measurements.route_apply_p95_seconds, 2.0),
        },
        PerfMetric {
            name: "throughput_overhead_percent",
            value: measurements.throughput_overhead_percent,
            threshold: "<=15",
            status: metric_status(measurements.throughput_overhead_percent, 15.0),
        },
    ];
    let soak_status = if measurements.soak_test_hours >= 24
        && metrics.iter().all(|metric| metric.status == "pass")
    {
        "pass"
    } else {
        "fail"
    };
    let captured_at_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| SystemError::Io(err.to_string()))?
        .as_secs();

    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| SystemError::Io(err.to_string()))?;
    }

    let mut out = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"evidence_mode\": \"measured\",\n  \"environment\": \"{}\",\n  \"captured_at_unix\": {},\n  \"soak_test_hours\": {},\n  \"soak_status\": \"{}\",\n  \"metrics\": [\n",
        environment, captured_at_unix, measurements.soak_test_hours, soak_status
    );
    for (index, metric) in metrics.iter().enumerate() {
        let comma = if index + 1 == metrics.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"value\":{},\"threshold\":\"{}\",\"status\":\"{}\"}}{}\n",
            metric.name, metric.value, metric.threshold, metric.status, comma
        ));
    }
    out.push_str("  ]\n}\n");

    fs::write(path, out).map_err(|err| SystemError::Io(err.to_string()))
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "linux")]
    use std::io::{BufRead, BufReader, Write};
    use std::net::IpAddr;
    #[cfg(target_os = "linux")]
    use std::os::unix::net::UnixListener;
    #[cfg(target_os = "linux")]
    use std::path::{Path, PathBuf};
    #[cfg(target_os = "linux")]
    use std::sync::atomic::{AtomicBool, Ordering};
    #[cfg(target_os = "linux")]
    use std::sync::{Arc, Mutex};
    #[cfg(target_os = "linux")]
    use std::thread;
    use std::time::Duration;
    #[cfg(target_os = "linux")]
    use std::time::{SystemTime, UNIX_EPOCH};

    use rustynet_backend_api::{
        BackendCapabilities, BackendError, BackendErrorKind, RouteKind, SocketEndpoint, TunnelStats,
    };
    use rustynet_backend_wireguard::WireguardBackend;
    use rustynet_policy::{ContextualPolicyRule, RuleAction};

    use super::*;

    #[test]
    fn windows_dns_bind_addr_requires_loopback_port_53() {
        let err = validate_windows_dns_bind_addr("127.0.0.1:53535".parse().expect("valid addr"))
            .expect_err("non-default resolver port should fail closed on Windows");
        assert!(matches!(err, SystemError::DnsApplyFailed(_)));
    }

    #[test]
    fn windows_dns_helpers_render_reviewed_netsh_args() {
        let args = windows_dns_set_args("rustynet0", "127.0.0.1".parse().expect("valid ip"))
            .expect("loopback DNS args should render");
        assert_eq!(
            args,
            vec![
                "interface".to_string(),
                "ipv4".to_string(),
                "set".to_string(),
                "dnsservers".to_string(),
                "name=rustynet0".to_string(),
                "source=static".to_string(),
                "address=127.0.0.1".to_string(),
                "validate=no".to_string(),
            ]
        );
        assert_eq!(
            windows_dns_clear_args("rustynet0"),
            vec![
                "interface".to_string(),
                "ipv4".to_string(),
                "delete".to_string(),
                "dnsservers".to_string(),
                "name=rustynet0".to_string(),
                "all".to_string(),
            ]
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum StartBehavior {
        AlreadyRunning,
        FailInternal,
    }

    #[derive(Debug, Clone, Copy)]
    struct ControlledStartBackend {
        behavior: StartBehavior,
    }

    impl ControlledStartBackend {
        fn new(behavior: StartBehavior) -> Self {
            Self { behavior }
        }
    }

    #[derive(Debug)]
    struct RecordingBackend {
        started: bool,
        peers: BTreeMap<NodeId, PeerConfig>,
        latest_handshakes_by_endpoint: BTreeMap<String, Option<u64>>,
        handshake_on_probe_by_endpoint: BTreeMap<String, Option<u64>>,
        probe_trigger_count_by_node: BTreeMap<NodeId, usize>,
        routes: Vec<Route>,
        exit_mode: ExitMode,
    }

    impl Default for RecordingBackend {
        fn default() -> Self {
            Self {
                started: false,
                peers: BTreeMap::new(),
                latest_handshakes_by_endpoint: BTreeMap::new(),
                handshake_on_probe_by_endpoint: BTreeMap::new(),
                probe_trigger_count_by_node: BTreeMap::new(),
                routes: Vec::new(),
                exit_mode: ExitMode::Off,
            }
        }
    }

    impl RecordingBackend {
        fn set_handshake_for_endpoint(
            &mut self,
            endpoint: SocketEndpoint,
            latest_handshake_unix: Option<u64>,
        ) {
            self.latest_handshakes_by_endpoint.insert(
                format!("{}:{}", endpoint.addr, endpoint.port),
                latest_handshake_unix,
            );
        }

        fn arm_handshake_on_probe(
            &mut self,
            endpoint: SocketEndpoint,
            latest_handshake_unix: Option<u64>,
        ) {
            self.handshake_on_probe_by_endpoint.insert(
                format!("{}:{}", endpoint.addr, endpoint.port),
                latest_handshake_unix,
            );
        }

        fn probe_trigger_count(&self, node_id: &NodeId) -> usize {
            self.probe_trigger_count_by_node
                .get(node_id)
                .copied()
                .unwrap_or(0)
        }
    }

    impl TunnelBackend for RecordingBackend {
        fn name(&self) -> &'static str {
            "recording-backend"
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                supports_roaming: true,
                supports_exit_nodes: true,
                supports_lan_routes: true,
                supports_ipv6: true,
            }
        }

        fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
            self.started = true;
            Ok(())
        }

        fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            self.peers.insert(peer.node_id.clone(), peer);
            Ok(())
        }

        fn update_peer_endpoint(
            &mut self,
            node_id: &NodeId,
            endpoint: SocketEndpoint,
        ) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            let Some(peer) = self.peers.get_mut(node_id) else {
                return Err(BackendError::invalid_input("peer is not configured"));
            };
            peer.endpoint = endpoint;
            Ok(())
        }

        fn current_peer_endpoint(
            &self,
            node_id: &NodeId,
        ) -> Result<Option<SocketEndpoint>, BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            Ok(self.peers.get(node_id).map(|peer| peer.endpoint))
        }

        fn peer_latest_handshake_unix(
            &mut self,
            node_id: &NodeId,
        ) -> Result<Option<u64>, BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            let Some(peer) = self.peers.get(node_id) else {
                return Err(BackendError::invalid_input("peer is not configured"));
            };
            Ok(self
                .latest_handshakes_by_endpoint
                .get(&format!("{}:{}", peer.endpoint.addr, peer.endpoint.port))
                .copied()
                .flatten())
        }

        fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            self.peers.remove(node_id);
            Ok(())
        }

        fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            self.routes = routes;
            Ok(())
        }

        fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            self.exit_mode = mode;
            Ok(())
        }

        fn stats(&self) -> Result<TunnelStats, BackendError> {
            Ok(TunnelStats {
                peer_count: self.peers.len(),
                bytes_tx: 0,
                bytes_rx: 0,
                using_relay_path: false,
            })
        }

        fn initiate_peer_handshake(
            &mut self,
            node_id: &NodeId,
            _force_resend: bool,
        ) -> Result<(), BackendError> {
            if !self.started {
                return Err(BackendError::not_running("backend not started"));
            }
            let Some(peer) = self.peers.get(node_id) else {
                return Err(BackendError::invalid_input("peer is not configured"));
            };
            let endpoint_key = format!("{}:{}", peer.endpoint.addr, peer.endpoint.port);
            *self
                .probe_trigger_count_by_node
                .entry(node_id.clone())
                .or_insert(0) += 1;
            if let Some(latest_handshake_unix) = self
                .handshake_on_probe_by_endpoint
                .get(&endpoint_key)
                .copied()
            {
                self.latest_handshakes_by_endpoint
                    .insert(endpoint_key, latest_handshake_unix);
            }
            Ok(())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            self.started = false;
            self.peers.clear();
            self.handshake_on_probe_by_endpoint.clear();
            self.probe_trigger_count_by_node.clear();
            self.routes.clear();
            self.exit_mode = ExitMode::Off;
            Ok(())
        }
    }

    impl TunnelBackend for ControlledStartBackend {
        fn name(&self) -> &'static str {
            "controlled-start-backend"
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                supports_roaming: true,
                supports_exit_nodes: true,
                supports_lan_routes: true,
                supports_ipv6: true,
            }
        }

        fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
            match self.behavior {
                StartBehavior::AlreadyRunning => {
                    Err(BackendError::already_running("backend already running"))
                }
                StartBehavior::FailInternal => Err(BackendError::internal("backend start failed")),
            }
        }

        fn configure_peer(&mut self, _peer: PeerConfig) -> Result<(), BackendError> {
            Ok(())
        }

        fn update_peer_endpoint(
            &mut self,
            _node_id: &NodeId,
            _endpoint: SocketEndpoint,
        ) -> Result<(), BackendError> {
            Ok(())
        }

        fn current_peer_endpoint(
            &self,
            _node_id: &NodeId,
        ) -> Result<Option<SocketEndpoint>, BackendError> {
            Ok(None)
        }

        fn peer_latest_handshake_unix(
            &mut self,
            _node_id: &NodeId,
        ) -> Result<Option<u64>, BackendError> {
            Ok(None)
        }

        fn remove_peer(&mut self, _node_id: &NodeId) -> Result<(), BackendError> {
            Ok(())
        }

        fn apply_routes(&mut self, _routes: Vec<Route>) -> Result<(), BackendError> {
            Ok(())
        }

        fn set_exit_mode(&mut self, _mode: ExitMode) -> Result<(), BackendError> {
            Ok(())
        }

        fn stats(&self) -> Result<TunnelStats, BackendError> {
            Ok(TunnelStats::default())
        }

        fn shutdown(&mut self) -> Result<(), BackendError> {
            Ok(())
        }
    }

    fn allow_shared_exit_policy() -> ContextualPolicySet {
        ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:alice".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedExit],
            }],
        }
    }

    fn trust_ok() -> TrustEvidence {
        TrustEvidence {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 20,
            clock_skew_secs: 10,
        }
    }

    fn sample_peer(id: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(id).expect("node id should parse"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.10".parse::<IpAddr>().expect("ip should parse"),
                port: 51820,
            },
            public_key: [9; 32],
            allowed_ips: vec!["100.100.20.2/32".to_string()],
        }
    }

    fn test_runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("node-a").expect("node should parse"),
            interface_name: "rustynet0".to_string(),
            mesh_cidr: "100.64.0.0/10".to_string(),
            local_cidr: "100.64.0.1/32".to_string(),
        }
    }

    fn sample_coordination_schedule(now_unix: u64) -> CoordinationSchedule {
        CoordinationSchedule {
            session_id: [0x11; 16],
            nonce: [0x22; 16],
            probe_start_unix: now_unix,
            wait_duration: Duration::ZERO,
        }
    }

    #[cfg(target_os = "linux")]
    fn parse_helper_request_command(line: &str) -> Option<String> {
        let payload: serde_json::Value = serde_json::from_str(line).ok()?;
        let program = payload.get("program")?.as_str()?;
        let args = payload.get("args")?.as_array()?;
        let parts = args
            .iter()
            .map(|value| value.as_str())
            .collect::<Option<Vec<_>>>()?;
        Some(format!("{program} {}", parts.join(" ")))
    }

    #[cfg(target_os = "linux")]
    fn phase10_test_socket_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        // Keep socket paths short enough for UNIX domain limits, especially on macOS.
        PathBuf::from("/tmp").join(format!(
            "rn10-{prefix}-{}-{unique:x}.sock",
            std::process::id()
        ))
    }

    #[cfg(target_os = "linux")]
    fn spawn_privileged_capture_helper(
        socket_path: &Path,
    ) -> (
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path).unwrap_or_else(|err| {
            panic!(
                "test helper socket should bind at {}: {err}",
                socket_path.display()
            )
        });
        listener
            .set_nonblocking(true)
            .expect("test helper socket should be non-blocking");

        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let commands_clone = Arc::clone(&commands);
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let reader_stream = match stream.try_clone() {
                            Ok(value) => value,
                            Err(_) => continue,
                        };
                        let mut reader = BufReader::new(reader_stream);
                        let mut line = String::new();
                        match reader.read_line(&mut line) {
                            Ok(read) if read > 0 => {
                                if let Some(command) = parse_helper_request_command(line.trim_end())
                                {
                                    commands_clone
                                        .lock()
                                        .expect("test helper command log should lock")
                                        .push(command);
                                } else {
                                    let _ = stream.write_all(
                                        b"{\"ok\":false,\"error\":\"invalid helper request\"}\n",
                                    );
                                    let _ = stream.flush();
                                    continue;
                                }
                            }
                            _ => {
                                let _ = stream.write_all(
                                    b"{\"ok\":false,\"error\":\"helper request read failed\"}\n",
                                );
                                let _ = stream.flush();
                                continue;
                            }
                        }
                        if stream
                            .write_all(
                                b"{\"ok\":true,\"status\":0,\"stdout\":\"\",\"stderr\":\"\"}\n",
                            )
                            .is_err()
                        {
                            continue;
                        }
                        let _ = stream.flush();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (commands, stop, handle)
    }

    #[cfg(target_os = "linux")]
    fn spawn_privileged_table_list_helper(
        socket_path: &Path,
        list_tables_stdout: String,
    ) -> (
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path).unwrap_or_else(|err| {
            panic!(
                "test helper socket should bind at {}: {err}",
                socket_path.display()
            )
        });
        listener
            .set_nonblocking(true)
            .expect("test helper socket should be non-blocking");

        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let commands_clone = Arc::clone(&commands);
        let stop_clone = Arc::clone(&stop);
        let tables_output = list_tables_stdout;

        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let reader_stream = match stream.try_clone() {
                            Ok(value) => value,
                            Err(_) => continue,
                        };
                        let mut reader = BufReader::new(reader_stream);
                        let mut line = String::new();
                        let command = match reader.read_line(&mut line) {
                            Ok(read) if read > 0 => {
                                let Some(parsed) = parse_helper_request_command(line.trim_end())
                                else {
                                    let _ = stream.write_all(
                                        b"{\"ok\":false,\"error\":\"invalid helper request\"}\n",
                                    );
                                    let _ = stream.flush();
                                    continue;
                                };
                                commands_clone
                                    .lock()
                                    .expect("test helper command log should lock")
                                    .push(parsed.clone());
                                parsed
                            }
                            _ => {
                                let _ = stream.write_all(
                                    b"{\"ok\":false,\"error\":\"helper request read failed\"}\n",
                                );
                                let _ = stream.flush();
                                continue;
                            }
                        };

                        let response = if command.contains("nft list tables") {
                            serde_json::json!({
                                "ok": true,
                                "status": 0,
                                "stdout": tables_output,
                                "stderr": ""
                            })
                        } else {
                            serde_json::json!({
                                "ok": true,
                                "status": 0,
                                "stdout": "",
                                "stderr": ""
                            })
                        };
                        if stream
                            .write_all(format!("{response}\n").as_bytes())
                            .is_err()
                        {
                            continue;
                        }
                        let _ = stream.flush();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (commands, stop, handle)
    }

    #[cfg(target_os = "linux")]
    fn spawn_privileged_scripted_helper(
        socket_path: &Path,
        scripted_responses: Vec<(String, PrivilegedCommandOutput)>,
    ) -> (
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
    ) {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path).unwrap_or_else(|err| {
            panic!(
                "test helper socket should bind at {}: {err}",
                socket_path.display()
            )
        });
        listener
            .set_nonblocking(true)
            .expect("test helper socket should be non-blocking");

        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let commands_clone = Arc::clone(&commands);
        let stop_clone = Arc::clone(&stop);
        let responses = scripted_responses;

        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _addr)) => {
                        if stream.set_nonblocking(false).is_err() {
                            continue;
                        }
                        let reader_stream = match stream.try_clone() {
                            Ok(value) => value,
                            Err(_) => continue,
                        };
                        let mut reader = BufReader::new(reader_stream);
                        let mut line = String::new();
                        let command = match reader.read_line(&mut line) {
                            Ok(read) if read > 0 => {
                                let Some(parsed) = parse_helper_request_command(line.trim_end())
                                else {
                                    let _ = stream.write_all(
                                        b"{\"ok\":false,\"error\":\"invalid helper request\"}\n",
                                    );
                                    let _ = stream.flush();
                                    continue;
                                };
                                commands_clone
                                    .lock()
                                    .expect("test helper command log should lock")
                                    .push(parsed.clone());
                                parsed
                            }
                            _ => {
                                let _ = stream.write_all(
                                    b"{\"ok\":false,\"error\":\"helper request read failed\"}\n",
                                );
                                let _ = stream.flush();
                                continue;
                            }
                        };

                        let scripted = responses
                            .iter()
                            .find(|(needle, _)| command.contains(needle.as_str()))
                            .map(|(_, output)| output.clone())
                            .unwrap_or(PrivilegedCommandOutput {
                                status: 0,
                                stdout: String::new(),
                                stderr: String::new(),
                            });
                        let response = serde_json::json!({
                            "ok": true,
                            "status": scripted.status,
                            "stdout": scripted.stdout,
                            "stderr": scripted.stderr,
                        });
                        if stream
                            .write_all(format!("{response}\n").as_bytes())
                            .is_err()
                        {
                            continue;
                        }
                        let _ = stream.flush();
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (commands, stop, handle)
    }

    #[test]
    fn transition_to_fail_closed_when_trust_is_invalid() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let err = controller.establish_control_trust(TrustEvidence {
            tls13_valid: false,
            ..trust_ok()
        });
        assert!(matches!(err, Err(Phase10Error::TrustRejected(_))));
        assert_eq!(controller.state(), DataplaneState::Init);
    }

    #[test]
    fn transactional_apply_commits_generation_and_exit_state() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect("apply should succeed");

        assert_eq!(controller.state(), DataplaneState::ExitActive);
        assert_eq!(controller.generation(), 1);
        assert_eq!(controller.last_safe_generation(), 1);
    }

    #[test]
    fn full_tunnel_apply_tracks_exit_mode_and_asserts_measured_policy() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect("full-tunnel apply should succeed");

        assert_eq!(controller.current_exit_mode(), ExitMode::FullTunnel);
        assert_eq!(controller.backend.exit_mode, ExitMode::FullTunnel);
        assert!(
            controller
                .system
                .operations
                .contains(&"assert_exit_policy:full_tunnel".to_string()),
            "phase 10 must assert measured full-tunnel truth before claiming ExitActive"
        );
    }

    #[test]
    fn apply_generation_flushes_routes_before_endpoint_bypass_rebuild() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let rollback_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "rollback_routes")
            .expect("route flush must happen before route rebuild");
        let endpoint_bypass_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "apply_peer_endpoint_bypass_routes")
            .expect("endpoint bypass routes must be re-applied");
        let apply_routes_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "apply_routes")
            .expect("managed routes must be re-applied");

        assert!(
            rollback_index < endpoint_bypass_index && endpoint_bypass_index < apply_routes_index,
            "route table 51820 must flush before endpoint bypass routes, and endpoint bypass routes must precede managed route re-apply"
        );
    }

    #[test]
    fn set_and_clear_exit_node_track_exit_mode_and_assert_measured_policy() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let exit_node = NodeId::new("exit-1").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let set_ops_start = controller.system.operations.len();
        controller
            .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
            .expect("policy should allow selecting exit");
        let set_ops = &controller.system.operations[set_ops_start..];
        assert_eq!(controller.current_exit_mode(), ExitMode::FullTunnel);
        assert_eq!(controller.backend.exit_mode, ExitMode::FullTunnel);
        assert!(
            set_ops.contains(&"assert_exit_policy:full_tunnel".to_string()),
            "exit selection must assert measured full-tunnel truth"
        );

        let clear_ops_start = controller.system.operations.len();
        controller
            .clear_exit_node()
            .expect("clearing exit selection should succeed");
        let clear_ops = &controller.system.operations[clear_ops_start..];
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        assert!(
            clear_ops.contains(&"assert_exit_policy:off".to_string()),
            "exit clearing must assert measured off-mode truth"
        );
    }

    #[test]
    fn peer_revocation_reasserts_measured_exit_policy_after_route_refresh() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: peer_id.clone(),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect("apply should succeed");

        let op_start = controller.system.operations.len();
        controller
            .apply_revocation(&peer_id)
            .expect("revocation refresh should succeed");
        let ops = &controller.system.operations[op_start..];

        assert!(
            ops.contains(&"rollback_routes".to_string())
                && ops.contains(&"apply_peer_endpoint_bypass_routes".to_string())
                && ops.contains(&"apply_routes".to_string())
                && ops.contains(&"assert_exit_policy:full_tunnel".to_string()),
            "peer revocation must rebuild owned routes and re-assert measured full-tunnel truth"
        );
    }

    #[test]
    fn relay_with_upstream_enables_tunnel_forwarding_path() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("relay-with-upstream apply should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "set_relay_forwarding:true")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_generation_handoff_deletes_previous_table_only_after_new_rules_apply() {
        let socket_path = phase10_test_socket_path("f");

        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");

        DataplaneSystem::set_generation(&mut system, 1);
        DataplaneSystem::apply_firewall_killswitch(&mut system)
            .expect("first generation firewall apply should succeed");
        let first_generation_count = commands.lock().expect("command log should lock").len();

        DataplaneSystem::set_generation(&mut system, 2);
        DataplaneSystem::apply_firewall_killswitch(&mut system)
            .expect("second generation firewall apply should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        let handoff_commands = &command_log[first_generation_count..];
        let delete_old_index = handoff_commands
            .iter()
            .position(|cmd| cmd.contains("nft delete table inet rustynet_g1"))
            .expect("old generation table must be pruned in second apply");
        let add_new_table_index = handoff_commands
            .iter()
            .position(|cmd| cmd.contains("nft add table inet rustynet_g2"))
            .expect("new generation table must be created");
        let add_new_forward_chain_index = handoff_commands
            .iter()
            .position(|cmd| cmd.contains("nft add chain inet rustynet_g2 forward"))
            .expect("new generation forward chain must be installed");
        let add_new_forward_rule_index = handoff_commands
            .iter()
            .position(|cmd| {
                cmd.contains(
                    "nft add rule inet rustynet_g2 forward iifname rustynet0 oifname enp0s9 accept",
                )
            })
            .expect("new generation egress allow rule must be installed");

        assert!(
            delete_old_index > add_new_table_index
                && delete_old_index > add_new_forward_chain_index
                && delete_old_index > add_new_forward_rule_index,
            "old generation table was pruned before new fail-closed rules were fully applied"
        );
        assert_eq!(
            delete_old_index,
            handoff_commands.len().saturating_sub(1),
            "old generation table prune must happen as the final handoff command"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn prune_owned_tables_preserves_active_and_target_generation_tables() {
        let socket_path = phase10_test_socket_path("p");
        let list_tables_stdout = [
            "table inet rustynet_g1",
            "table inet rustynet_g2",
            "table inet rustynet_g9",
            "table ip rustynet_nat_g1",
            "table ip rustynet_nat_g2",
            "table ip rustynet_nat_g9",
            "table inet non_rustynet",
        ]
        .join("\n");

        let (commands, stop, helper_thread) =
            spawn_privileged_table_list_helper(&socket_path, list_tables_stdout);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        DataplaneSystem::set_generation(&mut system, 2);
        system.firewall_table = Some("rustynet_g1".to_string());
        system.nat_table = Some("rustynet_nat_g1".to_string());

        DataplaneSystem::prune_owned_tables(&mut system).expect("prune should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table inet rustynet_g9")),
            "stale firewall generation table should be pruned"
        );
        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table ip rustynet_nat_g9")),
            "stale nat generation table should be pruned"
        );
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table inet rustynet_g1")),
            "active firewall table must not be pruned before handoff"
        );
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table inet rustynet_g2")),
            "target firewall table must not be pruned"
        );
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table ip rustynet_nat_g1")),
            "active nat table must not be pruned before handoff"
        );
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains("nft delete table ip rustynet_nat_g2")),
            "target nat table must not be pruned"
        );
    }

    #[test]
    fn apply_rejects_backend_start_failure_and_fail_closes() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            ControlledStartBackend::new(StartBehavior::FailInternal),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            Vec::new(),
            Vec::new(),
            ApplyOptions::default(),
        );

        let err = result.expect_err("backend start failure must be surfaced");
        assert!(matches!(
            err,
            Phase10Error::Backend(BackendError {
                kind: BackendErrorKind::Internal,
                ..
            })
        ));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn apply_accepts_already_running_backend_start() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            ControlledStartBackend::new(StartBehavior::AlreadyRunning),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                Vec::new(),
                Vec::new(),
                ApplyOptions::default(),
            )
            .expect("already-running start should not block reconcile apply");

        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
        assert_eq!(controller.generation(), 1);
    }

    #[test]
    fn apply_does_not_require_nat_when_not_full_tunnel_or_exit_serving() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_nat_forwarding"),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("nat should not be required for plain mesh apply");

        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
    }

    #[test]
    fn apply_exit_serving_requires_nat_forwarding() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_nat_forwarding"),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![Route {
                destination_cidr: "100.100.20.0/24".to_string(),
                via_node: NodeId::new("node-b").expect("node should parse"),
                kind: RouteKind::Mesh,
            }],
            ApplyOptions {
                serve_exit_node: true,
                ..ApplyOptions::default()
            },
        );

        assert!(result.is_err());
        assert_eq!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn apply_rollback_forces_fail_closed_when_system_step_fails() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_dns_protection"),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("node-b").expect("node should parse"),
                kind: RouteKind::ExitNodeDefault,
            }],
            ApplyOptions {
                protected_dns: true,
                ..ApplyOptions::default()
            },
        );

        assert!(result.is_err());
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.last_safe_generation(), 0);
    }

    #[test]
    fn lan_toggle_requires_toggle_route_advertisement_acl_and_policy() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let exit_node = NodeId::new("exit-1").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        controller
            .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
            .expect("policy should allow selecting exit");

        controller.advertise_lan_route(exit_node, "192.168.1.0/24");
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);

        let denied = controller.ensure_lan_route_allowed(RouteGrantRequest {
            user: "user:alice".to_string(),
            cidr: "192.168.1.0/24".to_string(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        });
        assert_eq!(denied.err(), Some(Phase10Error::LanAccessDenied));

        controller.set_lan_access(true);
        controller
            .ensure_lan_route_allowed(RouteGrantRequest {
                user: "user:alice".to_string(),
                cidr: "192.168.1.0/24".to_string(),
                protocol: Protocol::Tcp,
                context: TrafficContext::SharedExit,
            })
            .expect("grant should pass with toggle + route + acl + policy");
    }

    #[test]
    fn direct_relay_failover_and_failback_are_recorded() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let direct_endpoint = SocketEndpoint {
            addr: "198.51.100.55".parse::<IpAddr>().expect("ip should parse"),
            port: 51820,
        };
        let relay_endpoint = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip should parse"),
            port: 443,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");
        controller
            .configure_traversal_paths(&peer_id, Some(direct_endpoint), Some(relay_endpoint))
            .expect("traversal endpoints should configure");

        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
        assert_eq!(
            controller
                .backend
                .peers
                .get(&peer_id)
                .expect("peer should be present")
                .endpoint,
            direct_endpoint
        );
        assert!(controller.relay_path_armed(&peer_id));

        controller.set_stability_windows(0, 0);
        controller
            .mark_direct_failed(&peer_id)
            .expect("failover should arm hysteresis");
        controller
            .mark_direct_failed(&peer_id)
            .expect("failover should commit once stability is satisfied");
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Relay));
        assert_eq!(
            controller
                .backend
                .peers
                .get(&peer_id)
                .expect("peer should be present")
                .endpoint,
            relay_endpoint
        );

        controller
            .mark_direct_recovered(&peer_id)
            .expect("recovery signal should arm hysteresis");
        controller.set_stability_windows(0, 0);
        controller
            .mark_direct_recovered(&peer_id)
            .expect("failback should commit once stability is satisfied");
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
        assert_eq!(
            controller
                .backend
                .peers
                .get(&peer_id)
                .expect("peer should be present")
                .endpoint,
            direct_endpoint
        );
    }

    #[test]
    fn direct_failover_requires_a_provisioned_relay_endpoint() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let err = controller
            .mark_direct_failed(&peer_id)
            .expect_err("relay failover must require an explicit relay endpoint");
        assert_eq!(err, Phase10Error::RelayPathUnavailable);
    }

    #[test]
    fn traversal_probe_uses_existing_fresh_handshake_on_current_endpoint() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");
        let current_endpoint = controller
            .managed_peer_endpoint(&peer_id)
            .expect("managed endpoint should exist");
        controller
            .backend
            .set_handshake_for_endpoint(current_endpoint, Some(195));

        let report = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: current_endpoint,
                        source: crate::traversal::CandidateSource::Host,
                        priority: 900,
                        observed_at_unix: 190,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: current_endpoint,
                        source: crate::traversal::CandidateSource::Host,
                        priority: 900,
                        observed_at_unix: 190,
                    }],
                    relay_endpoint: Some(SocketEndpoint {
                        addr: "198.51.100.40".parse::<IpAddr>().expect("ip should parse"),
                        port: 443,
                    }),
                    now_unix: 200,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: None,
                    coordination_error: None,
                },
            )
            .expect("existing handshake should keep direct path");

        assert_eq!(report.decision, TraversalProbeDecision::Direct);
        assert_eq!(report.reason, TraversalProbeReason::ExistingFreshHandshake);
        assert_eq!(report.attempts, 0);
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
    }

    #[test]
    fn traversal_probe_promotes_direct_when_handshake_advances() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let direct_endpoint = SocketEndpoint {
            addr: "198.51.100.55".parse::<IpAddr>().expect("ip should parse"),
            port: 51820,
        };
        let relay_endpoint = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip should parse"),
            port: 443,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");
        controller
            .backend
            .arm_handshake_on_probe(direct_endpoint, Some(205));

        let report = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: direct_endpoint,
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 900,
                        observed_at_unix: 200,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: direct_endpoint,
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 900,
                        observed_at_unix: 200,
                    }],
                    relay_endpoint: Some(relay_endpoint),
                    now_unix: 210,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                },
            )
            .expect("probe should promote direct candidate");

        assert_eq!(report.decision, TraversalProbeDecision::Direct);
        assert_eq!(report.reason, TraversalProbeReason::FreshHandshakeObserved);
        assert_eq!(report.attempts, 1);
        assert_eq!(report.selected_endpoint, direct_endpoint);
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
        assert_eq!(
            controller.managed_peer_endpoint(&peer_id),
            Some(direct_endpoint)
        );
        assert_eq!(controller.backend.probe_trigger_count(&peer_id), 1);
    }

    #[test]
    fn traversal_probe_falls_back_to_relay_when_handshake_does_not_advance() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let relay_endpoint = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip should parse"),
            port: 443,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let report = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "203.0.113.77".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "203.0.113.77".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    relay_endpoint: Some(relay_endpoint),
                    now_unix: 210,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                },
            )
            .expect("relay fallback should be allowed");

        assert_eq!(report.decision, TraversalProbeDecision::Relay);
        assert_eq!(
            report.reason,
            TraversalProbeReason::DirectProbeExhaustedRelayArmed
        );
        assert_eq!(report.selected_endpoint, relay_endpoint);
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Relay));
        assert_eq!(
            controller.managed_peer_endpoint(&peer_id),
            Some(relay_endpoint)
        );
    }

    #[test]
    fn traversal_probe_keeps_signed_direct_programmed_when_handshake_does_not_advance_and_no_relay_exists()
     {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let direct_endpoint = SocketEndpoint {
            addr: "198.51.100.77".parse::<IpAddr>().expect("ip should parse"),
            port: 51820,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let report = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "198.51.100.10".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::Host,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: direct_endpoint,
                        source: crate::traversal::CandidateSource::Host,
                        priority: 900,
                        observed_at_unix: 200,
                    }],
                    relay_endpoint: None,
                    now_unix: 210,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                },
            )
            .expect("signed direct path should stay programmed without relay fallback");

        assert_eq!(report.decision, TraversalProbeDecision::Direct);
        assert_eq!(
            report.reason,
            TraversalProbeReason::DirectProbeExhaustedUnprovenDirect
        );
        assert_eq!(report.attempts, 3);
        assert_eq!(report.selected_endpoint, direct_endpoint);
        assert_eq!(report.latest_handshake_unix, None);
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
        assert_eq!(
            controller.managed_peer_endpoint(&peer_id),
            Some(direct_endpoint)
        );
    }

    #[test]
    fn traversal_probe_declines_direct_without_valid_coordination_when_relay_is_armed() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let relay_endpoint = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip should parse"),
            port: 443,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let report = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "198.51.100.10".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "198.51.100.11".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    relay_endpoint: Some(relay_endpoint),
                    now_unix: 210,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: None,
                    coordination_error: Some(
                        "validated traversal coordination for peer node-b is unavailable"
                            .to_string(),
                    ),
                },
            )
            .expect("relay fallback should be allowed");

        assert_eq!(report.decision, TraversalProbeDecision::Relay);
        assert_eq!(
            report.reason,
            TraversalProbeReason::CoordinationRequiredRelayArmed
        );
        assert_eq!(report.attempts, 0);
        assert_eq!(report.selected_endpoint, relay_endpoint);
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Relay));
    }

    #[test]
    fn traversal_probe_fails_closed_without_valid_coordination_and_without_relay() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let peer_id = NodeId::new("node-b").expect("node id should parse");

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let err = controller
            .evaluate_traversal_probes(
                &peer_id,
                TraversalProbeEvaluation {
                    local_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "198.51.100.10".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    direct_candidates: &[ProbeTraversalCandidate {
                        endpoint: SocketEndpoint {
                            addr: "198.51.100.11".parse::<IpAddr>().expect("ip should parse"),
                            port: 51820,
                        },
                        source: crate::traversal::CandidateSource::ServerReflexive,
                        priority: 700,
                        observed_at_unix: 200,
                    }],
                    relay_endpoint: None,
                    now_unix: 210,
                    engine_config: TraversalEngineConfig::default(),
                    handshake_freshness_secs: 30,
                    coordination_schedule: None,
                    coordination_error: Some(
                        "validated traversal coordination for peer node-b is unavailable"
                            .to_string(),
                    ),
                },
            )
            .expect_err("missing coordination must fail closed without relay");

        assert!(matches!(err, Phase10Error::TraversalProbeFailed(_)));
        assert!(
            err.to_string()
                .contains("validated traversal coordination for peer node-b is unavailable")
        );
    }

    #[test]
    fn audit_and_perf_reports_are_writable() {
        let temp_dir = std::env::temp_dir();
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let audit_path = temp_dir.join(format!(
            "phase10-state-transition-audit-{}-{}.log",
            std::process::id(),
            unique
        ));
        let perf_path = temp_dir.join(format!(
            "phase10-perf-budget-report-{}-{}.json",
            std::process::id(),
            unique
        ));

        write_state_transition_audit(
            &audit_path,
            &[TransitionEvent {
                from_state: DataplaneState::Init,
                to_state: DataplaneState::ControlTrusted,
                reason: "test".to_string(),
                generation: 0,
            }],
        )
        .expect("audit report should be written");
        write_phase10_perf_report(
            &perf_path,
            Phase10PerfMeasurement {
                soak_test_hours: 24,
                idle_cpu_percent: 1.2,
                idle_rss_mb: 82.0,
                reconnect_seconds: 2.0,
                route_apply_p95_seconds: 0.8,
                throughput_overhead_percent: 10.5,
            },
            "unit-test-linux-netns",
        )
        .expect("perf report should be written");

        let audit = std::fs::read_to_string(&audit_path).expect("audit should be readable");
        let perf = std::fs::read_to_string(&perf_path).expect("perf should be readable");
        assert!(audit.contains("generation=0"));
        assert!(perf.contains("idle_cpu_percent"));
        assert!(perf.contains("\"evidence_mode\": \"measured\""));
        assert!(perf.contains("\"captured_at_unix\": "));
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_file(&perf_path);
    }

    #[test]
    fn management_bypass_route_args_use_ipv4_routing_for_ipv4_cidr() {
        let cidr = "192.168.18.0/24"
            .parse::<ManagementCidr>()
            .expect("valid cidr");
        let args = LinuxCommandSystem::management_bypass_route_args(&cidr, "enp0s8");
        assert_eq!(
            args,
            vec![
                "route".to_string(),
                "replace".to_string(),
                "192.168.18.0/24".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn management_bypass_route_args_use_ipv6_routing_for_ipv6_cidr() {
        let cidr = "fd00::/64".parse::<ManagementCidr>().expect("valid cidr");
        let args = LinuxCommandSystem::management_bypass_route_args(&cidr, "enp0s8");
        assert_eq!(
            args,
            vec![
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "fd00::/64".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fail_closed_management_allow_routes_use_underlay_egress_interface() {
        let socket_path = phase10_test_socket_path("m");
        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            true,
            vec![
                "192.168.18.0/24"
                    .parse::<ManagementCidr>()
                    .expect("management cidr should parse"),
            ],
        )
        .expect("linux command system should initialize");

        DataplaneSystem::apply_routes(&mut system, &[]).expect("route apply should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("ip route replace 192.168.18.0/24 dev enp0s9 table 51820")),
            "management bypass route must use the configured underlay egress interface"
        );
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains("192.168.18.0/24 dev rustynet0 table 51820")),
            "management bypass route must not be re-routed through the tunnel interface"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fail_closed_management_allow_rules_preserve_inbound_and_outbound_ssh() {
        let socket_path = phase10_test_socket_path("m");
        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            true,
            vec![
                "192.168.18.0/24"
                    .parse::<ManagementCidr>()
                    .expect("management cidr should parse"),
            ],
        )
        .expect("linux command system should initialize");

        DataplaneSystem::apply_firewall_killswitch(&mut system)
            .expect("killswitch apply should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("tcp dport 22 accept")),
            "management allow rule must target destination SSH port"
        );
        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("tcp sport 22 accept")),
            "management allow rule must also preserve sshd reply traffic"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rollback_routes_flushes_ipv4_and_ipv6_table_51820() {
        let socket_path = phase10_test_socket_path("r");
        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");

        DataplaneSystem::rollback_routes(&mut system).expect("route rollback should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("ip route flush table 51820")),
            "route rollback must flush IPv4 table 51820 state"
        );
        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("ip -6 route flush table 51820")),
            "route rollback must flush IPv6 table 51820 state"
        );
    }

    #[cfg(target_os = "linux")]
    fn sample_linux_firewall_ruleset(
        interface_name: &str,
        egress_interface: &str,
        include_egress_allow: bool,
        dns_protected: bool,
        allow_tunnel_relay_forward: bool,
    ) -> String {
        let mut rules = format!(
            "table inet rustynet_g1 {{\n  chain killswitch {{\n    type filter hook output priority 0; policy drop;\n    oifname \"lo\" accept\n    ct state established,related accept\n    oifname \"{interface_name}\" accept\n"
        );
        if include_egress_allow {
            rules.push_str(format!("    oifname \"{egress_interface}\" accept\n").as_str());
        }
        if dns_protected {
            rules.push_str(
                format!(
                    "    udp dport 53 oifname != \"{interface_name}\" drop\n    tcp dport 53 oifname != \"{interface_name}\" drop\n    udp dport 53 accept\n    tcp dport 53 accept\n"
                )
                .as_str(),
            );
        }
        rules.push_str(
            "  }\n  chain forward {\n    type filter hook forward priority 0; policy drop;\n    ct state established,related accept\n",
        );
        rules.push_str(
            format!("    iifname \"{interface_name}\" oifname \"{egress_interface}\" accept\n")
                .as_str(),
        );
        if allow_tunnel_relay_forward {
            rules.push_str(
                format!("    iifname \"{interface_name}\" oifname \"{interface_name}\" accept\n")
                    .as_str(),
            );
        }
        rules.push_str("  }\n}\n");
        rules
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_full_tunnel_checks_rule_table_and_probe() {
        let socket_path = phase10_test_socket_path("x");
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "0: from all lookup local\n32765: from all lookup 51820\n32766: from all lookup main\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "default dev rustynet0 scope link\n203.0.113.10/32 dev enp0s9 scope link\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route get 1.1.1.1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "1.1.1.1 dev rustynet0 src 100.64.0.1 uid 0\n    cache\n"
                            .to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system
            .expected_peer_endpoint_bypass_routes
            .insert(ExpectedBypassRoute {
                destination: "203.0.113.10/32".to_string(),
                interface_name: "enp0s9".to_string(),
                family: RouteTableFamily::V4,
            });

        DataplaneSystem::assert_exit_policy(&mut system, ExitMode::FullTunnel)
            .expect("full-tunnel proof should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            command_log.iter().any(|cmd| cmd.contains("ip rule show")),
            "measured full-tunnel proof must inspect policy routing rules"
        );
        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("ip -4 route show table 51820")),
            "measured full-tunnel proof must inspect table 51820 contents"
        );
        assert!(
            command_log
                .iter()
                .any(|cmd| cmd.contains("ip -4 route get 1.1.1.1")),
            "measured full-tunnel proof must probe effective route truth"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_off_checks_rule_absence_and_underlay_probe() {
        let socket_path = phase10_test_socket_path("o");
        let (_commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout:
                            "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
                                .to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "203.0.113.10/32 dev enp0s9 scope link\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route get 1.1.1.1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout:
                            "1.1.1.1 via 192.168.64.1 dev enp0s9 src 192.168.64.8 uid 0\n    cache\n"
                                .to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system
            .expected_peer_endpoint_bypass_routes
            .insert(ExpectedBypassRoute {
                destination: "203.0.113.10/32".to_string(),
                interface_name: "enp0s9".to_string(),
                family: RouteTableFamily::V4,
            });

        DataplaneSystem::assert_exit_policy(&mut system, ExitMode::Off)
            .expect("off-mode proof should succeed");

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_off_rejects_tunnel_probe_route() {
        let socket_path = phase10_test_socket_path("n");
        let (_commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout:
                            "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
                                .to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "203.0.113.10/32 dev enp0s9 scope link\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route get 1.1.1.1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "1.1.1.1 dev rustynet0 src 100.64.0.1 uid 0\n    cache\n"
                            .to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system
            .expected_peer_endpoint_bypass_routes
            .insert(ExpectedBypassRoute {
                destination: "203.0.113.10/32".to_string(),
                interface_name: "enp0s9".to_string(),
                family: RouteTableFamily::V4,
            });

        let err = DataplaneSystem::assert_exit_policy(&mut system, ExitMode::Off)
            .expect_err("off-mode proof must fail when the effective route still uses the tunnel");

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            err.to_string()
                .contains("route probe unexpectedly uses tunnel interface"),
            "measured off-mode proof must reject tunnel egress"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_rejects_missing_owned_endpoint_bypass_route() {
        let socket_path = phase10_test_socket_path("xb");
        let (_commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "0: from all lookup local\n32765: from all lookup 51820\n32766: from all lookup main\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "default dev rustynet0 scope link\n".to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system
            .expected_peer_endpoint_bypass_routes
            .insert(ExpectedBypassRoute {
                destination: "203.0.113.10/32".to_string(),
                interface_name: "enp0s9".to_string(),
                family: RouteTableFamily::V4,
            });

        let err = DataplaneSystem::assert_exit_policy(&mut system, ExitMode::FullTunnel)
            .expect_err("full-tunnel proof must fail when endpoint bypass ownership drifted");

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            err.to_string()
                .contains("missing owned bypass route in table 51820")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_accepts_host_route_rendered_without_prefix() {
        let socket_path = phase10_test_socket_path("xbr");
        let (_commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "0: from all lookup local\n32765: from all lookup 51820\n32766: from all lookup main\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "default dev rustynet0 scope link\n203.0.113.10 dev enp0s9 scope link\n".to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route get 1.1.1.1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "1.1.1.1 dev rustynet0 src 100.64.0.1 uid 0\n    cache\n"
                            .to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system
            .expected_peer_endpoint_bypass_routes
            .insert(ExpectedBypassRoute {
                destination: "203.0.113.10/32".to_string(),
                interface_name: "enp0s9".to_string(),
                family: RouteTableFamily::V4,
            });

        DataplaneSystem::assert_exit_policy(&mut system, ExitMode::FullTunnel)
            .expect("host route rendered without /32 must still satisfy bypass ownership proof");

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_assert_exit_policy_rejects_missing_dns_fail_closed_rule() {
        let socket_path = phase10_test_socket_path("xd");
        let (_commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "nft list table inet rustynet_g1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: sample_linux_firewall_ruleset(
                            "rustynet0",
                            "enp0s9",
                            false,
                            false,
                            false,
                        ),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip rule show".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout:
                            "0: from all lookup local\n32766: from all lookup main\n32767: from all lookup default\n"
                                .to_string(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route show table 51820".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: String::new(),
                        stderr: String::new(),
                    },
                ),
                (
                    "ip -4 route get 1.1.1.1".to_string(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout:
                            "1.1.1.1 via 192.168.64.1 dev enp0s9 src 192.168.64.8 uid 0\n    cache\n"
                                .to_string(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        system.firewall_table = Some("rustynet_g1".to_string());
        system.dns_protected = true;

        let err = DataplaneSystem::assert_exit_policy(&mut system, ExitMode::Off)
            .expect_err("dns-protected proof must fail if dns fail-closed rules are missing");

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(err.to_string().contains("dns udp fail-closed rule missing"));
    }

    #[test]
    fn peer_endpoint_bypass_route_args_use_ipv4_host_route() {
        let args = LinuxCommandSystem::peer_endpoint_bypass_route_args(
            "192.168.18.40".parse().expect("valid ipv4"),
            "enp0s8",
        );
        assert_eq!(
            args,
            vec![
                "route".to_string(),
                "replace".to_string(),
                "192.168.18.40/32".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn traversal_bootstrap_allow_rule_args_use_ipv4_endpoint_on_egress_interface() {
        let args = LinuxCommandSystem::traversal_bootstrap_allow_rule_args(
            "rustynet_g1",
            "enp0s1",
            "203.0.113.10:3478"
                .parse::<SocketAddr>()
                .expect("endpoint should parse"),
        );
        assert_eq!(
            args,
            vec![
                "add".to_string(),
                "rule".to_string(),
                "inet".to_string(),
                "rustynet_g1".to_string(),
                "killswitch".to_string(),
                "oifname".to_string(),
                "enp0s1".to_string(),
                "ip".to_string(),
                "daddr".to_string(),
                "203.0.113.10".to_string(),
                "udp".to_string(),
                "dport".to_string(),
                "3478".to_string(),
                "accept".to_string(),
                "comment".to_string(),
                "rustynet_traversal_bootstrap".to_string(),
            ]
        );
    }

    #[test]
    fn peer_endpoint_bypass_route_args_use_ipv6_host_route() {
        let args = LinuxCommandSystem::peer_endpoint_bypass_route_args(
            "fd00::10".parse().expect("valid ipv6"),
            "enp0s8",
        );
        assert_eq!(
            args,
            vec![
                "-6".to_string(),
                "route".to_string(),
                "replace".to_string(),
                "fd00::10/128".to_string(),
                "dev".to_string(),
                "enp0s8".to_string(),
                "table".to_string(),
                "51820".to_string(),
            ]
        );
    }

    #[test]
    fn validate_binary_path_rejects_relative_paths() {
        let err = validate_binary_path("ip", PrivilegedCommandProgram::Ip)
            .expect_err("relative paths must be rejected");
        assert!(err.to_string().contains("must be absolute"));
    }

    #[cfg(unix)]
    #[test]
    fn validate_binary_path_rejects_symlink_to_untrusted_target() {
        let temp_dir = std::env::temp_dir().join(format!(
            "phase10-binary-symlink-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let target = temp_dir.join("nft-real");
        let symlink = temp_dir.join("nft-link");
        std::fs::write(&target, "#!/bin/sh\n").expect("target should be writable");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("target should be executable");
        std::os::unix::fs::symlink(&target, &symlink).expect("symlink should be creatable");

        let err = validate_binary_path(
            symlink.to_str().expect("symlink path should be utf8"),
            PrivilegedCommandProgram::Nft,
        )
        .expect_err("untrusted symlink targets must be rejected");
        assert!(err.to_string().contains("must be root-owned"));

        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn owned_anchor_names_filters_only_rustynet_anchors() {
        let parsed = MacosCommandSystem::owned_anchor_names_from_output(
            "com.apple\ncom.apple/rustynet_g1\ncom.apple/other\n  com.apple/rustynet_g77\n",
        );
        assert_eq!(
            parsed,
            vec![
                "com.apple/rustynet_g1".to_string(),
                "com.apple/rustynet_g77".to_string()
            ]
        );
    }

    #[test]
    fn macos_render_pf_rules_enforces_dns_fail_closed_when_enabled() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(rules.contains("pass out quick inet proto udp on utun9 to any port 53 keep state"));
        assert!(rules.contains("pass out quick inet proto tcp on utun9 to any port 53 keep state"));
        assert!(rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_render_pf_rules_omits_dns_fail_closed_rules_when_disabled() {
        let system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(!rules.contains("proto udp on utun9 to any port 53"));
        assert!(!rules.contains("proto tcp on utun9 to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_render_pf_rules_preserve_inbound_management_ssh_replies() {
        let system = MacosCommandSystem::new(
            "utun9",
            "en0",
            None,
            true,
            vec![
                "192.168.128.0/24"
                    .parse::<ManagementCidr>()
                    .expect("management cidr should parse"),
            ],
        )
        .expect("macos system should construct");
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(rules.contains(
            "pass out quick inet proto tcp from any to 192.168.128.0/24 port 22 keep state"
        ));
        assert!(rules.contains(
            "pass out quick inet proto tcp from any port 22 to 192.168.128.0/24 keep state"
        ));
    }

    #[test]
    fn macos_render_pf_rules_allow_configured_traversal_bootstrap_endpoints() {
        let system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct")
            .with_traversal_bootstrap_allow_endpoints(vec![
                "203.0.113.10:3478"
                    .parse::<SocketAddr>()
                    .expect("stun endpoint should parse"),
            ]);
        let rules = system
            .render_pf_rules(true)
            .expect("rule render should succeed");
        assert!(
            rules.contains(
                "pass out quick inet proto udp on en0 to 203.0.113.10 port 3478 keep state"
            )
        );
        assert!(rules.contains("block drop out quick all"));
    }

    #[test]
    fn macos_dns_rule_parser_accepts_port_alias_output() {
        let rules = "pass out quick inet proto udp on utun9 to any port = domain keep state\n\
                     block drop out quick inet proto udp to any port = domain\n";
        assert!(MacosCommandSystem::ruleset_contains_dns_rule(
            rules,
            "pass out quick",
            "udp",
            Some("utun9"),
        ));
        assert!(MacosCommandSystem::ruleset_contains_dns_rule(
            rules,
            "block drop out quick",
            "udp",
            None,
        ));
    }

    // ── A3: Hysteresis tests ───────────────────────────────────────────────

    fn make_controller_with_peer(
        direct_stability_ms: u64,
        relay_stability_ms: u64,
    ) -> (
        Phase10Controller<RecordingBackend, DryRunSystem>,
        NodeId,
        SocketEndpoint,
        SocketEndpoint,
    ) {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        controller.set_stability_windows(direct_stability_ms, relay_stability_ms);
        let peer_id = NodeId::new("node-b").expect("node id should parse");
        let direct_ep = SocketEndpoint {
            addr: "198.51.100.55".parse::<IpAddr>().expect("ip"),
            port: 51820,
        };
        let relay_ep = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip"),
            port: 443,
        };
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");
        controller
            .configure_traversal_paths(&peer_id, Some(direct_ep), Some(relay_ep))
            .expect("traversal endpoints should configure");
        (controller, peer_id, direct_ep, relay_ep)
    }

    #[test]
    fn test_no_switch_within_stability_window() {
        // Relay stability window is 5000ms; calls made before 5000ms elapsed
        // must NOT commit a path change.
        let (mut ctrl, peer_id, _direct_ep, _relay_ep) = make_controller_with_peer(3_000, 5_000);
        assert_eq!(ctrl.peer_path(&peer_id), Some(PathMode::Direct));

        // First call: sets pending
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        // Path not yet changed
        assert_eq!(ctrl.peer_path(&peer_id), Some(PathMode::Direct));

        // Second call (elapsed = 0ms, well within 5000ms window): no commit
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(ctrl.peer_path(&peer_id), Some(PathMode::Direct));

        // Backdate by only 4999ms (still within window): no commit
        ctrl.backdate_pending_since_for_test(&peer_id, Duration::from_millis(4999));
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(
            ctrl.peer_path(&peer_id),
            Some(PathMode::Direct),
            "path must not switch before stability window expires"
        );
    }

    #[test]
    fn test_switches_after_full_stability_window() {
        let (mut ctrl, peer_id, _direct_ep, relay_ep) = make_controller_with_peer(3_000, 5_000);

        // First call sets pending
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(ctrl.peer_path(&peer_id), Some(PathMode::Direct));

        // Backdate by 5001ms (beyond relay window): commit should fire
        ctrl.backdate_pending_since_for_test(&peer_id, Duration::from_millis(5001));
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(
            ctrl.peer_path(&peer_id),
            Some(PathMode::Relay),
            "path must switch after stability window expires"
        );
        assert_eq!(
            ctrl.backend
                .peers
                .get(&peer_id)
                .expect("peer present")
                .endpoint,
            relay_ep,
            "backend endpoint must reflect relay after commit"
        );
    }

    #[test]
    fn test_flap_resets_stability_window() {
        let (mut ctrl, peer_id, _direct_ep, _relay_ep) = make_controller_with_peer(3_000, 5_000);

        // Start Relay candidate window
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        // Backdate to just under the expiry (4800ms)
        ctrl.backdate_pending_since_for_test(&peer_id, Duration::from_millis(4800));

        // Flap back to Direct — clears Relay candidate because it matches
        // current path.  Then re-introduce Relay.
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Direct)
            .expect("consider should not error");
        // Now introduce Relay again — window must restart from zero
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        // Check that calling again immediately (elapsed ≈ 0) does not commit
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(
            ctrl.peer_path(&peer_id),
            Some(PathMode::Direct),
            "path must not switch: flap reset the stability window"
        );
    }

    #[test]
    fn test_fail_closed_bypasses_hysteresis() {
        let (mut ctrl, peer_id, _direct_ep, _relay_ep) = make_controller_with_peer(3_000, 5_000);

        // Set up a pending relay candidate (not yet committed)
        ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
            .expect("consider should not error");
        assert_eq!(ctrl.peer_path(&peer_id), Some(PathMode::Direct));

        // force_fail_closed must apply immediately regardless of hysteresis
        ctrl.force_fail_closed("test")
            .expect("fail closed should succeed");
        assert_eq!(
            ctrl.state(),
            DataplaneState::FailClosed,
            "fail_closed must apply immediately without waiting for stability window"
        );
    }

    #[test]
    fn test_commit_path_change_is_the_only_apply_path() {
        // Verify that reconfigure_managed_peer (the backend endpoint update) is
        // only called through commit_path_change_for_peer, never directly from
        // consider_path_change_for_peer before the window expires.
        let (mut ctrl, peer_id, direct_ep, _relay_ep) = make_controller_with_peer(3_000, 5_000);

        let initial_ep = ctrl
            .backend
            .peers
            .get(&peer_id)
            .expect("peer present")
            .endpoint;
        assert_eq!(initial_ep, direct_ep);

        // Multiple consider calls within the window must not touch the backend
        for _ in 0..10 {
            ctrl.consider_path_change_for_peer(&peer_id, PathMode::Relay)
                .expect("consider should not error");
        }
        let ep_after_considers = ctrl
            .backend
            .peers
            .get(&peer_id)
            .expect("peer present")
            .endpoint;
        assert_eq!(
            ep_after_considers, direct_ep,
            "backend endpoint must not change until stability window elapses"
        );
    }

    #[test]
    fn test_path_change_count_bounded_during_flap() {
        // Simulate 60s of alternating Direct/Relay at 500ms intervals.
        // With direct_window=3000ms and relay_window=5000ms, at most a few
        // committed changes should occur (each requires its full window).
        let (mut ctrl, peer_id, _direct_ep, _relay_ep) = make_controller_with_peer(3_000, 5_000);

        let mut committed_changes = 0usize;
        let total_steps = 120usize; // 60s / 500ms
        let mut last_path = ctrl.peer_path(&peer_id);
        let mut _elapsed_ms: u64 = 0;

        for step in 0..total_steps {
            let candidate = if step % 2 == 0 {
                PathMode::Relay
            } else {
                PathMode::Direct
            };
            _elapsed_ms += 500;
            ctrl.consider_path_change_for_peer(&peer_id, candidate)
                .expect("consider should not error");
            // Simulate time passing by backdating pending_since by 500ms each
            // step (only when a pending exists; this is a rough simulation)
            ctrl.backdate_pending_since_for_test(&peer_id, Duration::from_millis(500));
            ctrl.consider_path_change_for_peer(&peer_id, candidate)
                .expect("consider should not error");

            let new_path = ctrl.peer_path(&peer_id);
            if new_path != last_path {
                committed_changes += 1;
                last_path = new_path;
            }
        }

        // With 500ms alternating flaps and a 5000ms relay window and 3000ms
        // direct window, genuine commits are very rare. Allow a generous bound
        // of ≤ 4 committed changes in 60s.
        assert!(
            committed_changes <= 4,
            "too many path changes ({committed_changes}) during sustained flap in 60s window"
        );
    }

    // ── M4: Membership enforcement tests ──────────────────────────────────

    #[test]
    fn test_active_member_provisioned() {
        use rustynet_policy::{MembershipDirectory, MembershipStatus};
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-b", MembershipStatus::Active);
        controller.set_membership(membership);

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![],
            ApplyOptions::default(),
        );
        assert!(
            result.is_ok(),
            "active member must be provisioned: {result:?}"
        );
        let peer_id = NodeId::new("node-b").expect("node id");
        assert!(
            controller.backend.peers.contains_key(&peer_id),
            "backend must have the provisioned peer"
        );
    }

    #[test]
    fn test_revoked_member_provisioning_denied() {
        use rustynet_policy::{MembershipDirectory, MembershipStatus};
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-b", MembershipStatus::Revoked);
        controller.set_membership(membership);

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![],
            ApplyOptions::default(),
        );
        assert!(
            matches!(result, Err(Phase10Error::MembershipRevoked(_))),
            "revoked peer must be denied: {result:?}"
        );
        let peer_id = NodeId::new("node-b").expect("node id");
        assert!(
            !controller.backend.peers.contains_key(&peer_id),
            "revoked peer must NOT be in backend"
        );
    }

    #[test]
    fn test_unknown_member_provisioning_denied() {
        use rustynet_policy::{MembershipDirectory, MembershipStatus};
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        // Register some other node so directory is populated (not empty)
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-c", MembershipStatus::Active);
        controller.set_membership(membership);

        // node-b is not in the directory at all
        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![],
            ApplyOptions::default(),
        );
        assert!(
            matches!(result, Err(Phase10Error::MembershipNotFound(_))),
            "unknown peer must be denied when directory is populated: {result:?}"
        );
    }

    #[test]
    fn test_revocation_removes_peer_and_routes_immediately() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        let peer_id = NodeId::new("node-b").expect("node id");
        assert!(controller.backend.peers.contains_key(&peer_id));

        // Apply revocation — peer must be removed immediately
        controller
            .apply_revocation(&peer_id)
            .expect("revocation should succeed");

        assert!(
            !controller.backend.peers.contains_key(&peer_id),
            "revoked peer must be removed from backend immediately"
        );
        assert!(
            !controller.managed_peers.contains_key(&peer_id),
            "revoked peer must be removed from managed_peers immediately"
        );
    }

    // ── A4-b: Path Transition ACL Preservation ─────────────────────────────
    //
    // These tests verify that measured exit-policy proof is re-asserted on
    // every direct↔relay path transition. The invariant:
    // `assert_exit_policy:*` must appear in `DryRunSystem::operations` after
    // each committed path change — the ACL rule set must never be in a
    // more-permissive state after a transition than it was before.

    /// Helper: build a Phase10Controller in DataplaneApplied state with one
    /// managed peer (node-b) that has both direct and relay endpoints
    /// configured.  Stability windows are set to 0 so the second consecutive
    /// call to `consider_path_change_for_peer` always commits immediately.
    fn make_a4b_controller_with_both_endpoints_and_options(
        options: ApplyOptions,
    ) -> (
        Phase10Controller<RecordingBackend, DryRunSystem>,
        NodeId,
        SocketEndpoint,
        SocketEndpoint,
    ) {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        // Zero-length stability windows allow the second call to commit.
        controller.set_stability_windows(0, 0);

        let peer_id = NodeId::new("node-b").expect("node id");
        let direct_endpoint = SocketEndpoint {
            addr: "198.51.100.55".parse::<IpAddr>().expect("ip"),
            port: 51820,
        };
        let relay_endpoint = SocketEndpoint {
            addr: "198.51.100.40".parse::<IpAddr>().expect("ip"),
            port: 443,
        };

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_string(),
                    via_node: NodeId::new("node-b").expect("node"),
                    kind: RouteKind::Mesh,
                }],
                options,
            )
            .expect("apply should succeed");
        controller
            .configure_traversal_paths(&peer_id, Some(direct_endpoint), Some(relay_endpoint))
            .expect("traversal endpoints should configure");

        (controller, peer_id, direct_endpoint, relay_endpoint)
    }

    fn make_a4b_controller_with_both_endpoints() -> (
        Phase10Controller<RecordingBackend, DryRunSystem>,
        NodeId,
        SocketEndpoint,
        SocketEndpoint,
    ) {
        make_a4b_controller_with_both_endpoints_and_options(ApplyOptions::default())
    }

    #[test]
    fn test_a4b_direct_to_relay_transition_asserts_measured_exit_policy() {
        let (mut controller, peer_id, _direct_ep, _relay_ep) =
            make_a4b_controller_with_both_endpoints();
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));

        // Snapshot operations before transition.
        let ops_before = controller.system.operations.len();

        // Two consecutive calls commit the path change (stability window = 0 ms).
        controller
            .mark_direct_failed(&peer_id)
            .expect("first signal starts pending");
        controller
            .mark_direct_failed(&peer_id)
            .expect("second signal commits relay path");

        assert_eq!(
            controller.peer_path(&peer_id),
            Some(PathMode::Relay),
            "path must be Relay after committed failover"
        );

        // ACL invariant: measured off-mode proof must appear after the transition.
        let new_ops = &controller.system.operations[ops_before..];
        assert!(
            new_ops.contains(&"assert_exit_policy:off".to_string()),
            "assert_exit_policy:off must be called during direct→relay transition; ops={new_ops:?}"
        );

        // DataplaneState must remain applied (never FailClosed) during transition.
        assert_ne!(
            controller.state(),
            DataplaneState::FailClosed,
            "ACL transition must not push state to FailClosed"
        );
    }

    #[test]
    fn test_a4b_relay_to_direct_transition_asserts_measured_exit_policy() {
        let (mut controller, peer_id, _direct_ep, _relay_ep) =
            make_a4b_controller_with_both_endpoints();

        // First move to relay.
        controller.mark_direct_failed(&peer_id).expect("pending");
        controller
            .mark_direct_failed(&peer_id)
            .expect("commit relay");
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Relay));

        let ops_before = controller.system.operations.len();

        // Now recover back to direct.
        controller
            .mark_direct_recovered(&peer_id)
            .expect("pending recovery");
        controller
            .mark_direct_recovered(&peer_id)
            .expect("commit direct");

        assert_eq!(
            controller.peer_path(&peer_id),
            Some(PathMode::Direct),
            "path must be Direct after committed recovery"
        );

        // ACL invariant: measured off-mode proof must be called on relay→direct too.
        let new_ops = &controller.system.operations[ops_before..];
        assert!(
            new_ops.contains(&"assert_exit_policy:off".to_string()),
            "assert_exit_policy:off must be called during relay→direct transition; ops={new_ops:?}"
        );

        assert_ne!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn test_a4b_acl_operations_are_present_throughout_full_path_cycle() {
        let (mut controller, peer_id, _direct_ep, _relay_ep) =
            make_a4b_controller_with_both_endpoints();

        // The initial apply must include apply_firewall_killswitch.
        assert!(
            controller
                .system
                .operations
                .contains(&"apply_firewall_killswitch".to_string()),
            "apply_firewall_killswitch must be called during initial generation apply"
        );

        // Direct → Relay.
        controller.mark_direct_failed(&peer_id).expect("pending");
        controller
            .mark_direct_failed(&peer_id)
            .expect("commit relay");
        assert!(
            controller
                .system
                .operations
                .contains(&"assert_exit_policy:off".to_string()),
            "assert_exit_policy:off must appear after first path transition"
        );

        // Relay → Direct.
        let proof_count_after_first = controller
            .system
            .operations
            .iter()
            .filter(|op| *op == "assert_exit_policy:off")
            .count();
        controller.mark_direct_recovered(&peer_id).expect("pending");
        controller
            .mark_direct_recovered(&peer_id)
            .expect("commit direct");
        let proof_count_after_second = controller
            .system
            .operations
            .iter()
            .filter(|op| *op == "assert_exit_policy:off")
            .count();

        assert!(
            proof_count_after_second > proof_count_after_first,
            "assert_exit_policy:off call count must increase on relay→direct transition"
        );
        assert_ne!(controller.state(), DataplaneState::FailClosed);
    }

    #[test]
    fn managed_peer_reconfigure_asserts_current_full_tunnel_policy() {
        let (mut controller, peer_id, _direct_ep, _relay_ep) =
            make_a4b_controller_with_both_endpoints_and_options(ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                ..ApplyOptions::default()
            });

        let ops_before = controller.system.operations.len();
        controller
            .mark_direct_failed(&peer_id)
            .expect("first signal starts pending");
        controller
            .mark_direct_failed(&peer_id)
            .expect("second signal commits relay path");

        let new_ops = &controller.system.operations[ops_before..];
        assert_eq!(controller.current_exit_mode(), ExitMode::FullTunnel);
        assert!(
            new_ops.contains(&"assert_exit_policy:full_tunnel".to_string()),
            "managed-peer endpoint reconfiguration must assert the controller's current full-tunnel policy"
        );
    }

    #[test]
    fn test_a4b_force_fail_closed_overrides_pending_path_transition() {
        // Even when a path transition is in pending (hysteresis) state,
        // force_fail_closed must immediately move the system to FailClosed.
        // This ensures ACL rules can never be left in a partially-transitioned
        // state — the daemon's emergency shutdown path always wins.
        let (mut controller, peer_id, _direct_ep, _relay_ep) =
            make_a4b_controller_with_both_endpoints();
        assert_eq!(controller.peer_path(&peer_id), Some(PathMode::Direct));
        assert_ne!(controller.state(), DataplaneState::FailClosed);

        // Start a relay transition (but don't commit — one call only).
        controller
            .mark_direct_failed(&peer_id)
            .expect("first signal starts pending");

        // Peer must still be Direct (stability window not yet elapsed).
        assert_eq!(
            controller.peer_path(&peer_id),
            Some(PathMode::Direct),
            "peer must remain Direct while transition is pending"
        );

        // force_fail_closed must override the pending transition immediately.
        controller
            .force_fail_closed("test_a4b_override")
            .expect("force_fail_closed must succeed");

        assert_eq!(
            controller.state(),
            DataplaneState::FailClosed,
            "state must be FailClosed after force_fail_closed regardless of pending transition"
        );
    }
}
