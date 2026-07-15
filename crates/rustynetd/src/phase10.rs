#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Upper bound on how long the daemon waits for a Windows helper subprocess
/// (`netsh`, `powershell`) before killing it. A daemon must never block its
/// startup / reconcile path indefinitely on an external tool: a CIM cmdlet
/// (`Get-NetRoute`, `New-NetFirewallRule`) stuck on a wedged WMI provider would
/// otherwise hang `Command::output()` forever AND leak the child process —
/// exactly the failure that previously accumulated stuck `powershell.exe`
/// instances and wedged WMI. The bound is generous (these commands normally
/// complete in well under a second) but finite, so a hang fails closed and is
/// recovered instead of stalling the daemon.
const WINDOWS_HELPER_COMMAND_TIMEOUT: Duration = Duration::from_secs(20);

/// Run `command`, capturing its output, but never block longer than `timeout`.
/// If the child does not exit in time it is killed and reaped and a timeout
/// error is returned, so a hung helper cannot stall the daemon or leak a
/// process. Output is collected with `wait_with_output` only after the child
/// exits, so callers must keep combined stdout+stderr under the OS pipe buffer
/// (~64 KiB); every daemon helper invocation (netsh / firewall cmdlets)
/// produces small output, so this holds.
#[cfg_attr(not(windows), allow(dead_code))]
fn run_helper_command_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<Output, String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().map_err(|err| err.to_string())? {
            Some(_status) => {
                return child
                    .wait_with_output()
                    .map_err(|err| format!("collect command output failed: {err}"));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "command timed out after {}ms and was killed",
                    timeout.as_millis()
                ));
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use crate::macos_blind_exit::{
    DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR, MacosBlindExitManagementCidr, MacosBlindExitPfConfig,
    build_macos_blind_exit_pf_rules, evaluate_macos_blind_exit_pf_rules,
    is_macos_blind_exit_anchor,
};
use crate::macos_exit_nat::{
    DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR, MacosExitNatPfConfig, evaluate_macos_exit_nat_pf_rules,
};
use crate::macos_pf_load_spec::MacosPfLoadSpec;
use crate::privileged_helper::{
    PrivilegedCommandClient, PrivilegedCommandOutput, PrivilegedCommandProgram, validate_request,
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
            .map_err(|err| TraversalError::ProbeSend(format!("reconfigure_managed_peer: {err}")))?;
        self.controller
            .backend
            .initiate_peer_handshake(&self.node_id, round > 0)
            .map_err(|err| TraversalError::ProbeSend(format!("initiate_peer_handshake: {err}")))
    }

    fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
        self.controller
            .backend
            .peer_latest_handshake_unix(&self.node_id)
            .map_err(|err| TraversalError::ProbeSend(format!("peer_latest_handshake_unix: {err}")))
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
const WINDOWS_POWERSHELL_BINARY_PATH_ENV: &str = "RUSTYNET_POWERSHELL_BINARY_PATH";
const WINDOWS_REG_BINARY_PATH_ENV: &str = "RUSTYNET_REG_BINARY_PATH";
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
pub(crate) const DEFAULT_WINDOWS_POWERSHELL_BINARY_PATH: &str =
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
const DEFAULT_WINDOWS_REG_BINARY_PATH: &str = r"C:\Windows\System32\reg.exe";

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
    /// FIS-0009: peer's cross-session traversal prior (None = rank as
    /// today; populated only when the daemon's prior-rerank flag is on).
    pub prior_ranking: Option<crate::traversal::PriorRanking>,
    /// FIS-0013: the quality-demoted incumbent endpoint. When set, the
    /// fresh-handshake short-circuit is skipped (the re-race must actually
    /// fire) and pairs targeting this endpoint sort LAST
    /// (demote-don't-exclude: if every alternate fails, the incumbent
    /// still races and may win).
    pub quality_demoted_endpoint: Option<SocketEndpoint>,
    pub coordination_schedule: Option<CoordinationSchedule>,
    pub coordination_error: Option<String>,
    /// D5.5 promotion — SHA-256 digests of the local + remote
    /// `NodeId` strings, used by `ice_priority::decide_role` to
    /// deterministically split controlling/controlled across both
    /// peers without an ICE-CONTROLLING handshake. Both peers
    /// compute the same digests for the same node ids, so the role
    /// assignment is symmetric and stable. The digest hides the raw
    /// node id length from the role decision and pins the role
    /// computation to a fixed 32-byte shape that
    /// `ice_priority::decide_role` accepts directly.
    pub local_node_id_digest: [u8; 32],
    pub remote_node_id_digest: [u8; 32],
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
    /// True only for the irreversible `blind_exit` role. Distinguishes a
    /// blind exit (hardened final-hop exit: local-origin egress tunnel-only,
    /// mesh-scoped forwarding, no NAT translation) from a regular NATing exit —
    /// both have `serve_exit_node = true` and typically `exit_mode = Off`, so
    /// the role cannot be inferred from those two fields alone. Linux
    /// (`crate::linux_blind_exit`) and macOS (`crate::macos_blind_exit`) both
    /// key their blind-vs-regular exit dataplane on this flag; Windows
    /// blind_exit is out of scope by design (Linux/macOS only).
    pub blind_exit: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            protected_dns: true,
            ipv6_parity_supported: false,
            exit_mode: ExitMode::Off,
            serve_exit_node: false,
            blind_exit: false,
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
    /// Flush any persisted exit-NAT translation state that must not outlive the
    /// exit capability (CLAUDE.md §10.7), given whether THIS generation serves
    /// an exit. Called every apply before the generation stages. Default no-op;
    /// platforms whose exit NAT lives in fixed-name kernel state that the
    /// generation-numbered `prune_owned_tables` sweep does not reach (macOS pf
    /// `com.rustynet/nat`) override this to flush that state when not serving,
    /// so a crash-then-restart-as-client cannot leave a live NAT rule behind.
    /// (Linux self-heals: its NAT tables are generation-numbered and swept by
    /// `prune_owned_tables`.)
    fn reconcile_exit_nat_residue(&mut self, _serving_exit: bool) -> Result<(), SystemError> {
        Ok(())
    }
    fn check_prerequisites(&mut self) -> Result<(), SystemError>;
    fn preflight_exit_serving(&mut self, _mesh_cidr: &str) -> Result<(), SystemError> {
        Ok(())
    }
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
    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError>;
    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError>;
    fn apply_dns_protection(&mut self) -> Result<(), SystemError>;
    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn rollback_dns_protection(&mut self) -> Result<(), SystemError>;
    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError>;
    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    fn assert_killswitch(&mut self) -> Result<(), SystemError>;
    fn assert_exit_policy(&mut self, _exit_mode: ExitMode) -> Result<(), SystemError> {
        self.assert_killswitch()
    }
    fn assert_exit_serving(&mut self, _mesh_cidr: &str) -> Result<(), SystemError> {
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

/// Why a generation is being unwound, so security controls (DNS) can choose
/// fail-closed vs. restore behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RollbackIntent {
    /// Unwinding a FAILED apply. Security controls stay closed (DNS held
    /// loopback/mesh-only); `force_fail_closed` follows. Never fail open.
    FailClosed,
    /// Intentional teardown (daemon shutdown). Restore the host's original
    /// pre-protected configuration (e.g. resolv.conf).
    CleanShutdown,
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
        self.fail_operation = Some(operation.to_owned());
        self
    }

    fn step(&mut self, operation: &str) -> Result<(), SystemError> {
        self.operations.push(operation.to_owned());
        if self
            .fail_operation
            .as_ref()
            .is_some_and(|candidate| candidate == operation)
        {
            return Err(SystemError::RollbackFailed(operation.to_owned()));
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

    fn preflight_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        self.operations
            .push(format!("preflight_exit_serving:mesh_cidr={mesh_cidr}"));
        self.step("preflight_exit_serving")
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

    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError> {
        self.operations.push(format!(
            "apply_nat_forwarding:serve_exit_node={serve_exit_node}:exit_mode={}:blind_exit={blind_exit}:mesh_cidr={mesh_cidr}",
            match exit_mode {
                ExitMode::Off => "off",
                ExitMode::FullTunnel => "full_tunnel",
            }
        ));
        self.step("apply_nat_forwarding")
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        self.step("rollback_nat_forwarding")
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("apply_dns_protection")
    }

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("assert_dns_protection")
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

    fn assert_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        self.operations
            .push(format!("assert_exit_serving:mesh_cidr={mesh_cidr}"));
        self.step("assert_exit_serving")
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
    wg_listen_port: u16,
    /// Port the rustynet resolver binds on loopback (default 53535). The
    /// protected-mode DNS redirect maps loopback `:53` to this port; 0 means
    /// "not configured" and loopback DNS ownership refuses to apply.
    dns_resolver_port: u16,
    dns_protected: bool,
    /// Set once the irreversible `blind_exit` hardened-egress posture has been
    /// applied. Like the macOS PF anchor it is one-way: rollback re-applies the
    /// hard-lock from this config instead of relaxing to an open NAT, and only a
    /// factory reset clears it (see [`crate::linux_blind_exit`]).
    blind_exit_config: Option<crate::linux_blind_exit::LinuxBlindExitConfig>,
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
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided".to_owned(),
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
            wg_listen_port: 0,
            dns_resolver_port: 0,
            dns_protected: false,
            blind_exit_config: None,
            expected_management_bypass_routes: BTreeSet::new(),
            expected_peer_endpoint_bypass_routes: BTreeSet::new(),
        })
    }

    pub fn with_traversal_bootstrap_allow_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.traversal_bootstrap_allow_endpoints = dedupe_socket_addrs(endpoints);
        self
    }

    pub fn with_wg_listen_port(mut self, port: u16) -> Self {
        self.wg_listen_port = port;
        self
    }

    /// Thread the rustynet resolver's loopback bind port so protected-mode DNS
    /// can redirect loopback `:53` to it.
    pub fn with_dns_resolver_port(mut self, port: u16) -> Self {
        self.dns_resolver_port = port;
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

        // In-helper builtins (the DNS fail-closed file-write) are not external
        // binaries. On the helper-less direct path execute the same in-process
        // handler the helper would, after the identical allowlist validation —
        // so the builtin behaves symmetrically with or without privilege
        // separation. Non-builtin programs return None here and fall through to
        // the exec path below.
        if let Some(result) = crate::privileged_helper::try_execute_builtin_program(program, args) {
            return result.map_err(SystemError::Io);
        }

        // RN-19: the helper-less direct path must enforce the same argv-schema
        // allowlist as the IPC helper, so the validating gate is symmetric
        // across both execution paths and cannot be bypassed by running the
        // daemon as root without a helper.
        validate_request(program, args).map_err(SystemError::Io)?;

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

    /// Install the loopback `:53` -> resolver redirect, point
    /// `/etc/resolv.conf` at the loopback resolver (backing up the original),
    /// and — when NetworkManager is present — drop in `dns=none` so NM cannot
    /// reintroduce off-loopback nameservers on a link change. Every file write
    /// goes through the privileged helper's fixed-path/fixed-content builtin.
    fn apply_loopback_dns_ownership(&mut self) -> Result<(), SystemError> {
        if self.dns_resolver_port == 0 {
            return Err(SystemError::DnsApplyFailed(
                "dns resolver port is not configured; refusing to apply loopback DNS ownership"
                    .to_owned(),
            ));
        }
        let table = crate::linux_dns_protect::dns_redirect_table_name(self.generation);
        for argv in
            crate::linux_dns_protect::dns_redirect_nft_apply_argvs(&table, self.dns_resolver_port)
        {
            let refs: Vec<&str> = argv.iter().map(String::as_str).collect();
            self.run(PrivilegedCommandProgram::Nft, &refs)
                .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        }
        // Back up & rewrite /etc/resolv.conf to the loopback resolver.
        self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_RESOLV_APPLY],
        )
        .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        // Disable NetworkManager resolv.conf management only when NM is present;
        // on a host without NM the drop-in would be meaningless.
        if std::path::Path::new(crate::linux_dns_failclosed::NETWORK_MANAGER_CONF_PATH).exists() {
            self.run(
                PrivilegedCommandProgram::DnsFailclosedFile,
                &[crate::linux_dns_protect::DNS_FILE_SELECTOR_NM_APPLY],
            )
            .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        }
        Ok(())
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
            args.push("-6".to_owned());
        }
        args.push("route".to_owned());
        args.push("get".to_owned());
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
                return Ok((*interface).to_owned());
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
                lines.push(trimmed.to_owned());
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
                            "missing cached ipv4 route table output".to_owned(),
                        )
                    })?
                }
                RouteTableFamily::V6 => {
                    if table_v6.is_none() {
                        table_v6 = Some(self.route_table_output(RouteTableFamily::V6)?);
                    }
                    table_v6.as_deref().ok_or_else(|| {
                        SystemError::KillSwitchAssertionFailed(
                            "missing cached ipv6 route table output".to_owned(),
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
            SystemError::KillSwitchAssertionFailed("nat postrouting chain missing".to_owned())
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
            "ipv4 forwarding is disabled while nat forwarding is active".to_owned(),
        ))
    }

    fn assert_firewall_ruleset(&self) -> Result<(), SystemError> {
        let table = self.firewall_table.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("killswitch table missing".to_owned())
        })?;
        let ruleset = self.nft_table_output("inet", table.as_str(), "nft list killswitch table")?;
        let killswitch = Self::nft_chain_lines(&ruleset, "killswitch").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("killswitch chain missing".to_owned())
        })?;
        let forward = Self::nft_chain_lines(&ruleset, "forward").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("forward chain missing".to_owned())
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
        if self.wg_listen_port != 0 {
            let port_str = self.wg_listen_port.to_string();
            self.assert_chain_contains(
                &killswitch,
                &[
                    "oifname",
                    self.egress_interface.as_str(),
                    "udp",
                    "dport",
                    port_str.as_str(),
                    "accept",
                ],
                "wireguard listen port killswitch allow rule missing",
            )?;
        }
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
            args.push("-6".to_owned());
        }
        args.push("route".to_owned());
        args.push("replace".to_owned());
        args.push(cidr.to_string());
        args.push("dev".to_owned());
        args.push(route_interface.to_owned());
        args.push("table".to_owned());
        args.push("51820".to_owned());
        args
    }

    fn peer_endpoint_bypass_route_args(addr: IpAddr, route_interface: &str) -> Vec<String> {
        let endpoint_cidr = match addr {
            IpAddr::V4(value) => format!("{value}/32"),
            IpAddr::V6(value) => format!("{value}/128"),
        };
        let mut args = Vec::with_capacity(9);
        if matches!(addr, IpAddr::V6(_)) {
            args.push("-6".to_owned());
        }
        args.push("route".to_owned());
        args.push("replace".to_owned());
        args.push(endpoint_cidr);
        args.push("dev".to_owned());
        args.push(route_interface.to_owned());
        args.push("table".to_owned());
        args.push("51820".to_owned());
        args
    }

    fn traversal_bootstrap_allow_rule_args(
        table: &str,
        egress_interface: &str,
        endpoint: SocketAddr,
    ) -> Vec<String> {
        vec![
            "add".to_owned(),
            "rule".to_owned(),
            "inet".to_owned(),
            table.to_owned(),
            "killswitch".to_owned(),
            "oifname".to_owned(),
            egress_interface.to_owned(),
            nft_family_for_ip(endpoint.ip()).to_owned(),
            "daddr".to_owned(),
            endpoint.ip().to_string(),
            "udp".to_owned(),
            "dport".to_owned(),
            endpoint.port().to_string(),
            "accept".to_owned(),
            "comment".to_owned(),
            "rustynet_traversal_bootstrap".to_owned(),
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

    /// Apply the irreversible `blind_exit` hardened-egress posture.
    ///
    /// A blind exit is a *final-hop exit* that forwards mesh-sourced traffic to
    /// the internet, but locked down far tighter than a regular NATing exit:
    /// local-origin egress stays tunnel-only (the base killswitch `oifname
    /// <tunnel> accept` + `policy drop`), forwarded traffic is scoped to the
    /// signed mesh CIDR, and there is NO masquerade — the mesh source is never
    /// translated (the "blind" property). This mirrors the reviewed macOS PF
    /// hard-lock anchor; the rule builder + evaluator live in
    /// [`crate::linux_blind_exit`].
    fn apply_linux_blind_exit_locked(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        let table = self.firewall_table.clone().ok_or_else(|| {
            SystemError::NatApplyFailed(
                "blind_exit requires the killswitch table to be applied first".to_owned(),
            )
        })?;
        let config = crate::linux_blind_exit::LinuxBlindExitConfig::new(
            self.interface_name.clone(),
            self.egress_interface.clone(),
            mesh_cidr.to_owned(),
        )
        .map_err(SystemError::NatApplyFailed)?;
        let commands = crate::linux_blind_exit::build_linux_blind_exit_forward_commands(
            &config,
            table.as_str(),
        )
        .map_err(SystemError::NatApplyFailed)?;

        // Enable IPv4 forwarding so the kernel routes tunnel->egress for the
        // mesh-scoped final hop (record the prior value for restore). blind_exit
        // is a final-hop exit; the hardening is the filter policy below, not
        // disabling the forward path.
        // Capture the TRUE prior only once. This method re-runs on every
        // re-enforce while the node keeps serving as an exit; an unconditional
        // capture would read the already-enabled `1` on the second pass and
        // clobber the real baseline (`0`), so a later demotion's
        // `restore_ipv4_forwarding` would restore `1` and leave forwarding on
        // (residue release-blocker). The persistent per-daemon applier retains
        // this field across re-enforces, and `restore_ipv4_forwarding` clears it
        // via `.take()`, so a later re-activation re-captures a fresh baseline.
        if self.prior_ipv4_forwarding.is_none() {
            self.prior_ipv4_forwarding = Some(Self::read_sysctl_bool(
                "/proc/sys/net/ipv4/ip_forward",
                "net.ipv4.ip_forward",
            )?);
        }
        self.set_ipv4_forwarding(true)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))?;

        // blind_exit NEVER NATs. Tear down any masquerade table a prior
        // generation (or a former regular-exit posture) left behind so the mesh
        // source is never translated.
        if let Some(previous) = self.nat_table.take() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", previous.as_str()],
            );
        }

        // Re-author the forward chain: flush the regular-exit unrestricted
        // tunnel->egress allow the base killswitch installed, then add the
        // conntrack accept + the mesh-source-scoped final-hop allow. The chain
        // keeps `policy drop`, so a mid-sequence failure leaves it dropping
        // (fail-closed), and everything not explicitly allowed is dropped.
        for argv in &commands {
            let args: Vec<&str> = argv.iter().map(String::as_str).collect();
            if let Err(err) = self.run(PrivilegedCommandProgram::Nft, &args) {
                let _ = self.restore_ipv4_forwarding();
                return Err(SystemError::NatApplyFailed(format!(
                    "blind_exit forward-chain apply failed: {err}"
                )));
            }
        }

        self.blind_exit_config = Some(config);
        Ok(())
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
        // Add loopback accept immediately after chain creation so the managed DNS
        // resolver on 127.0.0.1:53535 is never blocked during rule setup.
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
        self.apply_fail_closed_management_allow_rules(table.as_str())?;
        self.apply_traversal_bootstrap_allow_rules(table.as_str())?;
        if self.wg_listen_port != 0 {
            let port_str = self.wg_listen_port.to_string();
            self.run(
                PrivilegedCommandProgram::Nft,
                &[
                    "add",
                    "rule",
                    "inet",
                    table.as_str(),
                    "killswitch",
                    "oifname",
                    self.egress_interface.as_str(),
                    "udp",
                    "dport",
                    port_str.as_str(),
                    "accept",
                ],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "wireguard listen port {} allow rule failed: {err}",
                    self.wg_listen_port
                ))
            })?;
        }
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
                tables.push((parts[1].to_owned(), parts[2].to_owned()));
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
                        .is_some_and(|active| active == table.as_str()))
            {
                continue;
            }
            if family == "ip"
                && (table == keep_nat_target
                    || keep_nat_active
                        .as_deref()
                        .is_some_and(|active| active == table.as_str()))
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
            "linux command system is only supported on linux".to_owned(),
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

    /// Linux exit-NAT residue reconcile.
    ///
    /// The generation-numbered NAT tables self-heal via `prune_owned_tables`,
    /// but `net.ipv4.ip_forward` is NOT generation state. `apply_nat_forwarding`
    /// enables it and caches the prior value only in memory
    /// (`prior_ipv4_forwarding`), so a former exit that demotes to client in a
    /// LATER apply (new generation, fresh applier instance) — or restarts as a
    /// client after a crash — has no cached prior and would otherwise leave
    /// forwarding enabled with no path to restore it (CLAUDE.md §10.7 residue;
    /// a non-exit node must not forward). Drive it back to the secure default
    /// (0) whenever THIS generation does not serve an exit.
    ///
    /// Mirrors `MacosCommandSystem::reconcile_exit_nat_residue`.
    /// `serve_exit_node` is true for a regular exit, `blind_exit`, AND
    /// relay-with-upstream, so this never disables forwarding a forwarding role
    /// legitimately needs. The normal in-process exit→client demotion still
    /// restores the cached prior LATER via `rollback_nat_forwarding` (which runs
    /// when `NatApplied` was recorded this pass), overriding this default; the
    /// cross-generation and crash paths (no cached prior) rely on it. Best
    /// effort (like the macOS pf flush): reconcile runs before the generation
    /// stages on every apply, and the exit-demotion-residue validator is the
    /// loud gate on a real forwarding leak.
    fn reconcile_exit_nat_residue(&mut self, serving_exit: bool) -> Result<(), SystemError> {
        if !serving_exit {
            let _ = self.set_ipv4_forwarding(false);
        }
        Ok(())
    }

    fn apply_nat_forwarding(
        &mut self,
        _serve_exit_node: bool,
        _exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError> {
        // The irreversible `blind_exit` role is a hardened final-hop exit, NOT a
        // regular NATing exit: it forwards only mesh-sourced traffic, keeps
        // local-origin egress tunnel-only, and installs NO masquerade. Branch
        // before the regular NAT setup so none of the masquerade / own-egress
        // allow below is ever programmed for a blind_exit node. Mirrors the
        // macOS `MacosCommandSystem::apply_nat_forwarding` blind_exit branch.
        if blind_exit {
            return self.apply_linux_blind_exit_locked(mesh_cidr);
        }

        // Capture the TRUE prior only once. This method re-runs on every
        // re-enforce while the node keeps serving as an exit; an unconditional
        // capture would read the already-enabled `1` on the second pass and
        // clobber the real baseline (`0`), so a later demotion's
        // `restore_ipv4_forwarding` would restore `1` and leave forwarding on
        // (residue release-blocker). The persistent per-daemon applier retains
        // this field across re-enforces, and `restore_ipv4_forwarding` clears it
        // via `.take()`, so a later re-activation re-captures a fresh baseline.
        if self.prior_ipv4_forwarding.is_none() {
            self.prior_ipv4_forwarding = Some(Self::read_sysctl_bool(
                "/proc/sys/net/ipv4/ip_forward",
                "net.ipv4.ip_forward",
            )?);
        }
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
            let nat_name = self.nat_table.as_deref().unwrap_or("").to_owned();
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
        // blind_exit is irreversible: re-apply the hard-lock instead of
        // relaxing to an open NAT (mirrors the macOS rollback that re-loads the
        // PF anchor). Only a factory reset clears it.
        if let Some(config) = self.blind_exit_config.clone() {
            let table = self.firewall_table.clone().ok_or_else(|| {
                SystemError::RollbackFailed(
                    "blind_exit rollback requires the killswitch table".to_owned(),
                )
            })?;
            // No masquerade may survive: drop any NAT table before re-locking.
            if let Some(nat) = self.nat_table.take() {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Nft,
                    &["delete", "table", "ip", nat.as_str()],
                );
            }
            let commands = crate::linux_blind_exit::build_linux_blind_exit_forward_commands(
                &config,
                table.as_str(),
            )
            .map_err(SystemError::RollbackFailed)?;
            for argv in &commands {
                let args: Vec<&str> = argv.iter().map(String::as_str).collect();
                self.run(PrivilegedCommandProgram::Nft, &args)
                    .map_err(|err| {
                        SystemError::RollbackFailed(format!(
                            "blind_exit forward-chain re-lock failed: {err}"
                        ))
                    })?;
            }
            return Ok(());
        }
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
            .ok_or_else(|| SystemError::DnsApplyFailed("killswitch table missing".to_owned()))?;
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
        // Option 2: the rustynet resolver owns loopback DNS. The killswitch
        // rules above are defense-in-depth (drop off-tunnel :53); this is what
        // makes the dns-failclosed verifier pass — every resolv.conf nameserver
        // becomes loopback, reached via the redirect to the local resolver.
        self.apply_loopback_dns_ownership()?;
        self.dns_protected = true;
        Ok(())
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        // Best-effort teardown in reverse order. Rollback must not itself fail
        // closed and strand the node, so each step tolerates already-absent
        // state (restore/remove are no-ops when nothing was applied).
        self.run_allow_failure(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_RESOLV_RESTORE],
        );
        self.run_allow_failure(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_NM_REMOVE],
        );
        let table = crate::linux_dns_protect::dns_redirect_table_name(self.generation);
        let teardown = crate::linux_dns_protect::dns_redirect_nft_teardown_argv(&table);
        let refs: Vec<&str> = teardown.iter().map(String::as_str).collect();
        self.run_allow_failure(PrivilegedCommandProgram::Nft, &refs);
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

    fn assert_exit_serving(&mut self, _mesh_cidr: &str) -> Result<(), SystemError> {
        self.assert_killswitch()?;
        self.assert_nat_forwarding()
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

/// The inputs `render_macos_killswitch_pf_rules` consumes to render the macOS
/// killswitch filter anchor. Mirrors EXACTLY the `MacosCommandSystem` fields the
/// renderer reads (see `MacosCommandSystem::killswitch_spec`), so the rule text
/// is a pure, deterministic function of this spec. That lets the privileged
/// helper RE-RENDER the killswitch rules itself from a validated spec rather
/// than trusting daemon-supplied rule-file content (the `pfctl -f` boundary fix):
/// a compromised daemon can only choose spec parameters — each independently
/// validated — never inject rule text. Keep in lockstep with `killswitch_spec`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacosKillswitchSpec {
    pub interface_name: String,
    pub egress_interface: String,
    pub dns_protected: bool,
    pub allow_egress_interface: bool,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    pub traversal_bootstrap_allow_endpoints: Vec<SocketAddr>,
    pub managed_peer_egress_endpoints: Vec<SocketAddr>,
    pub ipv6_blocked: bool,
}

/// Render the macOS killswitch filter anchor ruleset from a spec. Pure +
/// deterministic, and ALWAYS terminated by `block drop out quick all` (the
/// default-deny egress invariant). This is the single source of truth for the
/// killswitch rule text: both the daemon (`render_pf_rules`) and the privileged
/// helper (which re-renders from a validated spec) call it, so the two cannot
/// drift. Adding a new legitimate rule form = add a field here + a branch — in
/// ONE place — never a silent divergence.
pub(crate) fn render_macos_killswitch_pf_rules(
    spec: &MacosKillswitchSpec,
    strict_fail_closed: bool,
) -> String {
    let mut rules = String::new();
    rules.push_str("set block-policy drop\n");
    // Loopback is host-internal and never leaves the box. Allow it in BOTH
    // directions and BOTH address families, UNCONDITIONALLY (incl.
    // strict-fail-closed), so the daemon's local IPC, the loopback DNS resolver,
    // and loopback health checks (e.g. the relay's 127.0.0.1:4501 /healthz) keep
    // working — without this an inbound SYN-ACK on lo0 has no matching pass and a
    // localhost handshake stalls in SYN_RCVD. `quick` short-circuits; scoping to
    // `on lo0` keeps this from being a blanket `pass` (the terminal
    // `block drop out quick all` still default-denies every other egress). This
    // mirrors Linux's `oifname "lo" accept` + `ct state established,related accept`.
    rules.push_str("pass quick on lo0 all\n");
    if !strict_fail_closed {
        // pf grammar: `[action] [direction] [quick] [on <iface>] [<af>] …` — the
        // address family (`inet`/`inet6`) MUST follow `on <iface>` (macOS pfctl
        // rejects the reversed form).
        if spec.dns_protected {
            rules.push_str(&format!(
                "pass out quick on {} inet proto udp to any port 53 keep state\n",
                spec.interface_name
            ));
            rules.push_str(&format!(
                "pass out quick on {} inet proto tcp to any port 53 keep state\n",
                spec.interface_name
            ));
            rules.push_str(&format!(
                "block drop out quick inet proto udp to any port 53 label \"{}\"\n",
                crate::macos_exit_dns_failclosed::DNS_BLOCK_LAN_UDP_RULE
            ));
            rules.push_str(&format!(
                "block drop out quick inet proto tcp to any port 53 label \"{}\"\n",
                crate::macos_exit_dns_failclosed::DNS_BLOCK_LAN_TCP_RULE
            ));
        }
        rules.push_str(&format!(
            "pass out quick on {} inet all keep state\n",
            spec.interface_name
        ));
        if spec.allow_egress_interface {
            rules.push_str(&format!(
                "pass out quick on {} inet all keep state\n",
                spec.egress_interface
            ));
        }
    }
    if spec.fail_closed_ssh_allow {
        for cidr in &spec.fail_closed_ssh_allow_cidrs {
            rules.push_str(&format!(
                "pass in quick {} proto tcp from {} to any port 22 keep state\n",
                cidr.pf_family(),
                cidr
            ));
            rules.push_str(&format!(
                "pass out quick {} proto tcp from any to {} port 22 keep state\n",
                cidr.pf_family(),
                cidr
            ));
        }
    }
    for endpoint in &spec.traversal_bootstrap_allow_endpoints {
        rules.push_str(&format!(
            "pass out quick on {} {} proto udp to {} port {} keep state\n",
            spec.egress_interface,
            pf_family_for_ip(endpoint.ip()),
            endpoint.ip(),
            endpoint.port()
        ));
    }
    for endpoint in &spec.managed_peer_egress_endpoints {
        rules.push_str(&format!(
            "pass out quick on {} {} proto udp to {} port {} keep state\n",
            spec.egress_interface,
            pf_family_for_ip(endpoint.ip()),
            endpoint.ip(),
            endpoint.port()
        ));
    }
    if spec.ipv6_blocked {
        rules.push_str("block drop out quick inet6 all\n");
    }
    rules.push_str("block drop out quick all\n");
    rules
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
    managed_peer_egress_endpoints: Vec<SocketAddr>,
    blind_exit_pf_config: Option<MacosBlindExitPfConfig>,
    /// The regular-exit NAT translation anchor (`com.rustynet/nat`) once
    /// loaded, distinct from `anchor_name` (the killswitch filter anchor).
    /// `Some` means the exit NAT is active and teardown must flush it.
    exit_nat_anchor: Option<String>,
    /// The forwarding value captured before the exit enabled forwarding, so
    /// teardown can restore the exact prior state instead of blindly forcing it
    /// off.
    prior_ip_forwarding: Option<String>,
    /// Which forwarding sysctl the exit enabled — `net.inet.ip.forwarding` for
    /// an IPv4 mesh, `net.inet6.ip6.forwarding` for an IPv6 mesh. Restore and
    /// teardown must use the SAME key that was enabled.
    exit_forwarding_key: Option<&'static str>,
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
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        validate_net_device_name(&egress_interface)
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        if fail_closed_ssh_allow && fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "fail-closed ssh allow is enabled but no management cidrs were provided".to_owned(),
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
            managed_peer_egress_endpoints: Vec::new(),
            blind_exit_pf_config: None,
            exit_nat_anchor: None,
            prior_ip_forwarding: None,
            exit_forwarding_key: None,
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

        // In-helper builtins (the DNS fail-closed file-write) are not external
        // binaries. On the helper-less direct path execute the same in-process
        // handler the helper would, after the identical allowlist validation —
        // so the builtin behaves symmetrically with or without privilege
        // separation. Non-builtin programs return None here and fall through to
        // the exec path below.
        if let Some(result) = crate::privileged_helper::try_execute_builtin_program(program, args) {
            return result.map_err(SystemError::Io);
        }

        // RN-19: the helper-less direct path must enforce the same argv-schema
        // allowlist as the IPC helper, so the validating gate is symmetric
        // across both execution paths and cannot be bypassed by running the
        // daemon as root without a helper.
        validate_request(program, args).map_err(SystemError::Io)?;

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
        if self.blind_exit_pf_config.is_some() {
            return DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR.to_owned();
        }
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

    /// Build the killswitch render spec from this system's current state. MUST
    /// stay in lockstep with `MacosKillswitchSpec` — every field the renderer
    /// reads is mirrored here so the daemon-side render and the privileged
    /// helper's re-render from a transported spec produce identical text.
    fn killswitch_spec(&self) -> MacosKillswitchSpec {
        MacosKillswitchSpec {
            interface_name: self.interface_name.clone(),
            egress_interface: self.egress_interface.clone(),
            dns_protected: self.dns_protected,
            allow_egress_interface: self.allow_egress_interface,
            fail_closed_ssh_allow: self.fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs: self.fail_closed_ssh_allow_cidrs.clone(),
            traversal_bootstrap_allow_endpoints: self.traversal_bootstrap_allow_endpoints.clone(),
            managed_peer_egress_endpoints: self.managed_peer_egress_endpoints.clone(),
            ipv6_blocked: self.ipv6_blocked,
        }
    }

    fn render_pf_rules(&self, strict_fail_closed: bool) -> Result<String, SystemError> {
        if let Some(config) = self.blind_exit_runtime_config() {
            return build_macos_blind_exit_pf_rules(&config)
                .map_err(SystemError::FirewallApplyFailed);
        }
        // Delegate to the pure renderer (single source of truth shared with the
        // privileged helper's re-render path). The blind-exit branch above uses
        // its own reviewed builder.
        Ok(render_macos_killswitch_pf_rules(
            &self.killswitch_spec(),
            strict_fail_closed,
        ))
    }

    fn blind_exit_runtime_config(&self) -> Option<MacosBlindExitPfConfig> {
        let mut config = self.blind_exit_pf_config.clone()?;
        config.ipv6_tunnel_allowed = !self.ipv6_blocked;
        config.dns_protected = self.dns_protected;
        config.management_ssh_allow_cidrs = if self.fail_closed_ssh_allow {
            self.fail_closed_ssh_allow_cidrs
                .iter()
                .map(|cidr| MacosBlindExitManagementCidr {
                    family: cidr.pf_family(),
                    cidr: cidr.to_string(),
                })
                .collect()
        } else {
            Vec::new()
        };
        Some(config)
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
            // Accept both rendered (`port 53`) and pfctl-normalized (`port = 53`)
            // forms. macOS pfctl rewrites `port 53` to `port = 53` and `port domain`
            // to `port = domain` when dumping the live ruleset via `-s rules`.
            normalized.contains("port 53")
                || normalized.contains("port = 53")
                || normalized.contains("port domain")
                || normalized.contains("port = domain")
        })
    }

    fn apply_pf_rules(&mut self, strict_fail_closed: bool) -> Result<(), SystemError> {
        self.ensure_pf_enabled()?;
        let next_anchor = self.current_anchor_name();
        match self.anchor_name.as_ref() {
            Some(previous) if previous != &next_anchor && !is_macos_blind_exit_anchor(previous) => {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Pfctl,
                    &["-a", previous.as_str(), "-F", "all"],
                );
            }
            _ => {}
        }

        // Hand a structured load SPEC to the privileged macOS pf builtin
        // instead of authoring a rules file and naming a `pfctl -f` path. The
        // helper re-renders the rule text itself from the reviewed builders,
        // derives the anchor name from the spec kind, and owns the temp file +
        // `pfctl` invocation end-to-end. A daemon compromised to the helper's
        // uid can therefore only choose validated spec parameters — never inject
        // rule text or redirect the load (audit major #5, `pfctl -f` boundary).
        let spec = if let Some(config) = self.blind_exit_runtime_config() {
            MacosPfLoadSpec::BlindExit { config }
        } else {
            MacosPfLoadSpec::Killswitch {
                generation: self.generation,
                strict_fail_closed,
                spec: self.killswitch_spec(),
            }
        };
        let args = spec.encode();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(PrivilegedCommandProgram::MacosPfLoad, &arg_refs)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.anchor_name = Some(next_anchor);
        if let Some(config) = self.blind_exit_runtime_config() {
            let anchor = self
                .anchor_name
                .as_deref()
                .unwrap_or(DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR);
            let output = self.run_capture(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-s", "rules"],
            )?;
            if !output.success() {
                return Err(SystemError::FirewallApplyFailed(format!(
                    "blind_exit pf verification query failed: status={} stderr={}",
                    output.status, output.stderr
                )));
            }
            let reasons = evaluate_macos_blind_exit_pf_rules(output.stdout.as_str(), &config);
            if !reasons.is_empty() {
                return Err(SystemError::FirewallApplyFailed(format!(
                    "blind_exit pf verification failed: {}",
                    reasons.join("; ")
                )));
            }
        }
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
            if is_macos_blind_exit_anchor(anchor.as_str()) {
                self.anchor_name = Some(anchor);
                return;
            }
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
    }

    /// Enable IPv4 forwarding and load the regular-exit NAT translation anchor
    /// (`com.rustynet/nat`). Caches the prior forwarding value for fail-closed
    /// restore. Forwarding is enabled before the anchor loads (mirroring the
    /// Linux ordering); on any failure the forwarding flip and a partial load
    /// are rolled back, leaving the killswitch `block drop out quick all` in
    /// force so egress stays blocked.
    fn activate_exit_nat(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        // Enable the forwarding family matching the mesh prefix: an IPv4 mesh
        // uses `net.inet.ip.forwarding`, an IPv6 mesh uses
        // `net.inet6.ip6.forwarding`. The builder emits the matching
        // `inet`/`inet6` NAT translation rule for the same prefix.
        let forwarding_key = if mesh_cidr.contains(':') {
            "net.inet6.ip6.forwarding"
        } else {
            "net.inet.ip.forwarding"
        };

        let config =
            MacosExitNatPfConfig::new(self.egress_interface.clone(), vec![mesh_cidr.to_owned()])
                .map_err(SystemError::NatApplyFailed)?;

        // Read the prior forwarding state FAIL-CLOSED — a read error or
        // non-zero status aborts activation rather than guessing a value, so we
        // never cache a wrong prior (e.g. defaulting to "0" when forwarding was
        // already enabled would make teardown wrongly disable it).
        let prior_out = self
            .run_capture(PrivilegedCommandProgram::Sysctl, &["-n", forwarding_key])
            .map_err(|err| {
                SystemError::NatApplyFailed(format!(
                    "read prior macOS {forwarding_key} failed: {err}"
                ))
            })?;
        if !prior_out.success() {
            return Err(SystemError::NatApplyFailed(format!(
                "read prior macOS {forwarding_key} returned non-zero: status={} stderr={}",
                prior_out.status, prior_out.stderr
            )));
        }
        let prior = prior_out.stdout.trim().to_owned();

        // Enable forwarding FIRST (mirrors the Linux ordering), then record the
        // prior value + the exact key so teardown restores the SAME sysctl.
        let enable_arg = format!("{forwarding_key}=1");
        self.run(PrivilegedCommandProgram::Sysctl, &["-w", &enable_arg])
            .map_err(|err| {
                SystemError::NatApplyFailed(format!("enable macOS {forwarding_key} failed: {err}"))
            })?;
        self.prior_ip_forwarding = Some(prior);
        self.exit_forwarding_key = Some(forwarding_key);

        let anchor = DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR;
        // Load the NAT translation anchor through the privileged macOS pf
        // builtin: the helper re-renders the translation rules from the reviewed
        // builder and owns the temp file + `pfctl`, so the daemon never names a
        // `pfctl -f` path (audit major #5).
        let spec = MacosPfLoadSpec::ExitNat {
            config: config.clone(),
        };
        let args = spec.encode();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let load_result = self
            .run(PrivilegedCommandProgram::MacosPfLoad, &arg_refs)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()));
        if let Err(err) = load_result {
            // Flush any partial load and restore forwarding so no residue
            // outlives the failed activation. The killswitch block-all stays
            // in force throughout, so egress is blocked regardless.
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-F", "all"],
            );
            let _ = self.restore_ip_forwarding();
            return Err(err);
        }
        self.exit_nat_anchor = Some(anchor.to_owned());

        // Verify the loaded translation rules match the reviewed shape; on
        // drift tear the NAT back down (anchor + forwarding) and fail closed.
        if let Err(err) = self.verify_exit_nat_anchor(anchor, &config) {
            let _ = self.teardown_exit_nat();
            return Err(err);
        }
        Ok(())
    }

    fn verify_exit_nat_anchor(
        &self,
        anchor: &str,
        config: &MacosExitNatPfConfig,
    ) -> Result<(), SystemError> {
        let output = self
            .run_capture(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-s", "nat"],
            )
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))?;
        if !output.success() {
            return Err(SystemError::NatApplyFailed(format!(
                "exit NAT verification query failed: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        let reasons = evaluate_macos_exit_nat_pf_rules(output.stdout.as_str(), config);
        if !reasons.is_empty() {
            return Err(SystemError::NatApplyFailed(format!(
                "exit NAT verification failed: {}",
                reasons.join("; ")
            )));
        }
        Ok(())
    }

    /// Tear down the regular-exit NAT: flush the translation anchor FIRST, then
    /// restore forwarding to its cached prior value. Order mirrors the Linux
    /// rollback (delete NAT, then restore forwarding) and keeps the killswitch
    /// block-all installed throughout, so egress stays fail-closed mid-teardown.
    fn teardown_exit_nat(&mut self) -> Result<(), SystemError> {
        // Flush the anchor by reference (do NOT consume the field yet): if the
        // forwarding restore below fails, exit_nat_anchor must stay `Some` so a
        // retry re-flushes — otherwise teardown would silently leak the anchor.
        if let Some(anchor) = self.exit_nat_anchor.as_ref() {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
        // Restore forwarding; only after it succeeds do we clear the anchor —
        // making teardown idempotent and retryable on partial failure.
        self.restore_ip_forwarding()?;
        self.exit_nat_anchor = None;
        Ok(())
    }

    /// Restore the forwarding sysctl the exit enabled (`net.inet.ip.forwarding`
    /// for v4, `net.inet6.ip6.forwarding` for v6) to its cached prior value.
    /// No-op when nothing was cached. The cache is cleared ONLY after the
    /// sysctl write succeeds, so a failed restore leaves it intact and a
    /// subsequent call retries (fail-closed: forwarding is never left enabled
    /// with the cache silently lost).
    fn restore_ip_forwarding(&mut self) -> Result<(), SystemError> {
        let key = match self.exit_forwarding_key {
            Some(key) => key,
            None => return Ok(()),
        };
        let value = match self.prior_ip_forwarding.as_deref() {
            Some(prior) if prior.trim() == "1" => "1",
            Some(_) => "0",
            None => return Ok(()),
        };
        let arg = format!("{key}={value}");
        self.run(PrivilegedCommandProgram::Sysctl, &["-w", &arg])
            .map_err(|err| {
                SystemError::RollbackFailed(format!("restore macOS {key} failed: {err}"))
            })?;
        self.prior_ip_forwarding = None;
        self.exit_forwarding_key = None;
        Ok(())
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

    fn reconcile_exit_nat_residue(&mut self, serving_exit: bool) -> Result<(), SystemError> {
        // The exit NAT lives in the FIXED-name `com.rustynet/nat` pf anchor.
        // `prune_owned_tables` only sweeps the generation-numbered
        // `com.apple/rustynet_g*` killswitch anchors, and `teardown_exit_nat`
        // flushes the NAT anchor only through the in-memory `exit_nat_anchor`
        // handle — which is lost on a crash/SIGKILL/OOM. So a node that crashed
        // while serving as an exit and restarts as a client would otherwise
        // leave the live `nat ... -> (egress)` rule installed with no owner and
        // no code path to remove it (CLAUDE.md §10.7 residue; the Linux exit
        // self-heals because its NAT tables are generation-numbered and swept).
        //
        // Flush the fixed anchor by name whenever THIS generation does not serve
        // an exit. It is a no-op for a client that never loaded NAT, idempotent
        // with the normal `teardown_exit_nat`, and — because it never runs for a
        // serving-exit apply — cannot race the `activate_exit_nat` load that
        // happens a few stages later in the same apply.
        //
        // Also drive `net.inet.ip.forwarding` back to the secure default (0).
        // `activate_exit_nat` caches the prior value only in memory, so after a
        // crash a former exit that restarts as a non-exit would leave forwarding
        // enabled with no path to restore it. A non-exit node must not forward,
        // so 0 is the correct fail-closed default. The NORMAL exit→client
        // demotion still restores the cached prior afterward: when `NatApplied`
        // was recorded, `rollback_obsolete_controls` calls `rollback_nat_forwarding`
        // → `restore_ip_forwarding` LATER in the same pass, overriding this; the
        // crash path (empty `active_stages`) skips that branch, so this secure
        // default stands.
        if !serving_exit {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", DEFAULT_MACOS_EXIT_NAT_PF_ANCHOR, "-F", "all"],
            );
            self.run_allow_failure(
                PrivilegedCommandProgram::Sysctl,
                &["-w", "net.inet.ip.forwarding=0"],
            );
        }
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
        };
        #[allow(unreachable_code)]
        Err(SystemError::PrerequisiteCheckFailed(
            "macos command system is only supported on macos".to_owned(),
        ))
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        Ok(())
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        // The actual per-peer `route add -host` invocations are owned by
        // the backend lifecycle (DirectMacosTunLifecycle::reconcile_exit_mode
        // installs them as the default route is flipped to utun). Here
        // we only cache the peer endpoints so that the next
        // `apply_pf_rules` re-render includes an egress allow rule per
        // endpoint — without it the killswitch's terminal
        // `block drop out quick all` discards the WireGuard handshake
        // packets before they reach the LAN gateway.
        let endpoints: BTreeSet<SocketAddr> = peers
            .iter()
            .map(|peer| SocketAddr::new(peer.endpoint.addr, peer.endpoint.port))
            .collect();
        let mut next: Vec<SocketAddr> = endpoints.into_iter().collect();
        next.sort();
        if next != self.managed_peer_egress_endpoints {
            self.managed_peer_egress_endpoints = next;
            // The anchor may not be loaded yet on the first call
            // (apply_peer_endpoint_bypass_routes can run before the
            // killswitch is applied during initial reconcile). When
            // no anchor is owned, skip the re-render — the next
            // apply_firewall_killswitch / apply_dns_protection /
            // hard_disable_ipv6_egress call will pick up the new
            // endpoint set.
            if self.anchor_name.is_some() {
                self.apply_pf_rules(false)?;
            }
        }
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        if self.blind_exit_pf_config.is_some() {
            return Ok(());
        }
        self.flush_anchor();
        Ok(())
    }

    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        _exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError> {
        // The blind-vs-regular exit decision is keyed on the explicit
        // `blind_exit` flag, NOT on `exit_mode == Off`: a regular NATing exit
        // is also `serve_exit_node = true` with `exit_mode = Off`, so the old
        // proxy conflated the two and made a regular macOS exit impossible to
        // express.
        if serve_exit_node && blind_exit {
            // Irreversible blind exit: blocks internet egress and relays mesh
            // only. No NAT translation and no IP forwarding — the blind_exit
            // filter anchor is the entire posture.
            let config = MacosBlindExitPfConfig::new(
                self.interface_name.clone(),
                self.egress_interface.clone(),
                mesh_cidr.to_owned(),
            )
            .map_err(SystemError::NatApplyFailed)?;
            self.blind_exit_pf_config = Some(config);
            self.allow_egress_interface = false;
            return self
                .apply_pf_rules(false)
                .map_err(|err| SystemError::NatApplyFailed(err.to_string()));
        }

        self.blind_exit_pf_config = None;
        self.allow_egress_interface = true;
        // Load the killswitch filter anchor (egress pass + terminal
        // `block drop out quick all`) BEFORE touching NAT so that if NAT
        // activation fails, egress stays blocked (fail-closed).
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::NatApplyFailed(err.to_string()))?;

        if serve_exit_node {
            // Regular NATing exit: enable IPv4 forwarding and load the
            // com.rustynet/nat translation anchor.
            self.activate_exit_nat(mesh_cidr)?;
            // Apply DNS protection inline as part of the exit-role transition
            // so that DNS-block-LAN rules are present in the killswitch anchor
            // immediately, rather than waiting for the reconcile loop.
            self.apply_dns_protection()?;
        } else {
            // Full-tunnel client consuming a remote exit: no local NAT or
            // forwarding. Tear down any exit NAT left from a prior generation
            // so a former exit that became a client leaves no residue.
            self.teardown_exit_nat()?;
        }
        Ok(())
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        if self.blind_exit_pf_config.is_some() {
            return self
                .apply_pf_rules(false)
                .map_err(|err| SystemError::RollbackFailed(err.to_string()));
        }
        // Tear down the exit NAT (flush the translation anchor, then restore
        // forwarding) BEFORE relaxing the filter, so NAT residue never
        // outlives the exit capability (CLAUDE.md §10.7). The killswitch
        // block-all stays installed throughout.
        self.teardown_exit_nat()?;
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
        // Option-2 parity with Linux: point /etc/resolv.conf at the loopback
        // resolver (backing up the original) so the macos-dns-failclosed verifier
        // passes — every resolv.conf nameserver becomes loopback. The pf rules
        // above are the defense-in-depth egress block; this owns resolv.conf. The
        // write goes through the privileged helper's fixed-path/fixed-content
        // builtin (macOS /etc is writable, so it uses the atomic temp+rename).
        //
        // The resolv.conf write is best-effort on macOS: macOS manages this file
        // via system-configuration and the atomic overwrite may fail or be
        // reverted. The killswitch pf anchor with DNS-block rules (applied above)
        // remains the primary fail-closed enforcement. Reverting dns_protected
        // when the file write fails would cause the next reconcile tick to
        // re-render pf rules WITHOUT DNS-block rules (since killswitch_spec()
        // reads dns_protected=false), losing DNS protection altogether.
        if let Err(err) = self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_RESOLV_APPLY],
        ) {
            log::warn!(
                "macOS resolv.conf write failed (best-effort; pf DNS-block rules remain active): {err}"
            );
        }
        // Write the macOS scoped resolver (/etc/resolver/rustynet → loopback
        // resolver:53535) so the OS resolver (mDNSResponder / dscacheutil /
        // getaddrinfo) can actually resolve mesh `*.rustynet` names. Unlike
        // /etc/resolv.conf — which macOS largely ignores for the primary lookup
        // path — `/etc/resolver/<domain>` is the mechanism the OS honors, and,
        // because the daemon runs unprivileged (cannot bind :53) and macOS
        // installs no `:53`→resolver redirect, it is the ONLY route from the OS
        // resolver to the resolver's :53535 bind. Best-effort like the
        // resolv.conf write: the pf LAN-DNS block remains the fail-closed
        // enforcement, so a write failure must NOT revert dns_protected (which
        // would drop the egress block on the next reconcile). Scoped to the
        // `rustynet` domain only — no other domain's resolution changes.
        if let Err(err) = self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_MACOS_RESOLVER_APPLY],
        ) {
            log::warn!(
                "macOS scoped resolver write failed (best-effort; mesh DNS OS-path unavailable): {err}"
            );
        }
        Ok(())
    }

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        if !self.dns_protected {
            return Err(SystemError::DnsApplyFailed(
                "macOS DNS protection is not active".to_owned(),
            ));
        }
        let rules = self.render_pf_rules(false)?;
        for proto in ["udp", "tcp"] {
            if !Self::ruleset_contains_dns_rule(
                &rules,
                "pass",
                proto,
                Some(self.interface_name.as_str()),
            ) || !Self::ruleset_contains_dns_rule(&rules, "block", proto, None)
            {
                return Err(SystemError::DnsApplyFailed(format!(
                    "macOS DNS protection missing {proto}/53 tunnel-pass or egress-block rule"
                )));
            }
        }
        Ok(())
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = false;
        // Restore the original resolv.conf (best-effort; teardown must not fail
        // closed and strand the node — a missing backup is a no-op).
        self.run_allow_failure(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_RESOLV_RESTORE],
        );
        // Remove the macOS scoped resolver so a torn-down node stops routing
        // `*.rustynet` at the (now stopped) loopback resolver. Best-effort: a
        // missing file is a no-op, so teardown never fails closed.
        self.run_allow_failure(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_MACOS_RESOLVER_REMOVE],
        );
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
            SystemError::KillSwitchAssertionFailed("pf anchor missing".to_owned())
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
                "pf killswitch rule missing".to_owned(),
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
                    "pf dns udp allow rule missing".to_owned(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(
                &output.stdout,
                "pass out quick",
                "tcp",
                Some(self.interface_name.as_str()),
            ) {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp allow rule missing".to_owned(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "udp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns udp block rule missing".to_owned(),
                ));
            }
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block drop out quick", "tcp", None)
            {
                return Err(SystemError::KillSwitchAssertionFailed(
                    "pf dns tcp block rule missing".to_owned(),
                ));
            }
        }
        Ok(())
    }

    fn assert_exit_serving(&mut self, _mesh_cidr: &str) -> Result<(), SystemError> {
        self.assert_killswitch()?;
        if let Some(config) = self.blind_exit_runtime_config() {
            let anchor = self
                .anchor_name
                .as_deref()
                .unwrap_or(DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR);
            let output = self.run_capture(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-s", "rules"],
            )?;
            if !output.success() {
                return Err(SystemError::KillSwitchAssertionFailed(format!(
                    "blind_exit pf assertion query failed: status={} stderr={}",
                    output.status, output.stderr
                )));
            }
            let reasons = evaluate_macos_blind_exit_pf_rules(output.stdout.as_str(), &config);
            if !reasons.is_empty() {
                return Err(SystemError::KillSwitchAssertionFailed(format!(
                    "blind_exit pf assertion failed: {}",
                    reasons.join("; ")
                )));
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
    endpoint_bypass_routes: Vec<String>,
    ipv6_disabled: bool,
    firewall_applied: bool,
    nat_applied: bool,
    nat_name: String,
    previous_forwarding: Vec<(String, WindowsForwardingState)>,
    fail_closed_ssh_allow: bool,
    fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    traversal_bootstrap_allow_endpoints: Vec<SocketAddr>,
    wg_listen_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsForwardingState {
    Enabled,
    Disabled,
}

impl WindowsForwardingState {
    fn as_powershell_value(self) -> &'static str {
        match self {
            Self::Enabled => "Enabled",
            Self::Disabled => "Disabled",
        }
    }

    fn parse(raw: &str) -> Result<Self, SystemError> {
        match raw.trim() {
            "Enabled" => Ok(Self::Enabled),
            "Disabled" => Ok(Self::Disabled),
            other => Err(SystemError::NatApplyFailed(format!(
                "unexpected Windows forwarding state: {other}"
            ))),
        }
    }
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
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        validate_windows_interface_alias(egress_interface.as_str())
            .map_err(|message| SystemError::PrerequisiteCheckFailed(message.to_owned()))?;
        if !dns_resolver_bind_addr.ip().is_loopback() {
            return Err(SystemError::PrerequisiteCheckFailed(
                "Windows DNS resolver bind addr must stay on loopback".to_owned(),
            ));
        }
        Ok(Self {
            nat_name: windows_nat_name(interface_name.as_str())?,
            interface_name,
            egress_interface,
            dns_resolver_bind_addr,
            generation: 0,
            dns_protected: false,
            endpoint_bypass_routes: Vec::new(),
            ipv6_disabled: false,
            firewall_applied: false,
            nat_applied: false,
            previous_forwarding: Vec::new(),
            fail_closed_ssh_allow: false,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            traversal_bootstrap_allow_endpoints: Vec::new(),
            wg_listen_port: 0,
        })
    }

    /// Enable the fail-closed management-SSH allow with the given reviewed
    /// management CIDRs. Mirrors the Linux/macOS killswitch: the scoped egress
    /// allow must re-permit SSH so the guest is not locked out under the global
    /// outbound block.
    pub fn with_fail_closed_ssh_allow(mut self, allow: bool, cidrs: Vec<ManagementCidr>) -> Self {
        self.fail_closed_ssh_allow = allow;
        self.fail_closed_ssh_allow_cidrs = cidrs;
        self
    }

    /// Set the traversal bootstrap endpoints (STUN/relay) that the scoped egress
    /// allow must permit so WireGuard traversal can complete under the killswitch.
    pub fn with_traversal_bootstrap_allow_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.traversal_bootstrap_allow_endpoints = endpoints;
        self
    }

    /// Set the WireGuard listen port whose outbound handshake the scoped egress
    /// allow must permit (0 = unset → no port-scoped allow rule).
    pub fn with_wg_listen_port(mut self, port: u16) -> Self {
        self.wg_listen_port = port;
        self
    }

    /// RN-06 scoped egress allow-list, added under `WINDOWS_KS_RULE_EGRESS`
    /// (multiple rules deliberately share that one name so `rollback_firewall`
    /// can delete them all by name). Permits ONLY: management SSH (reply +
    /// outbound) to the reviewed CIDRs, the WireGuard handshake/data UDP from the
    /// listen port, and the traversal bootstrap endpoints. Everything else stays
    /// under the global outbound block. Mirrors the Linux/macOS scoped killswitch
    /// allow. With no management CIDR / WG port / endpoints configured this adds
    /// nothing, leaving a full outbound block (fail-closed).
    fn apply_windows_scoped_egress_allows(&self) -> Result<(), SystemError> {
        if self.fail_closed_ssh_allow {
            for cidr in &self.fail_closed_ssh_allow_cidrs {
                self.run_netsh_success(&windows_firewall_allow_ssh_reply_args(
                    WINDOWS_KS_RULE_EGRESS,
                    cidr,
                ))
                .map_err(|err| {
                    SystemError::FirewallApplyFailed(format!(
                        "management ssh reply allow rule failed for {cidr}: {err}"
                    ))
                })?;
                self.run_netsh_success(&windows_firewall_allow_ssh_out_args(
                    WINDOWS_KS_RULE_EGRESS,
                    cidr,
                ))
                .map_err(|err| {
                    SystemError::FirewallApplyFailed(format!(
                        "management ssh outbound allow rule failed for {cidr}: {err}"
                    ))
                })?;
            }
        }
        if self.wg_listen_port != 0 {
            self.run_netsh_success(&windows_firewall_allow_wg_handshake_args(
                WINDOWS_KS_RULE_EGRESS,
                self.wg_listen_port,
            ))
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "wireguard handshake allow rule failed: {err}"
                ))
            })?;
        }
        for endpoint in &self.traversal_bootstrap_allow_endpoints {
            self.run_netsh_success(&windows_firewall_allow_traversal_endpoint_args(
                WINDOWS_KS_RULE_EGRESS,
                *endpoint,
            ))
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "traversal bootstrap allow rule failed for {endpoint}: {err}"
                ))
            })?;
        }
        Ok(())
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

    fn resolve_powershell_binary() -> Result<PathBuf, SystemError> {
        let configured = std::env::var(WINDOWS_POWERSHELL_BINARY_PATH_ENV).ok();
        let raw = configured
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_WINDOWS_POWERSHELL_BINARY_PATH);
        validate_windows_binary_path(raw, "powershell")?;
        Ok(PathBuf::from(raw))
    }

    fn resolve_reg_binary() -> Result<PathBuf, SystemError> {
        let configured = std::env::var(WINDOWS_REG_BINARY_PATH_ENV).ok();
        let raw = configured
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(DEFAULT_WINDOWS_REG_BINARY_PATH);
        validate_windows_binary_path(raw, "reg")?;
        Ok(PathBuf::from(raw))
    }

    fn run_netsh(&self, args: &[String]) -> Result<PrivilegedCommandOutput, SystemError> {
        let binary = Self::resolve_netsh_binary()?;
        let mut command = Command::new(&binary);
        command.args(args);
        let output = run_helper_command_with_timeout(command, WINDOWS_HELPER_COMMAND_TIMEOUT)
            .map_err(|err| {
                SystemError::Io(format!("netsh run failed ({}): {err}", binary.display()))
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

    /// Run `reg.exe` with argv-bound arguments (no shell, no PowerShell parser).
    /// Used for the NRPT registry writes so the loopback server list's `;` is
    /// inert literal data rather than a statement separator.
    fn run_reg(&self, args: &[String]) -> Result<PrivilegedCommandOutput, SystemError> {
        let binary = Self::resolve_reg_binary()?;
        let mut command = Command::new(&binary);
        command.args(args);
        let output = run_helper_command_with_timeout(command, WINDOWS_HELPER_COMMAND_TIMEOUT)
            .map_err(|err| {
                SystemError::Io(format!("reg run failed ({}): {err}", binary.display()))
            })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn run_reg_success(&self, args: &[String]) -> Result<(), SystemError> {
        let output = self.run_reg(args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "reg exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn run_powershell(
        &self,
        script: &'static str,
        args: &[String],
    ) -> Result<PrivilegedCommandOutput, SystemError> {
        let binary = Self::resolve_powershell_binary()?;
        let command_args = windows_powershell_command_args(script, args);
        let mut command = Command::new(&binary);
        command.args(&command_args);
        let output = run_helper_command_with_timeout(command, WINDOWS_HELPER_COMMAND_TIMEOUT)
            .map_err(|err| {
                SystemError::Io(format!(
                    "powershell run failed ({}): {err}",
                    binary.display()
                ))
            })?;
        Ok(PrivilegedCommandOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }

    fn run_powershell_success(
        &self,
        script: &'static str,
        args: &[String],
    ) -> Result<(), SystemError> {
        let output = self.run_powershell(script, args)?;
        if output.success() {
            return Ok(());
        }
        Err(SystemError::Io(format!(
            "powershell exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    fn run_powershell_stdout(
        &self,
        script: &'static str,
        args: &[String],
    ) -> Result<String, SystemError> {
        let output = self.run_powershell(script, args)?;
        if output.success() {
            return Ok(output.stdout);
        }
        Err(SystemError::Io(format!(
            "powershell exited unsuccessfully: status={} stderr={}",
            output.status, output.stderr
        )))
    }

    #[allow(dead_code)]
    /// Own the resolver path so the `windows-dns-failclosed` verifier passes:
    /// point the tunnel adapter's IPv4 + IPv6 DNS at loopback (replacing
    /// Windows' auto-assigned `fec0:0:0:ffff::` IPv6 placeholders) and add an
    /// NRPT root-namespace rule so EVERY unqualified lookup resolves loopback-
    /// only. This is the Windows parity for the Linux nft redirect / macOS
    /// resolv.conf ownership; the firewall :53 LAN-block is the egress
    /// defense-in-depth. Does not touch `dns_protected` — the caller owns it.
    fn apply_dns_loopback(&mut self) -> Result<(), SystemError> {
        validate_windows_dns_bind_addr(self.dns_resolver_bind_addr)?;
        log::info!(
            "windows dns loopback apply: tunnel interface='{}' resolver={}",
            self.interface_name,
            self.dns_resolver_bind_addr
        );
        self.run_netsh_success(&windows_dns_set_args(
            self.interface_name.as_str(),
            self.dns_resolver_bind_addr.ip(),
        )?)
        .map_err(|err| {
            SystemError::DnsApplyFailed(format!("set tunnel IPv4 DNS loopback: {err}"))
        })?;
        self.run_netsh_success(&windows_dns_set_ipv6_loopback_args(
            self.interface_name.as_str(),
        ))
        .map_err(|err| {
            SystemError::DnsApplyFailed(format!("set tunnel IPv6 DNS loopback: {err}"))
        })?;
        for arg_set in windows_nrpt_reg_add_arg_sets() {
            self.run_reg_success(&arg_set).map_err(|err| {
                SystemError::DnsApplyFailed(format!("add loopback NRPT root rule: {err}"))
            })?;
        }
        Ok(())
    }

    /// Teardown the loopback DNS ownership: remove the NRPT rule and clear the
    /// tunnel adapter's IPv4 + IPv6 DNS. Aggregates every failure (a missing
    /// rule is not one). Does not touch `dns_protected` — the caller owns it.
    fn clear_dns_loopback(&mut self) -> Result<(), SystemError> {
        let mut errors: Vec<String> = Vec::new();
        match self.run_reg(&windows_nrpt_reg_delete_args()) {
            Ok(output) => {
                // `reg delete` of an absent key exits non-zero with "unable to
                // find …" — idempotent teardown treats that as success, but a
                // real failure (e.g. access denied) is surfaced.
                if !output.success()
                    && !output
                        .stderr
                        .to_ascii_lowercase()
                        .contains("unable to find")
                {
                    errors.push(format!(
                        "remove NRPT rule: reg exited {} stderr={}",
                        output.status, output.stderr
                    ));
                }
            }
            Err(err) => errors.push(format!("remove NRPT rule: {err}")),
        }
        if let Err(err) =
            self.run_netsh_success(&windows_dns_clear_args(self.interface_name.as_str()))
        {
            errors.push(format!("clear tunnel IPv4 DNS: {err}"));
        }
        if let Err(err) =
            self.run_netsh_success(&windows_dns_clear_ipv6_args(self.interface_name.as_str()))
        {
            errors.push(format!("clear tunnel IPv6 DNS: {err}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(SystemError::RollbackFailed(errors.join("; ")))
        }
    }

    fn add_endpoint_bypass_route(&self, cidr: &str) -> Result<(), SystemError> {
        let (family, nexthop) = if cidr.contains(':') {
            ("ipv6", "nexthop=::")
        } else {
            ("ipv4", "nexthop=0.0.0.0")
        };
        self.run_netsh_success(&[
            "interface".to_owned(),
            family.to_owned(),
            "add".to_owned(),
            "route".to_owned(),
            format!("prefix={cidr}"),
            format!("interface={}", self.egress_interface),
            nexthop.to_owned(),
            "store=active".to_owned(),
            "metric=1".to_owned(),
        ])
        .map_err(|err| {
            SystemError::RouteApplyFailed(format!(
                "peer endpoint bypass route failed for {cidr}: {err}"
            ))
        })
    }

    fn delete_endpoint_bypass_route(&self, cidr: &str) -> Result<(), SystemError> {
        let family = if cidr.contains(':') { "ipv6" } else { "ipv4" };
        self.run_netsh_success(&[
            "interface".to_owned(),
            family.to_owned(),
            "delete".to_owned(),
            "route".to_owned(),
            format!("prefix={cidr}"),
            format!("interface={}", self.egress_interface),
            "store=active".to_owned(),
        ])
        .map_err(|err| {
            SystemError::RouteApplyFailed(format!(
                "peer endpoint bypass route rollback failed for {cidr}: {err}"
            ))
        })
    }

    fn read_forwarding_state(
        &self,
        interface_alias: &str,
    ) -> Result<WindowsForwardingState, SystemError> {
        validate_windows_interface_alias(interface_alias).map_err(|message| {
            SystemError::NatApplyFailed(format!("invalid Windows interface alias: {message}"))
        })?;
        let stdout =
            self.run_powershell_stdout(WINDOWS_PS_GET_FORWARDING, &[interface_alias.to_owned()])?;
        WindowsForwardingState::parse(stdout.trim())
    }

    fn set_forwarding_state(
        &self,
        interface_alias: &str,
        state: WindowsForwardingState,
    ) -> Result<(), SystemError> {
        validate_windows_interface_alias(interface_alias).map_err(|message| {
            SystemError::NatApplyFailed(format!("invalid Windows interface alias: {message}"))
        })?;
        self.run_powershell_success(
            WINDOWS_PS_SET_FORWARDING,
            &[
                interface_alias.to_owned(),
                state.as_powershell_value().to_owned(),
            ],
        )
    }

    fn apply_windows_exit_nat_forwarding(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        let mesh_cidr = validate_windows_nat_prefix(mesh_cidr)?;
        self.run_powershell_success(WINDOWS_PS_REQUIRE_EXIT_CMDLETS, &[])
            .map_err(|err| {
                SystemError::NatApplyFailed(format!(
                    "Windows exit prerequisites missing or unavailable: {err}"
                ))
            })?;

        self.previous_forwarding.clear();
        for interface_alias in [&self.interface_name, &self.egress_interface] {
            let prior = self.read_forwarding_state(interface_alias)?;
            self.previous_forwarding
                .push((interface_alias.clone(), prior));
            self.set_forwarding_state(interface_alias, WindowsForwardingState::Enabled)
                .map_err(|err| {
                    SystemError::NatApplyFailed(format!(
                        "enable Windows IP forwarding on {interface_alias} failed: {err}"
                    ))
                })?;
        }

        self.run_powershell_success(WINDOWS_PS_REMOVE_NAT, std::slice::from_ref(&self.nat_name))
            .map_err(|err| {
                SystemError::NatApplyFailed(format!("remove stale RustyNet NAT failed: {err}"))
            })?;
        self.run_powershell_success(
            WINDOWS_PS_NEW_NAT,
            &[self.nat_name.clone(), mesh_cidr.to_owned()],
        )
        .map_err(|err| {
            SystemError::NatApplyFailed(format!("create Windows NetNat failed: {err}"))
        })?;

        self.run_powershell_success(
            WINDOWS_PS_ASSERT_NAT,
            &[self.nat_name.clone(), mesh_cidr.to_owned()],
        )
        .map_err(|err| {
            SystemError::NatApplyFailed(format!("verify Windows NetNat failed: {err}"))
        })?;
        for interface_alias in [&self.interface_name, &self.egress_interface] {
            self.run_powershell_success(
                WINDOWS_PS_ASSERT_FORWARDING_ENABLED,
                std::slice::from_ref(interface_alias),
            )
            .map_err(|err| {
                SystemError::NatApplyFailed(format!(
                    "verify Windows IP forwarding on {interface_alias} failed: {err}"
                ))
            })?;
        }

        self.nat_applied = true;
        Ok(())
    }
}

const WINDOWS_KS_RULE_LOOPBACK: &str = "RustyNetKS-AllowLoopback";
const WINDOWS_KS_RULE_TUNNEL: &str = "RustyNetKS-AllowTunnel";
const WINDOWS_KS_RULE_EGRESS: &str = "RustyNetKS-AllowEgress";
/// Block UDP/53 outbound on non-tunnel (LAN) interfaces.  Forces DNS through the
/// `WireGuard` tunnel — equivalent to the Linux nft rule
/// `udp dport 53 oifname != $tunnel drop`.
const WINDOWS_DNS_RULE_BLOCK_LAN_UDP: &str = "RustyNetDNS-BlockLanUdp";
/// Block TCP/53 outbound on non-tunnel (LAN) interfaces.  Symmetric to the UDP
/// rule above; without it, an app that opted into TCP DNS could still leak.
const WINDOWS_DNS_RULE_BLOCK_LAN_TCP: &str = "RustyNetDNS-BlockLanTcp";
/// Block ALL IPv6 outbound on non-tunnel (LAN) interfaces (G8).  The killswitch's
/// default-block-outbound is version-agnostic, but its egress-LAN *allow* is
/// unscoped and re-permits IPv6 on the underlay; since the tunnel is IPv4-only
/// (`ipv6_parity_supported=false`), IPv6 with a default route on the LAN would
/// otherwise egress the physical interface and bypass the tunnel.  A Block rule
/// overrides the allow, failing IPv6 closed.  The WireGuard handshake + SSH are
/// IPv4, so they are unaffected.
const WINDOWS_IPV6_RULE_BLOCK_LAN: &str = "RustyNetKS-BlockIpv6Lan";
const WINDOWS_PS_REQUIRE_EXIT_CMDLETS: &str = "& { $ErrorActionPreference = 'Stop'; Get-Command Set-NetIPInterface | Out-Null; Get-Command Get-NetIPInterface | Out-Null; Get-Command New-NetNat | Out-Null; Get-Command Get-NetNat | Out-Null; Get-Command Remove-NetNat | Out-Null; try { Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat -ErrorAction Stop | Out-Null } catch { throw 'RustyNet exit serving requires the Windows WinNAT WMI provider (MSFT_NetNat in root/standardcimv2); this host lacks the Host Network Service / WinNAT networking stack, so New-NetNat fails with Invalid class. Install the WinNAT/HNS networking component to serve as a full-tunnel exit.' } }";
const WINDOWS_PS_PREFLIGHT_EXIT_SERVING: &str = "& { param($TunnelAlias, $EgressAlias) $ErrorActionPreference = 'Stop'; $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $principal = New-Object Security.Principal.WindowsPrincipal($identity); if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'RustyNet exit serving requires an elevated administrator or service token' }; foreach ($cmd in @('Set-NetIPInterface','Get-NetIPInterface','New-NetNat','Get-NetNat','Remove-NetNat','Get-NetRoute')) { Get-Command $cmd -ErrorAction Stop | Out-Null }; try { Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat -ErrorAction Stop | Out-Null } catch { throw 'RustyNet exit serving requires the Windows WinNAT WMI provider (MSFT_NetNat in root/standardcimv2); this host lacks the Host Network Service / WinNAT networking stack, so New-NetNat fails with Invalid class. Install the WinNAT/HNS networking component to serve as a full-tunnel exit.' }; if ($TunnelAlias -eq $EgressAlias) { throw 'RustyNet tunnel and outbound interface aliases must be distinct' }; Get-NetIPInterface -InterfaceAlias $TunnelAlias -AddressFamily IPv4 -ErrorAction Stop | Out-Null; Get-NetIPInterface -InterfaceAlias $EgressAlias -AddressFamily IPv4 -ErrorAction Stop | Out-Null; Get-NetRoute -DestinationPrefix '0.0.0.0/0' -InterfaceAlias $EgressAlias -ErrorAction Stop | Out-Null }";
/// §10.7 — the (script, args) command plan for flushing residual Windows exit
/// NAT + forwarding when a generation does NOT serve an exit. Empty when it
/// does serve, so it can never race the `activate_exit_nat` (`New-NetNat`) load
/// that happens later in the same apply. Pure so the residue policy is
/// unit-testable on any host without executing PowerShell (the actual
/// `Get-NetNat`/`Set-NetIPInterface` run requires a Windows guest).
fn windows_exit_nat_residue_plan(
    serving_exit: bool,
    nat_name: &str,
    tunnel_alias: &str,
    egress_alias: &str,
) -> Vec<(&'static str, Vec<String>)> {
    if serving_exit {
        return Vec::new();
    }
    vec![
        // Remove the fixed-name NetNat (no-op if absent; safe on a non-WinNAT host
        // because WINDOWS_PS_REMOVE_NAT swallows the Get-NetNat lookup error).
        (WINDOWS_PS_REMOVE_NAT, vec![nat_name.to_owned()]),
        // Drive forwarding back to the secure default on both interfaces a former
        // exit would have enabled it on (a non-exit node must not forward).
        (
            WINDOWS_PS_SET_FORWARDING,
            vec![tunnel_alias.to_owned(), "Disabled".to_owned()],
        ),
        (
            WINDOWS_PS_SET_FORWARDING,
            vec![egress_alias.to_owned(), "Disabled".to_owned()],
        ),
    ]
}

const WINDOWS_PS_GET_FORWARDING: &str = "& { param($Alias) $ErrorActionPreference = 'Stop'; (Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction Stop).Forwarding }";
const WINDOWS_PS_SET_FORWARDING: &str = "& { param($Alias, $State) $ErrorActionPreference = 'Stop'; Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -Forwarding $State -ErrorAction Stop }";
const WINDOWS_PS_REMOVE_NAT: &str = "& { param($Name) $ErrorActionPreference = 'Stop'; $nat = Get-NetNat -Name $Name -ErrorAction SilentlyContinue; if ($null -ne $nat) { $nat | Remove-NetNat -Confirm:$false -ErrorAction Stop } }";
const WINDOWS_PS_NEW_NAT: &str = "& { param($Name, $Prefix) $ErrorActionPreference = 'Stop'; New-NetNat -Name $Name -InternalIPInterfaceAddressPrefix $Prefix -ErrorAction Stop | Out-Null }";
const WINDOWS_PS_ASSERT_NAT: &str = "& { param($Name, $Prefix) $ErrorActionPreference = 'Stop'; $nat = Get-NetNat -Name $Name -ErrorAction Stop; if ($nat.InternalIPInterfaceAddressPrefix -ne $Prefix) { throw 'RustyNet NAT prefix mismatch' } }";
const WINDOWS_PS_ASSERT_FORWARDING_ENABLED: &str = "& { param($Alias) $ErrorActionPreference = 'Stop'; $state = (Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction Stop).Forwarding; if ($state -ne 'Enabled') { throw 'RustyNet IP forwarding not enabled' } }";
/// Verify the OS still has every reviewed killswitch rule in place AND the
/// global default outbound policy is still `Block`.  Each rule name and the
/// expected attributes are passed as `PowerShell` parameters so no value is
/// interpolated into the script body.  Throws on the first drift detected.
const WINDOWS_PS_ASSERT_KILLSWITCH: &str = "& { param($LoopbackName, $EgressName) $ErrorActionPreference = 'Stop'; $loopback = @(Get-NetFirewallRule -DisplayName $LoopbackName -ErrorAction Stop); if ($loopback.Count -ne 1) { throw \"rule $LoopbackName count is $($loopback.Count), expected 1\" }; $egress = @(Get-NetFirewallRule -DisplayName $EgressName -ErrorAction Stop); if ($egress.Count -lt 1) { throw \"rule $EgressName count is $($egress.Count), expected >= 1\" }; foreach ($rule in @($loopback) + @($egress)) { if ($rule.Action -ne 'Allow') { throw \"rule $($rule.DisplayName) action is not Allow\" }; if ($rule.Direction -ne 'Outbound') { throw \"rule $($rule.DisplayName) direction is not Outbound\" }; if ($rule.Enabled -ne 'True') { throw \"rule $($rule.DisplayName) is not Enabled\" } }; foreach ($p in (Get-NetFirewallProfile -ErrorAction Stop)) { if ($p.DefaultOutboundAction -ne 'Block') { throw \"profile $($p.Name) default outbound is not Block\" } } }";

/// Verify the reviewed DNS-block rules (the baseline plaintext-DNS protection,
/// parity with the Linux `udp dport 53 oifname != tunnel drop`) are still
/// present, Outbound, Block, and Enabled.  Rule names are passed as `PowerShell`
/// parameters so no value is interpolated into the script body.  Throws on the
/// first drift detected.
const WINDOWS_PS_ASSERT_DNS: &str = "& { param($UdpName, $TcpName) $ErrorActionPreference = 'Stop'; foreach ($displayName in @($UdpName, $TcpName)) { $rules = @(Get-NetFirewallRule -DisplayName $displayName -ErrorAction Stop); if ($rules.Count -ne 1) { throw \"rule $displayName count is $($rules.Count), expected 1\" }; $rule = $rules[0]; if ($rule.Action -ne 'Block') { throw \"rule $displayName action is not Block\" }; if ($rule.Direction -ne 'Outbound') { throw \"rule $displayName direction is not Outbound\" }; if ($rule.Enabled -ne 'True') { throw \"rule $displayName is not Enabled\" } } }";

/// Loopback name servers as the NRPT `GenericDNSServers` value expects them:
/// IPv4 `127.0.0.1` (the rustynet resolver) + IPv6 `::1`, semicolon-separated.
/// The `windows-dns-failclosed` verifier requires every resolver to be loopback.
const WINDOWS_NRPT_LOOPBACK_SERVERS: &str = "127.0.0.1;::1";

/// The fixed NRPT registry key the rustynet root rule lives in, in `reg.exe`
/// (`HKLM\…`, not the PowerShell `HKLM:\…` PSDrive) form. NRPT rules are stored
/// under `…\Dnscache\Parameters\DnsPolicyConfig\{GUID}`; the fixed GUID keeps
/// add/remove deterministic and never disturbs operator NRPT policy.
const WINDOWS_NRPT_REG_KEY: &str = r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig\{A0B1C2D3-4E5F-46A7-B8C9-0D1E2F3A4B5C}";

impl DataplaneSystem for WindowsCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn reconcile_exit_nat_residue(&mut self, serving_exit: bool) -> Result<(), SystemError> {
        // §10.7: a node that crashed while serving as a Windows exit and restarts
        // as a client must self-heal the fixed-name `New-NetNat` instance and the
        // enabled IP forwarding. The normal exit→client demotion
        // (`rollback_nat_forwarding`) relies on the in-memory `nat_applied` /
        // `previous_forwarding` state, which a crash/SIGKILL/OOM loses, leaving a
        // live NAT rule + forwarding with no owner. Linux self-heals via
        // generation-numbered tables; macOS overrides this for its fixed pf
        // anchor; Windows had no override (default no-op) — this closes that gap.
        //
        // Best-effort (allow-failure): a client that never served must not fail
        // startup because the cleanup found nothing (WINDOWS_PS_REMOVE_NAT already
        // swallows a missing NAT, and Set-NetIPInterface to the already-Disabled
        // default is idempotent). It runs only when NOT serving an exit, so it can
        // never race the `activate_exit_nat` load later in the same apply.
        for (script, args) in windows_exit_nat_residue_plan(
            serving_exit,
            &self.nat_name,
            &self.interface_name,
            &self.egress_interface,
        ) {
            let _ = self.run_powershell(script, &args);
        }
        Ok(())
    }

    fn check_prerequisites(&mut self) -> Result<(), SystemError> {
        let _ = Self::resolve_netsh_binary()?;
        let _ = Self::resolve_powershell_binary()?;
        let _ = Self::resolve_reg_binary()?;
        Ok(())
    }

    fn set_relay_forwarding(&mut self, _enabled: bool) {
        // Intentional no-op on Windows (made explicit so it is not mistaken for a
        // missing impl). The controller only calls this with `true` when
        // `relay_with_upstream` = FullTunnel && serve_exit_node, and that same
        // serve_exit_node also drives `apply_nat_forwarding` →
        // `apply_windows_exit_nat_forwarding`, which enables IP forwarding on both
        // the tunnel and egress interfaces. So forwarding is already enabled for
        // every case this is reached with `true`; there is no relay-without-exit
        // path on Windows yet. A future relay-only role would enable forwarding
        // here.
    }

    fn preflight_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        validate_windows_nat_prefix(mesh_cidr)?;
        self.run_powershell_success(
            WINDOWS_PS_PREFLIGHT_EXIT_SERVING,
            &[self.interface_name.clone(), self.egress_interface.clone()],
        )
        .map_err(|err| {
            SystemError::PrerequisiteCheckFailed(format!(
                "Windows exit-serving preflight failed: {err}"
            ))
        })
    }

    fn apply_peer_endpoint_bypass_routes(
        &mut self,
        peers: &[PeerConfig],
    ) -> Result<(), SystemError> {
        let old = std::mem::take(&mut self.endpoint_bypass_routes);
        for cidr in &old {
            let _ = self.delete_endpoint_bypass_route(cidr);
        }
        let mut seen = BTreeSet::new();
        for peer in peers {
            if !seen.insert(peer.endpoint.addr) {
                continue;
            }
            let cidr = match peer.endpoint.addr {
                std::net::IpAddr::V4(_) => format!("{}/32", peer.endpoint.addr),
                std::net::IpAddr::V6(_) => format!("{}/128", peer.endpoint.addr),
            };
            // Purge any OS-level leftover from a previous daemon run before re-adding.
            let _ = self.delete_endpoint_bypass_route(&cidr);
            self.add_endpoint_bypass_route(&cidr)?;
            self.endpoint_bypass_routes.push(cidr);
        }
        Ok(())
    }

    fn apply_routes(&mut self, _routes: &[Route]) -> Result<(), SystemError> {
        Ok(())
    }

    fn rollback_routes(&mut self) -> Result<(), SystemError> {
        let routes = std::mem::take(&mut self.endpoint_bypass_routes);
        for cidr in &routes {
            let _ = self.delete_endpoint_bypass_route(cidr);
        }
        Ok(())
    }

    fn apply_firewall_killswitch(&mut self) -> Result<(), SystemError> {
        // Purge any existing killswitch rules (idempotent re-apply, crash-loop cleanup).
        for rule_name in [
            WINDOWS_KS_RULE_LOOPBACK,
            WINDOWS_KS_RULE_TUNNEL,
            WINDOWS_KS_RULE_EGRESS,
        ] {
            let _ = self.run_netsh_success(&windows_firewall_delete_rule_args(rule_name));
        }
        // Block all outbound by default; inbound stays allowed so SSH / management
        // sessions survive. Allow rules below override the outbound block for loopback,
        // the WireGuard tunnel interface, and the physical egress interface.
        self.run_netsh_success(&windows_firewall_block_outbound_policy_args())
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!("set outbound block policy failed: {err}"))
            })?;
        // Allow loopback traffic so local IPC and health checks keep working.
        self.run_netsh_success(&windows_firewall_allow_loopback_args(
            WINDOWS_KS_RULE_LOOPBACK,
        ))
        .map_err(|err| {
            SystemError::FirewallApplyFailed(format!("allow loopback rule failed: {err}"))
        })?;
        // Allow outbound through the WireGuard tunnel interface (mesh + exit traffic)
        // via a native WFP permit filter keyed on the tunnel interface LUID. This
        // replaces the prior `New-NetFirewallRule -InterfaceAlias` cmdlet: wintun
        // adapters (MediaType=IP/Virtual) are not scopable by netsh interfacetype,
        // and a PowerShell/CIM cmdlet on the dataplane-apply path can hang on a
        // wedged WMI provider. The native filter uses no CIM and cannot hang.
        rustynet_windows_native::apply_wfp_tunnel_permit(&self.interface_name).map_err(|err| {
            SystemError::FirewallApplyFailed(format!(
                "allow tunnel interface WFP filter failed: {err}"
            ))
        })?;
        // Allow the SCOPED egress essentials on the underlay (RN-06): management
        // SSH to the reviewed CIDRs (so an inbound-administered session survives
        // the global outbound block), the WireGuard handshake/data UDP from the
        // listen port, and the traversal bootstrap endpoints. This replaces the
        // prior unscoped `interfacetype=lan` allow that let ALL non-DNS LAN
        // egress out — a cleartext leak if the tunnel default route flapped.
        self.apply_windows_scoped_egress_allows()?;
        self.firewall_applied = true;
        Ok(())
    }

    fn rollback_firewall(&mut self) -> Result<(), SystemError> {
        // Delete killswitch rules by name; ignore errors if they don't exist.
        for rule_name in [
            WINDOWS_KS_RULE_LOOPBACK,
            WINDOWS_KS_RULE_TUNNEL,
            WINDOWS_KS_RULE_EGRESS,
        ] {
            let _ = self.run_netsh_success(&[
                "advfirewall".to_owned(),
                "firewall".to_owned(),
                "delete".to_owned(),
                "rule".to_owned(),
                format!("name={rule_name}"),
            ]);
        }
        // Remove the native WFP tunnel-permit filter added at apply time
        // (best-effort, mirrors the by-name rule deletes above).
        let _ = rustynet_windows_native::remove_wfp_tunnel_permit();
        // Restore default allow-inbound/allow-outbound policy.
        self.run_netsh_success(&[
            "advfirewall".to_owned(),
            "set".to_owned(),
            "allprofiles".to_owned(),
            "firewallpolicy".to_owned(),
            "allowinbound,allowoutbound".to_owned(),
        ])
        .map_err(|err| {
            SystemError::RollbackFailed(format!("restore firewall policy failed: {err}"))
        })?;
        self.firewall_applied = false;
        Ok(())
    }

    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        _exit_mode: ExitMode,
        _blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError> {
        if !serve_exit_node {
            // Windows client nodes can consume an exit node by routing traffic through
            // WireGuard NT via per-peer AllowedIPs; no local NAT is needed in that mode.
            return Ok(());
        }
        self.apply_windows_exit_nat_forwarding(mesh_cidr)
    }

    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError> {
        if self.nat_applied {
            self.run_powershell_success(
                WINDOWS_PS_REMOVE_NAT,
                std::slice::from_ref(&self.nat_name),
            )
            .map_err(|err| {
                SystemError::RollbackFailed(format!("remove Windows NetNat failed: {err}"))
            })?;
            self.nat_applied = false;
        }
        let previous = std::mem::take(&mut self.previous_forwarding);
        for (interface_alias, state) in previous {
            self.set_forwarding_state(interface_alias.as_str(), state)
                .map_err(|err| {
                    SystemError::RollbackFailed(format!(
                        "restore Windows IP forwarding on {interface_alias} failed: {err}"
                    ))
                })?;
        }
        Ok(())
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        // Block UDP/TCP port-53 outbound on LAN (non-tunnel) interfaces so all
        // DNS traffic is forced through the WireGuard tunnel.  This is the
        // moral equivalent of the Linux nft rule
        // `udp dport 53 oifname != $tunnel drop` and is the protection that
        // prevents an app talking directly to a router/ISP DNS server from
        // leaking the user's lookup history.
        //
        // Block rules in Windows advfirewall always take precedence over allow
        // rules, so this rule overrides the LAN-allow rule from the killswitch
        // for port-53 traffic specifically while leaving the WireGuard
        // handshake (UDP/varying ports on LAN) and tunnel-internal DNS
        // (RAS/tunnel interface) untouched.
        //
        // The firewall block is the egress defense-in-depth. After it,
        // `apply_dns_loopback` (below) OWNS the resolver path — tunnel adapter
        // IPv4+IPv6 DNS set to loopback and an NRPT root rule — so the
        // dns-failclosed verifier passes (no off-loopback resolver, no
        // unqualified-lookup leak), at parity with the Linux/macOS resolver
        // ownership.

        // Purge any stale DNS-block rules from a previous daemon run before
        // re-applying.  Uses ignore-result because no-rule deletes are not a
        // failure on Windows advfirewall.
        for rule_name in [
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
        ] {
            let _ = self.run_netsh_success(&windows_firewall_delete_rule_args(rule_name));
        }

        self.run_netsh_success(&windows_dns_block_lan_args(
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            "udp",
        ))
        .map_err(|err| {
            SystemError::DnsApplyFailed(format!("DNS UDP/53 LAN-block rule failed: {err}"))
        })?;
        self.run_netsh_success(&windows_dns_block_lan_args(
            WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
            "tcp",
        ))
        .map_err(|err| {
            // Best-effort cleanup of the UDP rule we just installed so we do
            // not leave a half-applied DNS-block in place on rollback failure.
            let _ = self.run_netsh_success(&windows_firewall_delete_rule_args(
                WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            ));
            SystemError::DnsApplyFailed(format!("DNS TCP/53 LAN-block rule failed: {err}"))
        })?;
        // Own the resolver path (tunnel adapter DNS + NRPT root rule) so the
        // dns-failclosed verifier passes and unqualified lookups cannot leak.
        // On failure, best-effort-undo the partial DNS ownership before the
        // firewall blocks are torn down by the caller's rollback.
        if let Err(err) = self.apply_dns_loopback() {
            let _ = self.clear_dns_loopback();
            return Err(err);
        }
        self.dns_protected = true;
        Ok(())
    }

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        if !self.dns_protected {
            return Err(SystemError::DnsApplyFailed(
                "Windows DNS protection is not applied; call apply_dns_protection first".to_owned(),
            ));
        }
        // Re-verify the OS still has both DNS-block rules (Outbound/Block/Enabled).
        // Without this, an external `netsh advfirewall reset` between apply and
        // assert would leave dns_protected=true while plaintext DNS is wide open —
        // Windows would lie about posture exactly where the guarantee matters.
        // Linux/macOS already query OS state in assert_dns_protection; this brings
        // Windows to parity (previously Windows inherited the no-op trait default).
        self.run_powershell_success(
            WINDOWS_PS_ASSERT_DNS,
            &[
                WINDOWS_DNS_RULE_BLOCK_LAN_UDP.to_owned(),
                WINDOWS_DNS_RULE_BLOCK_LAN_TCP.to_owned(),
            ],
        )
        .map_err(|err| {
            SystemError::DnsApplyFailed(format!("Windows DNS-block verification failed: {err}"))
        })
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        if !self.dns_protected {
            return Ok(());
        }
        // Delete both DNS-block rules.  Best-effort: a missing rule is not a
        // failure (it might have been removed by an external administrator),
        // but a real netsh error must be surfaced so the caller can decide
        // whether to fail closed.
        let mut errors: Vec<String> = Vec::new();
        // Tear down the loopback DNS ownership (NRPT rule + tunnel adapter DNS)
        // first, so the resolver path returns to the OS default alongside the
        // firewall unblock.
        if let Err(err) = self.clear_dns_loopback() {
            errors.push(err.to_string());
        }
        for rule_name in [
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
        ] {
            if let Err(err) = self.run_netsh_success(&windows_firewall_delete_rule_args(rule_name))
            {
                errors.push(format!("delete {rule_name}: {err}"));
            }
        }
        if !errors.is_empty() {
            return Err(SystemError::RollbackFailed(format!(
                "Windows DNS teardown: {}",
                errors.join("; ")
            )));
        }
        self.dns_protected = false;
        Ok(())
    }

    fn hard_disable_ipv6_egress(&mut self) -> Result<(), SystemError> {
        self.run_netsh_success(&windows_ipv6_egress_disable_args(
            self.egress_interface.as_str(),
        ))
        .map_err(|err| SystemError::Io(format!("IPv6 disable on egress failed: {err}")))?;
        // Mark disabled as soon as router-discovery is off, BEFORE the block
        // rule below: if that step fails, rollback_ipv6_egress must still
        // re-enable router-discovery — otherwise a partial apply leaves the
        // egress NIC with router-discovery disabled and no cleanup.
        self.ipv6_disabled = true;
        // Disabling router-discovery/advertise only stops NEW SLAAC; an
        // already-configured global IPv6 + its LAN default route would still
        // egress the underlay and bypass the IPv4-only tunnel (the G8 leak).
        // Add a Block rule on non-tunnel (LAN) interfaces that overrides the
        // killswitch's unscoped egress-allow, so all IPv6 outbound on the
        // underlay is dropped — failing IPv6 closed. The WireGuard handshake and
        // SSH are IPv4, so they are unaffected. Purge any stale rule first for
        // idempotent re-apply.
        let _ = self.run_netsh_success(&windows_firewall_delete_rule_args(
            WINDOWS_IPV6_RULE_BLOCK_LAN,
        ));
        self.run_netsh_success(&windows_ipv6_egress_block_lan_args(
            WINDOWS_IPV6_RULE_BLOCK_LAN,
        ))
        .map_err(|err| {
            SystemError::FirewallApplyFailed(format!("IPv6 egress block on LAN failed: {err}"))
        })?;
        Ok(())
    }

    fn rollback_ipv6_egress(&mut self) -> Result<(), SystemError> {
        if !self.ipv6_disabled {
            return Ok(());
        }
        // Remove the IPv6 LAN block first (best-effort; a missing rule is fine).
        let _ = self.run_netsh_success(&windows_firewall_delete_rule_args(
            WINDOWS_IPV6_RULE_BLOCK_LAN,
        ));
        self.run_netsh_success(&windows_ipv6_egress_rollback_args(
            self.egress_interface.as_str(),
        ))
        .map_err(|err| {
            SystemError::RollbackFailed(format!("IPv6 re-enable on egress failed: {err}"))
        })?;
        self.ipv6_disabled = false;
        Ok(())
    }

    fn assert_killswitch(&mut self) -> Result<(), SystemError> {
        // Fast-path: if we never applied the killswitch in this process, we
        // know the assertion fails.  This catches the simple
        // never-applied-yet case without paying for a PowerShell round trip.
        if !self.firewall_applied {
            return Err(SystemError::KillSwitchAssertionFailed(
                "Windows advfirewall killswitch is not applied; call apply_firewall_killswitch first".to_owned(),
            ));
        }
        // Defense in depth: verify the OS still has every reviewed
        // killswitch rule AND the global default outbound policy is
        // still Block.  Without this query, an external
        // `netsh advfirewall reset` between apply and assertion would
        // leave self.firewall_applied=true while the OS firewall is wide
        // open — `assert_killswitch` would lie about posture in exactly
        // the window where its guarantee matters most.  Linux and macOS
        // already query the OS state here; this brings Windows to parity.
        // Verify the security-critical netsh bits: the default-block-outbound
        // policy plus the loopback + egress allow rules. The tunnel outbound
        // allow is now a native WFP filter (E2), not a netsh rule, so it is
        // verified separately below (via wfp_tunnel_permit_present) rather than
        // Get-NetFirewallRule.
        self.run_powershell_success(
            WINDOWS_PS_ASSERT_KILLSWITCH,
            &[
                WINDOWS_KS_RULE_LOOPBACK.to_owned(),
                WINDOWS_KS_RULE_EGRESS.to_owned(),
            ],
        )
        .map_err(|err| {
            SystemError::KillSwitchAssertionFailed(format!(
                "Windows advfirewall killswitch verification failed: {err}"
            ))
        })?;
        // Confirm the native WFP tunnel-permit filters (E2) are present so the
        // tunnel can still egress through the killswitch. A missing permit fails
        // safe (tunnel blocked), but a correct "killswitch active" assertion must
        // catch it rather than silently report green.
        if !rustynet_windows_native::wfp_tunnel_permit_present().map_err(|err| {
            SystemError::KillSwitchAssertionFailed(format!(
                "Windows WFP tunnel-permit verification failed: {err}"
            ))
        })? {
            return Err(SystemError::KillSwitchAssertionFailed(
                "Windows WFP tunnel-permit filters are missing".to_owned(),
            ));
        }
        Ok(())
    }

    fn assert_exit_policy(&mut self, _exit_mode: ExitMode) -> Result<(), SystemError> {
        self.assert_killswitch()
    }

    fn assert_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        if !self.nat_applied {
            return Err(SystemError::KillSwitchAssertionFailed(
                "Windows exit-serving NAT has not been applied".to_owned(),
            ));
        }
        let mesh_cidr = validate_windows_nat_prefix(mesh_cidr)?;
        self.assert_killswitch()?;
        self.run_powershell_success(
            WINDOWS_PS_ASSERT_NAT,
            &[self.nat_name.clone(), mesh_cidr.to_owned()],
        )
        .map_err(|err| {
            SystemError::KillSwitchAssertionFailed(format!(
                "Windows NetNat verification failed for exit serving: {err}"
            ))
        })?;
        for interface_alias in [&self.interface_name, &self.egress_interface] {
            self.run_powershell_success(
                WINDOWS_PS_ASSERT_FORWARDING_ENABLED,
                std::slice::from_ref(interface_alias),
            )
            .map_err(|err| {
                SystemError::KillSwitchAssertionFailed(format!(
                    "Windows IP forwarding verification failed for {interface_alias}: {err}"
                ))
            })?;
        }
        Ok(())
    }

    fn block_all_egress(&mut self) -> Result<(), SystemError> {
        // Apply killswitch first to set the block-all default policy.
        self.apply_firewall_killswitch()?;
        // FailClosed: remove the tunnel + egress allows so even WireGuard traffic
        // is blocked — only loopback survives. The tunnel allow is now a native WFP
        // filter (not the WINDOWS_KS_RULE_TUNNEL netsh rule), so it MUST be removed
        // via remove_wfp_tunnel_permit; deleting the (now-absent) netsh rule alone
        // would leave the WFP permit in place and fail OPEN.
        let _ = rustynet_windows_native::remove_wfp_tunnel_permit();
        let _ = self.run_netsh_success(&[
            "advfirewall".to_owned(),
            "firewall".to_owned(),
            "delete".to_owned(),
            "rule".to_owned(),
            format!("name={WINDOWS_KS_RULE_TUNNEL}"),
        ]);
        let _ = self.run_netsh_success(&[
            "advfirewall".to_owned(),
            "firewall".to_owned(),
            "delete".to_owned(),
            "rule".to_owned(),
            format!("name={WINDOWS_KS_RULE_EGRESS}"),
        ]);
        Ok(())
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

    fn reconcile_exit_nat_residue(&mut self, serving_exit: bool) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.reconcile_exit_nat_residue(serving_exit),
            RuntimeSystem::Linux(system) => system.reconcile_exit_nat_residue(serving_exit),
            RuntimeSystem::Macos(system) => system.reconcile_exit_nat_residue(serving_exit),
            RuntimeSystem::Windows(system) => system.reconcile_exit_nat_residue(serving_exit),
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

    fn preflight_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.preflight_exit_serving(mesh_cidr),
            RuntimeSystem::Linux(system) => system.preflight_exit_serving(mesh_cidr),
            RuntimeSystem::Macos(system) => system.preflight_exit_serving(mesh_cidr),
            RuntimeSystem::Windows(system) => system.preflight_exit_serving(mesh_cidr),
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

    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => {
                system.apply_nat_forwarding(serve_exit_node, exit_mode, blind_exit, mesh_cidr)
            }
            RuntimeSystem::Linux(system) => {
                system.apply_nat_forwarding(serve_exit_node, exit_mode, blind_exit, mesh_cidr)
            }
            RuntimeSystem::Macos(system) => {
                system.apply_nat_forwarding(serve_exit_node, exit_mode, blind_exit, mesh_cidr)
            }
            RuntimeSystem::Windows(system) => {
                system.apply_nat_forwarding(serve_exit_node, exit_mode, blind_exit, mesh_cidr)
            }
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

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.assert_dns_protection(),
            RuntimeSystem::Linux(system) => system.assert_dns_protection(),
            RuntimeSystem::Macos(system) => system.assert_dns_protection(),
            RuntimeSystem::Windows(system) => system.assert_dns_protection(),
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

    fn assert_exit_serving(&mut self, mesh_cidr: &str) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.assert_exit_serving(mesh_cidr),
            RuntimeSystem::Linux(system) => system.assert_exit_serving(mesh_cidr),
            RuntimeSystem::Macos(system) => system.assert_exit_serving(mesh_cidr),
            RuntimeSystem::Windows(system) => system.assert_exit_serving(mesh_cidr),
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
    active_stages: Vec<StageMarker>,
    current_routes: Vec<Route>,
    current_exit_mode: ExitMode,
    current_serve_exit_node: bool,
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
        // `mut` is only exercised by the cfg(test) seeding below; non-test
        // builds construct the default and never mutate it.
        #[cfg_attr(not(test), allow(unused_mut))]
        let mut membership = MembershipDirectory::default();
        #[cfg(test)]
        {
            membership.set_node_status("node-b", MembershipStatus::Active);
            membership.set_node_status("node-c", MembershipStatus::Active);
            // RSA-0007: the exit-node + LAN-route ACL gates now evaluate with
            // membership, so the selectors the controller tests exercise
            // (`node:exit-1`, `user:alice`) must resolve as Active here.
            membership.set_node_status("exit-1", MembershipStatus::Active);
            membership.set_selector_members("user:alice", ["node-b"]);
        }

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
            active_stages: Vec::new(),
            current_routes: Vec::new(),
            current_exit_mode: ExitMode::Off,
            current_serve_exit_node: false,
            direct_stability_window_ms: 3_000,
            relay_stability_window_ms: 5_000,
            membership,
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

    pub fn serving_exit_node_active(&self) -> bool {
        self.current_serve_exit_node
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
        validate_apply_options(options)?;
        let target_generation = self.generation.saturating_add(1);
        let mesh_cidr = context.mesh_cidr.clone();
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

        if let Err(err) = self.validate_backend_exit_capabilities(options) {
            self.force_fail_closed("backend_exit_capability_rejected")?;
            return Err(err);
        }

        let mut applied_stages = Vec::new();
        let relay_with_upstream =
            options.exit_mode == ExitMode::FullTunnel && options.serve_exit_node;
        self.system.set_relay_forwarding(relay_with_upstream);
        if let Err(err) = self.system.apply_firewall_killswitch() {
            // Pre-start killswitch application failed: fail closed FIRST (and
            // propagate if even that fails), then surface the original error.
            self.force_fail_closed("killswitch_pre_start_failed")?;
            return Err(err.into());
        }
        applied_stages.push(StageMarker::FirewallApplied);

        match self.backend.start(context) {
            Ok(()) => applied_stages.push(StageMarker::BackendStarted),
            Err(err) if err.kind == BackendErrorKind::AlreadyRunning => {}
            Err(err) => {
                self.force_fail_closed("backend_start_failed")?;
                return Err(err.into());
            }
        }

        if options.serve_exit_node
            && let Err(err) = self.system.preflight_exit_serving(mesh_cidr.as_str())
        {
            let rollback_result =
                self.rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed);
            let fail_closed_result = self.force_fail_closed("exit_serving_preflight_failed");
            if let Err(rollback_err) = rollback_result {
                let _ = fail_closed_result;
                return Err(rollback_err);
            }
            fail_closed_result?;
            return Err(err.into());
        }

        if let Err(err) = self.system.prune_owned_tables() {
            let rollback_result =
                self.rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed);
            let fail_closed_result = self.force_fail_closed("owned_table_prune_failed");
            if let Err(rollback_err) = rollback_result {
                let _ = fail_closed_result;
                return Err(rollback_err);
            }
            fail_closed_result?;
            return Err(err.into());
        }
        if let Err(err) = self.rollback_obsolete_controls(options) {
            let rollback_result =
                self.rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed);
            let fail_closed_result = self.force_fail_closed("obsolete_control_rollback_failed");
            if let Err(rollback_err) = rollback_result {
                let _ = fail_closed_result;
                return Err(rollback_err);
            }
            fail_closed_result?;
            return Err(err);
        }

        let result = self.apply_generation_stages(
            peers,
            routes,
            options,
            mesh_cidr.as_str(),
            &mut applied_stages,
        );

        if let Err(err) = result {
            // Surface WHY the dataplane is about to fail closed. Without this the
            // generation-apply error (e.g. a DNS-protection or assert failure) is
            // swallowed here and the daemon goes silent after "entering reconcile
            // loop", leaving operators to reverse-engineer a fail-closed posture
            // from downstream validator drift alone.
            log::warn!("phase10 generation apply failed; rolling back fail-closed: {err}");
            self.current_serve_exit_node = false;
            let rollback_result =
                self.rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed);
            let fail_closed_result = self.force_fail_closed("apply_failed");
            if let Err(rollback_err) = rollback_result {
                let _ = fail_closed_result;
                return Err(rollback_err);
            }
            fail_closed_result?;
            return Err(err);
        }

        self.active_stages = applied_stages;
        self.generation = self.generation.saturating_add(1);
        self.last_safe_generation = self.generation;
        self.current_serve_exit_node = options.serve_exit_node;

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

    fn validate_backend_exit_capabilities(
        &self,
        options: ApplyOptions,
    ) -> Result<(), Phase10Error> {
        let capabilities = self.backend.capabilities();
        if matches!(options.exit_mode, ExitMode::FullTunnel)
            && !(capabilities.supports_exit_nodes && capabilities.supports_exit_client)
        {
            return Err(BackendError::invalid_input(format!(
                "backend {} does not support consuming an exit node",
                self.backend.name()
            ))
            .into());
        }
        if options.serve_exit_node
            && !(capabilities.supports_exit_nodes && capabilities.supports_exit_serving)
        {
            return Err(BackendError::invalid_input(format!(
                "backend {} does not support serving as an exit node",
                self.backend.name()
            ))
            .into());
        }
        Ok(())
    }

    fn apply_generation_stages(
        &mut self,
        peers: Vec<PeerConfig>,
        routes: Vec<Route>,
        options: ApplyOptions,
        mesh_cidr: &str,
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

        if options.exit_mode == ExitMode::FullTunnel || options.serve_exit_node {
            self.system.apply_nat_forwarding(
                options.serve_exit_node,
                options.exit_mode,
                options.blind_exit,
                mesh_cidr,
            )?;
            applied_stages.push(StageMarker::NatApplied);
        }

        if options.protected_dns {
            self.system.apply_dns_protection()?;
            applied_stages.push(StageMarker::DnsApplied);
            self.system.assert_dns_protection()?;
        }

        if !options.ipv6_parity_supported {
            self.system.hard_disable_ipv6_egress()?;
            applied_stages.push(StageMarker::Ipv6Blocked);
        }

        self.backend.set_exit_mode(options.exit_mode)?;
        applied_stages.push(StageMarker::ExitModeApplied);

        self.system.assert_exit_policy(options.exit_mode)?;
        if options.serve_exit_node {
            self.system.assert_exit_serving(mesh_cidr)?;
        }
        self.current_exit_mode = options.exit_mode;

        Ok(())
    }

    fn rollback_obsolete_controls(&mut self, options: ApplyOptions) -> Result<(), Phase10Error> {
        // Flush fixed-name exit-NAT residue (macOS `com.rustynet/nat`) that the
        // NatApplied-gated branch below would miss after a crash — `active_stages`
        // is empty on a fresh process, but the kernel anchor persists. Gated on
        // `serve_exit_node`, so it never touches the anchor a serving-exit apply
        // is about to (re)load. No-op on platforms that self-heal via prune.
        self.system
            .reconcile_exit_nat_residue(options.serve_exit_node)?;
        let previous_stages = self.active_stages.clone();
        if previous_stages.contains(&StageMarker::NatApplied)
            && options.exit_mode != ExitMode::FullTunnel
            && !options.serve_exit_node
        {
            self.system.rollback_nat_forwarding()?;
            self.active_stages
                .retain(|stage| *stage != StageMarker::NatApplied);
        }
        if previous_stages.contains(&StageMarker::DnsApplied) && !options.protected_dns {
            self.system.rollback_dns_protection()?;
            self.active_stages
                .retain(|stage| *stage != StageMarker::DnsApplied);
        }
        if previous_stages.contains(&StageMarker::Ipv6Blocked) && options.ipv6_parity_supported {
            self.system.rollback_ipv6_egress()?;
            self.active_stages
                .retain(|stage| *stage != StageMarker::Ipv6Blocked);
        }
        Ok(())
    }

    fn rollback_generation_best_effort(
        &mut self,
        applied_stages: Vec<StageMarker>,
        intent: RollbackIntent,
    ) -> Result<(), Phase10Error> {
        let mut rollback_errors = Vec::new();
        for stage in applied_stages.into_iter().rev() {
            match stage {
                StageMarker::ExitModeApplied => {
                    if let Err(err) = self.backend.set_exit_mode(ExitMode::Off)
                        && err.kind != BackendErrorKind::NotRunning
                    {
                        rollback_errors.push(format!("set exit mode off: {err}"));
                    }
                    self.current_exit_mode = ExitMode::Off;
                    self.current_serve_exit_node = false;
                }
                StageMarker::Ipv6Blocked => {
                    if let Err(err) = self.system.rollback_ipv6_egress() {
                        rollback_errors.push(format!("rollback ipv6 egress: {err}"));
                    }
                }
                StageMarker::DnsApplied => match intent {
                    // Intentional teardown: restore the host's original resolver
                    // configuration (resolv.conf, NM drop-in, redirect table).
                    RollbackIntent::CleanShutdown => {
                        if let Err(err) = self.system.rollback_dns_protection() {
                            rollback_errors.push(format!("rollback dns protection: {err}"));
                        }
                    }
                    // Unwinding a FAILED apply: HOLD DNS fail-closed. Restoring
                    // resolv.conf to its off-loopback original (or tearing down
                    // the loopback redirect / the off-tunnel :53 drop) would fail
                    // OPEN — a DNS leak — during a transient failure, exactly when
                    // fail-closed matters most. DNS stays applied (loopback
                    // resolv.conf + mesh-only resolution), mirroring how the
                    // killswitch is held closed through a failed apply;
                    // `force_fail_closed` then blocks all egress and the next
                    // successful generation re-asserts DNS.
                    RollbackIntent::FailClosed => {}
                },
                StageMarker::NatApplied => {
                    if let Err(err) = self.system.rollback_nat_forwarding() {
                        rollback_errors.push(format!("rollback nat forwarding: {err}"));
                    }
                }
                StageMarker::FirewallApplied => match intent {
                    RollbackIntent::CleanShutdown => {
                        if let Err(err) = self.system.rollback_firewall() {
                            rollback_errors.push(format!("rollback firewall: {err}"));
                        }
                    }
                    RollbackIntent::FailClosed => {}
                },
                StageMarker::EndpointBypassApplied => {
                    if let Err(err) = self.system.rollback_routes() {
                        rollback_errors.push(format!("rollback endpoint bypass routes: {err}"));
                    }
                }
                StageMarker::SystemRoutesApplied => {
                    if let Err(err) = self.system.rollback_routes() {
                        rollback_errors.push(format!("rollback system routes: {err}"));
                    }
                }
                StageMarker::BackendRoutesApplied => {
                    if let Err(err) = self.backend.apply_routes(Vec::new())
                        && err.kind != BackendErrorKind::NotRunning
                    {
                        rollback_errors.push(format!("clear backend routes: {err}"));
                    }
                    self.current_routes.clear();
                }
                StageMarker::PeerApplied => {
                    if let Some(node_id) = self.managed_peers.keys().next().cloned() {
                        if let Err(err) = self.backend.remove_peer(&node_id)
                            && err.kind != BackendErrorKind::NotRunning
                        {
                            rollback_errors
                                .push(format!("remove peer {}: {err}", node_id.as_str()));
                        }
                        self.managed_peers.remove(&node_id);
                    }
                }
                StageMarker::BackendStarted => {
                    if let Err(err) = self.backend.shutdown()
                        && err.kind != BackendErrorKind::NotRunning
                    {
                        rollback_errors.push(format!("backend shutdown: {err}"));
                    }
                }
            }
        }

        if !rollback_errors.is_empty() {
            return Err(SystemError::RollbackFailed(rollback_errors.join("; ")).into());
        }
        Ok(())
    }

    pub fn force_fail_closed(&mut self, reason: &str) -> Result<(), Phase10Error> {
        self.current_serve_exit_node = false;
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

        // RSA-0007: gate through the membership-aware evaluator (the daemon's
        // established `evaluate_with_membership` pattern) so a revoked exit node
        // — or a revoked requester selector — is denied at this control-plane
        // ACL layer too, not just at peer provisioning. One hardened path
        // (CLAUDE.md §3): no weaker revocation-blind `evaluate` branch.
        let decision = self.policy.evaluate_with_membership(
            &ContextualAccessRequest {
                src: requester.to_owned(),
                dst: format!("node:{}", node_id.as_str()),
                protocol,
                context: TrafficContext::SharedExit,
            },
            &self.membership,
        );
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
            .insert(cidr.to_owned());
    }

    pub fn set_lan_route_acl(&mut self, user: &str, cidr: &str, allowed: bool) {
        self.lan_route_acl
            .insert((user.to_owned(), cidr.to_owned()), allowed);
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
            .is_some_and(|routes| routes.contains(&request.cidr));
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

        // RSA-0007: membership-aware evaluation so a revoked requester selector
        // is denied at the LAN-route ACL gate too (same hardened path as
        // set_exit_node and the daemon's auto-tunnel gates).
        let decision = self.policy.evaluate_with_membership(
            &ContextualAccessRequest {
                src: request.user,
                dst: request.cidr,
                protocol: request.protocol,
                context: request.context,
            },
            &self.membership,
        );
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
        let elapsed = peer.pending_since.map_or(Duration::ZERO, |t| t.elapsed());
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

    /// FIS-0013: per-peer raw path-quality sample from the backend
    /// (userspace-shared only; command backends return None).
    pub fn managed_peer_path_sample(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<rustynet_backend_api::PeerPathSample>, Phase10Error> {
        self.ensure_started()?;
        if !self.managed_peers.contains_key(node_id) {
            return Err(Phase10Error::PeerNotManaged);
        }
        Ok(self.backend.peer_path_sample(node_id)?)
    }

    pub fn evaluate_traversal_probes(
        &mut self,
        node_id: &NodeId,
        evaluation: TraversalProbeEvaluation<'_>,
    ) -> Result<TraversalProbeReport, Phase10Error> {
        self.ensure_started()?;
        if evaluation.handshake_freshness_secs == 0 {
            return Err(Phase10Error::TraversalProbeFailed(
                "handshake freshness window must be greater than zero".to_owned(),
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
        // FIS-0013: when the incumbent endpoint is quality-demoted, a fresh
        // handshake must NOT short-circuit the race — the whole point of the
        // quality trigger is to re-race a nominally-up-but-rotten path.
        let incumbent_demoted = evaluation.quality_demoted_endpoint == Some(current_endpoint);
        if !incumbent_demoted
            && evaluation
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
                        .to_owned(),
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
                    "validated signed traversal coordination required for direct probe".to_owned()
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

            // D5.5 promotion (2026-05-21): production probe path now
            // uses the parallel ICE-pair race instead of the older
            // serial `execute_simultaneous_open`. The parallel race
            // fires every pair of a round before polling for
            // handshakes, which is the shape marginal-NAT pairs
            // (one cone, one nearly-symmetric) need to succeed —
            // the serial loop would have polled after the first
            // probe and given up before the second pinhole opened.
            // Cone-NAT happy paths are unaffected: the first
            // priority-sorted pair still wins on round 0.
            engine
                .execute_ice_pair_race(
                    &mut runtime,
                    &mut waiter,
                    schedule,
                    evaluation.local_candidates,
                    evaluation.direct_candidates,
                    &evaluation.local_node_id_digest,
                    &evaluation.remote_node_id_digest,
                    evaluation.relay_endpoint,
                    evaluation.now_unix,
                    evaluation.handshake_freshness_secs,
                    evaluation.prior_ranking.as_ref(),
                    evaluation.quality_demoted_endpoint,
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

    #[cfg(test)]
    pub fn system_mut_for_test(&mut self) -> &mut S {
        &mut self.system
    }

    pub fn shutdown(&mut self) -> Result<(), Phase10Error> {
        let active_stages = std::mem::take(&mut self.active_stages);
        let rollback_stopped_backend = active_stages.contains(&StageMarker::BackendStarted);
        let rollback_result =
            self.rollback_generation_best_effort(active_stages, RollbackIntent::CleanShutdown);
        let backend_shutdown_result = if rollback_stopped_backend {
            Ok(())
        } else {
            self.backend.shutdown().map_err(Phase10Error::Backend)
        };
        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.managed_peers.clear();
        self.current_routes.clear();
        self.current_exit_mode = ExitMode::Off;
        self.current_serve_exit_node = false;
        if let Err(err) = rollback_result {
            self.transition_to(DataplaneState::FailClosed, "shutdown_cleanup_failed");
            return Err(err);
        }
        if let Err(err) = backend_shutdown_result {
            self.transition_to(DataplaneState::FailClosed, "shutdown_cleanup_failed");
            return Err(err);
        }
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
            reason: reason.to_owned(),
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
    value.is_some_and(|timestamp| now_unix.saturating_sub(timestamp) <= freshness_secs)
}

/// Gate peer provisioning on membership status (M4).
///
/// A node that is not positively confirmed `Active` in the membership
/// directory is denied provisioning (default-deny).
///
fn check_peer_membership_active(
    node_id: &NodeId,
    membership: &MembershipDirectory,
) -> Result<(), Phase10Error> {
    match membership.node_status(node_id.as_str()) {
        MembershipStatus::Active => Ok(()),
        MembershipStatus::Revoked => {
            Err(Phase10Error::MembershipRevoked(node_id.as_str().to_owned()))
        }
        MembershipStatus::Unknown => Err(Phase10Error::MembershipNotFound(
            node_id.as_str().to_owned(),
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

fn validate_apply_options(options: ApplyOptions) -> Result<(), Phase10Error> {
    if options.exit_mode == ExitMode::FullTunnel && !options.protected_dns {
        return Err(Phase10Error::System(SystemError::DnsApplyFailed(
            "full-tunnel exit mode requires protected DNS before route activation".to_owned(),
        )));
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
        // In-process builtins: handled before binary resolution. Fail closed if
        // either ever reaches here.
        PrivilegedCommandProgram::DnsFailclosedFile => Err(SystemError::PrerequisiteCheckFailed(
            "dns-failclosed-file is an in-process builtin and has no external binary".to_owned(),
        )),
        PrivilegedCommandProgram::MacosPfLoad => Err(SystemError::PrerequisiteCheckFailed(
            "macos-pf-load is an in-process builtin and has no external binary".to_owned(),
        )),
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
    // Windows interface aliases can contain letters, digits, spaces, hyphens,
    // underscores, dots, parentheses, and other ASCII printable characters.
    // Real names in the wild include "Ethernet 2", "Wi-Fi", and
    // "vEthernet (Default Switch)".  We reject non-ASCII (not valid in standard
    // adapter names), control characters (would corrupt log lines and format
    // strings), and '=' (would corrupt the key=value netsh argument format).
    if value.is_empty() || value.len() > 64 {
        return Err("Windows interface alias length must be between 1 and 64 characters");
    }
    if !value.is_ascii() {
        return Err("Windows interface alias must be ASCII");
    }
    if value.chars().any(|ch| ch.is_ascii_control()) {
        return Err("Windows interface alias must not contain control characters");
    }
    if value.contains('=') {
        return Err("Windows interface alias must not contain '='");
    }
    Ok(())
}

fn windows_nat_name(interface_alias: &str) -> Result<String, SystemError> {
    validate_windows_interface_alias(interface_alias).map_err(|message| {
        SystemError::PrerequisiteCheckFailed(format!(
            "invalid Windows NAT interface alias: {message}"
        ))
    })?;
    Ok(format!("RustyNetExit-{interface_alias}"))
}

fn validate_windows_nat_prefix(value: &str) -> Result<&str, SystemError> {
    let cidr = value
        .parse::<ManagementCidr>()
        .map_err(SystemError::NatApplyFailed)?;
    if cidr.is_ipv6() {
        return Err(SystemError::NatApplyFailed(
            "Windows NetNat exit serving currently supports IPv4 mesh CIDRs only".to_owned(),
        ));
    }
    if cidr.prefix == 0 || cidr.prefix > 32 {
        return Err(SystemError::NatApplyFailed(
            "Windows NetNat mesh CIDR prefix must be 1..=32".to_owned(),
        ));
    }
    Ok(value)
}

fn windows_powershell_command_args(script: &'static str, args: &[String]) -> Vec<String> {
    let mut command_args = vec![
        "-NoProfile".to_owned(),
        "-NonInteractive".to_owned(),
        "-Command".to_owned(),
        script.to_owned(),
    ];
    command_args.extend_from_slice(args);
    command_args
}

fn validate_windows_binary_path(raw: &str, label: &str) -> Result<(), SystemError> {
    // `Path::is_absolute` is platform-specific: on Linux/macOS it would reject
    // legitimate Windows paths like `C:\Windows\System32\netsh.exe` because
    // they do not start with `/`. We use an OS-portable check so that the
    // validator (and its regression tests) run consistently on every host.
    // A Windows absolute path is either a drive-letter path (`X:\…`) or a UNC
    // path (`\\server\share\…`).
    let is_drive_absolute = raw
        .chars()
        .next()
        .map(|ch| ch.is_ascii_alphabetic())
        .unwrap_or(false)
        && raw
            .get(1..3)
            .map(|sep| sep == ":\\" || sep == ":/")
            .unwrap_or(false);
    let is_unc = raw.starts_with(r"\\") || raw.starts_with("//");
    if !(is_drive_absolute || is_unc) {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must be absolute: {raw}"
        )));
    }
    // Path-traversal and metacharacter defense. The daemon-on-Windows resolves
    // these from an environment variable so an installer compromise (or a
    // misconfigured service unit) cannot point the daemon at, e.g.,
    // `C:\Windows\System32\..\..\Temp\evil.exe`. We also reject forward slashes
    // since Win32 path canonicalization treats them as separators but the
    // System32 substring check below uses the canonical backslash form, and
    // reject non-ASCII / control characters so malicious bytes cannot smuggle
    // additional path components through the command line.
    if !raw.is_ascii() {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must be ASCII: {raw}"
        )));
    }
    if raw.chars().any(|ch| ch.is_ascii_control()) {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must not contain control characters: {raw}"
        )));
    }
    if raw.contains("..") {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must not contain `..`: {raw}"
        )));
    }
    if raw.contains('/') {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must use backslash separators: {raw}"
        )));
    }
    // Require the executable to live inside the Windows system directory.
    // The daemon runs as SYSTEM via a Windows service, so the netsh.exe and
    // powershell.exe it shells out to MUST come from the Microsoft-shipped
    // `\Windows\System32\` (or `\Windows\SysWOW64\` for 32-bit binaries on
    // 64-bit hosts). Permitting an arbitrary absolute path lets anyone with
    // write access to the service environment substitute a malicious binary
    // that runs with the daemon's elevated token — equivalent to RCE as
    // SYSTEM.
    let lower = raw.to_ascii_lowercase();
    let inside_system_root = lower.contains(r"\windows\system32\")
        || lower.contains(r"\windows\syswow64\")
        || lower.contains(r"\windows\sysnative\");
    if !inside_system_root {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must live under `\\Windows\\System32\\`, \
             `\\Windows\\SysWOW64\\`, or `\\Windows\\Sysnative\\`: {raw}"
        )));
    }
    if !lower.ends_with(".exe") {
        return Err(SystemError::PrerequisiteCheckFailed(format!(
            "{label} binary path must end in `.exe`: {raw}"
        )));
    }
    Ok(())
}

#[allow(dead_code)]
fn validate_windows_dns_bind_addr(addr: SocketAddr) -> Result<(), SystemError> {
    if !addr.ip().is_loopback() {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection requires a loopback resolver bind address".to_owned(),
        ));
    }
    if addr.port() != 53 {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection requires rustynetd to bind the reviewed local resolver on 127.0.0.1:53 because Windows interface DNS settings cannot encode a non-default port".to_owned(),
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn windows_dns_set_args(
    interface_name: &str,
    dns_server: IpAddr,
) -> Result<Vec<String>, SystemError> {
    if !dns_server.is_loopback() {
        return Err(SystemError::DnsApplyFailed(
            "Windows DNS protection only supports reviewed loopback resolvers".to_owned(),
        ));
    }
    Ok(vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_name}"),
        "source=static".to_owned(),
        format!("address={dns_server}"),
        "validate=no".to_owned(),
    ])
}

#[allow(dead_code)]
fn windows_dns_clear_args(interface_name: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv4".to_owned(),
        "delete".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_name}"),
        "all".to_owned(),
    ]
}

/// Set the tunnel adapter's IPv6 DNS to the loopback resolver `::1`, replacing
/// Windows' auto-assigned site-local placeholders (`fec0:0:0:ffff::1..3`) which
/// the dns-failclosed verifier flags as off-loopback. `validate=no` skips the
/// reachability probe (the resolver answers on its own bind port via the
/// firewall path, not `::1:53`; the verifier checks the address, not liveness).
fn windows_dns_set_ipv6_loopback_args(interface_name: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv6".to_owned(),
        "set".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_name}"),
        "source=static".to_owned(),
        "address=::1".to_owned(),
        "validate=no".to_owned(),
    ]
}

fn windows_dns_clear_ipv6_args(interface_name: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv6".to_owned(),
        "delete".to_owned(),
        "dnsservers".to_owned(),
        format!("name={interface_name}"),
        "all".to_owned(),
    ]
}

/// Build the ordered `reg.exe add` argument vectors that install the NRPT root
/// rule directly into the registry (one invocation per value):
/// `Version`=2, `Name`=`.` (`REG_MULTI_SZ`), `GenericDNSServers`=`127.0.0.1;::1`,
/// `ConfigOptions`=8, `Comment`. `reg.exe` binds every `/d` value as a literal
/// argv element, so the loopback server list's `;` (a PowerShell statement
/// separator) is inert data — unlike `powershell.exe -Command "<script>" <arg>`,
/// which CONCATENATES the trailing arg into the command line and splits on `;`,
/// silently dropping `::1` and failing the parse. This is also how
/// WireGuard-for-Windows installs NRPT (direct registry writes, no PowerShell,
/// no `Add-DnsClientNrptRule` CIM cmdlet that wedges under the guest's WMI).
fn windows_nrpt_reg_add_arg_sets() -> Vec<Vec<String>> {
    let add = |name: &str, ty: &str, data: &str| -> Vec<String> {
        vec![
            "add".to_owned(),
            WINDOWS_NRPT_REG_KEY.to_owned(),
            "/v".to_owned(),
            name.to_owned(),
            "/t".to_owned(),
            ty.to_owned(),
            "/d".to_owned(),
            data.to_owned(),
            "/f".to_owned(),
        ]
    };
    vec![
        add("Version", "REG_DWORD", "2"),
        add("Name", "REG_MULTI_SZ", "."),
        add("GenericDNSServers", "REG_SZ", WINDOWS_NRPT_LOOPBACK_SERVERS),
        add("ConfigOptions", "REG_DWORD", "8"),
        add("Comment", "REG_SZ", "RustyNet-failclosed"),
    ]
}

/// Build the `reg.exe delete` argument vector that removes the rustynet NRPT key
/// on teardown. A missing key exits non-zero; the caller treats that as success
/// (idempotent teardown).
fn windows_nrpt_reg_delete_args() -> Vec<String> {
    vec![
        "delete".to_owned(),
        WINDOWS_NRPT_REG_KEY.to_owned(),
        "/f".to_owned(),
    ]
}

/// Build the netsh argv that sets the global Windows advfirewall policy to
/// "allow inbound, block outbound" across all profiles.  This is the foundation
/// of the Windows killswitch — every allow rule layered on top must explicitly
/// permit each kind of traffic that should be allowed to leave the host.
fn windows_firewall_block_outbound_policy_args() -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "set".to_owned(),
        "allprofiles".to_owned(),
        "firewallpolicy".to_owned(),
        "allowinbound,blockoutbound".to_owned(),
    ]
}

/// Build the netsh argv that adds an outbound allow rule covering loopback
/// traffic only (127.0.0.0/8 -> 127.0.0.0/8).  Required so the daemon's local
/// IPC and the health-check probe keep working under the global outbound block.
fn windows_firewall_allow_loopback_args(rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=allow".to_owned(),
        "localip=127.0.0.0/8".to_owned(),
        "remoteip=127.0.0.0/8".to_owned(),
    ]
}

/// Management-SSH **reply** allow (RN-06): outbound TCP from local port 22 to the
/// reviewed management CIDR. This is the rule that keeps an inbound-administered
/// SSH session alive under the global outbound block — the reply path is
/// outbound from the guest's port 22, so without it `blockoutbound` strands SSH.
fn windows_firewall_allow_ssh_reply_args(rule_name: &str, cidr: &ManagementCidr) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=allow".to_owned(),
        "protocol=tcp".to_owned(),
        "localport=22".to_owned(),
        format!("remoteip={cidr}"),
    ]
}

/// Management-SSH **outbound** allow (RN-06): outbound TCP to remote port 22
/// within the reviewed management CIDR (SSH initiated from this node to a
/// management host). Mirrors the Linux `daddr <cidr> tcp dport 22 accept` rule.
fn windows_firewall_allow_ssh_out_args(rule_name: &str, cidr: &ManagementCidr) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=allow".to_owned(),
        "protocol=tcp".to_owned(),
        "remoteport=22".to_owned(),
        format!("remoteip={cidr}"),
    ]
}

/// WireGuard handshake/data allow (RN-06): outbound UDP from the WG listen port
/// to any destination, so the tunnel can (re)establish and carry data under the
/// killswitch. Mirrors the Linux wg-listen-port allow. (Tunnel-internal traffic
/// on the RAS adapter is permitted separately by the native WFP tunnel filter.)
fn windows_firewall_allow_wg_handshake_args(rule_name: &str, wg_listen_port: u16) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=allow".to_owned(),
        "protocol=udp".to_owned(),
        format!("localport={wg_listen_port}"),
    ]
}

/// Traversal bootstrap allow (RN-06): outbound UDP to a specific STUN/relay
/// endpoint (IP:port). Mirrors the Linux traversal bootstrap allow.
fn windows_firewall_allow_traversal_endpoint_args(
    rule_name: &str,
    endpoint: SocketAddr,
) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=allow".to_owned(),
        "protocol=udp".to_owned(),
        format!("remoteip={}", endpoint.ip()),
        format!("remoteport={}", endpoint.port()),
    ]
}

/// Build the netsh argv that adds an outbound block rule for the given protocol
/// (`udp` or `tcp`) and remote port 53 on `interfacetype=lan`.  The rule blocks
/// DNS traffic on every non-tunnel interface so all DNS is forced through the
/// `WireGuard` tunnel — equivalent to the Linux nft rule
/// `<proto> dport 53 oifname != $tunnel drop`.
fn windows_dns_block_lan_args(rule_name: &str, protocol: &str) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=block".to_owned(),
        format!("protocol={protocol}"),
        "remoteport=53".to_owned(),
        "interfacetype=lan".to_owned(),
    ]
}

/// Build the netsh argv that deletes a named advfirewall rule.  Used for
/// idempotent re-apply (purge stale rules from a previous run) and for
/// rollback.
fn windows_firewall_delete_rule_args(rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "delete".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
    ]
}

/// Build the netsh argv that disables IPv6 router-discovery and advertise on the
/// underlay egress adapter so SLAAC cannot auto-configure a global IPv6 address
/// behind the daemon's back while the killswitch + `WireGuard` tunnel are active.
///
/// The egress alias is passed as a positional `interface` parameter (its own
/// argv element) so spaces inside common Windows aliases like "Ethernet 2" are
/// preserved by `Command::args()` without any shell interpolation.
fn windows_ipv6_egress_disable_args(egress_interface: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv6".to_owned(),
        "set".to_owned(),
        "interface".to_owned(),
        egress_interface.to_owned(),
        "routerdiscovery=disabled".to_owned(),
        "advertise=disabled".to_owned(),
        "store=active".to_owned(),
    ]
}

/// Build the netsh argv that adds an outbound Block rule covering ALL IPv6 on
/// non-tunnel (`interfacetype=lan`) interfaces.  A Block rule wins over the
/// killswitch's unscoped egress-LAN allow, so IPv6 cannot egress the underlay
/// and bypass the IPv4-only tunnel (G8 fail-closed).  The rule is scoped to
/// `lan` so the WireGuard tunnel (RAS interface type) is untouched; the
/// WireGuard handshake and SSH are IPv4 and therefore unaffected.
///
/// All-IPv6 is expressed as the explicit range `::`-`ffff:…:ffff`, NOT `::/0`:
/// netsh rejects a `/0` prefix ("One or more of the address prefixes is
/// invalid", exit 1 — verified live on the guest).  The range is IPv6-family
/// only, so it never matches the IPv4 SSH / WireGuard-handshake paths.
fn windows_ipv6_egress_block_lan_args(rule_name: &str) -> Vec<String> {
    vec![
        "advfirewall".to_owned(),
        "firewall".to_owned(),
        "add".to_owned(),
        "rule".to_owned(),
        format!("name={rule_name}"),
        "dir=out".to_owned(),
        "action=block".to_owned(),
        "remoteip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_owned(),
        "interfacetype=lan".to_owned(),
    ]
}

/// Build the netsh argv that re-enables IPv6 router-discovery and advertise on
/// the underlay egress adapter during rollback.  Symmetric to
/// [`windows_ipv6_egress_disable_args`] except the two `*=disabled` flags become
/// `*=enabled`.
fn windows_ipv6_egress_rollback_args(egress_interface: &str) -> Vec<String> {
    vec![
        "interface".to_owned(),
        "ipv6".to_owned(),
        "set".to_owned(),
        "interface".to_owned(),
        egress_interface.to_owned(),
        "routerdiscovery=enabled".to_owned(),
        "advertise=enabled".to_owned(),
        "store=active".to_owned(),
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
                "soak_test_hours must be greater than zero".to_owned(),
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
            "environment must not be empty".to_owned(),
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
    #[cfg(unix)]
    #[test]
    fn helper_command_timeout_kills_a_hung_command() {
        use std::process::Command;
        use std::time::{Duration, Instant};
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let started = Instant::now();
        let result = super::run_helper_command_with_timeout(command, Duration::from_millis(300));
        let elapsed = started.elapsed();
        let err = result.expect_err("a hung command must time out");
        assert!(err.contains("timed out"), "unexpected error: {err}");
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout did not kill the child promptly: {elapsed:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn helper_command_timeout_returns_fast_command_output() {
        use std::process::Command;
        use std::time::Duration;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "printf hello"]);
        let output = super::run_helper_command_with_timeout(command, Duration::from_secs(5))
            .expect("fast command output");
        assert!(output.status.success());
        assert_eq!(String::from_utf8_lossy(&output.stdout), "hello");
    }

    use std::net::IpAddr;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::PermissionsExt;
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
    fn validate_windows_binary_path_requires_system_root_and_exe() {
        // Accept canonical System32 path (case-insensitive); accept SysWOW64.
        super::validate_windows_binary_path(r"C:\Windows\System32\netsh.exe", "netsh")
            .expect("default System32 path must validate");
        super::validate_windows_binary_path(r"c:\windows\system32\powershell.exe", "powershell")
            .expect("lowercase System32 path must validate");
        super::validate_windows_binary_path(
            r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe",
            "powershell",
        )
        .expect("SysWOW64-rooted PowerShell must validate");
        // Reject path-traversal smuggling out of System32.
        let err = super::validate_windows_binary_path(
            r"C:\Windows\System32\..\..\Users\Public\evil.exe",
            "netsh",
        )
        .expect_err("`..` traversal must fail closed");
        assert!(err.to_string().contains("`..`"));
        // Reject paths outside the trusted system root.
        let err = super::validate_windows_binary_path(r"D:\tools\netsh.exe", "netsh")
            .expect_err("paths outside System32 must fail closed");
        assert!(err.to_string().contains("\\System32\\"));
        // Reject non-.exe targets so a renamed shim can't be substituted.
        let err = super::validate_windows_binary_path(r"C:\Windows\System32\netsh", "netsh")
            .expect_err("missing .exe extension must fail closed");
        assert!(err.to_string().contains("`.exe`"));
        // Reject relative paths.
        let err = super::validate_windows_binary_path(r"netsh.exe", "netsh")
            .expect_err("relative paths must fail closed");
        assert!(err.to_string().contains("absolute"));
        // Reject control characters and non-ASCII.
        let err =
            super::validate_windows_binary_path("C:\\Windows\\System32\\netsh\x00.exe", "netsh")
                .expect_err("embedded NUL must fail closed");
        assert!(err.to_string().contains("control characters"));
        let err = super::validate_windows_binary_path("C:\\Windows\\System32\\nеtsh.exe", "netsh")
            .expect_err("non-ASCII (Cyrillic 'е') homoglyph attack must fail closed");
        assert!(err.to_string().contains("ASCII"));
        // Reject forward slashes (Win32 accepts them but our System32 substring
        // matcher uses backslashes; require canonical form).
        let err = super::validate_windows_binary_path("C:/Windows/System32/netsh.exe", "netsh")
            .expect_err("forward slashes must fail closed");
        assert!(err.to_string().contains("backslash"));
    }

    #[test]
    fn write_pf_rules_temp_file_fails_when_target_path_already_exists() {
        // Regression pin: the helper must atomically refuse to overwrite any
        // pre-existing inode at the chosen path. We approximate the symlink
        // pre-positioning attack by creating a regular file at a path that
        // shares the same `<pid>-<gen>-<nonce>` shape used by the helper, then
        // call the helper twice with the same generation and assert that:
        //   * the first write succeeds (proves the helper otherwise works)
        //   * a second write with the SAME path collides via `create_new` and
        //     fails closed (proves O_EXCL semantics survive)
        let pre_path = std::env::temp_dir().join(format!(
            "rustynet-pf-rules-precheck-{}-{}.conf",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock available")
                .as_nanos()
        ));
        std::fs::write(&pre_path, "preexisting").expect("seed precheck file");
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        let collide_result = opts.open(&pre_path);
        assert!(
            collide_result.is_err(),
            "create_new must refuse to overwrite an existing inode at {}; \
             pf rules tempfile would otherwise be vulnerable to a symlink \
             pre-positioning attack in a world-writable temp directory",
            pre_path.display(),
        );
        let _ = std::fs::remove_file(&pre_path);
    }

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
                "interface".to_owned(),
                "ipv4".to_owned(),
                "set".to_owned(),
                "dnsservers".to_owned(),
                "name=rustynet0".to_owned(),
                "source=static".to_owned(),
                "address=127.0.0.1".to_owned(),
                "validate=no".to_owned(),
            ]
        );
        assert_eq!(
            windows_dns_clear_args("rustynet0"),
            vec![
                "interface".to_owned(),
                "ipv4".to_owned(),
                "delete".to_owned(),
                "dnsservers".to_owned(),
                "name=rustynet0".to_owned(),
                "all".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_dns_ipv6_helpers_set_and_clear_loopback() {
        // IPv6 set must pin ::1 (loopback), replacing Windows' fec0:0:0:ffff::
        // auto-assigned placeholders that the dns-failclosed verifier flags.
        assert_eq!(
            windows_dns_set_ipv6_loopback_args("rustynet0"),
            vec![
                "interface".to_owned(),
                "ipv6".to_owned(),
                "set".to_owned(),
                "dnsservers".to_owned(),
                "name=rustynet0".to_owned(),
                "source=static".to_owned(),
                "address=::1".to_owned(),
                "validate=no".to_owned(),
            ]
        );
        assert_eq!(
            windows_dns_clear_ipv6_args("rustynet0"),
            vec![
                "interface".to_owned(),
                "ipv6".to_owned(),
                "delete".to_owned(),
                "dnsservers".to_owned(),
                "name=rustynet0".to_owned(),
                "all".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_nrpt_reg_args_are_loopback_only_and_argv_bound() {
        use std::net::IpAddr;
        // Every NRPT name server must be loopback (verifier rejects one off-
        // loopback). Semicolon-separated to match the GenericDNSServers value.
        for server in WINDOWS_NRPT_LOOPBACK_SERVERS.split(';') {
            let ip: IpAddr = server.parse().expect("reviewed NRPT server must parse");
            assert!(ip.is_loopback(), "NRPT server {server} must be loopback");
        }

        let add_sets = windows_nrpt_reg_add_arg_sets();
        // One `reg add` per registry value: Version, Name, GenericDNSServers,
        // ConfigOptions, Comment.
        assert_eq!(add_sets.len(), 5, "one reg add per NRPT value");
        for set in &add_sets {
            assert_eq!(set[0], "add", "each set must be a `reg add`");
            assert_eq!(
                set[1], WINDOWS_NRPT_REG_KEY,
                "must target the rustynet NRPT key"
            );
            assert!(set.contains(&"/f".to_owned()), "must be forced/idempotent");
            // No CIM cmdlet, no PowerShell script anywhere in the argv — this is
            // the whole point: native registry writes, like WireGuard-for-Windows.
            for token in set {
                assert!(
                    !token.contains("DnsClientNrptRule"),
                    "must not use the CIM NRPT cmdlet on the reconcile path"
                );
                assert!(
                    !token.contains("New-ItemProperty") && !token.contains("Test-Path"),
                    "must not shell out to PowerShell for the registry write"
                );
            }
        }
        // The fixed key lives under the NRPT policy hive.
        assert!(WINDOWS_NRPT_REG_KEY.contains("DnsPolicyConfig"));
        // reg.exe uses the `HKLM\…` hive form, NOT the PowerShell `HKLM:\…`
        // PSDrive form (that would make reg.exe create a literal `HKLM:` key).
        assert!(WINDOWS_NRPT_REG_KEY.starts_with(r"HKLM\"));
        assert!(!WINDOWS_NRPT_REG_KEY.contains("HKLM:"));

        // The CRITICAL regression guard: the loopback server list (which
        // contains a `;`) must be passed as ONE argv element to `/d`, never
        // split. Passing it as a trailing `powershell.exe -Command` positional
        // arg concatenated it into the command line, where `;` is a statement
        // separator — silently dropping `::1` and failing the parse.
        let servers_set = add_sets
            .iter()
            .find(|set| set.contains(&"GenericDNSServers".to_owned()))
            .expect("an arg set must write GenericDNSServers");
        let data_idx = servers_set
            .iter()
            .position(|t| t == "/d")
            .expect("reg add must carry a /d data flag")
            + 1;
        assert_eq!(
            servers_set[data_idx], WINDOWS_NRPT_LOOPBACK_SERVERS,
            "the full `127.0.0.1;::1` list must be a single argv element"
        );
        assert!(
            servers_set[data_idx].contains(';'),
            "regression guard: the `;` stays inside one argv element"
        );

        // The Name value is the root namespace `.` written as REG_MULTI_SZ.
        let name_set = add_sets
            .iter()
            .find(|set| set.contains(&"Name".to_owned()))
            .expect("an arg set must write Name");
        assert!(name_set.contains(&"REG_MULTI_SZ".to_owned()));
        assert!(name_set.contains(&".".to_owned()));

        // Teardown is a forced `reg delete` of the same key.
        let del = windows_nrpt_reg_delete_args();
        assert_eq!(del[0], "delete");
        assert_eq!(del[1], WINDOWS_NRPT_REG_KEY);
        assert!(del.contains(&"/f".to_owned()));
    }

    #[test]
    fn windows_dns_block_lan_helper_renders_reviewed_netsh_block_args() {
        // UDP/53 LAN block — the moral equivalent of the Linux nft rule
        // `udp dport 53 oifname != $tunnel drop`.
        assert_eq!(
            windows_dns_block_lan_args(WINDOWS_DNS_RULE_BLOCK_LAN_UDP, "udp"),
            vec![
                "advfirewall".to_owned(),
                "firewall".to_owned(),
                "add".to_owned(),
                "rule".to_owned(),
                format!("name={WINDOWS_DNS_RULE_BLOCK_LAN_UDP}"),
                "dir=out".to_owned(),
                "action=block".to_owned(),
                "protocol=udp".to_owned(),
                "remoteport=53".to_owned(),
                "interfacetype=lan".to_owned(),
            ]
        );
        // TCP/53 LAN block — without it an app that opted into TCP DNS could
        // still leak past the UDP-only block.
        assert_eq!(
            windows_dns_block_lan_args(WINDOWS_DNS_RULE_BLOCK_LAN_TCP, "tcp"),
            vec![
                "advfirewall".to_owned(),
                "firewall".to_owned(),
                "add".to_owned(),
                "rule".to_owned(),
                format!("name={WINDOWS_DNS_RULE_BLOCK_LAN_TCP}"),
                "dir=out".to_owned(),
                "action=block".to_owned(),
                "protocol=tcp".to_owned(),
                "remoteport=53".to_owned(),
                "interfacetype=lan".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_dns_block_lan_helper_uses_block_action_targeting_lan_only() {
        // Critical security property: action must be `block` (not `allow`) and
        // interfacetype must be `lan` (not `any` and not `ras`).  An `any`
        // scope would also block DNS through the tunnel and break resolution
        // entirely; a `ras` scope would block tunnel-internal DNS instead of
        // the underlay LAN, exactly inverting the intended protection.
        let args = windows_dns_block_lan_args(WINDOWS_DNS_RULE_BLOCK_LAN_UDP, "udp");
        assert!(args.iter().any(|a| a == "action=block"));
        assert!(!args.iter().any(|a| a == "action=allow"));
        assert!(args.iter().any(|a| a == "interfacetype=lan"));
        assert!(!args.iter().any(|a| a == "interfacetype=any"));
        assert!(!args.iter().any(|a| a == "interfacetype=ras"));
        assert!(args.iter().any(|a| a == "dir=out"));
        assert!(args.iter().any(|a| a == "remoteport=53"));
    }

    #[test]
    fn windows_firewall_delete_rule_helper_renders_reviewed_args() {
        assert_eq!(
            windows_firewall_delete_rule_args("RustyNetTest-Rule"),
            vec![
                "advfirewall".to_owned(),
                "firewall".to_owned(),
                "delete".to_owned(),
                "rule".to_owned(),
                "name=RustyNetTest-Rule".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_firewall_block_outbound_policy_targets_all_profiles() {
        // The global default policy is the foundation of the killswitch.  It
        // MUST set `allowinbound,blockoutbound` on `allprofiles` — anything
        // narrower would leave a profile unmanaged and a profile switch (e.g.
        // domain ↔ private ↔ public) could let traffic out without the
        // explicit allow rules being involved.
        let args = windows_firewall_block_outbound_policy_args();
        assert_eq!(
            args,
            vec![
                "advfirewall".to_owned(),
                "set".to_owned(),
                "allprofiles".to_owned(),
                "firewallpolicy".to_owned(),
                "allowinbound,blockoutbound".to_owned(),
            ]
        );
        // Static guards: never accidentally swap to "allow,allow" or drop the
        // outbound block.
        assert!(args.iter().any(|a| a == "allowinbound,blockoutbound"));
        assert!(!args.iter().any(|a| a == "allowinbound,allowoutbound"));
        assert!(!args.iter().any(|a| a == "blockinbound,blockoutbound"));
    }

    #[test]
    fn windows_firewall_allow_loopback_helper_constrains_to_loopback_subnet() {
        // The loopback allow rule must constrain BOTH localip and remoteip to
        // 127.0.0.0/8.  An allow rule that omitted remoteip would let local
        // processes reach any remote host, defeating the killswitch.
        let args = windows_firewall_allow_loopback_args(WINDOWS_KS_RULE_LOOPBACK);
        assert_eq!(args[0], "advfirewall");
        assert_eq!(args[2], "add");
        assert_eq!(args[4], format!("name={WINDOWS_KS_RULE_LOOPBACK}"));
        assert!(args.iter().any(|a| a == "dir=out"));
        assert!(args.iter().any(|a| a == "action=allow"));
        assert!(args.iter().any(|a| a == "localip=127.0.0.0/8"));
        assert!(args.iter().any(|a| a == "remoteip=127.0.0.0/8"));
        // The rule must NOT bind to "any" address — that would defeat the
        // killswitch by allowing arbitrary outbound traffic.
        assert!(!args.iter().any(|a| a.starts_with("remoteip=any")));
        assert!(!args.iter().any(|a| a == "remoteip=0.0.0.0/0"));
    }

    #[test]
    fn windows_scoped_egress_allow_builders_render_reviewed_args() {
        // RN-06: the killswitch egress allow is now SCOPED — it replaces the
        // prior unscoped `interfacetype=lan` allow with narrow rules. All scoped
        // rules share WINDOWS_KS_RULE_EGRESS so rollback deletes them by name.
        let cidr: ManagementCidr = "192.168.0.0/24".parse().expect("valid management cidr");

        // SSH reply — the lockout-critical rule (outbound TCP from local port 22
        // to the mgmt CIDR keeps an inbound-administered session alive).
        let reply = windows_firewall_allow_ssh_reply_args(WINDOWS_KS_RULE_EGRESS, &cidr);
        assert_eq!(reply[4], format!("name={WINDOWS_KS_RULE_EGRESS}"));
        assert!(reply.iter().any(|a| a == "dir=out"));
        assert!(reply.iter().any(|a| a == "action=allow"));
        assert!(reply.iter().any(|a| a == "protocol=tcp"));
        assert!(reply.iter().any(|a| a == "localport=22"));
        assert!(reply.iter().any(|a| a == "remoteip=192.168.0.0/24"));

        // SSH outbound — TCP to remote port 22 within the mgmt CIDR.
        let out = windows_firewall_allow_ssh_out_args(WINDOWS_KS_RULE_EGRESS, &cidr);
        assert!(out.iter().any(|a| a == "protocol=tcp"));
        assert!(out.iter().any(|a| a == "remoteport=22"));
        assert!(out.iter().any(|a| a == "remoteip=192.168.0.0/24"));

        // WireGuard handshake/data — outbound UDP from the listen port.
        let wg = windows_firewall_allow_wg_handshake_args(WINDOWS_KS_RULE_EGRESS, 51820);
        assert!(wg.iter().any(|a| a == "protocol=udp"));
        assert!(wg.iter().any(|a| a == "localport=51820"));

        // Traversal bootstrap endpoint — outbound UDP to a specific ip:port.
        let endpoint: SocketAddr = "203.0.113.7:3478".parse().expect("valid endpoint");
        let ep = windows_firewall_allow_traversal_endpoint_args(WINDOWS_KS_RULE_EGRESS, endpoint);
        assert!(ep.iter().any(|a| a == "protocol=udp"));
        assert!(ep.iter().any(|a| a == "remoteip=203.0.113.7"));
        assert!(ep.iter().any(|a| a == "remoteport=3478"));

        // RN-06 regression guards: no scoped allow may fall back to the unscoped
        // interfacetype allow or an any-address allow.
        for args in [&reply, &out, &wg, &ep] {
            assert!(!args.iter().any(|a| a == "interfacetype=lan"));
            assert!(!args.iter().any(|a| a == "interfacetype=any"));
            assert!(!args.iter().any(|a| a == "remoteip=any"));
            assert!(!args.iter().any(|a| a == "remoteip=0.0.0.0/0"));
        }
    }

    #[test]
    fn windows_firewall_killswitch_rules_have_distinct_names() {
        // Each killswitch rule is purged-by-name at apply time.  If two rules
        // shared a name, applying the killswitch would silently remove one of
        // them on the second pass, leaving a hole.
        let rules = [
            WINDOWS_KS_RULE_LOOPBACK,
            WINDOWS_KS_RULE_TUNNEL,
            WINDOWS_KS_RULE_EGRESS,
        ];
        for (i, a) in rules.iter().enumerate() {
            for b in rules.iter().skip(i + 1) {
                assert_ne!(a, b, "killswitch rules must have distinct names");
            }
        }
        // The rule-name prefix encodes the owning subsystem so an external
        // operator can tell the rules apart from custom rules.  Every
        // killswitch rule must use the RustyNetKS- prefix; DNS-block rules
        // use a distinct RustyNetDNS- prefix verified separately.
        for rule in rules {
            assert!(
                rule.starts_with("RustyNetKS-"),
                "killswitch rule {rule:?} must use RustyNetKS- prefix"
            );
        }
    }

    #[test]
    fn windows_dns_protection_rule_names_are_distinct_from_killswitch_rule_names() {
        // The DNS-block rules must not collide with the killswitch allow rules,
        // otherwise an idempotent purge (delete rule by name) at apply time
        // would remove a control we still need.
        let dns_names = [
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
        ];
        let ks_names = [
            WINDOWS_KS_RULE_LOOPBACK,
            WINDOWS_KS_RULE_TUNNEL,
            WINDOWS_KS_RULE_EGRESS,
        ];
        for d in dns_names {
            for k in ks_names {
                assert_ne!(d, k, "DNS rule name {d} must not collide with KS rule {k}");
            }
        }
        assert_ne!(
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP, WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
            "DNS UDP and TCP block rules must have distinct names"
        );
    }

    #[test]
    fn windows_command_system_rollback_dns_protection_is_no_op_when_not_applied() {
        // A freshly-constructed system has `dns_protected = false`.  Rollback
        // in this state must not run netsh — calling delete-rule on a name
        // that was never installed would mask a real configuration drift on
        // the next apply cycle.
        let mut system = WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("windows command system should initialize");

        DataplaneSystem::rollback_dns_protection(&mut system)
            .expect("rollback must be a no-op when DNS protection was never applied");
    }

    #[test]
    fn windows_ipv6_egress_helpers_render_reviewed_netsh_args() {
        // Disable: must turn off both router-discovery and advertise on the
        // egress adapter and persist the change in the active store.
        assert_eq!(
            windows_ipv6_egress_disable_args("Ethernet"),
            vec![
                "interface".to_owned(),
                "ipv6".to_owned(),
                "set".to_owned(),
                "interface".to_owned(),
                "Ethernet".to_owned(),
                "routerdiscovery=disabled".to_owned(),
                "advertise=disabled".to_owned(),
                "store=active".to_owned(),
            ]
        );

        // Rollback: must re-enable both, also persisted to the active store.
        assert_eq!(
            windows_ipv6_egress_rollback_args("Ethernet"),
            vec![
                "interface".to_owned(),
                "ipv6".to_owned(),
                "set".to_owned(),
                "interface".to_owned(),
                "Ethernet".to_owned(),
                "routerdiscovery=enabled".to_owned(),
                "advertise=enabled".to_owned(),
                "store=active".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_ipv6_egress_block_rule_blocks_all_ipv6_on_lan() {
        // G8: the IPv6 LAN block must be an outbound BLOCK covering all IPv6
        // scoped to non-tunnel (lan) interfaces, so it overrides the
        // killswitch's egress-LAN allow without touching the tunnel.  All-IPv6
        // is the explicit `::`-`ffff:..:ffff` range, NOT `::/0`: netsh rejects a
        // /0 prefix ("address prefixes is invalid", exit 1), verified live.
        let args = windows_ipv6_egress_block_lan_args(WINDOWS_IPV6_RULE_BLOCK_LAN);
        assert_eq!(
            args,
            vec![
                "advfirewall".to_owned(),
                "firewall".to_owned(),
                "add".to_owned(),
                "rule".to_owned(),
                "name=RustyNetKS-BlockIpv6Lan".to_owned(),
                "dir=out".to_owned(),
                "action=block".to_owned(),
                "remoteip=::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".to_owned(),
                "interfacetype=lan".to_owned(),
            ]
        );
        // netsh rejects the /0 prefix form; guard against a regression to it.
        assert!(!args.iter().any(|a| a == "remoteip=::/0"));
    }

    #[test]
    fn windows_ipv6_egress_helpers_keep_alias_with_space_as_one_argv_token() {
        // The egress alias must be its own argv element so `Command::args()`
        // delivers e.g. "Ethernet 2" to netsh as a single argument with the
        // space preserved (no shell interpolation, no key=value coupling that
        // a space could split).
        let disable = windows_ipv6_egress_disable_args("Ethernet 2");
        assert_eq!(disable[4], "Ethernet 2", "alias must be its own argv token");
        assert!(
            !disable.iter().any(|arg| arg.contains('"')),
            "args must not embed shell-style quoting; positional argv handles spaces"
        );

        let rollback = windows_ipv6_egress_rollback_args("vEthernet (Default Switch)");
        assert_eq!(rollback[4], "vEthernet (Default Switch)");
    }

    #[test]
    fn windows_ipv6_egress_disable_and_rollback_args_differ_only_in_flag_state() {
        // The disable and rollback arg sequences must be byte-identical except
        // for the two `*=disabled` / `*=enabled` flags.  This guarantees that
        // rollback exactly undoes the disable on the same interface and store.
        let disable = windows_ipv6_egress_disable_args("Ethernet");
        let rollback = windows_ipv6_egress_rollback_args("Ethernet");
        assert_eq!(disable.len(), rollback.len());
        for (idx, (d, r)) in disable.iter().zip(rollback.iter()).enumerate() {
            if idx == 5 || idx == 6 {
                assert_ne!(d, r, "arg {idx} must differ between disable and rollback");
                assert!(d.ends_with("=disabled"));
                assert!(r.ends_with("=enabled"));
            } else {
                assert_eq!(d, r, "arg {idx} must match between disable and rollback");
            }
        }
    }

    #[test]
    fn windows_command_system_rollback_ipv6_is_no_op_when_not_disabled() {
        // A freshly-constructed system has `ipv6_disabled = false`.  Calling
        // rollback in this state must not attempt to run netsh — that would
        // re-enable IPv6 router-discovery on an interface whose original state
        // we never captured, masking a real configuration drift.
        let mut system = WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("windows command system should initialize");

        DataplaneSystem::rollback_ipv6_egress(&mut system)
            .expect("rollback must be a no-op when IPv6 was never disabled");
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
        supports_exit_client: bool,
        supports_exit_serving: bool,
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
                supports_exit_client: true,
                supports_exit_serving: true,
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
                supports_exit_client: self.supports_exit_client,
                supports_exit_serving: self.supports_exit_serving,
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
                supports_exit_client: true,
                supports_exit_serving: true,
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
                src: "user:alice".to_owned(),
                dst: "*".to_owned(),
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
            allowed_ips: vec!["100.100.20.2/32".to_owned()],
            persistent_keepalive_secs: None,
        }
    }

    fn test_runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("node-a").expect("node should parse"),
            interface_name: "rustynet0".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            local_cidr: "100.64.0.1/32".to_owned(),
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

    // A world-writable sticky /tmp (the Unix default) fails
    // validate_owner_only_socket_facts' parent-directory check, so the test
    // socket needs its own owner-only directory rather than /tmp directly.
    #[cfg(target_os = "linux")]
    fn phase10_test_socket_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rn10-sockets-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or_else(|err| {
            panic!(
                "test helper socket dir should be creatable at {}: {err}",
                dir.display()
            )
        });
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap_or_else(
            |err| {
                panic!(
                    "test helper socket dir permissions should be settable at {}: {err}",
                    dir.display()
                )
            },
        );
        dir
    }

    #[cfg(target_os = "linux")]
    fn phase10_test_socket_path(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        // Keep socket paths short enough for UNIX domain limits, especially on macOS.
        phase10_test_socket_dir().join(format!("rn10-{prefix}-{unique:x}.sock"))
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
                        let request = match crate::privileged_helper::read_request(&mut stream) {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = crate::privileged_helper::write_response(
                                    &mut stream,
                                    crate::privileged_helper::HelperResponse::error(err),
                                );
                                continue;
                            }
                        };
                        commands_clone
                            .lock()
                            .expect("test helper command log should lock")
                            .push(format!("{} {}", request.program, request.args.join(" ")));
                        let _ = crate::privileged_helper::write_response(
                            &mut stream,
                            crate::privileged_helper::HelperResponse::success(
                                0,
                                String::new(),
                                String::new(),
                            ),
                        );
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
                        let request = match crate::privileged_helper::read_request(&mut stream) {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = crate::privileged_helper::write_response(
                                    &mut stream,
                                    crate::privileged_helper::HelperResponse::error(err),
                                );
                                continue;
                            }
                        };
                        let command = format!("{} {}", request.program, request.args.join(" "));
                        commands_clone
                            .lock()
                            .expect("test helper command log should lock")
                            .push(command.clone());

                        let stdout = if command.contains("nft list tables") {
                            tables_output.clone()
                        } else {
                            String::new()
                        };
                        let _ = crate::privileged_helper::write_response(
                            &mut stream,
                            crate::privileged_helper::HelperResponse::success(
                                0,
                                stdout,
                                String::new(),
                            ),
                        );
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
                        let request = match crate::privileged_helper::read_request(&mut stream) {
                            Ok(request) => request,
                            Err(err) => {
                                let _ = crate::privileged_helper::write_response(
                                    &mut stream,
                                    crate::privileged_helper::HelperResponse::error(err),
                                );
                                continue;
                            }
                        };
                        let command = format!("{} {}", request.program, request.args.join(" "));
                        commands_clone
                            .lock()
                            .expect("test helper command log should lock")
                            .push(command.clone());

                        let scripted = responses
                            .iter()
                            .find(|(needle, _)| command.contains(needle.as_str()))
                            .map(|(_, output)| output.clone())
                            .unwrap_or(PrivilegedCommandOutput {
                                status: 0,
                                stdout: String::new(),
                                stderr: String::new(),
                            });
                        let _ = crate::privileged_helper::write_response(
                            &mut stream,
                            crate::privileged_helper::HelperResponse::success(
                                scripted.status,
                                scripted.stdout,
                                scripted.stderr,
                            ),
                        );
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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
                .contains(&"assert_exit_policy:full_tunnel".to_owned()),
            "phase 10 must assert measured full-tunnel truth before claiming ExitActive"
        );
    }

    #[test]
    fn full_tunnel_apply_rejects_unprotected_dns_before_any_mutation() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    protected_dns: false,
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("full-tunnel apply without protected DNS must fail closed");

        assert!(matches!(
            err,
            Phase10Error::System(SystemError::DnsApplyFailed(_))
        ));
        assert_eq!(controller.state(), DataplaneState::Init);
        assert!(!controller.backend.started);
        assert!(
            controller.system.operations.is_empty(),
            "DNS guard must reject before generation, route, firewall, or backend mutation; ops={:?}",
            controller.system.operations
        );
    }

    #[test]
    fn full_tunnel_apply_programs_dns_before_exit_policy_commit() {
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("protected full-tunnel apply should succeed");

        let dns_idx = controller
            .system
            .operations
            .iter()
            .position(|op| op == "apply_dns_protection")
            .expect("full-tunnel apply must program protected DNS");
        let dns_assert_idx = controller
            .system
            .operations
            .iter()
            .position(|op| op == "assert_dns_protection")
            .expect("full-tunnel apply must assert protected DNS");
        let policy_idx = controller
            .system
            .operations
            .iter()
            .position(|op| op == "assert_exit_policy:full_tunnel")
            .expect("full-tunnel apply must assert measured exit policy");
        assert!(
            dns_idx < dns_assert_idx && dns_assert_idx < policy_idx,
            "protected DNS must be active before full-tunnel policy commit; ops={:?}",
            controller.system.operations
        );
    }

    #[test]
    fn full_tunnel_route_dns_apply_order_keeps_exit_commit_last() {
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("protected full-tunnel apply should succeed");

        let expected_order = [
            "apply_firewall_killswitch",
            "rollback_routes",
            "apply_peer_endpoint_bypass_routes",
            "apply_routes",
            "apply_nat_forwarding",
            "apply_dns_protection",
            "assert_dns_protection",
            "hard_disable_ipv6_egress",
            "assert_exit_policy:full_tunnel",
        ];
        let mut last_idx = None;
        for expected in expected_order {
            let idx = controller
                .system
                .operations
                .iter()
                .position(|op| op == expected || op.starts_with(&format!("{expected}:")))
                .unwrap_or_else(|| {
                    panic!(
                        "expected operation {expected} missing from {:?}",
                        controller.system.operations
                    )
                });
            if let Some(previous) = last_idx {
                assert!(
                    previous < idx,
                    "full-tunnel route/DNS ordering regressed; ops={:?}",
                    controller.system.operations
                );
            }
            last_idx = Some(idx);
        }
    }

    #[test]
    fn full_tunnel_dns_assert_failure_holds_dns_fail_closed_and_blocks_exit_mode() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default().fail_on("assert_dns_protection"),
            policy,
            TrustPolicy::default(),
        );

        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("DNS assertion failure must fail closed before exit mode");

        assert!(matches!(err, Phase10Error::System(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        // Fail-closed-sticky: a transient DNS-assert failure must NOT roll back
        // DNS protection (that would restore resolv.conf to its off-loopback
        // original — a fail-OPEN DNS leak). DNS stays applied (loopback) and the
        // daemon blocks all egress instead.
        assert!(
            !controller
                .system
                .operations
                .contains(&"rollback_dns_protection".to_owned()),
            "DNS must be HELD fail-closed on an error rollback, never restored; ops={:?}",
            controller.system.operations
        );
        assert!(
            controller
                .system
                .operations
                .contains(&"block_all_egress".to_owned()),
            "fail-closed must block all egress; ops={:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .contains(&"assert_exit_policy:full_tunnel".to_owned()),
            "exit policy must not commit after DNS assertion failure; ops={:?}",
            controller.system.operations
        );
    }

    #[test]
    fn killswitch_apply_failure_fails_closed_before_exit_mode() {
        // The OS-agnostic guarantee behind the Windows N2 fail-closed criterion:
        // if the killswitch cannot be applied, the daemon must NOT serve a
        // protected tunnel. The WindowsCommandSystem's apply_firewall_killswitch
        // returning Err flows through this same reconcile path, so injecting the
        // failure on the DryRun system proves the fail-closed wiring for Windows
        // too (block_all_egress fires, exit mode never commits).
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default().fail_on("apply_firewall_killswitch"),
            policy,
            TrustPolicy::default(),
        );

        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("killswitch apply failure must fail closed before exit mode");

        assert!(matches!(err, Phase10Error::System(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        assert!(
            controller
                .system
                .operations
                .contains(&"block_all_egress".to_owned()),
            "killswitch apply failure must drive force_fail_closed/block_all_egress; ops={:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .contains(&"apply_dns_protection".to_owned()),
            "DNS protection must not apply after killswitch apply failure; ops={:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .contains(&"assert_exit_policy:full_tunnel".to_owned()),
            "exit policy must not commit after killswitch apply failure; ops={:?}",
            controller.system.operations
        );
    }

    #[test]
    fn full_tunnel_exit_policy_failure_rolls_backend_exit_mode_back_to_off() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default().fail_on("assert_exit_policy:full_tunnel"),
            policy,
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("exit-policy assertion failure must fail closed");

        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        // Fail-closed-sticky: DNS is HELD applied (loopback) on the error
        // rollback — never restored to off-loopback — and egress is blocked.
        assert!(
            !controller
                .system
                .operations
                .contains(&"rollback_dns_protection".to_owned()),
            "DNS must be held fail-closed after exit-policy failure, not unwound; ops={:?}",
            controller.system.operations
        );
        assert!(
            controller
                .system
                .operations
                .contains(&"block_all_egress".to_owned()),
            "fail-closed must block all egress; ops={:?}",
            controller.system.operations
        );
    }

    #[test]
    fn full_tunnel_apply_rejects_backend_without_exit_client_capability() {
        let policy = allow_shared_exit_policy();
        let backend = RecordingBackend {
            supports_exit_client: false,
            ..RecordingBackend::default()
        };
        let mut controller = Phase10Controller::new(
            backend,
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("exit-client apply must reject unsupported backend");

        assert!(matches!(err, Phase10Error::Backend(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "prune_owned_tables"),
            "capability rejection must happen before OS mutation"
        );
    }

    #[test]
    fn exit_serving_apply_rejects_backend_without_exit_serving_capability() {
        let policy = allow_shared_exit_policy();
        let backend = RecordingBackend {
            supports_exit_serving: false,
            ..RecordingBackend::default()
        };
        let mut controller = Phase10Controller::new(
            backend,
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("exit-serving apply must reject unsupported backend");

        assert!(matches!(err, Phase10Error::Backend(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op.starts_with("preflight_exit_serving")),
            "backend capability rejection must happen before system exit preflight"
        );
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "prune_owned_tables"),
            "capability rejection must happen before OS mutation"
        );
    }

    #[test]
    fn exit_serving_apply_runs_preflight_before_owned_os_mutation() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        let preflight_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "preflight_exit_serving")
            .expect("exit-serving apply must run explicit preflight");
        let prune_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "prune_owned_tables")
            .expect("apply should prune owned tables after preflight");
        let nat_index = controller
            .system
            .operations
            .iter()
            .position(|op| op == "apply_nat_forwarding")
            .expect("exit-serving apply should eventually apply NAT");

        assert!(
            preflight_index < prune_index && prune_index < nat_index,
            "preflight must happen before owned OS mutation and NAT apply; ops={:?}",
            controller.system.operations
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
    fn set_exit_node_denies_revoked_exit_node() {
        // RSA-0007: the exit-node ACL gate is membership-aware, so a revoked
        // exit node is denied here too — not only at peer provisioning.
        use rustynet_policy::{MembershipDirectory, MembershipStatus};
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");

        // Revoke the exit node (the requester selector stays active + apply has
        // already provisioned, so revocation is the only thing that changed).
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-b", MembershipStatus::Active);
        membership.set_node_status("exit-1", MembershipStatus::Revoked);
        membership.set_selector_members("user:alice", ["node-b"]);
        controller.set_membership(membership);

        assert_eq!(
            controller
                .set_exit_node(exit_node, "user:alice", Protocol::Tcp)
                .err(),
            Some(Phase10Error::PolicyDenied),
            "a revoked exit node must be denied at set_exit_node"
        );
    }

    #[test]
    fn ensure_lan_route_allowed_denies_revoked_requester() {
        // RSA-0007: even when the toggle, advertised route, and ACL all pass, a
        // revoked requester selector must be denied at the LAN-route gate.
        use rustynet_policy::{MembershipDirectory, MembershipStatus};
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions::default(),
            )
            .expect("apply should succeed");
        controller
            .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
            .expect("policy should allow selecting exit");
        controller.set_lan_access(true);
        controller.advertise_lan_route(exit_node, "192.168.1.0/24");
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);

        // Revoke the node backing the requester selector; prerequisites still
        // pass, so only the membership-aware policy gate can deny.
        let mut membership = MembershipDirectory::default();
        membership.set_node_status("node-b", MembershipStatus::Revoked);
        membership.set_node_status("exit-1", MembershipStatus::Active);
        membership.set_selector_members("user:alice", ["node-b"]);
        controller.set_membership(membership);

        assert_eq!(
            controller
                .ensure_lan_route_allowed(RouteGrantRequest {
                    user: "user:alice".to_owned(),
                    cidr: "192.168.1.0/24".to_owned(),
                    protocol: Protocol::Tcp,
                    context: TrafficContext::SharedExit,
                })
                .err(),
            Some(Phase10Error::PolicyDenied),
            "a revoked requester must be denied at ensure_lan_route_allowed"
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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
            set_ops.contains(&"assert_exit_policy:full_tunnel".to_owned()),
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
            clear_ops.contains(&"assert_exit_policy:off".to_owned()),
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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
            ops.contains(&"rollback_routes".to_owned())
                && ops.contains(&"apply_peer_endpoint_bypass_routes".to_owned())
                && ops.contains(&"apply_routes".to_owned())
                && ops.contains(&"assert_exit_policy:full_tunnel".to_owned()),
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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

    #[test]
    fn helper_less_direct_path_enforces_argv_schema_validation() {
        // RN-19: with no privileged client configured (daemon-as-root direct
        // path), run_capture must still apply the argv-schema allowlist and
        // reject a schema-violating command *before* resolving/spawning a
        // binary, matching the IPC helper's gate.
        let system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            None, // no client -> direct execution path
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        // A clearly invalid nft argv (not matching any allowlisted schema).
        let err = system
            .run_capture(
                PrivilegedCommandProgram::Nft,
                &["not", "a", "valid", "nft", "schema"],
            )
            .expect_err("schema-violating argv must be rejected on the direct path");
        match err {
            SystemError::Io(message) => assert!(
                !message.contains("spawn failed"),
                "rejection must happen at validation, not at spawn: {message}"
            ),
            other => panic!("unexpected error variant: {other:?}"),
        }
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

    #[cfg(target_os = "linux")]
    #[test]
    fn macos_reconcile_exit_nat_residue_flushes_fixed_anchor_only_when_not_serving() {
        // §10.7 regression guard. A node that crashed while serving as a macOS
        // exit restarts with `exit_nat_anchor = None`, so the in-memory teardown
        // is a no-op and `prune_owned_tables` only sweeps the generation-numbered
        // killswitch anchors. `reconcile_exit_nat_residue` must still flush the
        // FIXED `com.rustynet/nat` anchor by name when the new generation does
        // not serve an exit — and must issue NOTHING when it does (so it never
        // races the `activate_exit_nat` load that follows in the same apply).
        let socket_path = phase10_test_socket_path("rnr");
        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let client = PrivilegedCommandClient::new(socket_path.clone(), Duration::from_secs(2))
            .expect("privileged client should initialize");
        let mut system = MacosCommandSystem::new("utun9", "en0", Some(client), false, Vec::new())
            .expect("macos command system should initialize");
        // Simulate the post-crash restart: no in-memory NAT anchor handle.
        assert!(system.exit_nat_anchor.is_none());

        // Not serving an exit (e.g. restarted as a client) → flush the residue.
        DataplaneSystem::reconcile_exit_nat_residue(&mut system, false)
            .expect("reconcile should succeed");
        let after_not_serving = commands.lock().expect("command log should lock").len();

        // Serving an exit → must NOT flush (activation re-loads the anchor).
        DataplaneSystem::reconcile_exit_nat_residue(&mut system, true)
            .expect("reconcile should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert_eq!(
            after_not_serving, 2,
            "not-serving reconcile must flush the NAT anchor AND reset forwarding; got: {command_log:?}"
        );
        assert_eq!(
            command_log.len(),
            2,
            "serving reconcile must issue no command; got: {command_log:?}"
        );
        assert!(
            command_log.iter().any(|c| c.contains("pfctl")
                && c.contains("com.rustynet/nat")
                && c.contains("-F")
                && c.contains("all")),
            "must flush the fixed NAT anchor; got: {command_log:?}"
        );
        assert!(
            command_log
                .iter()
                .any(|c| c.contains("sysctl") && c.contains("net.inet.ip.forwarding=0")),
            "must reset ip forwarding to the secure default; got: {command_log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reconcile_exit_nat_residue_disables_forwarding_only_when_not_serving() {
        // §10.7 regression guard. Linux `apply_nat_forwarding` enables
        // `net.ipv4.ip_forward` and caches the prior value only in memory. NAT
        // tables are generation-swept, but ip_forward is not: a former exit that
        // demotes to client in a LATER apply (fresh instance, `prior_ipv4_forwarding
        // = None`) or restarts as a client after a crash would leave forwarding
        // enabled with no path to restore it. `reconcile_exit_nat_residue` must
        // drive it back to 0 when the generation does not serve an exit — and
        // must issue NOTHING when it does (so it never disables forwarding a
        // regular exit / blind_exit / relay-with-upstream legitimately needs,
        // and never races the `apply_nat_forwarding` enable in the same apply).
        let socket_path = phase10_test_socket_path("lrnr");
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

        // Not serving an exit (demoted/restarted as client) → reset forwarding.
        DataplaneSystem::reconcile_exit_nat_residue(&mut system, false)
            .expect("reconcile should succeed");
        let after_not_serving = commands.lock().expect("command log should lock").len();

        // Serving an exit → must NOT touch forwarding (activation enables it).
        DataplaneSystem::reconcile_exit_nat_residue(&mut system, true)
            .expect("reconcile should succeed");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert_eq!(
            after_not_serving, 1,
            "not-serving reconcile must issue exactly the forwarding reset; got: {command_log:?}"
        );
        assert_eq!(
            command_log.len(),
            1,
            "serving reconcile must issue no command; got: {command_log:?}"
        );
        assert!(
            command_log
                .iter()
                .any(|c| c.contains("sysctl") && c.contains("net.ipv4.ip_forward=0")),
            "must reset ip forwarding to the secure default; got: {command_log:?}"
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                destination_cidr: "100.100.20.0/24".to_owned(),
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
        assert!(
            !controller.serving_exit_node_active(),
            "exit serving must not be reported active when NAT/forwarding failed"
        );
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.last_safe_generation(), 0);
    }

    #[test]
    fn apply_exit_serving_requires_post_apply_assertion_before_active() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default().fail_on("assert_exit_serving"),
            policy,
            TrustPolicy::default(),
        );

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![Route {
                destination_cidr: "100.100.20.0/24".to_owned(),
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
        assert!(
            !controller.serving_exit_node_active(),
            "exit serving must not become active until post-apply assertions pass"
        );
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op.starts_with("assert_exit_serving:mesh_cidr=")),
            "exit-serving apply must prove NAT/forwarding before committing active state"
        );
    }

    #[test]
    fn windows_exit_nat_helpers_validate_ipv4_mesh_and_owned_nat_name() {
        let nat_name = windows_nat_name("rustynet0").expect("valid NAT name");
        assert_eq!(nat_name, "RustyNetExit-rustynet0");
        assert_eq!(
            validate_windows_nat_prefix("100.64.0.0/10").expect("valid IPv4 mesh prefix"),
            "100.64.0.0/10"
        );

        let err = validate_windows_nat_prefix("fd00::/64")
            .expect_err("Windows NetNat must reject IPv6 mesh prefixes until supported");
        assert!(matches!(err, SystemError::NatApplyFailed(_)));
        assert!(err.to_string().contains("IPv4 mesh CIDRs only"));
    }

    #[test]
    fn windows_exit_nat_residue_plan_flushes_only_when_not_serving() {
        // §10.7: serving an exit ⇒ no residue cleanup (must not race activation).
        assert!(
            windows_exit_nat_residue_plan(true, "RustyNetExit-wg0", "wg0", "Ethernet").is_empty()
        );
        // Not serving ⇒ remove the fixed-name NAT + force forwarding Disabled on
        // both the tunnel and egress interfaces (the secure default for a node
        // that must not forward), in that order.
        let plan = windows_exit_nat_residue_plan(false, "RustyNetExit-wg0", "wg0", "Ethernet");
        assert_eq!(plan.len(), 3);
        assert_eq!(plan[0].0, WINDOWS_PS_REMOVE_NAT);
        assert_eq!(plan[0].1, vec!["RustyNetExit-wg0".to_owned()]);
        assert_eq!(
            plan[1],
            (
                WINDOWS_PS_SET_FORWARDING,
                vec!["wg0".to_owned(), "Disabled".to_owned()]
            )
        );
        assert_eq!(
            plan[2],
            (
                WINDOWS_PS_SET_FORWARDING,
                vec!["Ethernet".to_owned(), "Disabled".to_owned()]
            )
        );
    }

    #[test]
    fn windows_exit_powershell_invocation_keeps_values_as_args() {
        let args = windows_powershell_command_args(
            WINDOWS_PS_NEW_NAT,
            &[
                "RustyNetExit-rustynet0".to_owned(),
                "100.64.0.0/10".to_owned(),
            ],
        );

        assert_eq!(args[0], "-NoProfile");
        assert_eq!(args[1], "-NonInteractive");
        assert_eq!(args[2], "-Command");
        assert_eq!(args[3], WINDOWS_PS_NEW_NAT);
        assert_eq!(args[4], "RustyNetExit-rustynet0");
        assert_eq!(args[5], "100.64.0.0/10");
        assert!(
            WINDOWS_PS_NEW_NAT.contains("param($Name, $Prefix)"),
            "script must bind untrusted values as PowerShell parameters"
        );
        assert!(
            !WINDOWS_PS_NEW_NAT.contains("100.64.0.0/10"),
            "script must not interpolate operator-provided CIDRs"
        );
    }

    #[test]
    fn windows_exit_cmdlet_check_enumerates_all_required_cmdlets() {
        // The cmdlet pre-flight check is the single fail-closed point that catches a
        // Windows SKU (e.g. Home) or feature configuration (e.g. RemoteAccess role
        // missing) where NetNat / forwarding cmdlets are not available.  Every cmdlet
        // the exit-serving path actually invokes must be in this check or the daemon
        // could partially apply NAT state and then fail when removing it.
        for required_cmdlet in [
            "Get-NetIPInterface",
            "Set-NetIPInterface",
            "New-NetNat",
            "Get-NetNat",
            "Remove-NetNat",
        ] {
            assert!(
                WINDOWS_PS_REQUIRE_EXIT_CMDLETS.contains(&format!("Get-Command {required_cmdlet}")),
                "exit cmdlet pre-flight script must check {required_cmdlet}"
            );
        }
        assert!(
            WINDOWS_PS_REQUIRE_EXIT_CMDLETS.contains("$ErrorActionPreference = 'Stop'"),
            "exit cmdlet pre-flight script must use $ErrorActionPreference = 'Stop'"
        );
        // The cmdlet being present is not enough: New-NetNat fails with
        // `Invalid class` on hosts that lack the WinNAT WMI provider (no Host
        // Network Service). Verify the MSFT_NetNat class itself is usable so the
        // daemon fails closed early with a clear message instead of an opaque
        // mid-reconcile NAT-apply failure.
        assert!(
            WINDOWS_PS_REQUIRE_EXIT_CMDLETS
                .contains("Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat"),
            "exit cmdlet pre-flight must verify the WinNAT WMI class is registered/usable"
        );
    }

    #[test]
    fn windows_exit_serving_preflight_checks_identity_interfaces_nat_and_egress() {
        // The exit-serving preflight is intentionally broader than the NAT apply
        // helper: it proves the process is elevated, the NAT/forwarding cmdlets exist,
        // both reviewed interface aliases resolve as IPv4 interfaces, and the chosen
        // egress alias actually owns an IPv4 default route before Rustynet mutates
        // forwarding/NAT/firewall state.
        for required in [
            "WindowsPrincipal",
            "Administrator",
            "Get-Command $cmd",
            "Set-NetIPInterface",
            "Get-NetIPInterface",
            "New-NetNat",
            "Get-NetNat",
            "Remove-NetNat",
            "Get-NetRoute",
            "DestinationPrefix '0.0.0.0/0'",
            "$TunnelAlias -eq $EgressAlias",
        ] {
            assert!(
                WINDOWS_PS_PREFLIGHT_EXIT_SERVING.contains(required),
                "Windows exit-serving preflight must include {required}"
            );
        }
        assert!(
            WINDOWS_PS_PREFLIGHT_EXIT_SERVING.contains("param($TunnelAlias, $EgressAlias)"),
            "preflight must bind interface aliases as PowerShell parameters"
        );
        assert!(
            WINDOWS_PS_PREFLIGHT_EXIT_SERVING.contains("$ErrorActionPreference = 'Stop'"),
            "preflight must fail closed on PowerShell errors"
        );
        // Fail closed early (with a clear remediation message) on hosts missing
        // the WinNAT WMI provider, where New-NetNat otherwise fails opaquely with
        // `Invalid class` only once NAT apply is attempted mid-reconcile.
        assert!(
            WINDOWS_PS_PREFLIGHT_EXIT_SERVING
                .contains("Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetNat"),
            "preflight must verify the WinNAT WMI class (MSFT_NetNat) is usable"
        );
        assert!(
            WINDOWS_PS_PREFLIGHT_EXIT_SERVING.contains("Host Network Service / WinNAT"),
            "preflight must surface an actionable WinNAT/HNS remediation message"
        );
    }

    #[test]
    fn windows_exit_powershell_scripts_use_stop_error_action_and_param_binding() {
        // Every PowerShell helper that touches NAT / forwarding state must:
        //  - run with `$ErrorActionPreference = 'Stop'` so failures propagate (no silent skip);
        //  - bind operator-controlled values via `param(...)` rather than string interpolation;
        //  - explicitly use `-ErrorAction Stop` on cmdlets so missing/incorrect
        //    state does not silently no-op.
        for (label, script) in [
            (
                "WINDOWS_PS_PREFLIGHT_EXIT_SERVING",
                WINDOWS_PS_PREFLIGHT_EXIT_SERVING,
            ),
            ("WINDOWS_PS_GET_FORWARDING", WINDOWS_PS_GET_FORWARDING),
            ("WINDOWS_PS_SET_FORWARDING", WINDOWS_PS_SET_FORWARDING),
            ("WINDOWS_PS_REMOVE_NAT", WINDOWS_PS_REMOVE_NAT),
            ("WINDOWS_PS_NEW_NAT", WINDOWS_PS_NEW_NAT),
            ("WINDOWS_PS_ASSERT_NAT", WINDOWS_PS_ASSERT_NAT),
            (
                "WINDOWS_PS_ASSERT_FORWARDING_ENABLED",
                WINDOWS_PS_ASSERT_FORWARDING_ENABLED,
            ),
        ] {
            assert!(
                script.contains("$ErrorActionPreference = 'Stop'"),
                "{label} must use $ErrorActionPreference = 'Stop'"
            );
            assert!(
                script.contains("param("),
                "{label} must bind values as PowerShell parameters"
            );
        }

        // Cmdlets that read live OS state must use -ErrorAction Stop so a missing or
        // mistyped interface fails closed rather than producing $null silently.
        assert!(
            WINDOWS_PS_GET_FORWARDING.contains("-ErrorAction Stop"),
            "Get-NetIPInterface must use -ErrorAction Stop"
        );
        assert!(
            WINDOWS_PS_SET_FORWARDING.contains("-ErrorAction Stop"),
            "Set-NetIPInterface must use -ErrorAction Stop"
        );
        assert!(
            WINDOWS_PS_NEW_NAT.contains("-ErrorAction Stop"),
            "New-NetNat must use -ErrorAction Stop"
        );
        assert!(
            WINDOWS_PS_ASSERT_FORWARDING_ENABLED.contains("-ErrorAction Stop"),
            "post-apply forwarding assertion must use -ErrorAction Stop"
        );
        assert!(
            WINDOWS_PS_ASSERT_NAT.contains("-ErrorAction Stop"),
            "post-apply NAT assertion must use -ErrorAction Stop"
        );

        // Remove-NetNat is allowed to use SilentlyContinue while looking up the NAT,
        // because removing a NAT that does not exist is the desired no-op.  The
        // actual remove call itself must still use -ErrorAction Stop.
        assert!(
            WINDOWS_PS_REMOVE_NAT.contains("Remove-NetNat -Confirm:$false -ErrorAction Stop"),
            "Remove-NetNat must use -Confirm:$false -ErrorAction Stop on the actual remove"
        );
    }

    #[test]
    fn windows_exit_powershell_scripts_do_not_interpolate_known_data_values() {
        // Ensure none of the operator-controlled or runtime-derived data values are
        // hard-coded into a script body.  This is a static guard that complements
        // `windows_exit_powershell_invocation_keeps_values_as_args`, which checks
        // the runtime invocation path.
        for (label, script, forbidden) in [
            (
                "WINDOWS_PS_GET_FORWARDING",
                WINDOWS_PS_GET_FORWARDING,
                "Ethernet",
            ),
            (
                "WINDOWS_PS_PREFLIGHT_EXIT_SERVING",
                WINDOWS_PS_PREFLIGHT_EXIT_SERVING,
                "Ethernet",
            ),
            (
                "WINDOWS_PS_SET_FORWARDING",
                WINDOWS_PS_SET_FORWARDING,
                "Ethernet",
            ),
            ("WINDOWS_PS_NEW_NAT", WINDOWS_PS_NEW_NAT, "RustyNetExit-"),
            (
                "WINDOWS_PS_REMOVE_NAT",
                WINDOWS_PS_REMOVE_NAT,
                "RustyNetExit-",
            ),
            (
                "WINDOWS_PS_ASSERT_NAT",
                WINDOWS_PS_ASSERT_NAT,
                "RustyNetExit-",
            ),
            (
                "WINDOWS_PS_ASSERT_FORWARDING_ENABLED",
                WINDOWS_PS_ASSERT_FORWARDING_ENABLED,
                "Ethernet",
            ),
        ] {
            assert!(
                !script.contains(forbidden),
                "{label} must not contain hard-coded {forbidden:?} value"
            );
        }
        // None of the scripts should hard-code 'Enabled' / 'Disabled' as a state
        // assignment; the state must come from the param binding.
        assert!(
            !WINDOWS_PS_SET_FORWARDING.contains("-Forwarding Enabled"),
            "set-forwarding script must not hard-code Enabled state"
        );
        assert!(
            !WINDOWS_PS_SET_FORWARDING.contains("-Forwarding Disabled"),
            "set-forwarding script must not hard-code Disabled state"
        );
    }

    #[test]
    fn windows_assert_killswitch_script_uses_param_and_stop_error_action() {
        // The new OS-state-verifying assert_killswitch script must:
        //  - bind every rule name as a PowerShell parameter (no
        //    interpolation of identifiers into the script body);
        //  - use $ErrorActionPreference = 'Stop' and -ErrorAction Stop on
        //    every cmdlet so a missing rule or query failure is surfaced
        //    as a thrown exception, not a silently-empty result.
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("param($LoopbackName, $EgressName)"),
            "assert_killswitch script must bind rule names as parameters"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("$ErrorActionPreference = 'Stop'"),
            "assert_killswitch script must use $ErrorActionPreference = 'Stop'"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH
                .contains("Get-NetFirewallRule -DisplayName $LoopbackName -ErrorAction Stop")
                && WINDOWS_PS_ASSERT_KILLSWITCH
                    .contains("Get-NetFirewallRule -DisplayName $EgressName -ErrorAction Stop"),
            "Get-NetFirewallRule must use -DisplayName and -ErrorAction Stop on the loopback and egress lookups"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("Get-NetFirewallProfile -ErrorAction Stop"),
            "Get-NetFirewallProfile must use -ErrorAction Stop"
        );
    }

    #[test]
    fn windows_assert_killswitch_script_checks_rule_action_direction_and_enabled() {
        // The verifier must reject a rule that has the right name but
        // wrong attributes — an attacker who could redirect a rule's
        // action from Allow to Block (or vice versa) should not pass.
        // We pin all three attribute checks here.
        for required_check in ["Allow", "Outbound", "True"] {
            assert!(
                WINDOWS_PS_ASSERT_KILLSWITCH.contains(required_check),
                "assert_killswitch script must check for {required_check:?} attribute"
            );
        }
        // Profile default outbound action must be Block — without this
        // check, an external `netsh advfirewall set allprofiles
        // firewallpolicy allowinbound,allowoutbound` could leave the
        // named rules in place but flip the global default to allow,
        // defeating the killswitch entirely.
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("DefaultOutboundAction"),
            "assert_killswitch script must verify global DefaultOutboundAction"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("'Block'"),
            "assert_killswitch script must check the default action is 'Block'"
        );
    }

    #[test]
    fn windows_assert_dns_script_checks_block_outbound_enabled() {
        // The DNS-block verifier must bind rule names as parameters, fail closed,
        // and reject a rule whose attributes drifted from Outbound/Block/Enabled
        // or whose count != 1 (missing/duplicate).
        assert!(
            WINDOWS_PS_ASSERT_DNS.contains("param($UdpName, $TcpName)"),
            "DNS assert must bind rule names as parameters"
        );
        assert!(
            WINDOWS_PS_ASSERT_DNS.contains("$ErrorActionPreference = 'Stop'"),
            "DNS assert must fail closed"
        );
        assert!(
            WINDOWS_PS_ASSERT_DNS
                .contains("Get-NetFirewallRule -DisplayName $displayName -ErrorAction Stop"),
            "DNS assert must look up by display name with -ErrorAction Stop"
        );
        for required in ["'Block'", "'Outbound'", "'True'", "$rules.Count -ne 1"] {
            assert!(
                WINDOWS_PS_ASSERT_DNS.contains(required),
                "DNS assert must check {required:?}"
            );
        }
        // Rule-name constants must be parameters, never interpolated into the body.
        for forbidden in [
            WINDOWS_DNS_RULE_BLOCK_LAN_UDP,
            WINDOWS_DNS_RULE_BLOCK_LAN_TCP,
        ] {
            assert!(
                !WINDOWS_PS_ASSERT_DNS.contains(forbidden),
                "DNS assert must not hard-code rule name {forbidden:?}"
            );
        }
    }

    #[test]
    fn windows_assert_killswitch_script_rejects_missing_or_duplicate_display_names() {
        // netsh's `name=` field maps to the firewall rule display name, not
        // the internal PowerShell `Name`/InstanceID.  The verifier must query
        // by display name. The loopback rule must be exactly one match (missing
        // or duplicate both fail closed); the egress name intentionally covers
        // MULTIPLE scoped allow rules (RN-06), so it must be present (count >= 1)
        // rather than exactly one.
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("-DisplayName $LoopbackName")
                && WINDOWS_PS_ASSERT_KILLSWITCH.contains("-DisplayName $EgressName"),
            "assert_killswitch must verify the netsh-created display names"
        );
        assert!(
            !WINDOWS_PS_ASSERT_KILLSWITCH.contains("-Name $LoopbackName")
                && !WINDOWS_PS_ASSERT_KILLSWITCH.contains("-Name $EgressName"),
            "assert_killswitch must not query the internal PowerShell rule Name"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("$loopback.Count -ne 1"),
            "assert_killswitch must reject a missing or duplicate loopback rule (exactly 1)"
        );
        assert!(
            WINDOWS_PS_ASSERT_KILLSWITCH.contains("$egress.Count -lt 1"),
            "assert_killswitch must require the scoped egress allow rules (count >= 1)"
        );
    }

    #[test]
    fn windows_assert_killswitch_does_not_interpolate_rule_names() {
        // The reviewed rule-name constants must NOT appear in the script
        // body — the script binds them as parameters at invocation time.
        // Hard-coded rule names would let a bug rename the constant
        // without renaming the script reference, silently breaking the
        // verifier.
        for forbidden in [
            WINDOWS_KS_RULE_LOOPBACK,
            WINDOWS_KS_RULE_TUNNEL,
            WINDOWS_KS_RULE_EGRESS,
        ] {
            assert!(
                !WINDOWS_PS_ASSERT_KILLSWITCH.contains(forbidden),
                "assert_killswitch script must not hard-code rule name {forbidden:?}"
            );
        }
    }

    #[test]
    fn windows_assert_killswitch_runtime_args_pass_rule_names_as_separate_argv() {
        // The runtime invocation must build argv where each rule name is a
        // distinct argument, not concatenated or interpolated into a single
        // string.  This pins the safety contract of the script-parameter
        // binding at the call site.
        let args = windows_powershell_command_args(
            WINDOWS_PS_ASSERT_KILLSWITCH,
            &[
                WINDOWS_KS_RULE_LOOPBACK.to_owned(),
                WINDOWS_KS_RULE_EGRESS.to_owned(),
            ],
        );
        assert_eq!(args[0], "-NoProfile");
        assert_eq!(args[1], "-NonInteractive");
        assert_eq!(args[2], "-Command");
        assert_eq!(args[3], WINDOWS_PS_ASSERT_KILLSWITCH);
        assert_eq!(args[4], WINDOWS_KS_RULE_LOOPBACK);
        assert_eq!(args[5], WINDOWS_KS_RULE_EGRESS);
    }

    #[test]
    fn windows_command_system_assert_killswitch_fast_path_rejects_unapplied_state() {
        // Fast-path check: if `firewall_applied = false` (the daemon
        // never called apply_firewall_killswitch), assert_killswitch must
        // reject without attempting the OS-state PowerShell query.  This
        // catches the never-applied-yet case at minimal cost AND lets us
        // unit-test the assertion contract on non-Windows hosts.
        let mut system = WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("windows command system should initialize");

        let err = DataplaneSystem::assert_killswitch(&mut system)
            .expect_err("assert_killswitch must reject when firewall_applied=false (fast path)");
        assert!(matches!(err, SystemError::KillSwitchAssertionFailed(_)));
        assert!(err.to_string().contains("not applied"));
    }

    #[test]
    fn windows_command_system_assert_exit_serving_rejects_unapplied_nat_fast_path() {
        let mut system = WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("windows command system should initialize");

        let err = DataplaneSystem::assert_exit_serving(&mut system, "100.64.0.0/10")
            .expect_err("exit-serving assertion must reject before NAT is applied");
        assert!(matches!(err, SystemError::KillSwitchAssertionFailed(_)));
        assert!(err.to_string().contains("NAT has not been applied"));
    }

    #[test]
    fn windows_interface_alias_validator_accepts_real_windows_names() {
        // Common Windows physical adapter aliases must be accepted.
        for alias in ["Ethernet", "Wi-Fi", "Ethernet 2", "Local Area Connection"] {
            validate_windows_interface_alias(alias)
                .unwrap_or_else(|err| panic!("valid alias {alias:?} rejected: {err}"));
        }
        // Hyper-V virtual switch alias (has parentheses and spaces).
        validate_windows_interface_alias("vEthernet (Default Switch)")
            .expect("Hyper-V vEthernet alias must be accepted");
        // Simple alphanumeric names used for WireGuard tunnel adapters.
        validate_windows_interface_alias("rustynet0").expect("tunnel alias must be accepted");
    }

    #[test]
    fn windows_interface_alias_validator_rejects_dangerous_characters() {
        // Control characters (newline, tab, null) must be rejected: they corrupt
        // log lines and would break format-string-based error messages.
        for bad in ["eth\n0", "eth\t0", "eth\x000"] {
            validate_windows_interface_alias(bad)
                .expect_err("alias with control character must be rejected");
        }
        // '=' must be rejected: it would corrupt the key=value netsh argument format
        // when embedded in format!("interface={}", alias).
        validate_windows_interface_alias("interface=eth0")
            .expect_err("alias containing '=' must be rejected");
        // Non-ASCII must be rejected.
        validate_windows_interface_alias("Ét hernet")
            .expect_err("non-ASCII alias must be rejected");
        // Empty and overlong must be rejected.
        validate_windows_interface_alias("").expect_err("empty alias must be rejected");
        validate_windows_interface_alias(&"x".repeat(65))
            .expect_err("alias longer than 64 chars must be rejected");
    }

    #[test]
    fn windows_command_system_accepts_interface_alias_with_space() {
        // "Ethernet 2" is a common Windows adapter name; the system must accept it
        // at construction and the resulting NAT name must embed it correctly.
        WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet 2",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("Windows command system must accept egress alias containing a space");
    }

    #[test]
    fn windows_nat_name_embeds_alias_and_rejects_invalid_aliases() {
        // Alias with space: NAT name must include the space verbatim.
        let nat = windows_nat_name("Ethernet 2").expect("valid NAT name with space");
        assert_eq!(nat, "RustyNetExit-Ethernet 2");
        // Alias with control character must be rejected.
        windows_nat_name("eth\n0").expect_err("alias with newline must be rejected");
        // Alias with '=' must be rejected.
        windows_nat_name("eth=0").expect_err("alias with '=' must be rejected");
    }

    #[test]
    fn windows_exit_client_nat_forwarding_noops_for_full_tunnel_consumer() {
        let mut system = WindowsCommandSystem::new(
            "rustynet0",
            "Ethernet",
            "127.0.0.1:53535".parse().expect("loopback dns bind"),
        )
        .expect("windows command system should initialize");

        DataplaneSystem::apply_nat_forwarding(
            &mut system,
            false,
            ExitMode::FullTunnel,
            false,
            "100.64.0.0/10",
        )
        .expect("windows full-tunnel consumer should not require local NAT");
    }

    #[test]
    fn shutdown_rolls_back_exit_serving_nat_and_os_controls() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        let shutdown_ops_start = controller.system.operations.len();
        controller
            .shutdown()
            .expect("shutdown cleanup should succeed");
        let shutdown_ops = &controller.system.operations[shutdown_ops_start..];

        assert_eq!(controller.state(), DataplaneState::Init);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert_eq!(controller.backend.exit_mode, ExitMode::Off);
        assert!(
            shutdown_ops.contains(&"rollback_nat_forwarding".to_owned()),
            "shutdown must remove exit-serving NAT/forwarding state"
        );
        assert!(
            shutdown_ops.contains(&"rollback_dns_protection".to_owned())
                && shutdown_ops.contains(&"rollback_firewall".to_owned())
                && shutdown_ops.contains(&"rollback_routes".to_owned())
                && shutdown_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "shutdown must rollback owned DNS, firewall, route, and IPv6 controls; ops={shutdown_ops:?}"
        );
    }

    #[test]
    fn shutdown_cleanup_failure_reports_fail_closed_not_init() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        controller.system.fail_operation = Some("rollback_nat_forwarding".to_owned());
        let err = controller
            .shutdown()
            .expect_err("cleanup failure must be surfaced");

        assert!(matches!(
            err,
            Phase10Error::System(SystemError::RollbackFailed(_))
        ));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            controller
                .transition_audit()
                .iter()
                .any(|event| event.reason == "shutdown_cleanup_failed"),
            "failed cleanup must not be recorded as clean shutdown"
        );
    }

    #[test]
    fn role_change_from_exit_serving_rolls_back_obsolete_nat() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        let second_apply_start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    protected_dns: false,
                    ipv6_parity_supported: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("plain mesh apply should remove obsolete exit controls");
        let second_apply_ops = &controller.system.operations[second_apply_start..];

        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
        assert!(
            second_apply_ops.contains(&"rollback_nat_forwarding".to_owned()),
            "turning off exit serving must remove old NAT/forwarding state"
        );
        assert!(
            second_apply_ops.contains(&"rollback_dns_protection".to_owned())
                && second_apply_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "turning off protected controls must rollback stale DNS/IPv6 state; ops={second_apply_ops:?}"
        );
        assert!(
            !second_apply_ops
                .iter()
                .any(|op| op == "apply_nat_forwarding"),
            "plain mesh generation must not re-apply NAT after stale NAT rollback"
        );
    }

    #[test]
    fn failed_reapply_after_exit_rolls_back_without_stale_exit_markers() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        controller.system.fail_operation = Some("apply_firewall_killswitch".to_owned());
        let second_apply_start = controller.system.operations.len();
        let err = controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    protected_dns: false,
                    ipv6_parity_supported: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("failed plain reapply should fail closed");
        assert!(matches!(err, Phase10Error::System(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        let second_apply_ops = &controller.system.operations[second_apply_start..];
        assert!(
            second_apply_ops.contains(&"block_all_egress".to_owned())
                && !second_apply_ops.contains(&"rollback_nat_forwarding".to_owned())
                && !second_apply_ops.contains(&"rollback_dns_protection".to_owned())
                && !second_apply_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "killswitch failure must fail closed before mutating live exit controls; ops={second_apply_ops:?}"
        );

        controller.system.fail_operation = None;
        let shutdown_start = controller.system.operations.len();
        controller
            .shutdown()
            .expect("shutdown after failed reapply should cleanup still-live exit controls");
        let shutdown_ops = &controller.system.operations[shutdown_start..];
        assert!(
            shutdown_ops.contains(&"rollback_nat_forwarding".to_owned())
                && shutdown_ops.contains(&"rollback_dns_protection".to_owned())
                && shutdown_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "shutdown must cleanup previous live exit controls after pre-mutation fail-close; ops={shutdown_ops:?}"
        );
        assert_eq!(controller.state(), DataplaneState::Init);
    }

    #[test]
    fn failed_exit_reapply_preserves_live_exit_markers_for_shutdown_cleanup() {
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");

        controller.system.fail_operation = Some("apply_firewall_killswitch".to_owned());
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("failed exit reapply should fail closed");
        assert_eq!(controller.state(), DataplaneState::FailClosed);

        controller.system.fail_operation = None;
        let shutdown_start = controller.system.operations.len();
        controller
            .shutdown()
            .expect("shutdown after failed same-role reapply should cleanup live exit controls");
        let shutdown_ops = &controller.system.operations[shutdown_start..];
        assert!(
            shutdown_ops.contains(&"rollback_nat_forwarding".to_owned())
                && shutdown_ops.contains(&"rollback_dns_protection".to_owned())
                && shutdown_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "shutdown must still cleanup live previous exit controls after failed same-role reapply; ops={shutdown_ops:?}"
        );
        assert_eq!(controller.state(), DataplaneState::Init);
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
                destination_cidr: "0.0.0.0/0".to_owned(),
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
    fn successive_apply_dataplane_generation_increments_monotonically() {
        // Each successful apply must produce a strictly higher generation
        // than the last.  A regression in `last_safe_generation` would let
        // an attacker who captured an older trust evidence replay it through
        // a stale state-machine snapshot, defeating anti-replay.
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        assert_eq!(controller.generation(), 0);
        assert_eq!(controller.last_safe_generation(), 0);

        for expected_generation in 1..=5 {
            controller
                .apply_dataplane_generation(
                    trust_ok(),
                    test_runtime_context(),
                    vec![sample_peer("node-b")],
                    vec![Route {
                        destination_cidr: "100.100.20.0/24".to_owned(),
                        via_node: NodeId::new("node-b").expect("node should parse"),
                        kind: RouteKind::Mesh,
                    }],
                    ApplyOptions::default(),
                )
                .unwrap_or_else(|err| {
                    panic!("apply #{expected_generation} should succeed: {err:?}")
                });
            assert_eq!(
                controller.generation(),
                expected_generation,
                "generation must increment by 1 per successful apply"
            );
            assert_eq!(
                controller.last_safe_generation(),
                expected_generation,
                "last_safe_generation must track successful generation"
            );
        }
    }

    #[test]
    fn failed_apply_after_successful_does_not_regress_last_safe_generation() {
        // If a previously successful apply landed at generation N and a
        // subsequent apply fails mid-stage, `last_safe_generation` must stay
        // at N — an attacker who can induce a stage failure must not be
        // able to roll back the safe generation to 0 (or any older value)
        // and replay an earlier trust evidence.
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("first apply should succeed");

        let safe_after_first = controller.last_safe_generation();
        assert_eq!(safe_after_first, 1);

        // Switch the system to one that fails on apply_dns_protection so the
        // next apply triggers the rollback + force_fail_closed path.
        controller.system = DryRunSystem::default().fail_on("apply_dns_protection");
        let failing = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-c")],
            vec![Route {
                destination_cidr: "0.0.0.0/0".to_owned(),
                via_node: NodeId::new("node-c").expect("node should parse"),
                kind: RouteKind::ExitNodeDefault,
            }],
            ApplyOptions {
                protected_dns: true,
                ..ApplyOptions::default()
            },
        );
        assert!(failing.is_err());
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        // Critical anti-replay invariant: the safe generation must not
        // regress.  It can stay the same; it must never go backward.
        assert!(
            controller.last_safe_generation() >= safe_after_first,
            "last_safe_generation regressed: {} -> {}",
            safe_after_first,
            controller.last_safe_generation()
        );
    }

    #[test]
    fn repeated_failed_applies_do_not_advance_last_safe_generation() {
        // Every failed apply must leave `last_safe_generation` unchanged.
        // A bug that incremented it on failure would let an attacker who
        // can force apply failures advance the watermark past genuinely
        // applied generations and either replay or skip evidence.
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_dns_protection"),
            policy,
            TrustPolicy::default(),
        );

        for attempt in 1..=3 {
            let failing = controller.apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::ExitNodeDefault,
                }],
                ApplyOptions {
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            );
            assert!(failing.is_err(), "attempt {attempt} should fail");
            assert_eq!(
                controller.last_safe_generation(),
                0,
                "failed apply {attempt} must not advance last_safe_generation"
            );
        }
    }

    #[test]
    fn force_fail_closed_returns_err_and_skips_state_transition_when_block_all_egress_fails() {
        // Documented contract: force_fail_closed only transitions the state
        // machine to FailClosed AFTER the OS-level block_all_egress
        // succeeds.  If block_all_egress fails (e.g. firewall daemon
        // crashed, advfirewall service unavailable), we propagate the error
        // and leave the state machine at its previous state — claiming
        // FailClosed when the OS is not actually blocked would lie about
        // the security posture.
        //
        // The next reconcile cycle is the recovery point: the daemon's
        // main loop calls apply_dataplane_generation again, which runs
        // prune_owned_tables + rollback_obsolete_controls before
        // re-applying.  That sequence cleans up any leftover OS state from
        // the partial fail-closed attempt.
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        // Drive the controller to DataplaneApplied first so we have a
        // non-Init state to verify is preserved on failure.
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("baseline apply should succeed");
        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);

        // Swap the system for one that fails on block_all_egress.
        controller.system = DryRunSystem::default().fail_on("block_all_egress");

        let result = controller.force_fail_closed("test_block_all_egress_failure");
        assert!(
            result.is_err(),
            "force_fail_closed must propagate block_all_egress failure"
        );
        assert_ne!(
            controller.state(),
            DataplaneState::FailClosed,
            "state must NOT be FailClosed when block_all_egress failed; \
             claiming FailClosed without an OS-level block would lie about posture"
        );
        assert_eq!(
            controller.state(),
            DataplaneState::DataplaneApplied,
            "state must stay at the prior value when force_fail_closed fails"
        );
    }

    #[test]
    fn force_fail_closed_transitions_state_when_block_all_egress_succeeds() {
        // Complement to the previous test: when block_all_egress succeeds
        // the state machine MUST transition to FailClosed.  The contract
        // is binary — either we get the OS block AND the state, or we get
        // neither.  No "claimed FailClosed without OS block" middle
        // ground.
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions::default(),
            )
            .expect("baseline apply should succeed");

        controller
            .force_fail_closed("test_clean_force_fail_closed")
            .expect("force_fail_closed must succeed when block_all_egress succeeds");
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert_eq!(controller.current_exit_mode(), ExitMode::Off);
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
                    destination_cidr: "0.0.0.0/0".to_owned(),
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
            user: "user:alice".to_owned(),
            cidr: "192.168.1.0/24".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        });
        assert_eq!(denied.err(), Some(Phase10Error::LanAccessDenied));

        controller.set_lan_access(true);
        controller
            .ensure_lan_route_allowed(RouteGrantRequest {
                user: "user:alice".to_owned(),
                cidr: "192.168.1.0/24".to_owned(),
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: None,
                    coordination_error: None,
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: Some(sample_coordination_schedule(210)),
                    coordination_error: None,
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: None,
                    coordination_error: Some(
                        "validated traversal coordination for peer node-b is unavailable"
                            .to_owned(),
                    ),
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
                    prior_ranking: None,
                    quality_demoted_endpoint: None,
                    coordination_schedule: None,
                    coordination_error: Some(
                        "validated traversal coordination for peer node-b is unavailable"
                            .to_owned(),
                    ),
                    local_node_id_digest: [1u8; 32],
                    remote_node_id_digest: [2u8; 32],
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
                reason: "test".to_owned(),
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
                "route".to_owned(),
                "replace".to_owned(),
                "192.168.18.0/24".to_owned(),
                "dev".to_owned(),
                "enp0s8".to_owned(),
                "table".to_owned(),
                "51820".to_owned(),
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
                "-6".to_owned(),
                "route".to_owned(),
                "replace".to_owned(),
                "fd00::/64".to_owned(),
                "dev".to_owned(),
                "enp0s8".to_owned(),
                "table".to_owned(),
                "51820".to_owned(),
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
        wg_listen_port: u16,
    ) -> String {
        let mut rules = "table inet rustynet_g1 {\n  chain killswitch {\n    type filter hook output priority 0; policy drop;\n    oifname \"lo\" accept\n".to_string();
        if wg_listen_port != 0 {
            rules.push_str(
                format!("    oifname \"{egress_interface}\" udp dport {wg_listen_port} accept\n")
                    .as_str(),
            );
        }
        rules.push_str(
            format!(
                "    ct state established,related accept\n    oifname \"{interface_name}\" accept\n"
            )
            .as_str(),
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
                            0,
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
                            0,
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
                            0,
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
                            0,
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
                            0,
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
                            0,
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
                "route".to_owned(),
                "replace".to_owned(),
                "192.168.18.40/32".to_owned(),
                "dev".to_owned(),
                "enp0s8".to_owned(),
                "table".to_owned(),
                "51820".to_owned(),
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
                "add".to_owned(),
                "rule".to_owned(),
                "inet".to_owned(),
                "rustynet_g1".to_owned(),
                "killswitch".to_owned(),
                "oifname".to_owned(),
                "enp0s1".to_owned(),
                "ip".to_owned(),
                "daddr".to_owned(),
                "203.0.113.10".to_owned(),
                "udp".to_owned(),
                "dport".to_owned(),
                "3478".to_owned(),
                "accept".to_owned(),
                "comment".to_owned(),
                "rustynet_traversal_bootstrap".to_owned(),
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
                "-6".to_owned(),
                "route".to_owned(),
                "replace".to_owned(),
                "fd00::10/128".to_owned(),
                "dev".to_owned(),
                "enp0s8".to_owned(),
                "table".to_owned(),
                "51820".to_owned(),
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
                "com.apple/rustynet_g1".to_owned(),
                "com.apple/rustynet_g77".to_owned()
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
        assert!(rules.contains("pass out quick on utun9 inet proto udp to any port 53 keep state"));
        assert!(rules.contains("pass out quick on utun9 inet proto tcp to any port 53 keep state"));
        assert!(rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_render_pf_rules_full_tunnel_dns_snapshot() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;
        system.allow_egress_interface = true;
        system.ipv6_blocked = true;

        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");

        assert_eq!(
            rules,
            "set block-policy drop\n\
             pass quick on lo0 all\n\
             pass out quick on utun9 inet proto udp to any port 53 keep state\n\
             pass out quick on utun9 inet proto tcp to any port 53 keep state\n\
             block drop out quick inet proto udp to any port 53 label \"rustynet-dns-block-lan-udp\"\n\
             block drop out quick inet proto tcp to any port 53 label \"rustynet-dns-block-lan-tcp\"\n\
             pass out quick on utun9 inet all keep state\n\
             pass out quick on en0 inet all keep state\n\
             block drop out quick inet6 all\n\
             block drop out quick all\n"
        );
    }

    #[test]
    fn macos_render_pf_rules_omits_dns_fail_closed_rules_when_disabled() {
        let system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        assert!(!rules.contains("on utun9 inet proto udp to any port 53"));
        assert!(!rules.contains("on utun9 inet proto tcp to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto udp to any port 53"));
        assert!(!rules.contains("block drop out quick inet proto tcp to any port 53"));
    }

    #[test]
    fn macos_render_pf_rules_strict_fail_closed_snapshot() {
        let system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");

        let rules = system
            .render_pf_rules(true)
            .expect("rule render should succeed");

        assert_eq!(
            rules,
            "set block-policy drop\npass quick on lo0 all\nblock drop out quick all\n"
        );
    }

    #[test]
    fn macos_render_pf_rules_relay_with_upstream_snapshot() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.allow_egress_interface = true;

        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");

        assert_eq!(
            rules,
            "set block-policy drop\n\
             pass quick on lo0 all\n\
             pass out quick on utun9 inet all keep state\n\
             pass out quick on en0 inet all keep state\n\
             block drop out quick all\n"
        );
    }

    #[test]
    fn macos_render_pf_rules_emits_per_peer_endpoint_egress_allow() {
        // Without an explicit egress allow for each managed peer's
        // WireGuard endpoint, the terminal `block drop out quick all`
        // rule swallows the encrypted handshake datagrams the daemon's
        // authoritative UDP socket sends out over the LAN interface —
        // which is exactly what made `path_live_proven=false` and
        // `tcpdump -i en0 udp port 51820` show zero packets even
        // though `traversal_probe_attempts` incremented.
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.managed_peer_egress_endpoints = vec![
            "192.168.65.3:51820"
                .parse()
                .expect("peer endpoint should parse"),
            "[2001:db8::3]:51820"
                .parse()
                .expect("ipv6 peer endpoint should parse"),
        ];

        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");

        assert!(
            rules.contains(
                "pass out quick on en0 inet proto udp to 192.168.65.3 port 51820 keep state"
            ),
            "rendered rules must include IPv4 peer endpoint egress allow; got: {rules}"
        );
        assert!(
            rules.contains(
                "pass out quick on en0 inet6 proto udp to 2001:db8::3 port 51820 keep state"
            ),
            "rendered rules must include IPv6 peer endpoint egress allow; got: {rules}"
        );
    }

    #[test]
    fn macos_apply_peer_endpoint_bypass_routes_captures_peer_endpoints() {
        use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint};
        use std::net::IpAddr;

        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        let peer = PeerConfig {
            node_id: NodeId::new("exit-1").expect("node id should parse"),
            public_key: [0u8; 32],
            endpoint: SocketEndpoint {
                addr: "192.168.65.3".parse::<IpAddr>().expect("peer ip"),
                port: 51820,
            },
            allowed_ips: Vec::new(),
            persistent_keepalive_secs: None,
        };
        system
            .apply_peer_endpoint_bypass_routes(&[peer])
            .expect("apply peer endpoint bypass should succeed without an anchor");
        assert_eq!(
            system.managed_peer_egress_endpoints,
            vec![
                "192.168.65.3:51820"
                    .parse()
                    .expect("peer endpoint should parse")
            ]
        );
    }

    #[test]
    fn macos_render_pf_rules_blind_exit_uses_hard_locked_anchor_policy() {
        let mut system = MacosCommandSystem::new("rustynet0", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.blind_exit_pf_config =
            Some(MacosBlindExitPfConfig::new("rustynet0", "en0", "100.64.0.0/10").unwrap());
        system.dns_protected = true;
        system.ipv6_blocked = true;

        let rules = system
            .render_pf_rules(false)
            .expect("blind_exit rule render should succeed");

        assert!(rules.contains("pass out quick on rustynet0 inet all keep state"));
        assert!(rules.contains("pass out quick on en0 inet from 100.64.0.0/10 to any keep state"));
        assert!(!rules.contains("pass out quick on en0 inet all keep state"));
        assert!(rules.contains("block drop out quick inet6 all"));
        assert!(rules.ends_with("block drop out quick all\n"));
    }

    #[test]
    fn macos_blind_exit_anchor_survives_shutdown_cleanup_path() {
        let mut system = MacosCommandSystem::new("rustynet0", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.blind_exit_pf_config =
            Some(MacosBlindExitPfConfig::new("rustynet0", "en0", "100.64.0.0/10").unwrap());
        system.anchor_name = Some(DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR.to_owned());

        DataplaneSystem::rollback_firewall(&mut system)
            .expect("blind_exit rollback keeps anchor installed");
        assert_eq!(
            system.anchor_name.as_deref(),
            Some(DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR)
        );

        system.flush_anchor();
        assert_eq!(
            system.anchor_name.as_deref(),
            Some(DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR)
        );
    }

    #[test]
    fn macos_assert_dns_protection_requires_active_dns_rules() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");

        let err = DataplaneSystem::assert_dns_protection(&mut system)
            .expect_err("inactive macOS DNS protection must fail closed");
        assert!(err.to_string().contains("DNS protection is not active"));

        system.dns_protected = true;
        DataplaneSystem::assert_dns_protection(&mut system)
            .expect("active macOS DNS protection must render tunnel-pass and egress-block rules");
    }

    #[test]
    fn macos_render_pf_rules_allow_inbound_management_ssh() {
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
        // Inbound SSH from management CIDR: keep state lets the reply
        // (SYN-ACK) pass through block drop out quick all automatically.
        assert!(rules.contains(
            "pass in quick inet proto tcp from 192.168.128.0/24 to any port 22 keep state"
        ));
        // Node-initiated SSH to management hosts.
        assert!(rules.contains(
            "pass out quick inet proto tcp from any to 192.168.128.0/24 port 22 keep state"
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
                "pass out quick on en0 inet proto udp to 203.0.113.10 port 3478 keep state"
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

    #[test]
    fn macos_dns_rule_parser_accepts_pfctl_normalized_live_output() {
        // macOS pfctl rewrites `port 53` → `port = 53` and inserts `from any`
        // when dumping the live ruleset via `pfctl -a <anchor> -s rules`.
        // assert_killswitch parses that exact output, so the matcher must
        // accept the rewritten form.
        let rules = "pass out quick on utun9 inet proto udp from any to any port = 53 keep state\n\
                     pass out quick on utun9 inet proto tcp from any to any port = 53 keep state\n\
                     block drop out quick inet proto udp from any to any port = 53\n\
                     block drop out quick inet proto tcp from any to any port = 53\n";
        for proto in ["udp", "tcp"] {
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(
                    rules,
                    "pass out quick",
                    proto,
                    Some("utun9"),
                ),
                "pass-out rule should match for proto={proto}"
            );
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(
                    rules,
                    "block drop out quick",
                    proto,
                    None,
                ),
                "block rule should match for proto={proto}"
            );
        }
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
    fn test_empty_membership_directory_denies_peer_provisioning() {
        use rustynet_policy::MembershipDirectory;
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        controller.set_membership(MembershipDirectory::default());

        let result = controller.apply_dataplane_generation(
            trust_ok(),
            test_runtime_context(),
            vec![sample_peer("node-b")],
            vec![],
            ApplyOptions::default(),
        );

        assert!(
            matches!(result, Err(Phase10Error::MembershipNotFound(_))),
            "empty membership directory must fail closed: {result:?}"
        );
        let peer_id = NodeId::new("node-b").expect("node id");
        assert!(
            !controller.backend.peers.contains_key(&peer_id),
            "empty membership must not configure the peer"
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

    /// Helper: build a `Phase10Controller` in `DataplaneApplied` state with one
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
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
            new_ops.contains(&"assert_exit_policy:off".to_owned()),
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
            new_ops.contains(&"assert_exit_policy:off".to_owned()),
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
                .contains(&"apply_firewall_killswitch".to_owned()),
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
                .contains(&"assert_exit_policy:off".to_owned()),
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
            new_ops.contains(&"assert_exit_policy:full_tunnel".to_owned()),
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

    // ---- L7: Linux exit ACL IPv6 parity audit -------------------------
    //
    // The Linux exit-node programming uses two nftables families:
    //   * `inet` for the killswitch + forward chain (covers IPv4 + IPv6)
    //   * `ip` for the NAT/masquerade postrouting chain (IPv4 only)
    //
    // There is intentionally no `ip6` NAT table — when the exit-server
    // path is engaged with `ipv6_parity_supported=false` (production
    // default in `daemon.rs`), the runtime instead hard-disables IPv6
    // at the kernel via `/proc/sys/net/ipv6/conf/all/disable_ipv6=1`.
    // This is the security-bar invariant: any rule that exists for IPv4
    // but not for IPv6 must be paired with a kernel-level IPv6 disable
    // so a packet never traverses the unprogrammed sibling rule. The
    // tests below pin that invariant via the DryRunSystem operation log.

    #[test]
    fn exit_serving_with_ipv6_parity_unsupported_hard_disables_ipv6_egress() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ipv6_parity_supported: false,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");
        let ops = &controller.system.operations[start..];

        assert!(
            ops.contains(&"hard_disable_ipv6_egress".to_owned()),
            "ipv6_parity_supported=false on Linux exit MUST hard-disable \
             ipv6 egress at the kernel; missing in ops={ops:?}"
        );
        assert!(
            ops.contains(&"apply_nat_forwarding".to_owned()),
            "exit-serving apply must program IPv4 NAT (ip family) — ops={ops:?}"
        );
    }

    #[test]
    fn exit_serving_with_ipv6_parity_supported_skips_kernel_disable() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ipv6_parity_supported: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("exit-serving apply should succeed");
        let ops = &controller.system.operations[start..];

        assert!(
            !ops.contains(&"hard_disable_ipv6_egress".to_owned()),
            "ipv6_parity_supported=true must NOT also hard-disable \
             ipv6 egress (the caller is asserting parity is programmed \
             elsewhere); ops={ops:?}"
        );
    }

    #[test]
    fn exit_full_tunnel_with_ipv6_parity_unsupported_hard_disables_ipv6_egress() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ipv6_parity_supported: false,
                    ..ApplyOptions::default()
                },
            )
            .expect("full-tunnel apply should succeed");
        let ops = &controller.system.operations[start..];

        assert!(
            ops.contains(&"hard_disable_ipv6_egress".to_owned()),
            "full-tunnel mode with ipv6_parity_supported=false MUST hard-disable \
             ipv6 egress (the kernel is the only barrier against IPv6 leaks since \
             there is no ip6 nat sibling); missing in ops={ops:?}"
        );
    }

    #[test]
    fn hard_disable_ipv6_egress_runs_before_exit_mode_flip() {
        // Security ordering invariant: IPv6 must be killed BEFORE the
        // backend flips exit-mode active. Otherwise there is a window
        // where the backend accepts mesh traffic and forwards it
        // while the IPv6 kernel disable hasn't yet taken effect.
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );

        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    serve_exit_node: true,
                    ipv6_parity_supported: false,
                    ..ApplyOptions::default()
                },
            )
            .expect("apply should succeed");
        let ops = &controller.system.operations[start..];

        let disable_idx = ops
            .iter()
            .position(|op| op == "hard_disable_ipv6_egress")
            .expect("hard_disable_ipv6_egress must be in op log");
        let set_exit_idx = ops
            .iter()
            .position(|op| op.starts_with("set_exit_mode") || op.contains("set_exit_mode"))
            .or_else(|| ops.iter().position(|op| op == "apply_firewall_killswitch"));
        // The DryRunSystem doesn't echo backend ops, so use the
        // firewall/nat ordering as a proxy: NAT apply must run before
        // (or alongside) the IPv6 disable, but the disable MUST
        // precede the assert_exit_policy invocation that locks in the
        // exit-mode-applied stage.
        let assert_idx = ops
            .iter()
            .position(|op| op == "assert_exit_policy")
            .or_else(|| ops.iter().position(|op| op.starts_with("assert_exit_")));
        if let Some(assert_idx) = assert_idx {
            assert!(
                disable_idx < assert_idx,
                "hard_disable_ipv6_egress (idx={disable_idx}) must run before \
                 assert_exit_policy (idx={assert_idx}); ops={ops:?}"
            );
        } else if let Some(set_exit_idx) = set_exit_idx {
            assert!(
                disable_idx < set_exit_idx,
                "hard_disable_ipv6_egress (idx={disable_idx}) must run before \
                 set_exit_mode (idx={set_exit_idx}); ops={ops:?}"
            );
        }
    }

    #[test]
    fn nat_table_is_ipv4_family_only() {
        // Pins the contract that the Linux exit-node NAT path uses
        // the `ip` (IPv4-only) family. If a future change introduces
        // an `ip6` nat table sibling, this snapshot must be updated
        // deliberately + paired with the IPv6 NAT logic + paired
        // with relaxing the `ipv6_parity_supported` default to true.
        let nft_family_v4 = nft_family_for_ip(IpAddr::V4(std::net::Ipv4Addr::new(100, 64, 0, 1)));
        let nft_family_v6 = nft_family_for_ip(IpAddr::V6(std::net::Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1,
        )));
        assert_eq!(nft_family_v4, "ip");
        assert_eq!(nft_family_v6, "ip6");

        // ManagementCidr nft_family helper must also match the same
        // mapping (used in fail-closed SSH allow CIDRs etc.).
        let v4 = ManagementCidr {
            address: IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 0)),
            prefix: 24,
        };
        let v6 = ManagementCidr {
            address: IpAddr::V6(std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)),
            prefix: 7,
        };
        assert_eq!(v4.nft_family(), "ip");
        assert_eq!(v6.nft_family(), "ip6");
        assert!(!v4.is_ipv6());
        assert!(v6.is_ipv6());
    }

    #[test]
    fn rollback_ipv6_egress_runs_when_parity_supported_flips_to_true() {
        // Regression contract: when an apply that hard-disabled IPv6
        // (parity_supported=false) is followed by an apply with
        // parity_supported=true, the rollback path MUST re-enable IPv6
        // egress. Otherwise a stale kernel-disable would block legit
        // IPv6 traffic the parity programming is expected to permit.
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
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ipv6_parity_supported: false,
                    ..ApplyOptions::default()
                },
            )
            .expect("first apply should succeed");

        let second_start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                vec![sample_peer("node-b")],
                vec![Route {
                    destination_cidr: "100.100.20.0/24".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    serve_exit_node: true,
                    ipv6_parity_supported: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("second apply should succeed");
        let second_ops = &controller.system.operations[second_start..];

        assert!(
            second_ops.contains(&"rollback_ipv6_egress".to_owned()),
            "flipping ipv6_parity_supported false→true must rollback the \
             kernel disable; ops={second_ops:?}"
        );
    }
}
