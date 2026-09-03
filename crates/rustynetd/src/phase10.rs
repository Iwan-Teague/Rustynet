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
use crate::macos_tandem_dns_redirect::{
    MacosTandemDnsRedirectPfConfig, evaluate_macos_tandem_dns_redirect_filter,
    evaluate_macos_tandem_dns_redirect_translation,
};
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
use rustynet_control::managed_dns_handoff::MeshIpv4Prefix;
#[cfg(test)]
use rustynet_control::tandem_dns_redirect::TandemDnsEgressBlockPolicy;
use rustynet_control::tandem_dns_redirect::TandemDnsRedirectDecision;
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
const NETWORKSETUP_BINARY_PATH_ENV: &str = "RUSTYNET_NETWORKSETUP_BINARY_PATH";
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
const DEFAULT_NETWORKSETUP_BINARY_PATH: &str =
    crate::macos_dns_sc_protect::NETWORKSETUP_BINARY_PATH;
const DEFAULT_WIREGUARD_GO_BINARY_PATH: &str = "/usr/local/bin/wireguard-go";
const DEFAULT_KILL_BINARY_PATH: &str = "/bin/kill";
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const DEFAULT_WINDOWS_NETSH_BINARY_PATH: &str = r"C:\Windows\System32\netsh.exe";
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
        // Containment, not just syntax. A management CIDR becomes the match
        // clause of a TCP/22 allow rule on THREE backends -- macOS pf, Linux
        // nftables, and Windows netsh -- and every one of them was reachable
        // with `0.0.0.0/0`, which authorises unrestricted port-22 egress past
        // the killswitch. Syntactic validation accepted it: `/0` is a
        // well-formed prefix.
        //
        // Bounding it HERE is deliberate. This is the single place all three
        // backends funnel through, so a per-backend guard is the one shape that
        // can drift between platforms while looking fixed on the one that was
        // audited. Reusing `validate_mesh_egress_source_cidr` rather than
        // reimplementing the check keeps the *policy* from drifting too: one
        // supernet table, one set of tests.
        //
        // Strictest practical default: a management network is a bounded
        // operator range by definition (RFC1918, RFC6598 CGNAT, RFC4193 ULA, or
        // link-local), so this false-rejects nothing real. An operator wanting a
        // globally-routable management range must widen the supernet table
        // explicitly -- a visible, reviewable change rather than a `/0` typo.
        // Closes PF-02 and WIN-05 and the Linux nft twin of both.
        crate::macos_pf_mesh_cidr::validate_mesh_egress_source_cidr(value).map_err(|err| {
            format!("invalid management cidr {value}: must be a bounded operator range ({err})")
        })?;
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
    /// I4 — the race observed a fresh handshake but the runtime could not
    /// attribute it to an endpoint, so the programmed endpoint is the
    /// top-priority pair rather than a proven one. This is the production
    /// case today, because `handshake_endpoint` has no non-test
    /// implementation; `FreshHandshakeObserved` is consequently
    /// unreachable at runtime until real attribution lands.
    UnattributedHandshakeObserved,
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
            TraversalProbeReason::UnattributedHandshakeObserved => {
                "unattributed_handshake_observed"
            }
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
    /// M2 amendment (MacosClientResolverNotServingDiagnosisReview_2026-09-02
    /// §3.3): when set, the `ScopedResolverOnly` posture sub-apply would be
    /// SKIPPED here and left to a later heal pass. NO caller sets it anymore:
    /// the original M2 bootstrap deferral is RETIRED — M1's hoisted-bind probe
    /// servicer answers the loopback resolver probe for ANY posture, so the
    /// scoped apply completes in-bootstrap and `validate_baseline_runtime`
    /// (which runs inside the old deferral window) sees the resolver live.
    /// Retained so the deferral path stays expressible (and unit-tested) at
    /// the engine layer without a signature change; both daemon call sites
    /// (bootstrap and reconcile) now pass `false`. The skip emits NO ops — no
    /// probe, no scoped-file write, no assert — so the generation's DNS
    /// posture stays exactly `Untouched` (the zero-leak state).
    /// `FullyProtected` is NEVER deferred by this flag: deferring the full
    /// posture would leave a tunnel-up node resolving general DNS with no pf
    /// floor and no pins — a real leak window under Requirements.md:186 /
    /// SecurityMinimumBar §8. Default `false`.
    pub defer_scoped_dns_posture: bool,
}

impl Default for ApplyOptions {
    fn default() -> Self {
        Self {
            protected_dns: true,
            ipv6_parity_supported: false,
            exit_mode: ExitMode::Off,
            serve_exit_node: false,
            blind_exit: false,
            defer_scoped_dns_posture: false,
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
    /// QH-60 apply-scoped context: whether THIS generation engages
    /// full-tunnel policy routing (the `ip rule … table 51820` lookup). The
    /// management-bypass anchoring check refuses a dead carve-out only when
    /// that rule will actually be installed. Deliberately NOT defaulted: the
    /// production `RuntimeSystem` dispatches arm-by-arm, and a defaulted
    /// no-op would let a missing arm silently pin `engaged=false` — the
    /// check would then never refuse, which is the fail-open direction.
    fn set_full_tunnel_engaged(&mut self, engaged: bool);
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
    /// QH-52 residual: clear a firewalld zone binding left behind by a CRASH —
    /// a process that served a forwarding role died while bound; on restart as
    /// a plain client `active_stages` is empty, so the demotion arm (which
    /// keys on the recorded `HostFirewallAdmitted` marker) never runs and
    /// nothing else drops the binding. The crash-restart sibling of
    /// `reconcile_exit_nat_residue`, with the same shape: called once per
    /// process by the controller before the generation stages, probe-first so
    /// a node whose host firewall holds no binding pays one query and nothing
    /// more.
    ///
    /// Default no-op: firewalld is Linux-only, and (unlike the admit/withdraw
    /// pair) this is teardown reporting, not a fail-closed gate — a platform
    /// with nothing to reconcile genuinely has nothing to do, so a defaulted
    /// body cannot hide a missing enforcement the way it could for a stage the
    /// controller gates an apply on.
    fn reconcile_firewalld_zone_residue(&mut self) -> Result<(), SystemError> {
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
    /// QH-53: ask the host firewall (firewalld, when present) to admit
    /// forwarded tunnel traffic for a node serving a forwarding role. Runs
    /// AFTER backend start (the tunnel interface must exist for the zone
    /// bind) and before generation commit; the controller gates it on
    /// `serve_exit_node`.
    ///
    /// Deliberately NOT defaulted: the production `RuntimeSystem` dispatches
    /// trait methods arm-by-arm, so a defaulted method would let a missing
    /// dispatch arm silently no-op this enforcement on the real daemon while
    /// every DryRun-driven test stays green. A new system type must decide
    /// explicitly.
    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError>;
    /// QH-52: the exact inverse of `admit_host_firewall_forwarding`. Remove the
    /// tunnel interface's host-firewall (firewalld) zone binding when the node
    /// stops serving a forwarding role — an in-place relay/exit demotion, a
    /// fail-closed unwind, or daemon shutdown.
    ///
    /// CLAUDE.md §10.7: undeploy precedes revocation, and a control installed by
    /// a role must be removed when the role is. A binding that outlives the role
    /// is deploy residue on the operator's host firewall, and it is the residue
    /// class this project treats as release-blocking precisely because nothing
    /// else in the system will ever remove it — the binding is runtime-only, so
    /// it is invisible in firewalld's on-disk configuration and survives until
    /// firewalld itself is reloaded.
    ///
    /// Teardown semantics, NOT a fail-closed gate: a leftover binding can only
    /// admit forwarded traffic this daemon has already stopped authorising
    /// (our own forward chain is `policy drop` and a drop is terminal), so a
    /// failed withdrawal must be REPORTED, never allowed to fail a healthy
    /// generation closed. Call sites record it into the same teardown-failure
    /// accounting every other rollback stage uses.
    ///
    /// Not defaulted, for the same reason `admit_host_firewall_forwarding` is
    /// not: `RuntimeSystem` dispatches arm-by-arm, and a default would let a
    /// missing arm silently no-op the removal on the real daemon while every
    /// DryRun test stayed green.
    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError>;
    fn rollback_firewall(&mut self) -> Result<(), SystemError>;
    fn apply_nat_forwarding(
        &mut self,
        serve_exit_node: bool,
        exit_mode: ExitMode,
        blind_exit: bool,
        mesh_cidr: &str,
    ) -> Result<(), SystemError>;
    fn rollback_nat_forwarding(&mut self) -> Result<(), SystemError>;
    /// QH-47: invalidate the conntrack entries a masquerade generation change
    /// makes wrong.
    ///
    /// A netfilter `nat` chain is traversed only for the FIRST packet of a
    /// flow; afterwards the binding lives in the conntrack entry and later
    /// packets never re-enter the hook. So a flow established BEFORE a
    /// masquerade was installed is never masqueraded, and — because every
    /// packet refreshes the entry — a steady stream keeps that stale binding
    /// alive indefinitely instead of ageing it out. The withdrawal direction is
    /// the §10.7 one: flows that hold a NAT binding keep egressing through a
    /// host that has stopped serving the exit.
    ///
    /// The selector is the mesh source network and nothing else. See
    /// [`crate::linux_conntrack_flush`] for why a table-wide flush is not just
    /// avoided but unrepresentable.
    ///
    /// Callers must treat the result as a REPORT, not a gate: the outcome is
    /// logged (including `ToolAbsent`, which must never be silently swallowed)
    /// and never used to fail an otherwise-healthy generation. Refusing an
    /// apply because `conntrack-tools` is not installed would make every
    /// minimal-install host unable to serve as an exit, converting "some
    /// pre-existing flows keep a stale binding until they close" into "the node
    /// cannot serve the role at all" — disproportionate, since new flows are
    /// bound correctly either way.
    ///
    /// Deliberately NOT defaulted, for the same reason
    /// `admit_host_firewall_forwarding` is not: `RuntimeSystem` dispatches
    /// arm-by-arm, and a default would let a missing arm silently no-op the
    /// flush on the real daemon while every DryRun test stayed green.
    fn flush_nat_conntrack(
        &mut self,
        mesh_cidr: &str,
        reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError>;
    fn apply_dns_protection(&mut self) -> Result<(), SystemError>;
    /// Apply the DNS control for a specific [`DnsPosture`] (M2,
    /// MacosClientDnsFailclosedDiagnosis_2026-09-02 §6). The default forwards
    /// to [`DataplaneSystem::apply_dns_protection`], which is the
    /// FullyProtected behavior: safe to default BECAUSE it forwards to an
    /// implemented method — unlike `flush_nat_conntrack`, whose deliberate
    /// no-default guards against a silent no-op, this default can never turn
    /// an installed control into a skipped one. A platform that only
    /// implements full protection simply applies full protection for every
    /// posture, which is fail-closed (over-protecting, never under-).
    fn apply_dns_protection_for_posture(
        &mut self,
        _posture: DnsPosture,
    ) -> Result<(), SystemError> {
        self.apply_dns_protection()
    }
    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        Ok(())
    }
    /// Whether the system currently reports the DNS fail-closed posture as
    /// installed. Default false: only a system with a real runtime
    /// `dns_protected` flag overrides this. The daemon's S1 posture
    /// re-assert (MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2) gates on
    /// it, so a system that cannot observe the posture must never claim it.
    fn dns_protected(&self) -> bool {
        false
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

/// Why a conntrack flush is being issued (QH-47). Carried into logs and into
/// the DryRun operation trace so a test can assert the DIRECTION of the
/// transition, not merely that some flush happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatConntrackFlushReason {
    /// This generation installed or changed a masquerade. Flows established
    /// before it hold a stale un-NATed binding.
    MasqueradeInstalled,
    /// This generation removed a masquerade (exit/relay demotion, fail-closed
    /// unwind, or shutdown). Flows still hold a NAT binding the node no longer
    /// justifies.
    MasqueradeWithdrawn,
}

impl NatConntrackFlushReason {
    pub fn as_str(self) -> &'static str {
        match self {
            NatConntrackFlushReason::MasqueradeInstalled => "masquerade_installed",
            NatConntrackFlushReason::MasqueradeWithdrawn => "masquerade_withdrawn",
        }
    }
}

/// The DNS fail-closed posture a macOS node must hold
/// (MacosClientDnsFailclosedDiagnosis_2026-09-02 §5/§6, as amended by the
/// review A1). The prior binary model — protect everything or touch nothing —
/// could not express a plain mesh client, which needs scoped `*.rustynet`
/// resolution (Requirements §3.5) but must not pin the machine's general DNS
/// at a loopback listener nothing general traffic relies on.
///
/// The invariant this type encodes: DNS is EITHER fully protected OR
/// mesh-scoped-only OR untouched. A half-applied general pin without a live
/// loopback primary and a pf floor is never a valid posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPosture {
    /// Full fail-closed protection: live loopback resolver as the machine's
    /// primary, every general DNS path pinned to it, a pf DNS-block floor
    /// under the pins, and the scoped `*.rustynet` resolver. Guards
    /// `dns_protected` (killswitch floor emission, S1 re-assert).
    FullyProtected,
    /// Plain mesh client: only the scoped `/etc/resolver/rustynet` file,
    /// routing `*.rustynet` to the daemon's loopback listener. NO general
    /// pins, NO pf floor, NO primary rewrite — the machine's own DNS is
    /// untouched, so mesh-name queries cannot leak to the LAN resolver.
    ScopedResolverOnly,
    /// No DNS control installed at all. Constructed only where
    /// `protected_dns=false` opts the node out; never returned by
    /// [`macos_dns_posture`], which must always pick a protective posture.
    Untouched,
}

impl DnsPosture {
    pub fn as_str(self) -> &'static str {
        match self {
            DnsPosture::FullyProtected => "fully_protected",
            DnsPosture::ScopedResolverOnly => "scoped_resolver_only",
            DnsPosture::Untouched => "untouched",
        }
    }
}

/// Which DNS posture applies to a node with the given exit posture.
///
/// A node serving as an exit (or running full-tunnel exit mode) handles ALL
/// of the machine's traffic and gets [`DnsPosture::FullyProtected`]; a plain
/// mesh client gets [`DnsPosture::ScopedResolverOnly`]. Never returns
/// [`DnsPosture::Untouched`]: the untouched variant is reserved for the
/// `protected_dns=false` opt-out, decided at the apply site, not here.
pub(crate) fn macos_dns_posture(exit_mode: ExitMode, serve_exit_node: bool) -> DnsPosture {
    if exit_mode == ExitMode::FullTunnel || serve_exit_node {
        DnsPosture::FullyProtected
    } else {
        DnsPosture::ScopedResolverOnly
    }
}

#[cfg(test)]
mod dns_posture_tests {
    use super::{DnsPosture, ExitMode, macos_dns_posture};

    #[test]
    fn full_tunnel_exit_mode_yields_fully_protected() {
        assert_eq!(
            macos_dns_posture(ExitMode::FullTunnel, false),
            DnsPosture::FullyProtected
        );
    }

    #[test]
    fn serving_exit_node_yields_fully_protected() {
        assert_eq!(
            macos_dns_posture(ExitMode::Off, true),
            DnsPosture::FullyProtected
        );
    }

    #[test]
    fn both_exit_markers_yield_fully_protected() {
        assert_eq!(
            macos_dns_posture(ExitMode::FullTunnel, true),
            DnsPosture::FullyProtected
        );
    }

    #[test]
    fn plain_mesh_client_yields_scoped_resolver_only() {
        assert_eq!(
            macos_dns_posture(ExitMode::Off, false),
            DnsPosture::ScopedResolverOnly
        );
    }

    #[test]
    fn posture_decision_never_returns_untouched() {
        // Untouched is reserved for the protected_dns=false opt-out at the
        // apply site; the decision function must never select it.
        for (exit_mode, serve_exit_node) in [
            (ExitMode::Off, false),
            (ExitMode::Off, true),
            (ExitMode::FullTunnel, false),
            (ExitMode::FullTunnel, true),
        ] {
            assert_ne!(
                macos_dns_posture(exit_mode, serve_exit_node),
                DnsPosture::Untouched
            );
        }
    }

    #[test]
    fn posture_wire_names_are_stable() {
        assert_eq!(DnsPosture::FullyProtected.as_str(), "fully_protected");
        assert_eq!(
            DnsPosture::ScopedResolverOnly.as_str(),
            "scoped_resolver_only"
        );
        assert_eq!(DnsPosture::Untouched.as_str(), "untouched");
    }
}

/// The masquerade-relevant shape of a generation.
///
/// Two generations with EQUAL postures translate traffic identically, so a
/// re-apply of an identical generation invalidates no conntrack binding and
/// must not flush: the flush is bounded but not free (it drops mesh-sourced
/// flows that were perfectly healthy), and the reconcile loop re-applies
/// constantly. Only a genuine transition earns it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NatPosture {
    /// The egress masquerade is installed. False for `blind_exit`, which
    /// forwards without translating.
    masquerade: bool,
    /// The relay-with-upstream hairpin SNAT is installed.
    hairpin: bool,
    /// The mesh source network the masquerade rewrites — part of the posture
    /// because a changed mesh CIDR invalidates bindings just as surely as a
    /// changed rule does.
    mesh_cidr: String,
}

impl NatPosture {
    /// The posture a generation will have, or `None` when the NAT stage does
    /// not run at all for it.
    fn for_generation(options: ApplyOptions, mesh_cidr: &str) -> Option<Self> {
        if options.exit_mode != ExitMode::FullTunnel && !options.serve_exit_node {
            return None;
        }
        Some(Self {
            masquerade: !options.blind_exit,
            hairpin: options.exit_mode == ExitMode::FullTunnel
                && options.serve_exit_node
                && !options.blind_exit,
            mesh_cidr: mesh_cidr.to_owned(),
        })
    }

    /// Does this posture translate anything? A `blind_exit` posture does not,
    /// so a transition between two non-translating postures has no conntrack
    /// binding to invalidate.
    fn translates(posture: Option<&Self>) -> bool {
        posture.is_some_and(|posture| posture.masquerade || posture.hairpin)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StageMarker {
    BackendStarted,
    PeerApplied,
    EndpointBypassApplied,
    BackendRoutesApplied,
    SystemRoutesApplied,
    FirewallApplied,
    /// QH-52: this generation bound the tunnel interface into the host
    /// firewall's default zone (`admit_host_firewall_forwarding`). Recorded so
    /// the binding can be given back when the role ends — a control installed
    /// by a role and never removed is the §10.7 residue this marker exists to
    /// make trackable.
    HostFirewallAdmitted,
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
    /// The error the armed `fail_operation` fails with. `None` (the default,
    /// and what `fail_on`/`fail_on_from_now` arm) preserves the historic
    /// `RollbackFailed` behaviour; M3 tests arm a specific error (e.g.
    /// `DnsApplyFailed`) to drive the DNS-degraded error path exactly as the
    /// real macOS system reports it.
    fail_error: Option<SystemError>,
    generation: u64,
    relay_forwarding_enabled: bool,
    /// Mirrors the real systems' runtime posture flag: set by
    /// `apply_dns_protection`, cleared by `rollback_dns_protection`. The S1
    /// daemon posture re-assert gates on `dns_protected()`, so the DryRun
    /// system must track the same lifecycle the macOS system does.
    dns_protected: bool,
}

impl DryRunSystem {
    pub fn fail_on(mut self, operation: &str) -> Self {
        self.fail_operation = Some(operation.to_owned());
        self
    }

    /// Arm the failure AFTER construction.
    ///
    /// `fail_on` is a builder and can only fail a stage from the very first
    /// call onwards. QH-54's re-assert has to be exercised on a node whose
    /// apply already SUCCEEDED, so the same stage must be able to start
    /// healthy and then fail on a later call.
    pub fn fail_on_from_now(&mut self, operation: &str) {
        self.fail_operation = Some(operation.to_owned());
    }

    /// Arm a failure with a SPECIFIC error (M3): lets state-machine tests
    /// drive the DNS-degraded branch with the exact `SystemError` the macOS
    /// scoped posture apply reports, rather than the generic
    /// `RollbackFailed` stand-in.
    pub fn fail_on_with(&mut self, operation: &str, error: SystemError) {
        self.fail_operation = Some(operation.to_owned());
        self.fail_error = Some(error);
    }

    fn step(&mut self, operation: &str) -> Result<(), SystemError> {
        self.operations.push(operation.to_owned());
        if self
            .fail_operation
            .as_ref()
            .is_some_and(|candidate| candidate == operation)
        {
            return Err(self
                .fail_error
                .clone()
                .unwrap_or_else(|| SystemError::RollbackFailed(operation.to_owned())));
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

    fn set_full_tunnel_engaged(&mut self, engaged: bool) {
        self.operations
            .push(format!("set_full_tunnel_engaged:{engaged}"));
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

    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Through step() on purpose: fail_operation-driven tests must be able
        // to fail this stage and prove the controller propagates it.
        self.step("admit_host_firewall_forwarding")
    }

    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Through step() for the same reason as the admit: tests must be able
        // to fail the withdrawal and prove the controller reports it without
        // failing an otherwise-healthy generation closed.
        self.step("withdraw_host_firewall_forwarding")
    }

    fn reconcile_firewalld_zone_residue(&mut self) -> Result<(), SystemError> {
        // Through step() so DryRun-driven tests can observe when the probe ran
        // (once-per-process gating) and fail it to prove the controller's
        // residue accounting.
        self.step("reconcile_firewalld_zone_residue")
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

    fn flush_nat_conntrack(
        &mut self,
        mesh_cidr: &str,
        reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError> {
        self.step(&format!(
            "flush_nat_conntrack:{}:{mesh_cidr}",
            reason.as_str()
        ))?;
        Ok(crate::linux_conntrack_flush::ConntrackFlushOutcome::Flushed { entries: 0 })
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("apply_dns_protection")?;
        self.dns_protected = true;
        Ok(())
    }

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("assert_dns_protection")
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.step("rollback_dns_protection")?;
        self.dns_protected = false;
        Ok(())
    }

    fn dns_protected(&self) -> bool {
        self.dns_protected
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

/// Parse `ip -4 -o addr show dev <if>` output into connected
/// (address, prefix) pairs. Token-scanned: the `inet` keyword is located by
/// value, never by fixed column (QH-60 verification matrix).
fn parse_connected_v4_prefixes(stdout: &str) -> Vec<(std::net::Ipv4Addr, u8)> {
    let mut connected = Vec::new();
    for line in stdout.lines() {
        let mut tokens = line.split_whitespace();
        while let Some(token) = tokens.next() {
            if token != "inet" {
                continue;
            }
            let Some(cidr) = tokens.next() else { break };
            let Some((addr_raw, prefix_raw)) = cidr.split_once('/') else {
                break;
            };
            if let (Ok(addr), Ok(prefix)) = (
                addr_raw.parse::<std::net::Ipv4Addr>(),
                prefix_raw.parse::<u8>(),
            ) && prefix <= 32
            {
                connected.push((addr, prefix));
            }
            break;
        }
    }
    connected
}

/// True iff two IPv4 CIDRs share any address: their network bits agree under
/// the SHORTER prefix.
fn v4_cidrs_overlap(
    a: std::net::Ipv4Addr,
    a_prefix: u8,
    b: std::net::Ipv4Addr,
    b_prefix: u8,
) -> bool {
    let shared = a_prefix.min(b_prefix).min(32);
    if shared == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - u32::from(shared));
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

fn join_management_cidrs(cidrs: &[ManagementCidr]) -> String {
    cidrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_connected_prefixes(connected: &[(std::net::Ipv4Addr, u8)]) -> String {
    connected
        .iter()
        .map(|(addr, prefix)| format!("{addr}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
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
    /// QH-60 apply-scoped context; set by the controller before the stages.
    full_tunnel_engaged: bool,
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
            full_tunnel_engaged: false,
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

    /// Make a foreign host firewall stop destroying traffic this daemon has
    /// already authorised (QH-46).
    ///
    /// Our forward chain runs at `hook forward priority 0`, but a base chain's
    /// `accept` only means "continue to the next base chain at this hook".
    /// firewalld installs its own chain at `filter + 10`, ending in
    /// `reject with icmpx admin-prohibited`, and the tunnel device — created at
    /// runtime by this daemon, not by NetworkManager — is bound to no zone, so
    /// forwarded tunnel traffic falls through to that reject and dies BETWEEN
    /// the FORWARD and POSTROUTING hooks. A reject is terminal, so no rule we
    /// add later can rescue it.
    ///
    /// Runs via `admit_host_firewall_forwarding` AFTER backend start — the
    /// zone bind needs the tunnel interface to exist in sysfs, and the
    /// killswitch stage runs before the interface is created (QH-53) — and
    /// the controller gates it on `serve_exit_node`, which covers relay-with-
    /// upstream, terminal exit, and blind_exit alike. It FAILS CLOSED: if
    /// firewalld is present, or its presence could not be determined, and the
    /// interface is not confirmed bound afterwards, the generation apply
    /// fails before commit rather than leaving the node advertising a
    /// forwarding role whose traffic another firewall silently discards. A
    /// host with no firewalld is a no-op.
    fn ensure_host_firewall_admits_forwarding(&mut self) -> Result<(), SystemError> {
        use crate::linux_firewalld_zone::{FirewalldPosture, FirewalldZoneOp, FirewalldZoneSpec};

        let spec = FirewalldZoneSpec::new(FirewalldZoneOp::Bind, self.interface_name.as_str())
            .map_err(SystemError::PrerequisiteCheckFailed)?;
        let argv = spec.encode();
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = self.run_capture(
            PrivilegedCommandProgram::LinuxFirewalldZone,
            borrowed.as_slice(),
        )?;
        let posture = FirewalldPosture::parse(output.stdout.trim())
            .map_err(|err| SystemError::FirewallApplyFailed(format!("firewalld posture: {err}")))?;
        if !posture.forwarding_unobstructed() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "host firewall would discard forwarded tunnel traffic: firewalld {} and interface \
                 {} is not bound to its default zone{}",
                posture.presence.as_str(),
                self.interface_name,
                posture
                    .default_zone
                    .as_deref()
                    .map(|zone| format!(" ({zone})"))
                    .unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Give back the firewalld zone binding when the forwarding role ends
    /// (QH-52).
    ///
    /// The exact inverse of `ensure_host_firewall_admits_forwarding`, over the
    /// same two-token grammar and the same single privileged builtin, differing
    /// only in the op token and in the verdict it demands of the posture it
    /// reads back. `addInterface` and `removeInterface` are both re-read rather
    /// than trusted, so "the mutation returned success but had no effect" is
    /// not reportable as success in either direction.
    ///
    /// Failure semantics are inverted along with the direction. The bind fails
    /// the apply CLOSED, because serving a forwarding role whose traffic
    /// firewalld silently rejects is a false advertisement. The unbind cannot:
    /// the only thing a leftover binding does is admit forwarded traffic
    /// through firewalld, and by the time this runs our own forward chain has
    /// already stopped accepting that traffic — the binding grants nothing.
    /// So an unremovable binding is reported as residue by the caller and never
    /// used to tear down a node that is otherwise healthy.
    fn ensure_host_firewall_forwarding_withdrawn(&mut self) -> Result<(), SystemError> {
        use crate::linux_firewalld_zone::{FirewalldPosture, FirewalldZoneOp, FirewalldZoneSpec};

        let spec = FirewalldZoneSpec::new(FirewalldZoneOp::Unbind, self.interface_name.as_str())
            .map_err(SystemError::PrerequisiteCheckFailed)?;
        let argv = spec.encode();
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = self.run_capture(
            PrivilegedCommandProgram::LinuxFirewalldZone,
            borrowed.as_slice(),
        )?;
        let posture = FirewalldPosture::parse(output.stdout.trim())
            .map_err(|err| SystemError::FirewallApplyFailed(format!("firewalld posture: {err}")))?;
        if !posture.forwarding_admission_withdrawn() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "host firewall zone binding survived role demotion: firewalld {} and interface \
                 {} is still bound to its default zone{}",
                posture.presence.as_str(),
                self.interface_name,
                posture
                    .default_zone
                    .as_deref()
                    .map(|zone| format!(" ({zone})"))
                    .unwrap_or_default()
            )));
        }
        Ok(())
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

    /// QH-60: the management bypass is structurally on-link — the route is
    /// `ip route replace <cidr> dev <egress> table 51820` with no `via` — so
    /// a CIDR set overlapping no connected prefix on the egress interface
    /// describes a carve-out that cannot deliver replies. Engaging
    /// full-tunnel policy routing with a provably dead carve-out black-holes
    /// management (the QH-57 wedge). Refuse the apply instead, BEFORE the
    /// `ip rule … table 51820` engagement: the node stays reachable and the
    /// reconcile loop retries, so a DHCP race self-heals and the transient
    /// restricted state clears on the first successful apply.
    ///
    /// The quorum is IPv4-only while IPv6 parity is unsupported: each
    /// generation hard-disables IPv6 AFTER the routes stage, so a v6 quorum
    /// would pass on the first apply and refuse forever after. Under any
    /// exit mode other than FullTunnel the rule-51820 lookup is never
    /// installed, a wrong list is inert, and refusal would brick mesh-join
    /// for exit-less nodes — warn and install instead.
    fn ensure_management_bypass_anchored(&mut self) -> Result<(), SystemError> {
        let output = self
            .run_capture(
                PrivilegedCommandProgram::Ip,
                &[
                    "-4",
                    "-o",
                    "addr",
                    "show",
                    "dev",
                    self.egress_interface.as_str(),
                ],
            )
            .map_err(|err| {
                SystemError::RouteApplyFailed(format!(
                    "management bypass anchoring: egress address observation failed on {} \
                     (fail closed; recoverable, the reconcile loop will retry): {err}",
                    self.egress_interface
                ))
            })?;
        if !output.success() {
            return Err(SystemError::RouteApplyFailed(format!(
                "management bypass anchoring: egress address observation exited {} on {} \
                 (fail closed; recoverable, the reconcile loop will retry): {}",
                output.status,
                self.egress_interface,
                output.stderr.trim()
            )));
        }
        let connected = parse_connected_v4_prefixes(output.stdout.as_str());
        let mut anchored_any = false;
        let mut unanchored: Vec<String> = Vec::new();
        for cidr in &self.fail_closed_ssh_allow_cidrs {
            match cidr.address {
                IpAddr::V4(v4) => {
                    let hit = connected
                        .iter()
                        .any(|(net, prefix)| v4_cidrs_overlap(v4, cidr.prefix, *net, *prefix));
                    if hit {
                        anchored_any = true;
                    } else {
                        unanchored.push(cidr.to_string());
                    }
                }
                IpAddr::V6(_) => {
                    eprintln!(
                        "rustynetd: management CIDR {cidr} is IPv6 and excluded from the \
                         bypass anchoring quorum while IPv6 parity is unsupported"
                    );
                }
            }
        }
        if anchored_any {
            for cidr in &unanchored {
                eprintln!(
                    "rustynetd: management CIDR {cidr} overlaps no connected prefix on {} — \
                     its on-link bypass route cannot deliver to that range",
                    self.egress_interface
                );
            }
            return Ok(());
        }
        if !self.full_tunnel_engaged {
            eprintln!(
                "rustynetd: no management CIDR overlaps a connected prefix on {} \
                 (configured: [{}]; connected: [{}]); inert without full-tunnel, but a \
                 full-tunnel apply would refuse this carve-out (QH-60)",
                self.egress_interface,
                join_management_cidrs(&self.fail_closed_ssh_allow_cidrs),
                join_connected_prefixes(&connected),
            );
            return Ok(());
        }
        Err(SystemError::RouteApplyFailed(format!(
            "no management CIDR overlaps a connected prefix on {} (configured: [{}]; \
             connected: [{}]); engaging full-tunnel policy routing would black-hole \
             management, refusing before the table-51820 rule engages (QH-60; \
             recoverable, the reconcile loop will retry)",
            self.egress_interface,
            join_management_cidrs(&self.fail_closed_ssh_allow_cidrs),
            join_connected_prefixes(&connected),
        )))
    }

    fn apply_fail_closed_management_bypass_routes(&mut self) -> Result<(), SystemError> {
        self.expected_management_bypass_routes.clear();
        if !self.fail_closed_ssh_allow {
            return Ok(());
        }
        self.ensure_management_bypass_anchored()?;
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
        if Self::is_empty_fib_table_error(&output) {
            // iproute2 >= 6.19 (e.g. ubuntu 26.04) exits 2 with
            // "Error: ipv4/ipv6: FIB table does not exist." instead of the
            // older behavior of printing nothing and exiting 0 for a table
            // that has no routes yet. That is the legitimate pre-WireGuard
            // state (table 51820 not created until the first route is
            // added), not a reconcile failure — treat it as an empty table.
            return Ok(String::new());
        }
        Err(SystemError::KillSwitchAssertionFailed(format!(
            "{} failed: status={} stderr={}",
            args.join(" "),
            output.status,
            output.stderr.trim()
        )))
    }

    /// Narrow, fail-closed-preserving match for the iproute2 6.19+ "empty
    /// FIB table" CLI regression: only exit code 2 with a stderr containing
    /// the exact `FIB table does not exist` phrase (case-insensitive) is
    /// treated as an empty table. Every other exit code or stderr text
    /// (e.g. permission errors) remains a hard failure.
    fn is_empty_fib_table_error(output: &PrivilegedCommandOutput) -> bool {
        output.status == 2
            && output
                .stderr
                .to_ascii_lowercase()
                .contains("fib table does not exist")
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

    fn assert_chain_contains_strings(
        &self,
        chain_lines: &[String],
        tokens: &[String],
        message: &str,
    ) -> Result<(), SystemError> {
        let borrowed: Vec<&str> = tokens.iter().map(String::as_str).collect();
        self.assert_chain_contains(chain_lines, &borrowed, message)
    }

    // ── QH-29: shared rule-token builders ────────────────────────────────────
    //
    // Every nft rule the Linux dataplane emits is built from ONE of these
    // token sets, and the runtime self-assertions (`assert_nat_forwarding`,
    // `assert_firewall_ruleset`) match the SAME builder output. This is the
    // coupling point the QH-29 audit was about: before it, the emitters and
    // the matchers each spelled the rule tokens inline, so a format change on
    // one side (e.g. the `counter` observability token) could silently stop
    // the fail-closed assertion from matching — wrongly failing a healthy
    // node, or worse, matching nothing while reporting success. With a shared
    // builder, changing a token changes BOTH sides in the same commit, and
    // the `*_rule_tokens_agree_with_emitted_nft_argv` tests in `mod tests`
    // pin the pairing end-to-end by driving the real emitters through the
    // privileged-capture helper and checking these tokens against the
    // rendered `nft add rule` argv.
    //
    // Note on `counter`: it is an OBSERVABILITY-ONLY argv token (packet
    // counters for live debugging) deliberately OMITTED from every builder —
    // `chain_contains_all_tokens` matches each token as an independent
    // substring of the rendered line, so the extra `counter packets N bytes N`
    // text nft renders between match terms and the verdict never breaks the
    // match. Keep it that way: adding `counter` to a builder would couple the
    // assertion to nft's counter rendering.

    /// Killswitch: allow loopback (managed DNS resolver on 127.0.0.1 must
    /// survive the default-deny OUTPUT policy).
    fn loopback_accept_tokens() -> Vec<String> {
        vec!["oifname".into(), "lo".into(), "accept".into()]
    }

    /// Killswitch + forward: allow established/related traffic.
    ///
    /// These tokens feed TWO consumers that must agree (QH-29): the
    /// `nft add rule` argv sent through the privileged helper, and the
    /// fail-closed chain assertions. They are therefore ONE WORD PER ARGV
    /// ELEMENT, never a multi-word phrase: the helper's argv allowlist
    /// matches nft keywords as individual tokens (`"ct"`, `"state"`,
    /// `"established,related"`), and a phrase-shaped element
    /// (`"ct state established,related"`) renders identically in a
    /// `join(" ")` echo while being refused by every allowlist arm — which
    /// is exactly how the QH-29 refactor (f1b40e9e) briefly broke every
    /// Linux reconcile apply live (2026-08-29 run: permanent restriction,
    /// no `rustynet0`, managed-DNS oneshot timeout, NotRunning shutdown
    /// residue on both Debian nodes).
    fn established_related_accept_tokens() -> Vec<String> {
        vec![
            "ct".into(),
            "state".into(),
            "established,related".into(),
            "accept".into(),
        ]
    }

    /// Killswitch: allow anything leaving via the tunnel interface.
    fn tunnel_interface_accept_tokens(tunnel_interface: &str) -> Vec<String> {
        vec!["oifname".into(), tunnel_interface.into(), "accept".into()]
    }

    /// Killswitch: allow the node's own egress while NAT forwarding is active.
    fn killswitch_egress_allow_tokens(egress_interface: &str) -> Vec<String> {
        vec!["oifname".into(), egress_interface.into(), "accept".into()]
    }

    /// Killswitch: allow WireGuard handshake traffic by destination OR source
    /// port (traversal peers reply from arbitrary NAT-mapped ports, so the
    /// source-port rule is load-bearing, not redundant).
    fn wg_listen_port_allow_tokens(
        port_match: &str,
        egress_interface: &str,
        wg_listen_port: u16,
    ) -> Vec<String> {
        vec![
            "oifname".into(),
            egress_interface.into(),
            "udp".into(),
            port_match.into(),
            wg_listen_port.to_string(),
            "accept".into(),
        ]
    }

    /// Killswitch DNS protection: drop off-tunnel :53 (fail-closed half).
    fn dns_off_tunnel_drop_tokens(proto: &str, tunnel_interface: &str) -> Vec<String> {
        vec![
            proto.into(),
            "dport".into(),
            "53".into(),
            "oifname".into(),
            "!=".into(),
            tunnel_interface.into(),
            "drop".into(),
        ]
    }

    /// Killswitch DNS protection: allow on-tunnel :53 (tunnel half).
    fn dns_accept_tokens(proto: &str) -> Vec<String> {
        vec![proto.into(), "dport".into(), "53".into(), "accept".into()]
    }

    /// Forward chain: allow tunnel-sourced traffic out the underlay egress.
    fn forward_tunnel_to_egress_tokens(
        tunnel_interface: &str,
        egress_interface: &str,
    ) -> Vec<String> {
        vec![
            "iifname".into(),
            tunnel_interface.into(),
            "oifname".into(),
            egress_interface.into(),
            "accept".into(),
        ]
    }

    /// Forward chain: allow tunnel→tunnel hairpin forwarding for
    /// relay-with-upstream.
    fn forward_hairpin_accept_tokens(tunnel_interface: &str) -> Vec<String> {
        vec![
            "iifname".into(),
            tunnel_interface.into(),
            "oifname".into(),
            tunnel_interface.into(),
            "accept".into(),
        ]
    }

    /// NAT postrouting: masquerade tunnel traffic leaving the underlay
    /// egress (the rule whose absence once failed every exit node).
    fn nat_egress_masquerade_tokens(egress_interface: &str) -> Vec<String> {
        vec![
            "oifname".into(),
            egress_interface.into(),
            "masquerade".into(),
        ]
    }

    /// NAT postrouting: hairpin SNAT for relay-with-upstream (rewrites the
    /// inner source so packets satisfy the upstream exit's /32 cryptokey
    /// routing).
    fn nat_hairpin_masquerade_tokens(tunnel_interface: &str) -> Vec<String> {
        vec![
            "iifname".into(),
            tunnel_interface.into(),
            "oifname".into(),
            tunnel_interface.into(),
            "masquerade".into(),
        ]
    }

    /// Assemble a full `nft add rule` argv from a shared token builder,
    /// inserting `observability_tokens` (e.g. `counter`) before the final
    /// verdict/action token so emitters can add observability without the
    /// assertion builders ever seeing it.
    fn nft_add_rule_argv(
        family: &str,
        table: &str,
        chain: &str,
        rule_tokens: &[String],
        observability_tokens: &[&str],
    ) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "add".into(),
            "rule".into(),
            family.into(),
            table.into(),
            chain.into(),
        ];
        let split_at = rule_tokens.len().saturating_sub(1);
        argv.extend(rule_tokens[..split_at].iter().cloned());
        argv.extend(observability_tokens.iter().map(|token| token.to_string()));
        if let Some(verdict) = rule_tokens.last() {
            argv.push(verdict.clone());
        }
        argv
    }

    fn run_nft_rule_argv(
        &self,
        family: &str,
        table: &str,
        chain: &str,
        rule_tokens: &[String],
        observability_tokens: &[&str],
    ) -> Result<(), SystemError> {
        let argv = Self::nft_add_rule_argv(family, table, chain, rule_tokens, observability_tokens);
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        self.run(PrivilegedCommandProgram::Nft, &borrowed)
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

    /// Does a rendered `ip route show` destination denote the CIDR we asked
    /// the kernel to install?
    ///
    /// iproute2 does not echo destinations back verbatim, so a literal string
    /// compare is wrong in two ways:
    ///
    /// - a host route drops its prefix: `10.0.0.1/32` renders as `10.0.0.1`;
    /// - **the default route renders as `default`**, never as `0.0.0.0/0` or
    ///   `::/0`.
    ///
    /// The second case was unhandled, and it is reachable in production: the
    /// management-SSH bypass installs one route per
    /// `fail_closed_ssh_allow_cidrs` entry, so allowing SSH from anywhere
    /// (`0.0.0.0/0`) made `assert_expected_bypass_routes` compare "0.0.0.0/0"
    /// against a table containing "default dev enp0s1" and fail every time.
    /// The killswitch then failed its own assertion on every reconcile, which
    /// restricted the daemon and made every mutating command (`route
    /// advertise`, exit setup) impossible. The direction is at least safe --
    /// a false assertion failure fails closed -- but the node is unusable.
    fn route_destination_matches_rendered(expected: &str, rendered: &str) -> bool {
        if rendered == expected {
            return true;
        }
        let Some((address, prefix)) = expected.split_once('/') else {
            return false;
        };
        if prefix == "0" && matches!(address, "0.0.0.0" | "::") {
            return rendered == "default";
        }
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

    /// QH-29: runtime self-assertion for NAT forwarding. Matches the LIVE
    /// `nft list table ip <nat>` output against the SAME shared token
    /// builders `apply_nat_forwarding` emits its rules from — the pairing is
    /// pinned by `nat_rule_tokens_agree_with_emitted_nft_argv` in `mod tests`,
    /// so a rule-format change cannot silently stop this check from matching.
    fn assert_nat_forwarding(&self) -> Result<(), SystemError> {
        let Some(table) = self.nat_table.as_deref() else {
            return Ok(());
        };
        let ruleset = self.nft_table_output("ip", table, "nft list nat table")?;
        let postrouting = Self::nft_chain_lines(&ruleset, "postrouting").ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed("nat postrouting chain missing".to_owned())
        })?;
        self.assert_chain_contains_strings(
            &postrouting,
            &Self::nat_egress_masquerade_tokens(self.egress_interface.as_str()),
            "egress masquerade rule missing",
        )?;
        if self.allow_tunnel_relay_forward {
            self.assert_chain_contains_strings(
                &postrouting,
                &Self::nat_hairpin_masquerade_tokens(self.interface_name.as_str()),
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

    /// Assert a blind_exit node's live nft posture against its own evaluator.
    ///
    /// # IPV-10
    ///
    /// `evaluate_linux_blind_exit_ruleset` existed, was thorough, and was not on
    /// the daemon's assert path. Its only production caller was the
    /// evidence-report command (`linux_blind_exit_dataplane`), so a blind_exit
    /// node's runtime posture was checked when an operator or the lab asked for a
    /// report and never during operation -- while the module documented itself as
    /// the runtime check.
    ///
    /// macOS already does exactly this from its own `assert_exit_serving`, so
    /// this closes a platform asymmetry rather than inventing a control: the same
    /// class of drift (masquerade NAT appearing on a blind exit, an unrestricted
    /// forward, the operator's own egress leaking) was loud on macOS and silent
    /// on Linux.
    ///
    /// A no-op when blind_exit is not configured. `assert_nat_forwarding` still
    /// runs afterwards and is itself a no-op without a NAT table, which is the
    /// blind_exit case -- so nothing about the NAT path changes.
    fn assert_blind_exit_posture(&self) -> Result<(), SystemError> {
        let Some(config) = self.blind_exit_config.as_ref() else {
            return Ok(());
        };
        let table = self.firewall_table.clone().ok_or_else(|| {
            SystemError::KillSwitchAssertionFailed(
                "blind_exit assertion: killswitch table missing".to_owned(),
            )
        })?;
        let ruleset = self.nft_table_output(
            "inet",
            table.as_str(),
            "nft list blind_exit killswitch table",
        )?;
        let reasons =
            crate::linux_blind_exit::evaluate_linux_blind_exit_ruleset(ruleset.as_str(), config);
        if !reasons.is_empty() {
            return Err(SystemError::KillSwitchAssertionFailed(format!(
                "blind_exit nft assertion failed: {}",
                reasons.join("; ")
            )));
        }
        Ok(())
    }

    /// QH-29: runtime self-assertion for the inet fail-closed table. Matches
    /// the LIVE `nft list table inet <fw>` output against the SAME shared
    /// token builders `ensure_failclosed_table` / `apply_firewall_killswitch`
    /// / `apply_nat_forwarding` / `apply_dns_protection` emit their rules
    /// from — the pairing is pinned by
    /// `killswitch_and_dns_rule_tokens_agree_with_emitted_nft_argv` in
    /// `mod tests`. FAIL-CLOSED: every missing allow rule below is an error;
    /// the shared builders exist to keep these checks honest across rule
    /// format changes, never to weaken them.
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
        self.assert_chain_contains_strings(
            &killswitch,
            &Self::loopback_accept_tokens(),
            "loopback killswitch allow rule missing",
        )?;
        self.assert_chain_contains_strings(
            &killswitch,
            &Self::established_related_accept_tokens(),
            "established/related killswitch allow rule missing",
        )?;
        self.assert_chain_contains_strings(
            &killswitch,
            &Self::tunnel_interface_accept_tokens(self.interface_name.as_str()),
            "tunnel-interface killswitch allow rule missing",
        )?;
        if self.wg_listen_port != 0 {
            self.assert_chain_contains_strings(
                &killswitch,
                &Self::wg_listen_port_allow_tokens(
                    "dport",
                    self.egress_interface.as_str(),
                    self.wg_listen_port,
                ),
                "wireguard listen port killswitch allow rule missing",
            )?;
            self.assert_chain_contains_strings(
                &killswitch,
                &Self::wg_listen_port_allow_tokens(
                    "sport",
                    self.egress_interface.as_str(),
                    self.wg_listen_port,
                ),
                "wireguard source port killswitch allow rule missing",
            )?;
        }
        self.assert_chain_contains_strings(
            &forward,
            &Self::established_related_accept_tokens(),
            "forward established/related allow rule missing",
        )?;
        self.assert_chain_contains_strings(
            &forward,
            &Self::forward_tunnel_to_egress_tokens(
                self.interface_name.as_str(),
                self.egress_interface.as_str(),
            ),
            "forwarding allow rule to underlay egress missing",
        )?;
        if self.allow_tunnel_relay_forward {
            self.assert_chain_contains_strings(
                &forward,
                &Self::forward_hairpin_accept_tokens(self.interface_name.as_str()),
                "relay-with-upstream forwarding allow rule missing",
            )?;
        }
        if self.nat_table.is_some() {
            self.assert_chain_contains_strings(
                &killswitch,
                &Self::killswitch_egress_allow_tokens(self.egress_interface.as_str()),
                "egress-interface killswitch allow rule missing while nat forwarding is active",
            )?;
        }
        if self.dns_protected {
            for proto in ["udp", "tcp"] {
                self.assert_chain_contains_strings(
                    &killswitch,
                    &Self::dns_off_tunnel_drop_tokens(proto, self.interface_name.as_str()),
                    &format!("dns {proto} fail-closed rule missing"),
                )?;
                self.assert_chain_contains_strings(
                    &killswitch,
                    &Self::dns_accept_tokens(proto),
                    &format!("dns {proto} allow rule missing"),
                )?;
            }
        }
        // RN-27: everything above is a PRESENCE check on allow rules, and none
        // of it asserts a terminal drop at all -- so a chain whose `policy drop`
        // had been made unreachable by a broad accept passed every assertion.
        // nftables is first-match-wins within a chain and the policy is the
        // chain DEFAULT, applied only after every rule fails to match, so any
        // accept above it is evaluated first.
        //
        // When NAT forwarding is active the daemon deliberately installs a
        // wide-open `oifname "<underlay>" accept` here (asserted above). That is
        // a real killswitch hole tracked as its own finding, and closing it is
        // not this assertion's call -- so it is passed as ACKNOWLEDGED, which
        // stops it masking anything beneath it while leaving its own disposition
        // to the owning finding. Any other broad accept fails loudly.
        let acknowledged_wide_open: Vec<&str> = if self.nat_table.is_some() {
            vec![self.egress_interface.as_str()]
        } else {
            Vec::new()
        };
        crate::killswitch_precedence::evaluate_linux_killswitch_chain_precedence(
            killswitch.join("\n").as_str(),
            self.interface_name.as_str(),
            &acknowledged_wide_open,
        )
        .map_err(SystemError::KillSwitchAssertionFailed)?;
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
        // QH-29: rule bodies come from the shared token builders that
        // assert_firewall_ruleset matches against.
        self.run_nft_rule_argv(
            "inet",
            table.as_str(),
            "killswitch",
            &Self::loopback_accept_tokens(),
            &[],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.apply_fail_closed_management_allow_rules(table.as_str())?;
        self.apply_traversal_bootstrap_allow_rules(table.as_str())?;
        if self.wg_listen_port != 0 {
            self.run_nft_rule_argv(
                "inet",
                table.as_str(),
                "killswitch",
                &Self::wg_listen_port_allow_tokens(
                    "dport",
                    self.egress_interface.as_str(),
                    self.wg_listen_port,
                ),
                &[],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "wireguard listen port {} allow rule failed: {err}",
                    self.wg_listen_port
                ))
            })?;
            // Match outbound WireGuard by SOURCE port as well.  The dport rule
            // above only covers peers that happen to listen on our own port,
            // which holds on a LAN but is exactly the assumption NAT traversal
            // breaks: a peer reached at its server-reflexive candidate sits on
            // an arbitrary NAT-mapped port (e.g. 51.186.254.100:44883), so the
            // handshake datagram is dropped and traversal can never complete.
            // Every datagram the daemon emits leaves its bound WireGuard socket
            // with this source port, so matching on it keeps the rule as narrow
            // as the dport form while covering any peer endpoint.
            self.run_nft_rule_argv(
                "inet",
                table.as_str(),
                "killswitch",
                &Self::wg_listen_port_allow_tokens(
                    "sport",
                    self.egress_interface.as_str(),
                    self.wg_listen_port,
                ),
                &[],
            )
            .map_err(|err| {
                SystemError::FirewallApplyFailed(format!(
                    "wireguard source port {} allow rule failed: {err}",
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

    fn set_full_tunnel_engaged(&mut self, engaged: bool) {
        self.full_tunnel_engaged = engaged;
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
        // QH-29: every rule body below comes from the shared token builders
        // that assert_firewall_ruleset matches against — the generator and
        // the fail-closed matcher cannot drift apart silently.
        self.run_nft_rule_argv(
            "inet",
            table.as_str(),
            "killswitch",
            &Self::established_related_accept_tokens(),
            &[],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run_nft_rule_argv(
            "inet",
            table.as_str(),
            "killswitch",
            &Self::tunnel_interface_accept_tokens(self.interface_name.as_str()),
            &[],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run_nft_rule_argv(
            "inet",
            table.as_str(),
            "forward",
            &Self::established_related_accept_tokens(),
            &[],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        self.run_nft_rule_argv(
            "inet",
            table.as_str(),
            "forward",
            &Self::forward_tunnel_to_egress_tokens(
                self.interface_name.as_str(),
                self.egress_interface.as_str(),
            ),
            &[],
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        if self.allow_tunnel_relay_forward {
            // OBSERVABILITY, not behaviour: `counter` turns "the hairpin
            // forward-accept rule exists" into "it matched N packets". Whether
            // this rule ever matches is the single most useful fact when
            // diagnosing a relay-with-upstream forwarding failure, and its
            // absence cost multiple live-lab cycles: rule presence was
            // observable, rule *matching* was not.
            //
            // Safe for the runtime self-assertion: `counter` is inserted as an
            // observability token BEFORE the verdict and never enters the
            // shared builder, and `chain_contains_all_tokens` matches each
            // builder token as an independent substring of the rendered line,
            // so the extra `counter packets N bytes N` nft prints between the
            // match terms and the verdict does not break the match.
            self.run_nft_rule_argv(
                "inet",
                table.as_str(),
                "forward",
                &Self::forward_hairpin_accept_tokens(self.interface_name.as_str()),
                &["counter"],
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

    // QH-53: the firewalld zone bind is deliberately NOT part of the
    // killswitch apply. It needs the tunnel interface to exist, and the
    // killswitch runs before backend start creates it — binding here failed
    // every cold bootstrap of a forwarding node on a firewalld host. The bind
    // lives in admit_host_firewall_forwarding, called by the controller
    // after backend start.

    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Role gating (serve_exit_node) lives at the controller call site so
        // the stage is visible in DryRun op ordering; when called, always
        // verify — an unconditional check cannot be silently skipped by a
        // stale local flag.
        self.ensure_host_firewall_admits_forwarding()
    }

    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Role gating lives at the controller call sites, exactly as it does
        // for the admit, so the stage is visible in DryRun op ordering and the
        // demotion edge is testable without a firewalld host.
        self.ensure_host_firewall_forwarding_withdrawn()
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

    /// QH-52 residual: crash-restart reconcile of a firewalld zone binding.
    ///
    /// A process crash loses `active_stages`, so the demotion arm's
    /// `HostFirewallAdmitted` marker is gone on restart and a restart-as-client
    /// would otherwise leave the interface bound forever. Probe first
    /// (`FirewalldZoneOp::Query` — mutates nothing), then unbind ONLY when the
    /// posture is not already withdrawn:
    ///
    /// - probe capture could not run at all (no busctl on the host, helper
    ///   unavailable): log and return Ok. Returning Err here would make the
    ///   controller re-record the marker on EVERY apply on such hosts,
    ///   manufacturing per-apply withdrawal churn out of a missing diagnostic
    ///   tool — exactly the spurious-failure hazard the QH-52 note rejected.
    /// - posture unreadable or not withdrawn (bound, or presence unknown):
    ///   run the full idempotent withdrawal. It self-verifies by re-reading
    ///   the posture, so an unremovable binding surfaces as residue the same
    ///   way a demotion-time withdrawal does.
    fn reconcile_firewalld_zone_residue(&mut self) -> Result<(), SystemError> {
        use crate::linux_firewalld_zone::{FirewalldZoneOp, FirewalldZoneSpec};

        let spec = FirewalldZoneSpec::new(FirewalldZoneOp::Query, self.interface_name.as_str())
            .map_err(SystemError::PrerequisiteCheckFailed)?;
        let argv = spec.encode();
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = match self.run_capture(
            PrivilegedCommandProgram::LinuxFirewalldZone,
            borrowed.as_slice(),
        ) {
            Ok(output) => output,
            Err(err) => {
                log::warn!(
                    "host firewall zone binding reconcile probe unavailable, assuming no residue \
                     to clear: {err}"
                );
                return Ok(());
            }
        };
        match crate::linux_firewalld_zone::FirewalldPosture::parse(output.stdout.trim()) {
            Ok(posture) if posture.forwarding_admission_withdrawn() => Ok(()),
            posture => {
                if let Err(parse_err) = posture {
                    log::warn!(
                        "host firewall zone binding reconcile could not read the posture \
                         ({parse_err}); attempting the idempotent withdrawal"
                    );
                }
                self.ensure_host_firewall_forwarding_withdrawn()
            }
        }
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
        // QH-29: rule bodies come from the shared token builders that
        // assert_nat_forwarding / assert_firewall_ruleset match against.
        self.run_nft_rule_argv(
            "ip",
            nat_table.as_str(),
            "postrouting",
            &Self::nat_egress_masquerade_tokens(self.egress_interface.as_str()),
            &[],
        )
        .map_err(|err| {
            self.run_allow_failure(
                PrivilegedCommandProgram::Nft,
                &["delete", "table", "ip", nat_table.as_str()],
            );
            let _ = self.restore_ipv4_forwarding();
            SystemError::NatApplyFailed(err.to_string())
        })?;
        if self.allow_tunnel_relay_forward {
            // OBSERVABILITY, not behaviour — see the matching `counter` on the
            // hairpin forward-accept rule. This one matters even more: the
            // hairpin SNAT is load-bearing for the request leg (it rewrites the
            // inner source so the packet satisfies the upstream exit's cryptokey
            // routing, whose AllowedIPs for this node is a single /32), and
            // whether it MATCHED was previously unobservable — only that the rule
            // existed. `counter` is inserted before the verdict and never enters
            // the shared builder, and `chain_contains_all_tokens` matches each
            // builder token as an independent substring of the rendered line, so
            // it is safe for `assert_nat_forwarding`.
            if let Err(err) = self.run_nft_rule_argv(
                "ip",
                nat_table.as_str(),
                "postrouting",
                &Self::nat_hairpin_masquerade_tokens(self.interface_name.as_str()),
                &["counter"],
            ) {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Nft,
                    &["delete", "table", "ip", nat_table.as_str()],
                );
                let _ = self.restore_ipv4_forwarding();
                return Err(SystemError::NatApplyFailed(err.to_string()));
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
            if let Err(err) = self.run_nft_rule_argv(
                "inet",
                fw_table.as_str(),
                "killswitch",
                &Self::killswitch_egress_allow_tokens(egress_iface.as_str()),
                &[],
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

    /// QH-47. The one privileged builtin that can invalidate conntrack, driven
    /// over the two-token grammar; the daemon supplies only the mesh source
    /// network and cannot name an operation.
    ///
    /// Runs AFTER the nat table has been created or deleted, never before: a
    /// flush issued ahead of the rule change would be immediately undone by the
    /// next packet of a steady stream, which would re-create the entry against
    /// the OLD ruleset.
    fn flush_nat_conntrack(
        &mut self,
        mesh_cidr: &str,
        _reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError> {
        use crate::linux_conntrack_flush::{ConntrackFlushOutcome, ConntrackFlushSpec};

        let spec = ConntrackFlushSpec::for_mesh_source(mesh_cidr)
            .map_err(SystemError::PrerequisiteCheckFailed)?;
        let argv = spec.encode();
        let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
        let output = self.run_capture(
            PrivilegedCommandProgram::LinuxConntrackFlush,
            borrowed.as_slice(),
        )?;
        ConntrackFlushOutcome::parse(output.stdout.trim())
            .map_err(|err| SystemError::Io(format!("conntrack flush outcome: {err}")))
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        let table = self
            .firewall_table
            .clone()
            .ok_or_else(|| SystemError::DnsApplyFailed("killswitch table missing".to_owned()))?;
        // QH-29: rule bodies come from the shared token builders that
        // assert_firewall_ruleset matches against.
        for proto in ["udp", "tcp"] {
            self.run_nft_rule_argv(
                "inet",
                table.as_str(),
                "killswitch",
                &Self::dns_off_tunnel_drop_tokens(proto, self.interface_name.as_str()),
                &[],
            )
            .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
            self.run_nft_rule_argv(
                "inet",
                table.as_str(),
                "killswitch",
                &Self::dns_accept_tokens(proto),
                &[],
            )
            .map_err(|err| SystemError::DnsApplyFailed(err.to_string()))?;
        }
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
        self.assert_blind_exit_posture()?;
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

/// QH-29: the terminal default-deny rule every macOS killswitch anchor ends
/// with. `render_macos_killswitch_pf_rules` appends it (last line, unconditionally)
/// and `MacosCommandSystem::assert_killswitch` requires it in the LIVE
/// `pfctl -a <anchor> -s rules` output; both sides reference this one constant so
/// the generator↔matcher pairing cannot drift silently. The existing render
/// snapshot tests in `mod tests` (e.g. `macos_render_pf_rules_full_tunnel_dns_snapshot`)
/// additionally pin the full rendered rule text.
pub(crate) const MACOS_PF_TERMINAL_BLOCK_RULE: &str = "block drop out quick all";

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
    rules.push_str(MACOS_PF_TERMINAL_BLOCK_RULE);
    rules.push('\n');
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
    /// The DNS fail-closed posture this system last INSTALLED (M2). Fresh
    /// instance: [`DnsPosture::Untouched`] — nothing has been applied yet.
    /// Drives `assert_dns_protection` branching and posture-transition
    /// handling (FullyProtected → ScopedResolverOnly must tear the full
    /// posture down before installing the scoped one).
    dns_posture: DnsPosture,
    traversal_bootstrap_allow_endpoints: Vec<SocketAddr>,
    managed_peer_egress_endpoints: Vec<SocketAddr>,
    blind_exit_pf_config: Option<MacosBlindExitPfConfig>,
    /// The regular-exit NAT translation anchor (`com.rustynet/nat`) once
    /// loaded, distinct from `anchor_name` (the killswitch filter anchor).
    /// `Some` means the exit NAT is active and teardown must flush it.
    exit_nat_anchor: Option<String>,
    /// The generation-scoped tandem DNS redirect anchor
    /// (`com.rustynet/tdns_g<generation>`, D-6c) once loaded — distinct from
    /// `anchor_name` (killswitch) and `exit_nat_anchor` (`com.rustynet/nat`).
    /// `Some` means the redirect is active and teardown must flush it.
    tandem_dns_anchor: Option<String>,
    /// The forwarding value captured before the exit enabled forwarding, so
    /// teardown can restore the exact prior state instead of blindly forcing it
    /// off.
    prior_ip_forwarding: Option<String>,
    /// Which forwarding sysctl the exit enabled — `net.inet.ip.forwarding` for
    /// an IPv4 mesh, `net.inet6.ip6.forwarding` for an IPv6 mesh. Restore and
    /// teardown must use the SAME key that was enabled.
    exit_forwarding_key: Option<&'static str>,
    /// Durable path of the macOS DNS fail-closed backup document, derived
    /// from the daemon's actual state path (`--state` installs consult the
    /// backup beside their own state file). The apply write, the prior-read
    /// capture guard, the rollback restore, and the startup guard's derived
    /// path (daemon.rs) must ALL agree on this one path.
    dns_backup_path: std::path::PathBuf,
    /// M1 (MacosClientResolverNotServingDiagnosisReview_2026-09-02 §3.3):
    /// the daemon's bootstrap-time DNS probe servicer, when installed. While
    /// `bootstrap()` holds the runtime, the probe's wait window drains the
    /// daemon's hoisted resolver socket through this handle (which answers
    /// via the daemon's own `build_dns_response` responder) instead of
    /// relying on the main serve loop, which cannot run yet. `None` keeps the
    /// probe's original single-blocking-recv behaviour (reconcile-time
    /// applies and tests, where the serve loop is already live or the
    /// failure is the expected result).
    dns_probe_servicer: Option<std::sync::Arc<crate::daemon::DnsProbeServicer>>,
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
            dns_posture: DnsPosture::Untouched,
            traversal_bootstrap_allow_endpoints: Vec::new(),
            managed_peer_egress_endpoints: Vec::new(),
            blind_exit_pf_config: None,
            exit_nat_anchor: None,
            tandem_dns_anchor: None,
            prior_ip_forwarding: None,
            exit_forwarding_key: None,
            // Platform default; the daemon overrides this with the path
            // derived from its actual `--state` at construction
            // (`with_dns_backup_path`). Tests that never touch the DNS
            // apply/rollback paths only ever read this field.
            dns_backup_path: crate::macos_dns_sc_protect::networksetup_dns_backup_path(
                std::path::Path::new(crate::daemon::default_state_path()),
            ),
            dns_probe_servicer: None,
        })
    }

    pub fn with_traversal_bootstrap_allow_endpoints(mut self, endpoints: Vec<SocketAddr>) -> Self {
        self.traversal_bootstrap_allow_endpoints = dedupe_socket_addrs(endpoints);
        self
    }

    /// Point the DNS fail-closed backup at the durable sibling of THIS
    /// daemon's state file. Wired from `DaemonConfig::state_path` at
    /// construction so apply/rollback and the startup guard always agree on
    /// one path (MacosDnsBackupRebootSurvivalPlan_2026-09-02 Option A).
    pub fn with_dns_backup_path(mut self, path: std::path::PathBuf) -> Self {
        self.dns_backup_path = path;
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
            // M3 (MacosClientDnsFailclosedDiagnosis_2026-09-02 R2): the
            // DNS-block floor must accompany EVERY live loopback pin, not
            // just the ones this daemon's full posture installed. Any pf
            // re-render (bypass routes, killswitch, pre-NAT) while a general
            // pin persists — including residue a failed apply could not roll
            // back — would otherwise drop the floor under the pins: the
            // exact floor-less half state the plain-client failure was.
            dns_protected: self.dns_protected || self.has_live_loopback_dns_pins(),
            allow_egress_interface: self.allow_egress_interface,
            fail_closed_ssh_allow: self.fail_closed_ssh_allow,
            fail_closed_ssh_allow_cidrs: self.fail_closed_ssh_allow_cidrs.clone(),
            traversal_bootstrap_allow_endpoints: self.traversal_bootstrap_allow_endpoints.clone(),
            managed_peer_egress_endpoints: self.managed_peer_egress_endpoints.clone(),
            ipv6_blocked: self.ipv6_blocked,
        }
    }

    /// Does any enabled network service currently advertise a general DNS pin
    /// at the loopback resolver? Fail-closed: an unreadable system
    /// configuration counts as pins-present (the caller keeps the pf floor
    /// over a state it cannot verify). `dns_protected` short-circuits true —
    /// the full posture implies the pins by definition, and skipping the
    /// enumeration keeps every re-render cheap.
    fn has_live_loopback_dns_pins(&self) -> bool {
        if self.dns_protected {
            return true;
        }
        // networksetup DNS service pins are a macOS-only concept. On other
        // platforms a MacosCommandSystem is exercised only by the pure-logic
        // pf-render tests, where there is no networksetup to enumerate (the
        // enumeration would error and the macOS fail-closed default below
        // would spuriously latch the DNS floor). No live loopback pin can
        // exist off macOS, so the M3 latch does not fire.
        #[cfg(not(target_os = "macos"))]
        {
            false
        }
        #[cfg(target_os = "macos")]
        {
            let Ok(services) = self.enumerate_networksetup_services() else {
                return true;
            };
            for service in &services {
                match self.read_networksetup_service_dns(service) {
                    Ok(Some(servers)) => {
                        if crate::macos_dns_sc_protect::is_loopback_dns_server_list(&servers) {
                            return true;
                        }
                    }
                    Ok(None) => {}
                    // A service we cannot read is a service that MAY be pinned:
                    // keep the floor.
                    Err(_) => return true,
                }
            }
            false
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

    /// Activate the D-6c tandem transparent DNS redirect: load the
    /// generation-scoped `com.rustynet/tdns_g<generation>` anchor holding the
    /// reviewed `rdr` translation forms plus the containment filter. The
    /// rendered rules come from the pure control-plane decision (this method
    /// never re-decides); a contained/off decision is refused here so it can
    /// never install a rule. Fail-closed preconditions, in order:
    ///
    /// 1. no blind exit (an irreversible blind exit never hosts the DNS
    ///    service);
    /// 2. the base DNS fail-closed posture (`dns_protected`) must already be
    ///    live — the redirect ADDS translation on top of containment and must
    ///    never be the only thing standing between a client and a leak;
    /// 3. the decision must be `Redirect` (`NoRedirect`/`ContainNoRedirect`
    ///    refuse, leaving the base posture as the only DNS behavior).
    ///
    /// After a successful load the live anchor is verified against the same
    /// reviewed rule shapes (`pfctl -s nat` + `pfctl -s rules`); on drift the
    /// anchor is torn back down and the error propagates, so the base
    /// DNS-block posture is what remains.
    ///
    /// Public surface: the daemon's tandem reconcile loop is the (flagged)
    /// follow-up wiring; the Linux D-6c renderer landed the same way — the
    /// reviewed activation entry point exists and is proven, the caller is
    /// tracked in the phase-2 notes.
    pub fn activate_tandem_dns_redirect(
        &mut self,
        decision: &TandemDnsRedirectDecision,
        mesh_prefix: &MeshIpv4Prefix,
    ) -> Result<(), SystemError> {
        if self.blind_exit_pf_config.is_some() {
            return Err(SystemError::FirewallApplyFailed(
                "tandem DNS redirect refused: blind exit is active and never hosts the DNS service"
                    .to_owned(),
            ));
        }
        if !self.dns_protected {
            return Err(SystemError::FirewallApplyFailed(
                "tandem DNS redirect refused: base DNS fail-closed posture is not active; a \
                 redirect without containment underneath would be a plaintext escape"
                    .to_owned(),
            ));
        }
        let config = MacosTandemDnsRedirectPfConfig::from_redirect_decision(
            &self.interface_name,
            self.generation,
            decision,
            Some(mesh_prefix),
        )
        .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;

        self.ensure_pf_enabled()?;
        let spec = MacosPfLoadSpec::TandemDnsRedirect {
            config: config.clone(),
        };
        let args = spec.encode();
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        self.run(PrivilegedCommandProgram::MacosPfLoad, &arg_refs)
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        let anchor = spec.anchor_name();
        self.tandem_dns_anchor = Some(anchor.clone());

        // Verify BOTH halves of the anchor against the reviewed shapes; on
        // any drift tear the redirect back down so only the base posture
        // remains.
        if let Err(err) = self.verify_tandem_dns_redirect_anchor(&anchor, &config) {
            let _ = self.teardown_tandem_dns_redirect();
            return Err(err);
        }
        Ok(())
    }

    /// Verify the live tandem anchor: `pfctl -a <anchor> -s nat` must be
    /// exactly the reviewed rdr set and `pfctl -a <anchor> -s rules` exactly
    /// the reviewed containment filter set.
    fn verify_tandem_dns_redirect_anchor(
        &self,
        anchor: &str,
        config: &MacosTandemDnsRedirectPfConfig,
    ) -> Result<(), SystemError> {
        let nat_output = self
            .run_capture(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-s", "nat"],
            )
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        if !nat_output.success() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "tandem DNS redirect verification query failed: status={} stderr={}",
                nat_output.status, nat_output.stderr
            )));
        }
        let reasons =
            evaluate_macos_tandem_dns_redirect_translation(nat_output.stdout.as_str(), config);
        if !reasons.is_empty() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "tandem DNS redirect translation verification failed: {}",
                reasons.join("; ")
            )));
        }
        let rules_output = self
            .run_capture(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor, "-s", "rules"],
            )
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))?;
        if !rules_output.success() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "tandem DNS redirect filter verification query failed: status={} stderr={}",
                rules_output.status, rules_output.stderr
            )));
        }
        let reasons =
            evaluate_macos_tandem_dns_redirect_filter(rules_output.stdout.as_str(), config);
        if !reasons.is_empty() {
            return Err(SystemError::FirewallApplyFailed(format!(
                "tandem DNS redirect filter verification failed: {}",
                reasons.join("; ")
            )));
        }
        Ok(())
    }

    /// Tear down the tandem DNS redirect: flush ONLY the generation-scoped
    /// tandem anchor by reference, verify the flush, then clear the handle.
    /// The base exit NAT (`com.rustynet/nat`), the killswitch
    /// (`com.apple/rustynet_g*`), and the blind-exit anchor are never
    /// referenced, so teardown cannot leave redirect residue nor damage base
    /// posture. The handle stays `Some` until the flush is verified empty, so
    /// a failed teardown is retryable instead of silently leaking the anchor.
    fn teardown_tandem_dns_redirect(&mut self) -> Result<(), SystemError> {
        let Some(anchor) = self.tandem_dns_anchor.clone() else {
            return Ok(());
        };
        self.run_allow_failure(
            PrivilegedCommandProgram::Pfctl,
            &["-a", anchor.as_str(), "-F", "all"],
        );
        // Verify the anchor is actually empty before clearing the handle.
        let output = self.run_capture(
            PrivilegedCommandProgram::Pfctl,
            &["-a", anchor.as_str(), "-s", "nat"],
        )?;
        if output.success() && !output.stdout.trim().is_empty() {
            return Err(SystemError::RollbackFailed(format!(
                "tandem DNS redirect anchor {anchor} still holds translation rules after flush"
            )));
        }
        self.tandem_dns_anchor = None;
        Ok(())
    }

    /// List every tandem-owned anchor currently registered with pf
    /// (`com.rustynet/tdns_g*`), for crash-residue sweeping. Mirrors
    /// `list_owned_anchors`, which only sweeps the `com.apple/rustynet_g*`
    /// killswitch namespace.
    fn list_tandem_owned_anchors(&self) -> Result<Vec<String>, SystemError> {
        let output = self.run_capture(PrivilegedCommandProgram::Pfctl, &["-s", "Anchors"])?;
        if output.success() {
            return Ok(output
                .stdout
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && line.starts_with("com.rustynet/tdns_g"))
                .map(ToOwned::to_owned)
                .collect());
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
}

impl MacosCommandSystem {
    /// Enumerates the enabled macOS network services via the privileged
    /// helper's fixed-path `/usr/sbin/networksetup` (M1). Fails closed on any
    /// command or parse error — a partial service list must never be treated
    /// as complete, or unlisted services would keep leaking.
    fn enumerate_networksetup_services(&self) -> Result<Vec<String>, String> {
        let argv = crate::macos_dns_sc_protect::networksetup_listall_args();
        let output = self
            .run_capture(PrivilegedCommandProgram::NetworkSetup, &argv)
            .map_err(|err| err.to_string())?;
        if !output.success() {
            return Err(format!(
                "networksetup -listallnetworkservices failed: status={} stderr={}",
                output.status, output.stderr
            ));
        }
        crate::macos_dns_sc_protect::parse_networksetup_service_list(&output.stdout)
    }

    /// Reads one service's current DNS servers through the privileged helper
    /// (`networksetup -getdnsservers <service>`); `Ok(None)` means the service
    /// has no DNS servers configured.
    fn read_networksetup_service_dns(&self, service: &str) -> Result<Option<Vec<String>>, String> {
        let argv = crate::macos_dns_sc_protect::networksetup_getdns_args(service)?;
        let output = self
            .run_capture(PrivilegedCommandProgram::NetworkSetup, &argv)
            .map_err(|err| err.to_string())?;
        if !output.success() {
            return Err(format!(
                "networksetup -getdnsservers '{service}' failed: status={} stderr={}",
                output.status, output.stderr
            ));
        }
        match crate::macos_dns_sc_protect::parse_networksetup_getdns_output(&output.stdout)? {
            crate::macos_dns_sc_protect::NetworksetupDnsServers::None => Ok(None),
            crate::macos_dns_sc_protect::NetworksetupDnsServers::Servers(servers) => {
                Ok(Some(servers))
            }
        }
    }

    /// Restores every backed-up service DNS setting from the session-scoped
    /// backup file. Called from `rollback_dns_protection` (ordered BEFORE the
    /// pf anchor reload, §10.7) and reusable by the startup-recovery path.
    /// Fails closed with an operator-actionable message when the backup is
    /// missing while services are still pinned loopback, or when any restore
    /// command fails — the backup file is retained in that case so a retry
    /// (or the startup guard) can try again.
    fn restore_networksetup_dns_from_backup(&self) -> Result<(), String> {
        let backup_path = self.dns_backup_path.clone();
        match crate::macos_dns_sc_protect::read_networksetup_dns_backup(&backup_path) {
            Ok(Some(backup)) => {
                for entry in &backup.services {
                    let argv = match &entry.servers {
                        Some(servers) => {
                            let server_refs: Vec<&str> =
                                servers.iter().map(String::as_str).collect();
                            crate::macos_dns_sc_protect::networksetup_setdns_restore_args(
                                &entry.service,
                                &server_refs,
                            )?
                        }
                        None => crate::macos_dns_sc_protect::networksetup_setdns_empty_args(
                            &entry.service,
                        )?
                        .to_vec(),
                    };
                    let output = self
                        .run_capture(PrivilegedCommandProgram::NetworkSetup, &argv)
                        .map_err(|err| err.to_string())?;
                    if !output.success() {
                        return Err(format!(
                            "networksetup DNS restore for service '{}' failed: status={} stderr={} (manual fix: sudo /usr/sbin/networksetup -setdnsservers \"{}\" Empty; backup retained at {})",
                            entry.service,
                            output.status,
                            output.stderr,
                            entry.service,
                            backup_path.display()
                        ));
                    }
                }
                crate::macos_dns_sc_protect::remove_networksetup_dns_backup(&backup_path)?;
                Ok(())
            }
            Ok(None) => {
                // No backup: either protection never touched system
                // configuration, or the backup was lost. Fail loud ONLY if the
                // host is actually still pinned loopback (stranded); otherwise
                // there is nothing to restore.
                let services = self.enumerate_networksetup_services()?;
                let mut stranded = Vec::new();
                for service in &services {
                    if let Some(servers) = self.read_networksetup_service_dns(service)?
                        && crate::macos_dns_sc_protect::is_loopback_dns_server_list(&servers)
                    {
                        stranded.push(service.clone());
                    }
                }
                if stranded.is_empty() {
                    Ok(())
                } else {
                    Err(
                        crate::macos_dns_sc_protect::startup_recovery_manual_restore_message(
                            &stranded,
                            &backup_path,
                        ),
                    )
                }
            }
            Err(err) => Err(format!(
                "the networksetup DNS backup at {} is unreadable ({err}); restore manually before retrying",
                backup_path.display()
            )),
        }
    }

    /// Verify the daemon's loopback DNS resolver is bound AND answering on
    /// the scoped-resolver port (127.0.0.1:53535) — BEFORE any DNS mutation
    /// (review A6, MacosClientDnsFailclosedDiagnosisReview_2026-09-02). The
    /// daemon binds `dns_resolver_bind_addr` in its run loop before applying
    /// dataplane generations, but this apply-path probe does not trust that
    /// ordering: a resolver that is not answering means every pin this apply
    /// would write points at a dead :53535, and the scoped resolver file
    /// would route `*.rustynet` nowhere. Fail closed BEFORE mutating.
    ///
    /// The probe is a minimal RFC 1035 A query for the mesh zone root
    /// (`rustynet.`) over loopback UDP; any reply echoing the transaction id
    /// proves a DNS-speaking listener owns the port.
    fn verify_loopback_resolver_live(&self) -> Result<(), SystemError> {
        use std::net::UdpSocket;
        const PROBE_QUERY: [u8; 26] = [
            // Header: id "RN", RD flag, QDCOUNT=1, rest zero.
            0x52, 0x4e, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // QNAME "rustynet." (length-prefixed labels), QTYPE=A, QCLASS=IN.
            0x07, b'r', b'u', b's', b't', b'y', b'n', b'e', b't', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let port = crate::linux_dns_protect::MACOS_SCOPED_RESOLVER_LOOPBACK_PORT;
        let socket = UdpSocket::bind("127.0.0.1:0").map_err(|err| {
            SystemError::DnsApplyFailed(format!(
                "loopback DNS resolver probe socket bind failed: {err}"
            ))
        })?;
        socket
            .set_read_timeout(Some(Duration::from_millis(2_000)))
            .map_err(|err| {
                SystemError::DnsApplyFailed(format!("loopback DNS resolver probe timeout: {err}"))
            })?;
        socket.connect(("127.0.0.1", port)).map_err(|err| {
            SystemError::DnsApplyFailed(format!(
                "no loopback DNS resolver is listening on 127.0.0.1:{port}: {err}"
            ))
        })?;
        socket.send(&PROBE_QUERY).map_err(|err| {
            SystemError::DnsApplyFailed(format!(
                "loopback DNS resolver probe send to 127.0.0.1:{port} failed: {err}"
            ))
        })?;
        // M1: during bootstrap the main serve loop cannot be running (the
        // daemon is single-threaded and `bootstrap()` holds the runtime), so
        // when a probe servicer is installed its wait window must drain the
        // daemon's hoisted resolver socket itself — through the SAME
        // `build_dns_response` responder the serve loop uses, bounded by this
        // probe's existing 2 s deadline. Without a servicer (reconcile-time
        // applies, tests) the behaviour is the original single blocking recv.
        let deadline = std::time::Instant::now() + Duration::from_millis(2_000);
        let poll_interval = if self.dns_probe_servicer.is_some() {
            Duration::from_millis(50)
        } else {
            Duration::from_millis(2_000)
        };
        socket
            .set_read_timeout(Some(poll_interval))
            .map_err(|err| {
                SystemError::DnsApplyFailed(format!("loopback DNS resolver probe timeout: {err}"))
            })?;
        let mut reply = [0u8; 512];
        loop {
            if let Some(servicer) = &self.dns_probe_servicer {
                servicer.service_once();
            }
            match socket.recv(&mut reply) {
                Ok(len) => {
                    if len < 12 || reply[0] != PROBE_QUERY[0] || reply[1] != PROBE_QUERY[1] {
                        return Err(SystemError::DnsApplyFailed(format!(
                            "127.0.0.1:{port} answered with a malformed DNS reply ({len} bytes)"
                        )));
                    }
                    return Ok(());
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if std::time::Instant::now() >= deadline {
                        return Err(SystemError::DnsApplyFailed(format!(
                            "the loopback DNS resolver on 127.0.0.1:{port} did not answer: {err}"
                        )));
                    }
                }
                Err(err) => {
                    return Err(SystemError::DnsApplyFailed(format!(
                        "the loopback DNS resolver on 127.0.0.1:{port} did not answer: {err}"
                    )));
                }
            }
        }
    }

    /// Roll the node back to [`DnsPosture::Untouched`] after a failed apply,
    /// then surface the ORIGINAL apply failure (a rollback failure dominates:
    /// it means the node may still hold residue AND the apply failed).
    fn rollback_after_failed_apply(&mut self, original: SystemError) -> SystemError {
        match self.rollback_dns_protection() {
            Ok(()) => original,
            Err(rollback_err) => rollback_err,
        }
    }

    /// Install the [`DnsPosture::ScopedResolverOnly`] posture (M2): ONLY the
    /// scoped `/etc/resolver/rustynet` file, routing `*.rustynet` at the live
    /// loopback resolver. NO general pins, NO pf floor, NO resolv.conf or
    /// primary rewrite. Fail-closed end to end:
    ///
    /// 1. the resolver must answer (probe FIRST — a scoped file pointing at
    ///    a dead listener routes mesh names nowhere);
    /// 2. the system configuration must hold NO loopback general pin — one
    ///    present means stranded residue from a prior full-protection apply
    ///    whose teardown did not run. Startup recovery
    ///    (`run_startup_dns_recovery`, daemon.rs) restores those from the
    ///    durable backup BEFORE the daemon applies generations, so a pin seen
    ///    here is residue recovery could not clear and applying over it
    ///    would strand ALL of the machine's resolution at a listener this
    ///    posture never justifies;
    /// 3. the scoped-file write goes through the privileged helper's
    ///    fixed-path builtin and MUST succeed — there is no pf floor behind
    ///    this posture, so a silent failure would leak `*.rustynet` queries
    ///    to the LAN resolver.
    fn apply_scoped_resolver_only(&mut self) -> Result<(), SystemError> {
        self.verify_loopback_resolver_live()?;
        let services = self
            .enumerate_networksetup_services()
            .map_err(SystemError::DnsApplyFailed)?;
        for service in &services {
            let servers = self
                .read_networksetup_service_dns(service)
                .map_err(SystemError::DnsApplyFailed)?;
            if let Some(servers) = servers {
                if crate::macos_dns_sc_protect::is_loopback_dns_server_list(&servers) {
                    return Err(SystemError::DnsApplyFailed(format!(
                        "refusing {} posture: service '{service}' still pins loopback DNS (stranded residue; restore the original DNS before scoping)",
                        DnsPosture::ScopedResolverOnly.as_str()
                    )));
                }
            }
        }
        self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_MACOS_RESOLVER_APPLY],
        )
        .map_err(|err| {
            SystemError::DnsApplyFailed(format!(
                "macOS scoped resolver write failed (no pf floor behind this posture; failing closed): {err}"
            ))
        })?;
        self.dns_posture = DnsPosture::ScopedResolverOnly;
        self.dns_protected = false;
        Ok(())
    }

    /// Assert the [`DnsPosture::ScopedResolverOnly`] posture: the scoped
    /// resolver file must be PRESENT and readable (fail-closed direct read),
    /// and no network service may advertise a general loopback pin (a pin
    /// without the full posture's live primary + pf floor is exactly the
    /// half-applied drift the three-state model exists to forbid).
    fn assert_scoped_resolver_posture(&mut self) -> Result<(), SystemError> {
        let path = crate::linux_dns_protect::MACOS_SCOPED_RESOLVER_PATH;
        if let Err(err) = std::fs::read_to_string(path) {
            return Err(SystemError::DnsApplyFailed(format!(
                "macOS DNS posture drifted ({}/{}): scoped resolver unreadable: {err}",
                DnsPosture::ScopedResolverOnly.as_str(),
                crate::linux_dns_protect::MACOS_SCOPED_RESOLVER_PATH
            )));
        }
        let services = self
            .enumerate_networksetup_services()
            .map_err(SystemError::DnsApplyFailed)?;
        for service in &services {
            let servers = self
                .read_networksetup_service_dns(service)
                .map_err(SystemError::DnsApplyFailed)?;
            if let Some(servers) = servers {
                if crate::macos_dns_sc_protect::is_loopback_dns_server_list(&servers) {
                    return Err(SystemError::DnsApplyFailed(format!(
                        "macOS DNS posture drifted ({}): service '{service}' advertises loopback DNS pins without the full-protection floor",
                        DnsPosture::ScopedResolverOnly.as_str()
                    )));
                }
            }
        }
        Ok(())
    }
    /// Verify the pf DNS-block floor is LIVE in the loaded anchor (not merely
    /// rendered): query `pfctl -a <anchor> -s rules` and require both block
    /// rules. Blind-exit applies have verified the anchor live since
    /// MacosClientDnsFailclosedDiagnosis_2026-09-02 A5 flagged that the
    /// killswitch branch never did.
    fn verify_live_pf_dns_floor(&mut self) -> Result<(), SystemError> {
        let anchor = self.anchor_name.clone().ok_or_else(|| {
            SystemError::DnsApplyFailed("pf anchor missing after DNS apply".to_owned())
        })?;
        let output = self.run_capture(
            PrivilegedCommandProgram::Pfctl,
            &["-a", anchor.as_str(), "-s", "rules"],
        )?;
        if !output.success() {
            return Err(SystemError::DnsApplyFailed(format!(
                "pf DNS floor query failed: status={} stderr={}",
                output.status, output.stderr
            )));
        }
        for proto in ["udp", "tcp"] {
            if !Self::ruleset_contains_dns_rule(&output.stdout, "block", proto, None) {
                return Err(SystemError::DnsApplyFailed(format!(
                    "pf DNS-block floor not live after apply ({proto}/53 missing from anchor {anchor})"
                )));
            }
        }
        Ok(())
    }
}

impl DataplaneSystem for MacosCommandSystem {
    fn set_generation(&mut self, generation: u64) {
        self.generation = generation;
    }

    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // firewalld is Linux-only; on macOS the PF anchor design owns
        // coexistence with the host firewall. Nothing to admit here.
        Ok(())
    }

    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Nothing was ever bound, so nothing can be left behind. The macOS
        // exit-NAT residue class is handled by `reconcile_exit_nat_residue`.
        Ok(())
    }

    fn set_full_tunnel_engaged(&mut self, _engaged: bool) {
        // The QH-60 wedge is policy-routing-shaped; macOS management
        // survival rides pf rules, not table-51820 routes. No context needed.
    }

    fn prune_owned_tables(&mut self) -> Result<(), SystemError> {
        for anchor in self.list_owned_anchors()? {
            self.run_allow_failure(
                PrivilegedCommandProgram::Pfctl,
                &["-a", anchor.as_str(), "-F", "all"],
            );
        }
        self.anchor_name = None;
        // D2 (DnsPosture invariant — no half-states): the flush above just
        // dropped a live DNS-block floor along with every other owned anchor,
        // but loopback service pins are system-configuration state that prune
        // never touches. If pins are still installed — the previous
        // generation's FullyProtected posture, or residue a rollback could
        // not restore — the node would sit in the pin-without-floor half
        // state (the exact "pinned with pf rules absent" signature the
        // plain-client flap produced) until the DNS arm re-renders, and would
        // keep it for good when that apply fails and rolls back. The M3 latch
        // (`killswitch_spec`) puts the floor into every render while pins
        // persist, so one immediate re-render re-establishes it. A failure
        // propagates: the generation flow rolls this apply back fail-closed
        // (rollback restores pins BEFORE dropping the floor), so no error
        // path can leave pins over a dropped floor.
        if self.has_live_loopback_dns_pins() {
            self.apply_pf_rules(false)?;
        }
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
            // D-6c: the tandem DNS redirect anchor (`com.rustynet/tdns_g<N>`)
            // lives OUTSIDE the killswitch sweep prefix
            // (`com.apple/rustynet_g*`), and `teardown_tandem_dns_redirect`
            // flushes only through the in-memory handle — lost on a crash. A
            // node that crashed while redirecting and restarts as a non-exit
            // would otherwise strand the rdr rules. Flush every tandem-owned
            // anchor by name (the redirect requires a serving exit, so a
            // non-exit must never keep one) and drop any stale handle.
            for anchor in self.list_tandem_owned_anchors()? {
                self.run_allow_failure(
                    PrivilegedCommandProgram::Pfctl,
                    &["-a", anchor.as_str(), "-F", "all"],
                );
            }
            self.tandem_dns_anchor = None;
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
            // forwarding. Tear down any tandem DNS redirect FIRST (removing
            // the translation restores the base DNS fail-closed posture while
            // the rest of the teardown proceeds, CLAUDE.md §10.7 ordering),
            // then any exit NAT left from a prior generation so a former exit
            // that became a client leaves no residue.
            self.teardown_tandem_dns_redirect()?;
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
        // Tear down the tandem DNS redirect first: flushing the translation
        // anchor restores the base DNS fail-closed posture immediately, so
        // plain DNS is blocked again while the rest of the rollback proceeds
        // (CLAUDE.md §10.7). The killswitch block-all stays installed
        // throughout.
        self.teardown_tandem_dns_redirect()?;
        // Then tear down the exit NAT (flush the translation anchor, then
        // restore forwarding) BEFORE relaxing the filter, so NAT residue never
        // outlives the exit capability (CLAUDE.md §10.7).
        self.teardown_exit_nat()?;
        self.allow_egress_interface = false;
        self.apply_pf_rules(false)
            .map_err(|err| SystemError::RollbackFailed(err.to_string()))
    }

    /// macOS translates through `pf`, not netfilter/conntrack, so the QH-47
    /// builtin does not apply here and reports so explicitly rather than
    /// pretending to have flushed. The equivalent `pf` state invalidation
    /// (`pfctl -F states` scoped to the mesh source) is a separate change
    /// against a different privileged surface; it is NOT silently covered by
    /// this arm, and the ledger tracks it as follow-up.
    fn flush_nat_conntrack(
        &mut self,
        _mesh_cidr: &str,
        _reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError> {
        Ok(crate::linux_conntrack_flush::ConntrackFlushOutcome::PlatformUnsupported)
    }

    /// Read-only accessor over the real runtime posture flag (S1,
    /// MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2): the daemon's periodic
    /// DNS posture re-assert gates on this before calling
    /// `assert_dns_protection`, so it never runs against a node whose DNS
    /// posture was never applied (or was rolled back).
    fn dns_protected(&self) -> bool {
        self.dns_protected
    }

    fn apply_dns_protection(&mut self) -> Result<(), SystemError> {
        // A6 (MacosClientDnsFailclosedDiagnosisReview_2026-09-02): BEFORE any
        // mutation, the loopback resolver must be bound AND answering. The
        // daemon binds `dns_resolver_bind_addr` in its run loop before
        // applying generations, but this apply-path probe does not trust that
        // ordering — pinning every service at a resolver that is not
        // answering is the exact stranded state this hardening exists to
        // forbid.
        self.verify_loopback_resolver_live()?;
        self.dns_protected = true;
        if let Err(err) = self.apply_pf_rules(false) {
            self.dns_protected = false;
            return Err(SystemError::DnsApplyFailed(err.to_string()));
        }
        // A5: the pf load is not enough — VERIFY the DNS-block floor is LIVE
        // in the anchor's ruleset before mutating the system configuration.
        // Without this, a helper that loads a partial anchor leaves the pin
        // loop installing pins under a floor that does not exist.
        if let Err(err) = self.verify_live_pf_dns_floor() {
            return Err(self.rollback_after_failed_apply(err));
        }
        // M1 (owner-approved; MacosDnsFailclosedEnforcementGap_2026-08-28 §4):
        // enforce fail-closed DNS at the system-configuration layer. pf alone
        // cannot stop macOS from RESOLVING through the LAN DNS servers its
        // services still advertise — mDNSResponder keeps answering out of
        // 1.1.1.1/8.8.8.8 via paths the pf anchor does not block. Pinning every
        // enabled network service's DNS to the loopback resolver makes the OS's
        // advertised posture match the enforced posture (the QH-39
        // macos-dns-failclosed verifier passes).
        //
        // Fail-closed AND all-or-nothing (M2): enumeration, per-service backup
        // capture, the backup write, every per-service set, the resolv.conf
        // write, and the scoped-resolver write are mandatory. ANY failure after
        // the first mutation rolls the node back through
        // `rollback_dns_protection` so it ends UNTOUCHED — a half-applied
        // posture (pins without a live primary, or pins without the floor) is
        // never left behind. Drift that appears LATER on an otherwise-healthy
        // node is surfaced by the daemon's periodic DNS posture re-assert
        // (S1, MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2, 30 s cadence),
        // which schedules exactly one re-apply through
        // `dns_posture_reassert_pending`; a re-apply that fails escalates
        // through the standard apply-failure restriction ladder.
        let services = self
            .enumerate_networksetup_services()
            .map_err(SystemError::DnsApplyFailed)?;
        // M1 capture guard (MacosDnsFailclosedEnforcementGap_2026-08-28 §7):
        // the backup baseline must never record loopback. If a service's
        // CURRENT DNS is already the loopback posture this apply is about to
        // enforce, that value is residue from a prior apply whose teardown
        // did not run, and writing it into the backup would make a later
        // rollback "restore" the strand. The prior backup document (readable
        // ⇒ Some) holds the real originals and is preserved per service; a
        // present-but-unreadable prior backup fails the apply here (an
        // unverifiable document cannot vouch for an original); residue with
        // no prior entry refuses loudly naming the manual fix.
        // The durable backup path derived from THIS daemon's state file
        // (Option A): the capture guard, the pre-mutation write, the
        // rollback restore, and the startup guard all use the same sibling.
        let backup_path = self.dns_backup_path.clone();
        let prior_backup = match crate::macos_dns_sc_protect::read_networksetup_dns_backup(
            &backup_path,
        ) {
            Ok(found) => found,
            Err(err) => {
                return Err(SystemError::DnsApplyFailed(format!(
                    "a prior networksetup DNS backup exists at {} but is unreadable; refusing to build a new baseline over possible loopback residue: {err}",
                    backup_path.display()
                )));
            }
        };
        let mut backup_entries = Vec::with_capacity(services.len());
        for service in &services {
            let servers = self
                .read_networksetup_service_dns(service)
                .map_err(SystemError::DnsApplyFailed)?;
            backup_entries.push(
                crate::macos_dns_sc_protect::resolve_backup_baseline_entry(
                    service,
                    servers,
                    prior_backup.as_ref(),
                )
                .map_err(SystemError::DnsApplyFailed)?,
            );
        }
        // The backup is written BEFORE the first mutation: a crash mid-apply
        // leaves the host in a state the startup-recovery guard (daemon.rs)
        // can fully restore from. A write failure aborts the apply here —
        // before any `networksetup -setdnsservers` argv is issued — with the
        // prior backup intact (the node stays pf-protected, SC-unmutated).
        let backup = crate::macos_dns_sc_protect::build_networksetup_dns_backup(backup_entries)
            .map_err(SystemError::DnsApplyFailed)?;
        crate::macos_dns_sc_protect::write_networksetup_dns_backup(&backup_path, &backup)
            .map_err(SystemError::DnsApplyFailed)?;
        for service in &services {
            let argv = crate::macos_dns_sc_protect::networksetup_setdns_loopback_args(service)
                .map_err(SystemError::DnsApplyFailed)?;
            let output = self.run_capture(PrivilegedCommandProgram::NetworkSetup, &argv)?;
            if !output.success() {
                // M2: a failed pin no longer strands a floor-only node — roll
                // the whole posture back so the node ends untouched.
                let original = SystemError::DnsApplyFailed(format!(
                    "networksetup -setdnsservers '{service}' 127.0.0.1 failed: status={} stderr={}",
                    output.status, output.stderr
                ));
                return Err(self.rollback_after_failed_apply(original));
            }
        }
        // Option-2 parity with Linux: point /etc/resolv.conf at the loopback
        // resolver (backing up the original) so the macos-dns-failclosed
        // verifier passes — every resolv.conf nameserver becomes loopback. The
        // pf rules above are the defense-in-depth egress block; this owns
        // resolv.conf. The write goes through the privileged helper's
        // fixed-path/fixed-content builtin (macOS /etc is writable, so it uses
        // the atomic temp+rename).
        //
        // M2: this write is now FAIL-CLOSED, not best-effort. The prior
        // best-effort stance predates the all-or-nothing posture model: a
        // silently-missing resolv.conf entry is verifier-visible drift and a
        // leak path for non-scoped resolution hints. A failure rolls the node
        // back to untouched; the M3 pin latch (has_live_loopback_dns_pins in
        // killswitch_spec) keeps the pf floor rendered over any residue a
        // partial failure could not clear.
        if let Err(err) = self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_RESOLV_APPLY],
        ) {
            let original =
                SystemError::DnsApplyFailed(format!("macOS resolv.conf write failed: {err}"));
            return Err(self.rollback_after_failed_apply(original));
        }
        // Write the macOS scoped resolver (/etc/resolver/rustynet → loopback
        // resolver:53535) so the OS resolver (mDNSResponder / dscacheutil /
        // getaddrinfo) can actually resolve mesh `*.rustynet` names. Unlike
        // /etc/resolv.conf — which macOS largely ignores for the primary lookup
        // path — `/etc/resolver/<domain>` is the mechanism the OS honors, and,
        // because the daemon runs unprivileged (cannot bind :53) and macOS
        // installs no `:53`→resolver redirect, it is the ONLY route from the OS
        // resolver to the resolver's :53535 bind. Scoped to the `rustynet`
        // domain only — no other domain's resolution changes.
        //
        // M2: FAIL-CLOSED like every other step — the full posture without a
        // working scoped route means mesh names leak to the LAN resolver.
        if let Err(err) = self.run(
            PrivilegedCommandProgram::DnsFailclosedFile,
            &[crate::linux_dns_protect::DNS_FILE_SELECTOR_MACOS_RESOLVER_APPLY],
        ) {
            let original =
                SystemError::DnsApplyFailed(format!("macOS scoped resolver write failed: {err}"));
            return Err(self.rollback_after_failed_apply(original));
        }
        self.dns_posture = DnsPosture::FullyProtected;
        Ok(())
    }

    /// M2 posture dispatch: macOS is the only platform that distinguishes
    /// all three postures. `Untouched` is a no-op (the caller opted out via
    /// `protected_dns=false`); `ScopedResolverOnly` installs only the scoped
    /// resolver; `FullyProtected` is the full hardened sequence. A node
    /// DOWNGRADING from full protection must tear it down first — the
    /// rollback restores every service's original DNS and drops the pf
    /// floor — otherwise the machine keeps advertising loopback pins with
    /// no live primary behind the scoped posture.
    fn apply_dns_protection_for_posture(&mut self, posture: DnsPosture) -> Result<(), SystemError> {
        match posture {
            DnsPosture::Untouched => Ok(()),
            DnsPosture::ScopedResolverOnly => {
                if self.dns_posture == DnsPosture::FullyProtected {
                    self.rollback_dns_protection()?;
                }
                self.apply_scoped_resolver_only()
            }
            DnsPosture::FullyProtected => self.apply_dns_protection(),
        }
    }

    fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        match self.dns_posture {
            // Nothing was applied; asserting anything else would be a lie.
            // The `dns_protected` gate below remains the secondary guard for
            // the full posture (a system that cannot observe must never
            // claim — CLAUDE.md trait doc).
            DnsPosture::Untouched => Err(SystemError::DnsApplyFailed(
                "macOS DNS protection is not active".to_owned(),
            )),
            DnsPosture::ScopedResolverOnly => self.assert_scoped_resolver_posture(),
            DnsPosture::FullyProtected => {
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
                // M1 system-configuration assertion: every enabled network service
                // must still advertise ONLY the loopback resolver. Drift here is
                // exactly the leak the pf anchor cannot see (mDNSResponder resolving
                // through LAN DNS), so failing this assert drives the reconcile loop
                // to re-apply protection.
                let services = self
                    .enumerate_networksetup_services()
                    .map_err(SystemError::DnsApplyFailed)?;
                for service in &services {
                    let servers = self
                        .read_networksetup_service_dns(service)
                        .map_err(SystemError::DnsApplyFailed)?;
                    let Some(servers) = servers else {
                        return Err(SystemError::DnsApplyFailed(format!(
                            "macOS DNS protection drifted: service '{service}' no longer pins any DNS server (expected 127.0.0.1)"
                        )));
                    };
                    if !crate::macos_dns_sc_protect::is_loopback_dns_server_list(&servers) {
                        return Err(SystemError::DnsApplyFailed(format!(
                            "macOS DNS protection drifted: service '{service}' advertises non-loopback DNS servers {servers:?}"
                        )));
                    }
                }
                Ok(())
            }
        }
    }

    fn rollback_dns_protection(&mut self) -> Result<(), SystemError> {
        self.dns_protected = false;
        self.dns_posture = DnsPosture::Untouched;
        // M1 teardown ordering (CLAUDE.md §10.7): restore every service's
        // backed-up system-configuration DNS BEFORE the pf anchor reload below
        // drops the DNS-block rules. The reverse order leaves a window where
        // resolution is still advertised-loopback (nothing answers) while the
        // block is already gone. A failed SC restore returns WITHOUT dropping
        // the anchor: the host stays fail-closed (DNS blocked) and loud, and
        // the backup file is retained for a retry.
        if let Err(err) = self.restore_networksetup_dns_from_backup() {
            return Err(SystemError::RollbackFailed(err));
        }
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
        if !output.stdout.contains(MACOS_PF_TERMINAL_BLOCK_RULE) {
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
// QH-29 coupling note (Windows): the runtime self-assertions
// (`assert_dns_protection` / `assert_killswitch` / `assert_exit_serving`)
// do NOT pattern-match generated rule text. They query LIVE OS state
// (Get-NetFirewallRule / Get-NetNat / Get-NetIPInterface) keyed by the SAME
// shared rule-name constants (`WINDOWS_KS_RULE_*`, `WINDOWS_DNS_RULE_*`,
// the NAT name) that the apply/delete paths use, and delegate the shape
// checking to these pinned PowerShell payloads. The generator↔matcher
// coupling is therefore compile-time (one constant per rule name) and needs
// no separate agreement test; renaming a rule constant renames both sides in
// the same commit.
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

    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // QH-46 on Windows (WindowsWfpCoexistenceAudit_2026-08-28 §3): the
        // NetNat forward path installs no WFP filters of its own — forwarded
        // exit traffic relies on the ABSENCE of a foreign block at the
        // forwarded-traffic layers. Verify that posture the way the Linux arm
        // verifies its firewalld zone bind: a foreign non-permit filter at
        // IPFORWARD_V4/V6, or WFP state that cannot be read at all (unknown
        // treated as obstructed, mirroring FirewalldPosture), fails the
        // admit, and reassert_host_firewall_admission converts the failure
        // into the fail-closed rollback.
        rustynet_windows_native::assert_forwarded_traffic_admitted()
            .map_err(|err| SystemError::FirewallApplyFailed(err.to_string()))
    }

    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        // Paired with the admit above: Windows binds nothing at the forward
        // layers (the admit is detection-only), so demotion has no
        // host-firewall binding to give back. A surviving FOREIGN filter is
        // not ours to delete; it is re-detected (and fail-closed) by the next
        // admit or periodic re-assert, never torn down here — same rule as
        // the Linux unbind.
        Ok(())
    }

    fn set_full_tunnel_engaged(&mut self, _engaged: bool) {
        // The QH-60 wedge is policy-routing-shaped; Windows management
        // survival rides WFP/netsh rules, not table-51820 routes.
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

    /// Windows NAT is `NetNat`, not netfilter/conntrack. Reported explicitly
    /// rather than silently succeeding, for the same reason as the macOS arm.
    fn flush_nat_conntrack(
        &mut self,
        _mesh_cidr: &str,
        _reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError> {
        Ok(crate::linux_conntrack_flush::ConntrackFlushOutcome::PlatformUnsupported)
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
        // Confirm the native WFP tunnel-permit filters (E2) are present AND are
        // genuinely tunnel-scoped hard permits. A missing permit fails safe
        // (tunnel blocked), but a correct "killswitch active" assertion must
        // catch it rather than silently report green.
        //
        // WIN-03: the SCOPE argument is the security-critical part. These are
        // hard permits in a max-weight sublayer, built to win arbitration over
        // the default-block-outbound policy, so a filter whose interface
        // condition has been dropped or repointed at the underlay NIC is a total
        // outbound bypass. Passing the egress interface as forbidden makes that
        // case name itself instead of reading as a generic LUID mismatch.
        if !rustynet_windows_native::wfp_tunnel_permit_present(
            self.interface_name.as_str(),
            &[self.egress_interface.as_str()],
        )
        .map_err(|err| {
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

impl RuntimeSystem {
    /// M1: install the bootstrap-time DNS probe servicer. Only the macOS
    /// system consults it (inside `verify_loopback_resolver_live`); the other
    /// platforms' DNS paths have no loopback probe, so for them this is a
    /// documented no-op.
    pub(crate) fn set_dns_probe_servicer(
        &mut self,
        servicer: Option<std::sync::Arc<crate::daemon::DnsProbeServicer>>,
    ) {
        if let RuntimeSystem::Macos(system) = self {
            system.dns_probe_servicer = servicer;
        }
    }
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

    fn set_full_tunnel_engaged(&mut self, engaged: bool) {
        match self {
            RuntimeSystem::DryRun(system) => system.set_full_tunnel_engaged(engaged),
            RuntimeSystem::Linux(system) => system.set_full_tunnel_engaged(engaged),
            RuntimeSystem::Macos(system) => system.set_full_tunnel_engaged(engaged),
            RuntimeSystem::Windows(system) => system.set_full_tunnel_engaged(engaged),
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

    fn reconcile_firewalld_zone_residue(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.reconcile_firewalld_zone_residue(),
            RuntimeSystem::Linux(system) => system.reconcile_firewalld_zone_residue(),
            RuntimeSystem::Macos(system) => system.reconcile_firewalld_zone_residue(),
            RuntimeSystem::Windows(system) => system.reconcile_firewalld_zone_residue(),
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

    fn admit_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.admit_host_firewall_forwarding(),
            RuntimeSystem::Linux(system) => system.admit_host_firewall_forwarding(),
            RuntimeSystem::Macos(system) => system.admit_host_firewall_forwarding(),
            RuntimeSystem::Windows(system) => system.admit_host_firewall_forwarding(),
        }
    }

    fn withdraw_host_firewall_forwarding(&mut self) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.withdraw_host_firewall_forwarding(),
            RuntimeSystem::Linux(system) => system.withdraw_host_firewall_forwarding(),
            RuntimeSystem::Macos(system) => system.withdraw_host_firewall_forwarding(),
            RuntimeSystem::Windows(system) => system.withdraw_host_firewall_forwarding(),
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

    fn flush_nat_conntrack(
        &mut self,
        mesh_cidr: &str,
        reason: NatConntrackFlushReason,
    ) -> Result<crate::linux_conntrack_flush::ConntrackFlushOutcome, SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.flush_nat_conntrack(mesh_cidr, reason),
            RuntimeSystem::Linux(system) => system.flush_nat_conntrack(mesh_cidr, reason),
            RuntimeSystem::Macos(system) => system.flush_nat_conntrack(mesh_cidr, reason),
            RuntimeSystem::Windows(system) => system.flush_nat_conntrack(mesh_cidr, reason),
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

    // Explicit dispatch, NOT the trait default: the default would forward to
    // `RuntimeSystem::apply_dns_protection` and SILENTLY DROP the posture on
    // every platform — the exact arm-by-arm hazard `flush_nat_conntrack`
    // documents. macOS must see the posture to scope its apply.
    fn apply_dns_protection_for_posture(&mut self, posture: DnsPosture) -> Result<(), SystemError> {
        match self {
            RuntimeSystem::DryRun(system) => system.apply_dns_protection_for_posture(posture),
            RuntimeSystem::Linux(system) => system.apply_dns_protection_for_posture(posture),
            RuntimeSystem::Macos(system) => system.apply_dns_protection_for_posture(posture),
            RuntimeSystem::Windows(system) => system.apply_dns_protection_for_posture(posture),
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

    /// S1 (MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2): only the systems
    /// with a real runtime DNS posture flag report it. The macOS system owns
    /// the flag this re-assert exists for; the DryRun test system mirrors the
    /// same lifecycle so the daemon-level tests can drive drift and healing.
    /// The Linux and Windows systems stay on the trait default (false): the
    /// S1 posture re-assert is a macOS-runtime concern and must skip them.
    fn dns_protected(&self) -> bool {
        match self {
            RuntimeSystem::Macos(system) => system.dns_protected(),
            RuntimeSystem::DryRun(system) => system.dns_protected(),
            RuntimeSystem::Linux(_) | RuntimeSystem::Windows(_) => false,
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
    /// QH-47: the masquerade-relevant shape of the COMMITTED generation, so an
    /// identical re-apply can be told apart from a real NAT transition. `None`
    /// means the committed generation installs no NAT stage at all.
    current_nat_posture: Option<NatPosture>,
    /// The mesh CIDR of the apply in flight. Needed by the rollback path, which
    /// may have to flush a masquerade installed by a generation that never
    /// committed (so `current_nat_posture` does not describe it).
    in_flight_mesh_cidr: Option<String>,
    transitions: Vec<TransitionEvent>,
    selected_exit_node: Option<NodeId>,
    lan_access_enabled: bool,
    advertised_lan_routes: HashMap<NodeId, BTreeSet<String>>,
    lan_route_acl: HashMap<(String, String), bool>,
    managed_peers: BTreeMap<NodeId, ManagedPeer>,
    active_stages: Vec<StageMarker>,
    /// QH-52 residual: whether this process still owes its one-time
    /// crash-restart firewalld probe (see
    /// `reconcile_firewalld_zone_residue`). Consumed on the first apply that
    /// qualifies, so a plain-client node pays the probe busctl round-trip once
    /// per process rather than on every re-enforce apply.
    firewalld_zone_residue_probe_pending: bool,
    current_routes: Vec<Route>,
    current_exit_mode: ExitMode,
    current_serve_exit_node: bool,
    /// How long a Direct candidate must be continuously observed before committing (ms).
    pub direct_stability_window_ms: u64,
    /// How long a Relay candidate must be continuously observed before committing (ms).
    pub relay_stability_window_ms: u64,
    /// Membership directory used to gate peer provisioning and ACL evaluation.
    membership: MembershipDirectory,
    /// Test-only fault injection: when set, `apply_revocation` fails the way a
    /// backend/system teardown error would, so callers' fail-closed handling
    /// of a revocation teardown failure is exercisable in tests. Never
    /// compiled into production builds.
    #[cfg(test)]
    fail_revocation_teardown_for_test: bool,
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
            current_nat_posture: None,
            in_flight_mesh_cidr: None,
            transitions: Vec::new(),
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_lan_routes: HashMap::new(),
            lan_route_acl: HashMap::new(),
            managed_peers: BTreeMap::new(),
            active_stages: Vec::new(),
            firewalld_zone_residue_probe_pending: true,
            current_routes: Vec::new(),
            current_exit_mode: ExitMode::Off,
            current_serve_exit_node: false,
            direct_stability_window_ms: 3_000,
            relay_stability_window_ms: 5_000,
            membership,
            #[cfg(test)]
            fail_revocation_teardown_for_test: false,
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

    /// Whether the system currently reports the DNS fail-closed posture as
    /// installed (S1, MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2). The
    /// daemon's periodic DNS posture re-assert gates on this.
    pub fn dns_protected(&self) -> bool {
        self.system.dns_protected()
    }

    /// Forward the DNS posture assert to the system (S1,
    /// MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.2). The daemon's
    /// periodic posture re-assert observes through this single audited
    /// entry point, exactly like the apply path asserts at apply time.
    pub fn assert_dns_protection(&mut self) -> Result<(), SystemError> {
        self.system.assert_dns_protection()
    }

    /// Crate-internal escape hatch for system-only plumbing (M1: bootstrap
    /// probe servicer installation). Deliberately NOT part of the hardened
    /// state-machine surface: it forwards a closure to the system and adds no
    /// transitions, audit events, or policy decisions.
    pub(crate) fn with_system<R>(&mut self, apply: impl FnOnce(&mut S) -> R) -> R {
        apply(&mut self.system)
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
        // QH-47: the rollback path may have to flush a masquerade installed by
        // a generation that never committed, so the CIDR in flight is recorded
        // before any stage runs rather than read back from committed state.
        self.in_flight_mesh_cidr = Some(mesh_cidr.clone());
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
        self.system
            .set_full_tunnel_engaged(options.exit_mode == ExitMode::FullTunnel);
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

        // QH-53: the firewalld zone bind needs the tunnel interface to exist
        // in sysfs, so it must run AFTER backend start (which creates the
        // interface) — binding from the pre-start killswitch failed every
        // cold bootstrap of a forwarding node on a firewalld host. It still
        // runs BEFORE generation commit, so a host firewall that would
        // discard forwarded traffic fails the apply before the role is ever
        // advertised (the QH-46 guarantee). Gated on serve_exit_node, which
        // covers relay-with-upstream (FullTunnel && serve), a terminal exit,
        // AND blind_exit (both exit_mode Off): all of them forward through
        // the same FORWARD hook a foreign firewall can reject, so the
        // narrower relay_with_upstream gate would leave exits unbound.
        if options.serve_exit_node {
            if let Err(err) = self.system.admit_host_firewall_forwarding() {
                let rollback_result = self
                    .rollback_generation_best_effort(applied_stages, RollbackIntent::FailClosed);
                let fail_closed_result = self.force_fail_closed("host_firewall_admit_failed");
                if let Err(rollback_err) = rollback_result {
                    let _ = fail_closed_result;
                    return Err(rollback_err);
                }
                fail_closed_result?;
                return Err(err.into());
            }
            // QH-52: record the binding so the role that installed it can give
            // it back. Pushed AFTER BackendStarted, so the reverse-order unwind
            // withdraws the binding while the interface it names still exists.
            applied_stages.push(StageMarker::HostFirewallAdmitted);
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
        if let Err(err) = self.rollback_obsolete_controls(options, &mut applied_stages) {
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

        // QH-47: invalidate conntrack for a real NAT transition, and ONLY for a
        // real one. Both mutation points are already behind us — a withdrawal
        // was performed by `rollback_obsolete_controls` and an install by
        // `apply_generation_stages` — so a single site here is after the rule
        // change in either direction, which is the ordering that matters: a
        // flush issued BEFORE the change would be undone by the next packet of
        // a steady stream re-creating the entry against the old ruleset.
        let next_nat_posture = NatPosture::for_generation(options, mesh_cidr.as_str());
        if next_nat_posture != self.current_nat_posture
            && (NatPosture::translates(next_nat_posture.as_ref())
                || NatPosture::translates(self.current_nat_posture.as_ref()))
        {
            let (reason, flush_cidr) = if NatPosture::translates(next_nat_posture.as_ref()) {
                (
                    NatConntrackFlushReason::MasqueradeInstalled,
                    mesh_cidr.clone(),
                )
            } else {
                let previous_cidr = self
                    .current_nat_posture
                    .as_ref()
                    .map(|posture| posture.mesh_cidr.clone())
                    .unwrap_or_else(|| mesh_cidr.clone());
                (NatConntrackFlushReason::MasqueradeWithdrawn, previous_cidr)
            };
            self.report_nat_conntrack_flush(flush_cidr.as_str(), reason);
        }
        self.current_nat_posture = next_nat_posture;

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

    /// Issue the QH-47 conntrack flush and REPORT its outcome.
    ///
    /// Never returns an error and never fails a generation. The two conditions
    /// worth an operator's attention — the tool being absent, and the flush
    /// itself failing — are logged at warn so they surface, because the failure
    /// mode this control exists to prevent (traffic that silently keeps its old
    /// translation) is invisible without a log line saying the invalidation did
    /// not happen.
    fn report_nat_conntrack_flush(&mut self, mesh_cidr: &str, reason: NatConntrackFlushReason) {
        use crate::linux_conntrack_flush::ConntrackFlushOutcome;

        match self.system.flush_nat_conntrack(mesh_cidr, reason) {
            Ok(ConntrackFlushOutcome::Flushed { entries }) => {
                log::info!(
                    "flushed {entries} conntrack entries sourced from {mesh_cidr} after NAT \
                     generation change ({})",
                    reason.as_str()
                );
            }
            Ok(ConntrackFlushOutcome::ToolAbsent) => {
                log::warn!(
                    "conntrack-tools is not installed: conntrack entries sourced from \
                     {mesh_cidr} keep their previous NAT binding after a {} transition, so \
                     flows established before this generation are translated by the OLD rules \
                     until they close. Install conntrack-tools on nodes that change exit or \
                     relay role while traffic is flowing.",
                    reason.as_str()
                );
            }
            Ok(ConntrackFlushOutcome::PlatformUnsupported) => {
                log::debug!(
                    "conntrack flush not applicable on this platform ({})",
                    reason.as_str()
                );
            }
            Err(err) => {
                log::warn!(
                    "conntrack flush for {mesh_cidr} failed after a {} transition; flows \
                     established before this generation keep their previous NAT binding: {err}",
                    reason.as_str()
                );
            }
        }
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
            // M2: the posture is DECIDED from the generation's exit posture
            // (never inferred from observed state), then applied for that
            // posture. Exit-serving / full-tunnel nodes get the full
            // fail-closed sequence; plain mesh clients get scoped-only.
            let posture = macos_dns_posture(options.exit_mode, options.serve_exit_node);
            if options.defer_scoped_dns_posture && posture == DnsPosture::ScopedResolverOnly {
                // Retained deferral path (no daemon caller sets the flag
                // anymore — see the M2 amendment note on the field): the
                // scoped
                // sub-apply is skipped. The DNS arm emits NO ops here — no
                // probe, no scoped-file
                // write, no assert — and records nothing as applied, so this
                // generation's DNS posture remains exactly `Untouched` (the
                // zero-leak state) until a later pass applies it for real.
                log::info!(
                    "the {scoped} DNS posture sub-apply was deferred by the caller; a later pass owns it",
                    scoped = DnsPosture::ScopedResolverOnly.as_str()
                );
            } else {
                self.system.apply_dns_protection_for_posture(posture)?;
                applied_stages.push(StageMarker::DnsApplied);
                self.system.assert_dns_protection()?;
            }
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

    /// Remove controls the PREVIOUS generation installed that THIS generation
    /// no longer justifies. `applied_stages` is the generation being built: a
    /// control this pass fails to remove is re-recorded there, so the marker
    /// survives the commit and the next apply — or shutdown — tries again.
    fn rollback_obsolete_controls(
        &mut self,
        options: ApplyOptions,
        applied_stages: &mut Vec<StageMarker>,
    ) -> Result<(), Phase10Error> {
        // Flush fixed-name exit-NAT residue (macOS `com.rustynet/nat`) that the
        // NatApplied-gated branch below would miss after a crash — `active_stages`
        // is empty on a fresh process, but the kernel anchor persists. Gated on
        // `serve_exit_node`, so it never touches the anchor a serving-exit apply
        // is about to (re)load. No-op on platforms that self-heal via prune.
        self.system
            .reconcile_exit_nat_residue(options.serve_exit_node)?;
        let previous_stages = self.active_stages.clone();
        // QH-52 residual, the crash-restart edge. A process that died while
        // bound restarts with an empty `active_stages`, so the demotion arm
        // below never fires; this one-time probe covers it. Gated three ways:
        // consumed once per process (a plain-client node must not pay a
        // busctl round-trip on every re-enforce apply), never on an apply that
        // is about to serve (the admit stage below re-binds anyway, and a
        // serving node's binding is not residue), and never when the marker is
        // already recorded (the demotion arm below owns that reconcile —
        // double-withdrawing the same binding in one apply is noise). Same
        // deliberate non-propagation as the demotion arm: a leftover binding
        // is residue, not exposure, so a failed clear is re-recorded for the
        // next apply / shutdown retry instead of failing a healthy generation
        // closed.
        if self.firewalld_zone_residue_probe_pending
            && !options.serve_exit_node
            && !previous_stages.contains(&StageMarker::HostFirewallAdmitted)
        {
            self.firewalld_zone_residue_probe_pending = false;
            if let Err(err) = self.system.reconcile_firewalld_zone_residue() {
                log::warn!(
                    "host firewall zone binding survived a crash-restart reconcile; \
                     recording it for retry on the next apply and at shutdown: {err}"
                );
                applied_stages.push(StageMarker::HostFirewallAdmitted);
            }
        }
        // QH-52, the in-place demotion edge. A node that served a relay/exit in
        // the previous generation and does not in this one keeps its tunnel
        // interface — the interface is not rebuilt, so nothing else drops the
        // firewalld zone binding the forwarding role installed. Withdraw it
        // here, alongside the exit-NAT rollback, for the same reason and under
        // the same "previous generation had it, this one does not" gate.
        //
        // Deliberately NOT propagated: `rollback_obsolete_controls` failing
        // fails the whole apply closed, and a binding that could not be removed
        // must not take down a node that is otherwise fine. The binding grants
        // only forwarded traffic, and this generation's forward chain no longer
        // accepts any — so the cost of leaving it is residue, not exposure.
        // The marker is re-recorded into the generation being built so the
        // removal is retried on the next apply and again at shutdown, where the
        // failure escalates into `RollbackFailed` and the durable shutdown
        // residue marker.
        if previous_stages.contains(&StageMarker::HostFirewallAdmitted) && !options.serve_exit_node
        {
            match self.system.withdraw_host_firewall_forwarding() {
                Ok(()) => {
                    self.active_stages
                        .retain(|stage| *stage != StageMarker::HostFirewallAdmitted);
                }
                Err(err) => {
                    log::warn!(
                        "host firewall zone binding survived relay/exit demotion; \
                         retrying on the next apply and at shutdown: {err}"
                    );
                    applied_stages.push(StageMarker::HostFirewallAdmitted);
                }
            }
        }
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
        // QH-47: the committed posture is being unwound, so the next apply must
        // treat itself as a transition. Cleared unconditionally — erring toward
        // one extra flush of mesh-sourced flows is the safe direction; erring
        // toward a missed flush leaves traffic translated by rules that no
        // longer exist.
        let unwound_posture = self.current_nat_posture.take();
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
                    // QH-47: AFTER the nat table is gone, invalidate the
                    // bindings it left behind, so a fail-closed unwind or a
                    // shutdown cannot leave mesh flows still being translated
                    // out of a host that has withdrawn the capability
                    // (CLAUDE.md §10.7). Only when this generation actually
                    // translated: a blind_exit installs no masquerade and has
                    // no binding to invalidate.
                    let flush_cidr = unwound_posture
                        .as_ref()
                        .filter(|posture| posture.masquerade || posture.hairpin)
                        .map(|posture| posture.mesh_cidr.clone())
                        .or_else(|| self.in_flight_mesh_cidr.clone());
                    if let Some(flush_cidr) = flush_cidr {
                        self.report_nat_conntrack_flush(
                            flush_cidr.as_str(),
                            NatConntrackFlushReason::MasqueradeWithdrawn,
                        );
                    }
                }
                // QH-52. Unlike DNS and the killswitch below, this is withdrawn
                // under BOTH intents. Those two are HELD through a fail-closed
                // unwind because removing them would fail OPEN. The zone binding
                // is the opposite: it is a permission granted to a foreign
                // firewall, so removing it can only ever be more restrictive.
                // There is no fail-open direction to guard, and a fail-closed
                // node that keeps advertising its interface in firewalld's
                // default zone is exactly the residue QH-52 is about.
                StageMarker::HostFirewallAdmitted => {
                    if let Err(err) = self.system.withdraw_host_firewall_forwarding() {
                        rollback_errors.push(format!("withdraw host firewall admission: {err}"));
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

    /// Re-assert the host firewall's admission of forwarded tunnel traffic on a
    /// node that is ALREADY serving (QH-54).
    ///
    /// The firewalld zone binding is a property of the tunnel INTERFACE, and the
    /// interface can be destroyed and rebuilt underneath a committed generation.
    /// `recover_runtime_after_worker_exit`
    /// (`rustynet-backend-wireguard/src/userspace_shared/mod.rs:218`) does exactly
    /// that when the userspace worker dies: `SharedTunLifecycle::cleanup` runs
    /// `ip link del`, then `start_runtime` recreates the device. That recovery is
    /// invisible from here — it happens behind the `TunnelBackend` trait, inside
    /// the WireGuard adapter, and returns the retried operation as an ordinary
    /// success — so no apply follows it and nothing re-binds the recreated
    /// interface. The daemon's periodic reconcile only re-applies on a
    /// fail-closed/restricted state or an assignment/membership/route change, so
    /// a healthy forwarding node can keep advertising a role whose forwarded
    /// traffic firewalld silently discards until the next such change.
    ///
    /// Availability-only, and it must stay that way: a lost bind never opens
    /// anything, it only makes firewalld drop traffic this daemon authorised.
    ///
    /// **Why the assert lives here and not in the recovery path.** firewalld
    /// coexistence is a Linux host-firewall concern owned by this crate; putting
    /// a re-bind hook inside `recover_runtime_after_worker_exit` would push it
    /// into the WireGuard adapter, which is precisely the backend leakage
    /// AGENTS.md §3 forbids, and no protocol-agnostic recovery signal exists to
    /// hook instead — making one is the typed `WorkerUnavailable` + daemon
    /// recovery-coordinator work that QH-54's transport blueprints specify and
    /// that is not implemented.
    ///
    /// **One hardened path.** This calls the SAME
    /// `DataplaneSystem::admit_host_firewall_forwarding` the creation path calls
    /// at apply, under the same `serve_exit_node` gate, and handles failure the
    /// same way: unwind the generation, then `force_fail_closed`, under the same
    /// `host_firewall_admit_failed` reason. There is deliberately no second,
    /// softer re-bind. firewalld presence is decided inside that one delegate, so
    /// a host without firewalld is a no-op here for exactly the reason it is a
    /// no-op at creation, and an `Unknown` presence is treated as present in both.
    pub fn reassert_host_firewall_admission(&mut self) -> Result<(), Phase10Error> {
        // The apply-path gate, unchanged: a node that is not serving forwards
        // nothing to admit, and a fail-closed node has no live generation to
        // protect — its next apply binds from scratch.
        if !self.current_serve_exit_node || self.state == DataplaneState::FailClosed {
            return Ok(());
        }
        let Err(err) = self.system.admit_host_firewall_forwarding() else {
            return Ok(());
        };
        // Mirrors the apply-path failure handling verbatim, including the error
        // precedence: a rollback failure outranks the fail-close result, which
        // outranks the original admit error.
        let active_stages = std::mem::take(&mut self.active_stages);
        let rollback_result =
            self.rollback_generation_best_effort(active_stages, RollbackIntent::FailClosed);
        let fail_closed_result = self.force_fail_closed("host_firewall_admit_failed");
        if let Err(rollback_err) = rollback_result {
            let _ = fail_closed_result;
            return Err(rollback_err);
        }
        fail_closed_result?;
        Err(err.into())
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

    /// Withdraw a previously advertised LAN route.
    ///
    /// POL-14: `ensure_lan_route_allowed` is a POST-CONDITION check over
    /// `lan_access_enabled` + the advertised set + the ACL, so a caller can only
    /// evaluate the gate after establishing all three. That makes an exact
    /// inverse of `advertise_lan_route` a prerequisite for failing closed: a
    /// refused grant must leave no advertised residue behind, or the next
    /// evaluation of the gate would find a route this one was denied.
    ///
    /// Empties the node's entry rather than leaving an empty set, so a withdrawn
    /// route is indistinguishable from one never advertised.
    pub fn withdraw_lan_route(&mut self, node_id: &NodeId, cidr: &str) {
        if let Some(routes) = self.advertised_lan_routes.get_mut(node_id) {
            routes.remove(cidr);
            if routes.is_empty() {
                self.advertised_lan_routes.remove(node_id);
            }
        }
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
        #[cfg(test)]
        if self.fail_revocation_teardown_for_test {
            return Err(Phase10Error::Backend(BackendError::internal(
                "injected revocation teardown failure",
            )));
        }
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

    /// For testing: make the next `apply_revocation` fail as if the backend or
    /// route-refresh teardown had errored, so fail-closed revocation handling
    /// in callers is exercisable.
    #[cfg(test)]
    pub fn fail_revocation_teardown_for_test(&mut self) {
        self.fail_revocation_teardown_for_test = true;
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
            TraversalDecision::Direct { endpoint, reason } => {
                self.commit_verified_traversal_path_for_peer(node_id, PathMode::Direct)?;
                self.configure_traversal_paths(node_id, Some(endpoint), evaluation.relay_endpoint)?;
                self.reconfigure_managed_peer(node_id, endpoint, PathMode::Direct)?;

                // Carry the engine's own reason through instead of asserting
                // `FreshHandshakeObserved` for every Direct outcome. Only an
                // endpoint-attributed outcome may claim the attributed
                // reason: the ICE race attributes when the runtime reports a
                // handshake endpoint, and the serial simultaneous-open path
                // attributes by construction because it probes exactly one
                // endpoint and observes immediately afterwards. Everything
                // else degrades to the unattributed variant, so a future
                // engine reason cannot silently inherit a proof-sounding
                // label by being added to the enum.
                let reason = match reason {
                    TraversalDecisionReason::IcePairRaceHandshakeObserved
                    | TraversalDecisionReason::SimultaneousOpenHandshakeObserved => {
                        TraversalProbeReason::FreshHandshakeObserved
                    }
                    _ => TraversalProbeReason::UnattributedHandshakeObserved,
                };

                Ok(TraversalProbeReport {
                    decision: TraversalProbeDecision::Direct,
                    reason,
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
        PrivilegedCommandProgram::NetworkSetup => resolve_binary_path(
            NETWORKSETUP_BINARY_PATH_ENV,
            DEFAULT_NETWORKSETUP_BINARY_PATH,
            PrivilegedCommandProgram::NetworkSetup,
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
        PrivilegedCommandProgram::LinuxFirewalldZone => Err(SystemError::PrerequisiteCheckFailed(
            "linux-firewalld-zone is an in-process builtin and has no external binary".to_owned(),
        )),
        // The conntrack flush IS backed by an external tool, but the HELPER
        // resolves and invokes it — the daemon never names a binary for it, so
        // this daemon-side resolver must refuse rather than open a second path
        // to `conntrack` outside the builtin's argv construction (QH-47).
        PrivilegedCommandProgram::LinuxConntrackFlush => Err(SystemError::PrerequisiteCheckFailed(
            "linux-conntrack-flush is an in-helper builtin and has no daemon-resolved binary"
                .to_owned(),
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

    /// S1 (MacosDnsFailclosedS1S4FixDesign_2026-08-31 §2.4 test 7): the
    /// daemon's periodic DNS posture re-assert consumes exactly the error
    /// `MacosCommandSystem::assert_dns_protection` produces, so that error
    /// MUST name the drifted service AND the servers it now advertises — an
    /// anonymous "drift detected" would leave the operator unable to tell
    /// which service re-pinned to LAN DNS, or what it now resolves through.
    ///
    /// Source-pinned because producing the message behaviorally requires
    /// enumerating the live host's networksetup services (the system-
    /// configuration half of the assert runs against the real host, like the
    /// legend test further below); what needs protecting here is the
    /// operator-facing naming, not the enumeration.
    /// Invariant 2 of MacosDnsBackupRebootSurvivalPlan_2026-09-02 (apply
    /// ordering, against the durable path): in
    /// `MacosCommandSystem::apply_dns_protection` the backup write — with
    /// its abort-on-error `?` — appears BEFORE the first per-service
    /// mutation argv (`networksetup_setdns_loopback_args`), so a backup
    /// write failure can never be followed by a mutation (zero mutation
    /// argvs issued, prior backup intact). Source-pinned because exercising
    /// the ordering behaviorally requires the live privileged helper.
    #[test]
    fn macos_apply_writes_backup_before_first_mutation_argv() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        let macos_impl = code
            .find("impl DataplaneSystem for MacosCommandSystem")
            .expect("MacosCommandSystem must implement DataplaneSystem");
        let body = &code[macos_impl..];
        let fn_at = body
            .find("fn apply_dns_protection(&mut self) -> Result<(), SystemError> {")
            .expect("MacosCommandSystem must apply DNS protection");
        let body = &body[fn_at..];
        let body = &body[..body[1..]
            .find("\n    fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len())];

        let write_at = body
            .find("write_networksetup_dns_backup(&backup_path, &backup)")
            .expect("apply must write the durable backup document");
        let first_mutation_at = body
            .find("networksetup_setdns_loopback_args")
            .expect("apply must pin services to loopback");
        assert!(
            write_at < first_mutation_at,
            "the backup write must precede the first networksetup mutation argv"
        );
    }

    /// D2 (DnsPosture invariant — no half-states): `MacosCommandSystem::
    /// prune_owned_tables` flushes every owned pf anchor, which drops a live
    /// DNS-block floor, while loopback service pins survive the prune as
    /// system-configuration state. Whenever pins are still live the prune must
    /// re-establish the floor IMMEDIATELY (via the M3 latch's floor-carrying
    /// render) and propagate failure, so the generation flow rolls back
    /// fail-closed instead of parking the node in the pin-without-floor half
    /// state the plain-client flap photographed. Source-pinned because
    /// exercising the ordering behaviorally requires the live privileged
    /// helper (same rationale as
    /// `macos_apply_writes_backup_before_first_mutation_argv`).
    #[test]
    fn macos_prune_owned_tables_reestablishes_dns_floor_while_pins_live() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        let macos_impl = code
            .find("impl DataplaneSystem for MacosCommandSystem")
            .expect("MacosCommandSystem must implement DataplaneSystem");
        let body = &code[macos_impl..];
        let fn_at = body
            .find("fn prune_owned_tables(&mut self) -> Result<(), SystemError> {")
            .expect("MacosCommandSystem must prune owned tables");
        let body = &body[fn_at..];
        let body = &body[..body[1..]
            .find("\n    fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len())];

        let pins_probe_at = body
            .find("if self.has_live_loopback_dns_pins()")
            .expect("prune must probe for live loopback DNS pins after the anchor flush");
        let refloor_at = body
            .find("self.apply_pf_rules(false)?")
            .expect("prune must re-establish the pf DNS floor while pins are live");
        let ok_at = body
            .rfind("Ok(())")
            .expect("prune must report success explicitly");
        assert!(
            refloor_at < ok_at,
            "the floor re-render must gate the prune's success"
        );
        assert!(
            pins_probe_at < refloor_at,
            "the floor re-render must be gated on the live-pins probe"
        );
    }

    #[test]
    fn assert_dns_protection_drift_error_names_service_and_servers() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        let macos_impl = code
            .find("impl DataplaneSystem for MacosCommandSystem")
            .expect("MacosCommandSystem must implement DataplaneSystem");
        let body = &code[macos_impl..];
        let fn_at = body
            .find("fn assert_dns_protection(&mut self) -> Result<(), SystemError> {")
            .expect("MacosCommandSystem must assert the DNS posture");
        let body = &body[fn_at..];
        let body = &body[..body[1..]
            .find("\n    fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len())];

        assert!(
            body.contains(
                "macOS DNS protection drifted: service '{service}' advertises non-loopback DNS servers {servers:?}",
            ),
            "the drift error must name the drifted service AND the server list it \
             now advertises — S1's daemon logic surfaces exactly this error to \
             the operator"
        );
        assert!(
            body.contains(
                "macOS DNS protection drifted: service '{service}' no longer pins any DNS server (expected 127.0.0.1)",
            ),
            "the un-pinned-service drift error must name the service and the \
             expected loopback pin"
        );
        assert!(
            body.contains("is_loopback_dns_server_list(&servers)"),
            "the drift naming must be driven by the shared loopback classifier, \
             not an ad-hoc check"
        );
    }

    /// IPV-10: the blind_exit evaluator must be ON the daemon assert path.
    ///
    /// The evaluator itself is pure and thoroughly tested in
    /// `linux_blind_exit`; what this pins is that it is actually CALLED. That was
    /// the entire defect — a thorough check whose only production caller was the
    /// evidence-report command, so a blind_exit node's posture was verified when
    /// someone asked for a report and never during operation.
    ///
    /// A source pin because the Linux firewall-assertion tests are
    /// `cfg(target_os = "linux")` and never run on the macOS CI leg, so an
    /// unwiring would be invisible there — which is how it stayed unwired.
    #[test]
    fn linux_assert_exit_serving_checks_the_blind_exit_posture() {
        let source = include_str!("phase10.rs");

        // The Linux `assert_exit_serving` is the one that also asserts NAT
        // forwarding; anchor on that pair so this cannot match another platform's
        // implementation of the same trait method.
        let at = source
            .find("self.assert_blind_exit_posture()?;")
            .expect("the Linux assert path must call assert_blind_exit_posture");
        let window = &source[at.saturating_sub(200)..at];
        assert!(
            window.contains("fn assert_exit_serving"),
            "the blind_exit posture check must be called from assert_exit_serving, not \
             from some unrelated path"
        );
        let after = &source[at..source.len().min(at + 200)];
        assert!(
            after.contains("self.assert_nat_forwarding()"),
            "this must be the Linux assert_exit_serving, which also asserts NAT forwarding"
        );

        // And the posture check must consult the real evaluator rather than
        // reimplementing a weaker one locally.
        let body_at = source
            .find("fn assert_blind_exit_posture")
            .expect("the posture check must exist");
        let body: String = source[body_at..].chars().take(1600).collect();
        assert!(
            body.contains("evaluate_linux_blind_exit_ruleset"),
            "the posture check must call the audited evaluator"
        );
        assert!(
            body.contains("KillSwitchAssertionFailed"),
            "a failed blind_exit posture must fail the assertion, not warn"
        );
    }

    /// QH-53/QH-46: the firewalld coexistence check must run AFTER backend
    /// start (the zone bind needs the tunnel interface to exist in sysfs),
    /// BEFORE the serving stages, gated on `serve_exit_node` — and it must be
    /// GONE from the pre-start killswitch, where it failed every cold
    /// bootstrap of a forwarding node on a firewalld host (QH-53).
    ///
    /// Source pin, like the IPV-10 pin above: the behavioural twins are
    /// `cfg(target_os = "linux")` and invisible on the macOS CI leg. The
    /// backend-start ordering is ALSO only pinnable here — backend calls are
    /// not `DataplaneSystem` ops, so no DryRun order test can see them.
    #[test]
    fn linux_firewall_admit_runs_after_backend_start_and_never_in_the_killswitch() {
        let source = include_str!("phase10.rs");
        // Bound every search to real code: this test's own string literals
        // would otherwise satisfy (or violate) the pins.
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        // (a) The controller call site: directly after backend start, before
        // the exit-serving preflight, gated on serve_exit_node.
        let call_at = code
            .find("self.system.admit_host_firewall_forwarding()")
            .expect("the controller must call admit_host_firewall_forwarding");
        let start_at = code
            .find("self.backend.start(context)")
            .expect("the controller must start the backend");
        let preflight_at = code
            .find("self.system.preflight_exit_serving")
            .expect("the controller must preflight exit serving");
        assert!(
            start_at < call_at,
            "the host-firewall admit must run AFTER backend start — the zone \
             bind needs the tunnel interface backend start creates (QH-53)"
        );
        assert!(
            call_at - start_at < 1600,
            "the admit call must sit directly after the backend-start match, \
             not merely somewhere later in the apply"
        );
        assert!(
            call_at < preflight_at,
            "the host-firewall admit must run BEFORE the serving stages"
        );
        let gate_window = &code[call_at.saturating_sub(120)..call_at];
        assert!(
            gate_window.contains("if options.serve_exit_node"),
            "the admit must be gated on serve_exit_node: terminal exit, \
             blind_exit and relay-with-upstream all forward through the same \
             FORWARD hook a foreign firewall can reject"
        );

        // (b) The Linux impl delegates to the audited check, from inside
        // admit_host_firewall_forwarding itself.
        let ensure_call = code
            .find("self.ensure_host_firewall_admits_forwarding()")
            .expect("the Linux impl must delegate to the audited check");
        let before = &code[..ensure_call];
        let fn_start = before
            .rfind("fn admit_host_firewall_forwarding")
            .expect("the delegate must live in admit_host_firewall_forwarding");
        assert!(
            !before[fn_start..].contains("\n    fn "),
            "the delegate call must be inside admit_host_firewall_forwarding itself"
        );

        // (c) NEGATIVE pin: the Linux killswitch body must no longer bind
        // firewalld — bind-before-interface-creation IS the QH-53 defect.
        // Select the Linux body as the only apply_firewall_killswitch
        // implementation that drives nft.
        let mut searched = 0usize;
        let mut nft_bodies = 0usize;
        while let Some(rel) = code[searched..].find("fn apply_firewall_killswitch") {
            let fn_at = searched + rel;
            let after = &code[fn_at..];
            let body_end = after[1..]
                .find("\n    fn ")
                .map(|end| end + 1)
                .unwrap_or(after.len());
            let body = &after[..body_end];
            if body.contains("PrivilegedCommandProgram::Nft") {
                nft_bodies += 1;
                assert!(
                    !body.contains("ensure_host_firewall_admits_forwarding"),
                    "the pre-start killswitch must not bind firewalld: the \
                     tunnel interface does not exist yet at that point (QH-53)"
                );
            }
            searched = fn_at + 1;
        }
        assert_eq!(
            nft_bodies, 1,
            "exactly one apply_firewall_killswitch body drives nft (the Linux one)"
        );

        // (d) The production RuntimeSystem dispatch must forward the Linux
        // arm — a missing or stubbed arm would silently no-op the enforcement
        // on the real daemon while every DryRun-driven test stays green.
        assert!(
            code.contains(
                "RuntimeSystem::Linux(system) => system.admit_host_firewall_forwarding()"
            ),
            "the RuntimeSystem Linux arm must dispatch admit_host_firewall_forwarding"
        );

        // (e) The audited check itself keeps its fail-closed shape.
        let body_at = code
            .find("fn ensure_host_firewall_admits_forwarding")
            .expect("the firewalld coexistence check must exist");
        let body: String = code[body_at..].chars().take(2400).collect();
        assert!(
            body.contains("FirewalldPosture::parse"),
            "the check must parse the builtin's structured posture line"
        );
        assert!(
            body.contains("forwarding_unobstructed"),
            "the check must consult the audited forwarding_unobstructed verdict"
        );
        assert!(
            body.contains("FirewallApplyFailed"),
            "an obstructed forward path must fail the apply, not warn"
        );
    }

    /// A management CIDR must be a bounded operator range, not a default route.
    ///
    /// PF-02 / WIN-05 and the Linux nft twin: this one value becomes the match
    /// clause of a TCP/22 allow rule on macOS pf, Linux nftables AND Windows
    /// netsh. `0.0.0.0/0` parsed cleanly -- `/0` is a well-formed prefix -- and
    /// authorised unrestricted port-22 egress past the killswitch on all three.
    #[test]
    fn management_cidr_rejects_unbounded_ranges() {
        use std::str::FromStr;

        // The vectors. Each is syntactically valid and was previously accepted.
        for hostile in [
            "0.0.0.0/0",
            "::/0",
            "128.0.0.0/1",
            "8.8.8.0/24",
            "1.1.1.1/32",
            "2001:4860:4860::8888/128",
            "2000::/3",
        ] {
            assert!(
                super::ManagementCidr::from_str(hostile).is_err(),
                "an unbounded or globally-routable management CIDR must be rejected: {hostile:?}"
            );
        }

        // Real operator ranges must still parse -- including every value this
        // repo's own live lab uses, so the guard cannot break the lab it ships
        // with.
        for benign in [
            "192.168.64.0/24",
            "192.168.121.0/24",
            "192.168.8.0/24",
            "172.20.0.0/30",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "100.64.0.0/10",
            "fc00::/7",
            "fe80::/10",
        ] {
            super::ManagementCidr::from_str(benign).unwrap_or_else(|err| {
                panic!("a real operator range must parse: {benign:?}: {err}")
            });
        }

        // Malformed input still fails, and the prefix bound still holds.
        for malformed in ["192.168.1.0", "192.168.1.0/33", "notanip/24", "10.0.0.0/x"] {
            assert!(
                super::ManagementCidr::from_str(malformed).is_err(),
                "malformed management CIDR must be rejected: {malformed:?}"
            );
        }
    }

    /// The bound must live at the shared parser, not in a per-backend guard.
    ///
    /// The whole point of PF-02/WIN-05 being one finding across three backends
    /// is that they share this parser. A guard added in the pf renderer would
    /// leave nftables and netsh exposed while looking fixed on the platform
    /// that was audited, which is exactly how this survived the first audit.
    #[test]
    fn management_cidr_bound_lives_in_the_shared_parser() {
        let source = include_str!("phase10.rs");
        let from_str_at = source
            .find("impl std::str::FromStr for ManagementCidr")
            .expect("ManagementCidr must still implement FromStr");
        let body: String = source[from_str_at..].chars().take(2200).collect();
        assert!(
            body.contains("validate_mesh_egress_source_cidr"),
            "the containment check must be applied inside ManagementCidr::from_str, the one \
             place all three backends funnel through"
        );
    }
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
        // bind() applies the process umask, which on some hosts leaves the
        // socket group/other-writable; validate_owner_only_socket_facts (the
        // same check the real client applies) requires owner-only, so pin it
        // explicitly instead of depending on the host's umask.
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|err| {
                panic!(
                    "test helper socket permissions should be settable at {}: {err}",
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
        // bind() applies the process umask, which on some hosts leaves the
        // socket group/other-writable; validate_owner_only_socket_facts (the
        // same check the real client applies) requires owner-only, so pin it
        // explicitly instead of depending on the host's umask.
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|err| {
                panic!(
                    "test helper socket permissions should be settable at {}: {err}",
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
        // bind() applies the process umask, which on some hosts leaves the
        // socket group/other-writable; validate_owner_only_socket_facts (the
        // same check the real client applies) requires owner-only, so pin it
        // explicitly instead of depending on the host's umask.
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|err| {
                panic!(
                    "test helper socket permissions should be settable at {}: {err}",
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

    /// Provenance (QH-26): this negative formerly exercised `tls13_valid:
    /// false`. That field was retired as security theatre per DA-01
    /// (`DocCodeDiscrepancyAudit_2026-07-18.md`) in commit `f1ef83b1` — an
    /// unreviewed delegated-edit checkpoint; see
    /// `Qh26HonestRetirementPlan_2026-09-02.md`. The assertion now covers
    /// `signed_control_valid`, the sole remaining local attestation flag:
    /// it is producer-signed, pinned-key-verified and replay-protected (see
    /// the `verify_signed_trust_state_artifact` chain in `daemon.rs`) and is
    /// an attestation of the producer's control plane, not an independent
    /// measurement.
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
            signed_control_valid: false,
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

    /// M2 amendment: the retained (caller-unset) deferral path — a scoped
    /// apply with `defer_scoped_dns_posture` set — must emit NO DNS ops at
    /// all: no apply, no probe, no assert. The DNS posture of this
    /// generation stays `Untouched` (zero-leak). No daemon caller sets the
    /// flag anymore (bootstrap applies the scoped posture in-place via M1's
    /// hoisted-bind probe servicer), but the engine-level contract is kept
    /// and tested.
    #[test]
    fn defer_flag_scoped_posture_emits_no_dns_ops() {
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
                    destination_cidr: "10.0.0.0/8".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::Off,
                    serve_exit_node: false,
                    protected_dns: true,
                    defer_scoped_dns_posture: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("a deferred scoped apply must succeed without touching DNS");

        assert!(
            !controller
                .system
                .operations
                .contains(&"apply_dns_protection".to_owned()),
            "a deferred scoped DNS posture must not apply; ops={:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .contains(&"assert_dns_protection".to_owned()),
            "a deferred scoped DNS posture must not assert; ops={:?}",
            controller.system.operations
        );
        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
    }

    /// M2 amendment: with the deferral flag UNSET — the configuration BOTH
    /// daemon call sites now pass — a plain client's bootstrap apply
    /// (`ScopedResolverOnly`, exit Off, not serving) must EMIT the scoped
    /// DNS apply AND its assert: the hoisted-bind probe servicer answers the
    /// loopback probe in-bootstrap, so the resolver file lands before
    /// `validate_baseline_runtime` runs.
    #[test]
    fn scoped_posture_applies_in_bootstrap_when_not_deferred() {
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
                    destination_cidr: "10.0.0.0/8".to_owned(),
                    via_node: NodeId::new("node-b").expect("node should parse"),
                    kind: RouteKind::Mesh,
                }],
                ApplyOptions {
                    exit_mode: ExitMode::Off,
                    serve_exit_node: false,
                    protected_dns: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("a scoped apply with no deferral must succeed");

        assert!(
            controller
                .system
                .operations
                .contains(&"apply_dns_protection".to_owned()),
            "bootstrap must apply the scoped DNS posture; ops={:?}",
            controller.system.operations
        );
        assert!(
            controller
                .system
                .operations
                .contains(&"assert_dns_protection".to_owned()),
            "bootstrap must assert the scoped DNS posture; ops={:?}",
            controller.system.operations
        );
        assert_eq!(controller.state(), DataplaneState::DataplaneApplied);
    }

    /// M2 negative control: the SAME bootstrap deferral flag must NOT defer
    /// the `FullyProtected` posture (exit-serving node) — that posture is
    /// leak-relevant (pf floor, pins, resolv.conf) and stays in-bootstrap,
    /// serviced by the hoisted-bind probe servicer.
    #[test]
    fn bootstrap_defer_flag_never_defers_fully_protected_posture() {
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
                    serve_exit_node: true,
                    protected_dns: true,
                    defer_scoped_dns_posture: true,
                    ..ApplyOptions::default()
                },
            )
            .expect("a protected-DNS apply must proceed despite the scoped defer flag");

        assert!(
            controller
                .system
                .operations
                .contains(&"apply_dns_protection".to_owned()),
            "FullyProtected must stay in-bootstrap; ops={:?}",
            controller.system.operations
        );
        assert!(
            controller
                .system
                .operations
                .contains(&"assert_dns_protection".to_owned()),
            "FullyProtected must be asserted at apply time; ops={:?}",
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

        // Ordering: the killswitch emits the relay hairpin nft rule only if
        // set_relay_forwarding ran FIRST (the firewalld coexistence check
        // moved OUT of the killswitch to admit_host_firewall_forwarding —
        // QH-53). Presence of both ops is not enough — swapping the two calls
        // in the controller would leave every system-level test green while
        // production never emits the hairpin.
        let relay_position = controller
            .system
            .operations
            .iter()
            .position(|op| op == "set_relay_forwarding:true")
            .expect("relay forwarding op must be recorded");
        let firewall_position = controller
            .system
            .operations
            .iter()
            .position(|op| op == "apply_firewall_killswitch")
            .expect("firewall apply op must be recorded");
        assert!(
            relay_position < firewall_position,
            "set_relay_forwarding must run BEFORE apply_firewall_killswitch \
             (relay at {relay_position}, firewall at {firewall_position}) or the \
             hairpin forward rule is never emitted"
        );

        // QH-60: the apply must communicate the full-tunnel decision to the
        // system before the stages run, or the anchoring check can never
        // refuse. Presence of the op with the right VALUE is the wiring
        // proof; the Linux behavioural tests prove what the value does.
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "set_full_tunnel_engaged:true"),
            "a FullTunnel apply must engage the anchoring context"
        );

        // QH-53 ordering: the firewalld admit stage must run after the
        // killswitch (backend start sits between them — it is not a system op,
        // so the source pin carries that half) and before the serving stages.
        let admit_position = controller
            .system
            .operations
            .iter()
            .position(|op| op == "admit_host_firewall_forwarding")
            .expect("a serving apply must admit host-firewall forwarding");
        let preflight_position = controller
            .system
            .operations
            .iter()
            .position(|op| op == "preflight_exit_serving")
            .expect("a serving apply must preflight exit serving");
        assert!(
            firewall_position < admit_position && admit_position < preflight_position,
            "the firewalld admit must run between the killswitch and the \
             serving preflight (killswitch {firewall_position}, admit \
             {admit_position}, preflight {preflight_position})"
        );
    }

    /// QH-53 gate, absence direction: a node that serves nothing must never
    /// run the firewalld admit stage — the zone bind is a forwarding-role
    /// concern, and firewalld's zone is the only inbound filter on the tunnel
    /// of a plain client.
    #[test]
    fn client_apply_never_admits_host_firewall_forwarding() {
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
            .expect("plain client apply should succeed");

        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "admit_host_firewall_forwarding"),
            "a non-serving apply must not run the firewalld admit stage: {:?}",
            controller.system.operations
        );
    }

    /// QH-53 propagation: a failed firewalld admit must fail the WHOLE apply
    /// closed, before any generation commit — a swallowed error here would be
    /// the exact silently-tunnel-less-forwarder defect the stage exists to
    /// prevent.
    #[test]
    fn host_firewall_admit_failure_fails_the_apply_closed() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default().fail_on("admit_host_firewall_forwarding"),
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
                    serve_exit_node: true,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("a failed firewalld admit must fail the apply");

        assert!(matches!(err, Phase10Error::System(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "block_all_egress"),
            "fail-closed must block egress: {:?}",
            controller.system.operations
        );
        assert!(
            !controller.backend.started,
            "the started backend must be rolled back when the admit fails"
        );
    }

    /// Build a committed, serving generation and hand back the controller with
    /// its recorded ops cleared, so a following assertion sees only what the
    /// QH-54 re-assert itself does.
    fn serving_controller_after_apply() -> Phase10Controller<RecordingBackend, DryRunSystem> {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
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
            .expect("serving apply should succeed");
        assert!(
            controller.serving_exit_node_active(),
            "the fixture must leave a serving generation committed"
        );
        controller.system.operations.clear();
        controller
    }

    /// QH-54, presence direction. The userspace WireGuard backend can delete and
    /// recreate the tunnel interface underneath a committed generation when its
    /// worker dies (`recover_runtime_after_worker_exit` -> `ip link del` ->
    /// `start_runtime`), which drops the interface's firewalld zone binding. No
    /// apply follows that recovery, so the controller must be able to re-assert
    /// the admission on a live generation — and it must do so through the SAME
    /// stage the apply path uses, not a second re-bind of its own.
    #[test]
    fn a_serving_node_reasserts_host_firewall_admission_through_the_apply_stage() {
        let mut controller = serving_controller_after_apply();

        controller
            .reassert_host_firewall_admission()
            .expect("re-asserting an admitted posture must succeed");

        assert_eq!(
            controller.system.operations,
            vec!["admit_host_firewall_forwarding".to_owned()],
            "the re-assert must run the apply path's admit stage and nothing \
             else — a second re-bind path would be a fork of a security-sensitive \
             workflow (AGENTS.md §3)"
        );
        assert!(
            controller.serving_exit_node_active(),
            "a healthy re-assert must leave the serving generation untouched"
        );
    }

    /// QH-54, absence direction, role half. The re-assert carries the apply
    /// path's `serve_exit_node` gate and no other: a node that forwards nothing
    /// has no forwarded traffic to admit, and binding a plain client's tunnel
    /// into a zone would change the only inbound filter it has.
    ///
    /// The firewalld-presence half of "skips exactly like creation" is not
    /// modelled here on purpose — presence is decided INSIDE
    /// `admit_host_firewall_forwarding` (Absent posture ->
    /// `forwarding_unobstructed`, `Unknown` treated as present), and the whole
    /// point is that the re-assert has no presence branch of its own to test.
    /// `the_reassert_has_no_firewalld_logic_of_its_own` pins that structurally.
    #[test]
    fn a_client_node_never_reasserts_host_firewall_admission() {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
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
            .expect("plain client apply should succeed");
        controller.system.operations.clear();

        controller
            .reassert_host_firewall_admission()
            .expect("a non-serving re-assert is a no-op, not a failure");

        assert!(
            controller.system.operations.is_empty(),
            "a non-serving node must not run the admit stage: {:?}",
            controller.system.operations
        );
    }

    /// QH-54 negative. A re-assert that finds the posture broken must fail
    /// EXACTLY the way the apply path's admit failure does — unwind the
    /// generation, block egress, land in `FailClosed`, and surface the error.
    /// This is the availability fix's fail-open guard: the cheap alternative
    /// (log and carry on, because "it is only availability") would leave the
    /// node advertising a forwarding role whose traffic firewalld discards,
    /// which is the QH-46 guarantee inverted.
    #[test]
    fn a_failed_reassert_fails_closed_exactly_like_a_failed_apply_admit() {
        let mut controller = serving_controller_after_apply();
        assert!(
            controller.backend.started,
            "the fixture must leave the backend running"
        );
        controller
            .system
            .fail_on_from_now("admit_host_firewall_forwarding");

        let err = controller
            .reassert_host_firewall_admission()
            .expect_err("a broken posture must not be swallowed");

        assert!(matches!(err, Phase10Error::System(_)));
        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            !controller.serving_exit_node_active(),
            "a fail-closed node must stop claiming it serves an exit"
        );
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "block_all_egress"),
            "fail-closed must block egress: {:?}",
            controller.system.operations
        );
        assert!(
            !controller.backend.started,
            "the committed generation must be unwound, matching the apply path"
        );
    }

    /// QH-54 structural pin: one hardened path.
    ///
    /// The re-assert must delegate to `self.system.admit_host_firewall_forwarding()`
    /// and must contain no firewalld vocabulary of its own — no presence test, no
    /// zone name, no posture parse. A future edit that "optimises" the re-assert by
    /// inlining a cheaper query, or that softens it into a log-only path because the
    /// defect is availability-only, breaks here. Source-pinned because a behavioural
    /// test cannot see the absence of a branch.
    #[test]
    fn the_reassert_has_no_firewalld_logic_of_its_own() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];
        let fn_at = code
            .find("pub fn reassert_host_firewall_admission")
            .expect("the controller must expose the QH-54 re-assert");
        let rest = &code[fn_at..];
        let body_end = rest[1..]
            .find("\n    pub fn ")
            .or_else(|| rest[1..].find("\n    fn "))
            .map(|offset| offset + 1)
            .unwrap_or(rest.len());
        let body = &rest[..body_end];

        assert!(
            body.contains("self.system.admit_host_firewall_forwarding()"),
            "the re-assert must call the apply path's own stage"
        );
        for forked in [
            "FirewalldZoneOp",
            "FirewalldPresence",
            "FirewalldPosture",
            "FirewalldZoneSpec",
            "LinuxFirewalldZone",
        ] {
            assert!(
                !body.contains(forked),
                "the re-assert must not re-implement firewalld handling ({forked}); \
                 presence, zone and posture all belong to the single audited stage"
            );
        }
        assert!(
            body.contains("force_fail_closed(\"host_firewall_admit_failed\")"),
            "a failed re-assert must fail closed under the apply path's own reason"
        );
        assert!(
            body.contains("rollback_generation_best_effort"),
            "a failed re-assert must unwind the generation like the apply path"
        );
    }

    // ── QH-52: the demotion edge — a role that ends gives its binding back ──

    /// Re-apply the same node as a plain mesh client. This is the in-place
    /// relay/exit demotion: the tunnel interface is NOT rebuilt, so nothing
    /// else in the system drops the zone binding the forwarding role installed.
    fn demote_to_client(
        controller: &mut Phase10Controller<RecordingBackend, DryRunSystem>,
    ) -> Result<(), Phase10Error> {
        controller.apply_dataplane_generation(
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
    }

    /// QH-52, the defect itself. Before this, `FirewalldZoneOp::Unbind` had no
    /// daemon caller at all: a node demoted out of its relay/exit role kept its
    /// tunnel interface bound into firewalld's default zone forever. That is
    /// deploy residue on the operator's host firewall (CLAUDE.md §10.7) —
    /// installed by a role, never removed when the role ended.
    #[test]
    fn a_demoted_relay_withdraws_its_host_firewall_zone_binding() {
        let mut controller = serving_controller_after_apply();

        demote_to_client(&mut controller).expect("demotion to a plain client should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "demotion must give the zone binding back: {:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "admit_host_firewall_forwarding"),
            "a demoting apply must not re-admit what it is withdrawing: {:?}",
            controller.system.operations
        );
        assert!(
            !controller.serving_exit_node_active(),
            "the demoted node must stop claiming it serves a forwarding role"
        );
    }

    /// The withdrawal is gated on evidence that THIS daemon bound the interface.
    /// A node that never served must never drive the firewalld builtin at all —
    /// the mirror of the creation-path gate, and the reason a plain client on a
    /// firewalld host pays nothing for this fix.
    #[test]
    fn a_node_that_never_served_never_withdraws_a_binding_it_never_took() {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        );
        demote_to_client(&mut controller).expect("plain client apply should succeed");
        demote_to_client(&mut controller).expect("second plain client apply should succeed");

        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "a node with no binding must not ask the host firewall for anything: {:?}",
            controller.system.operations
        );
    }

    /// QH-54 interaction, the edge this work had to not fight. The periodic
    /// re-assert re-binds a SERVING node's interface. After a demotion it must
    /// observe not-serving and do nothing — otherwise the re-assert would
    /// silently restore the very binding the demotion just withdrew, and the
    /// residue would come back on a timer.
    #[test]
    fn the_periodic_reassert_does_not_rebind_after_a_demotion() {
        let mut controller = serving_controller_after_apply();
        demote_to_client(&mut controller).expect("demotion to a plain client should succeed");
        controller.system.operations.clear();

        controller
            .reassert_host_firewall_admission()
            .expect("a re-assert on a demoted node is a no-op, not a failure");

        assert!(
            controller.system.operations.is_empty(),
            "the re-assert must not touch the host firewall after a demotion: {:?}",
            controller.system.operations
        );
    }

    /// The chosen failure semantics, positive half. A withdrawal is TEARDOWN:
    /// the binding it removes grants only forwarded traffic, and the demoting
    /// generation's forward chain no longer accepts any. Failing the apply
    /// closed over it would take down a healthy node to fix residue — the
    /// availability cost with none of the security benefit. So the demotion
    /// succeeds and the failure is reported instead.
    #[test]
    fn a_failed_withdrawal_does_not_fail_the_demotion_closed() {
        let mut controller = serving_controller_after_apply();
        controller
            .system
            .fail_on_from_now("withdraw_host_firewall_forwarding");

        demote_to_client(&mut controller)
            .expect("an unremovable zone binding must not fail a healthy demotion closed");

        assert_ne!(
            controller.state(),
            DataplaneState::FailClosed,
            "teardown residue must not fail the dataplane closed"
        );
        assert!(
            controller.backend.started,
            "the demoted generation must stay committed and running"
        );
    }

    /// The chosen failure semantics, retry half. A binding that could not be
    /// removed is still installed, so its marker is re-recorded into the
    /// committed generation: the next apply tries again, and shutdown tries
    /// again after that. Dropping the marker on failure would convert a
    /// reported residue into a permanently forgotten one.
    #[test]
    fn an_unremovable_binding_is_retried_on_the_next_apply() {
        let mut controller = serving_controller_after_apply();
        controller
            .system
            .fail_on_from_now("withdraw_host_firewall_forwarding");
        demote_to_client(&mut controller).expect("demotion should survive the failed withdrawal");

        // Stop failing; the binding is still recorded as installed.
        controller.system.fail_on_from_now("no_such_stage");
        controller.system.operations.clear();
        demote_to_client(&mut controller).expect("the retrying apply should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "a withdrawal that failed must be retried on the next apply: {:?}",
            controller.system.operations
        );
    }

    /// Shutdown of a still-serving node is the second demotion path: the role
    /// ends because the daemon does. The binding is runtime-only and outlives
    /// the process, so leaving it is residue on the operator's host firewall
    /// with no owner left to remove it.
    #[test]
    fn shutdown_of_a_serving_node_withdraws_the_host_firewall_zone_binding() {
        let mut controller = serving_controller_after_apply();

        controller
            .shutdown()
            .expect("clean shutdown should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "shutdown must give the zone binding back: {:?}",
            controller.system.operations
        );
        assert!(
            !controller.backend.started,
            "shutdown must still stop the backend"
        );
    }

    /// The loud channel. On the shutdown path a failed withdrawal joins the
    /// same teardown-failure accounting every other rollback stage uses, so it
    /// becomes `RollbackFailed` — which QH-40's shutdown-residue marker turns
    /// into a durable, operator-acknowledged signal. "Report, do not block" is
    /// not "log and forget".
    #[test]
    fn a_failed_withdrawal_at_shutdown_surfaces_as_a_rollback_failure() {
        let mut controller = serving_controller_after_apply();
        controller
            .system
            .fail_on_from_now("withdraw_host_firewall_forwarding");

        let err = controller
            .shutdown()
            .expect_err("an unremovable binding must be reported at shutdown");

        match err {
            Phase10Error::System(SystemError::RollbackFailed(message)) => assert!(
                message.contains("withdraw host firewall admission"),
                "the residue must be named in the rollback failure: {message}"
            ),
            other => panic!("a failed withdrawal must surface as a rollback failure: {other:?}"),
        }
        assert_eq!(controller.state(), DataplaneState::FailClosed);
    }

    /// The binding is withdrawn under BOTH rollback intents. DNS and the
    /// killswitch are HELD through a fail-closed unwind because restoring them
    /// would fail OPEN; the zone binding is a permission granted to a foreign
    /// firewall, so removing it is strictly more restrictive and has no
    /// fail-open direction to guard.
    #[test]
    fn a_fail_closed_unwind_also_withdraws_the_host_firewall_zone_binding() {
        let mut controller = serving_controller_after_apply();
        controller
            .system
            .fail_on_from_now("admit_host_firewall_forwarding");

        controller
            .reassert_host_firewall_admission()
            .expect_err("a broken posture must fail the re-assert");

        assert_eq!(controller.state(), DataplaneState::FailClosed);
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "a fail-closed unwind must not keep the zone binding: {:?}",
            controller.system.operations
        );
    }

    /// Source-pinned ordering. The binding names an interface, so it can only
    /// be given back while that interface still exists. The marker is recorded
    /// AFTER `BackendStarted`, and `rollback_generation_best_effort` unwinds in
    /// reverse — so the withdrawal always runs before the backend teardown that
    /// destroys the device. A future edit that hoists the marker push above the
    /// backend start would silently make every shutdown withdrawal act on a
    /// device that is already gone, and no behavioural test can see that
    /// because the DryRun backend keeps no device.
    #[test]
    fn the_admission_marker_is_recorded_after_the_backend_start() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];
        let backend_started = code
            .find("Ok(()) => applied_stages.push(StageMarker::BackendStarted)")
            .expect("the apply must record the backend start");
        let admitted = code
            .find("applied_stages.push(StageMarker::HostFirewallAdmitted);")
            .expect("the apply must record the host firewall admission");
        assert!(
            backend_started < admitted,
            "the admission marker must be recorded after the backend start, so the \
             reverse-order unwind withdraws the binding while its interface still exists"
        );
    }

    // ---- QH-52 residual: the crash-restart edge ----
    //
    // QH-52's demotion arm keys on the recorded `HostFirewallAdmitted` marker,
    // and `active_stages` dies with the process. A crash while bound, then a
    // restart as a plain client, therefore left the binding BOUND with nothing
    // left to remove it. The reconcile probe (`reconcile_firewalld_zone_residue`)
    // closes that edge — the tests below pin its gating, its once-per-process
    // cost, and the marker handoff to the existing retry machinery.

    /// The defect itself. A fresh process (empty `active_stages`) applying a
    /// plain-client generation must run the one-time reconcile probe: on a
    /// firewalld host this is the ONLY thing that can find a binding the
    /// crashed predecessor installed. A second client apply must NOT probe
    /// again — the probe costs a busctl round-trip, and QH-52's note
    /// explicitly rejected putting one on every plain-client apply.
    #[test]
    fn a_crash_restarted_client_probes_for_a_stale_zone_binding_once() {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        );

        demote_to_client(&mut controller).expect("plain-client apply should succeed");
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "reconcile_firewalld_zone_residue"),
            "the first apply of a fresh (crash-restart analog) process must run the \
             residue probe: {:?}",
            controller.system.operations
        );

        controller.system.operations.clear();
        demote_to_client(&mut controller).expect("second plain-client apply should succeed");
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "reconcile_firewalld_zone_residue"),
            "the probe is once per process, not once per apply: {:?}",
            controller.system.operations
        );
    }

    /// An apply that is about to SERVE never probes: the admit stage below
    /// re-binds the interface anyway, so the probe could only find residue
    /// this same apply is about to overwrite — and unbinding a binding a
    /// serving generation wants would be fighting ourselves.
    #[test]
    fn a_serving_apply_never_probes_for_crash_residue() {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
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
            .expect("serving apply should succeed");

        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "reconcile_firewalld_zone_residue"),
            "a serving apply must not run the crash-residue probe: {:?}",
            controller.system.operations
        );
    }

    /// The in-process demotion edge is owned by the marker arm, not the
    /// probe: when `HostFirewallAdmitted` is recorded, the demotion arm
    /// withdraws and the probe must stay out of the way (no double reconcile
    /// of the same binding in one apply).
    #[test]
    fn an_in_process_demotion_does_not_double_probe() {
        let mut controller = serving_controller_after_apply();

        demote_to_client(&mut controller).expect("demotion should succeed");

        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "the marker arm must own the withdrawal: {:?}",
            controller.system.operations
        );
        assert!(
            !controller
                .system
                .operations
                .iter()
                .any(|op| op == "reconcile_firewalld_zone_residue"),
            "a demotion with the marker recorded must not also probe: {:?}",
            controller.system.operations
        );
    }

    /// A failed crash-restart reconcile must NOT fail the apply closed (a
    /// leftover binding is residue, not exposure), but it must not be
    /// forgotten either: the marker is recorded so the EXISTING QH-52 retry
    /// machinery picks the withdrawal up on the next apply and at shutdown.
    #[test]
    fn a_failed_crash_reconcile_is_recorded_and_retried_on_the_next_apply() {
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        );
        controller
            .system
            .fail_on_from_now("reconcile_firewalld_zone_residue");

        demote_to_client(&mut controller)
            .expect("a failed residue probe must not fail a healthy generation closed");
        assert!(
            controller.backend.started,
            "the generation must have committed despite the failed probe"
        );
        assert_eq!(
            controller.state(),
            DataplaneState::DataplaneApplied,
            "a failed teardown-report must not leave the node fail-closed"
        );

        controller.system.fail_on_from_now("no_such_stage");
        controller.system.operations.clear();
        demote_to_client(&mut controller).expect("the retrying apply should succeed");
        assert!(
            controller
                .system
                .operations
                .iter()
                .any(|op| op == "withdraw_host_firewall_forwarding"),
            "the failed probe must hand off to the marker arm, which retries the \
             withdrawal on the next apply: {:?}",
            controller.system.operations
        );
    }

    /// Source pin, in the style of
    /// `the_admission_marker_is_recorded_after_the_backend_start`: the probe's
    /// gating conditions are controller logic invisible to any single DryRun
    /// ordering, so pin the structure — consumed-once flag, the serving gate,
    /// the marker gate, the non-propagating error arm, and the marker
    /// handoff — directly in `rollback_obsolete_controls`.
    #[test]
    fn the_crash_reconcile_is_gated_once_per_process_and_never_while_serving() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        let arm_at = code
            .find("if let Err(err) = self.system.reconcile_firewalld_zone_residue()")
            .expect("the controller must call the reconcile probe non-propagating");
        // The arm lives in rollback_obsolete_controls, after previous_stages
        // is snapshotted (the demotion arm reads the same snapshot).
        let rollback_at = code
            .rfind("fn rollback_obsolete_controls")
            .expect("rollback_obsolete_controls must exist");
        assert!(
            arm_at > rollback_at,
            "the reconcile call must live in rollback_obsolete_controls"
        );
        let window = &code[rollback_at..arm_at];
        assert!(
            window.contains("self.firewalld_zone_residue_probe_pending"),
            "the probe must be gated on the once-per-process flag"
        );
        assert!(
            window.contains("!options.serve_exit_node"),
            "the probe must never run on an apply that is about to serve"
        );
        assert!(
            window.contains("!previous_stages.contains(&StageMarker::HostFirewallAdmitted)"),
            "the probe must defer to the marker arm when the marker is recorded"
        );
        assert!(
            window.contains("self.firewalld_zone_residue_probe_pending = false;"),
            "the flag must be consumed when the probe runs (once per process)"
        );
        let after = &code[arm_at..code.len().min(arm_at + 1400)];
        assert!(
            after.contains("if let Err(err) ="),
            "a failed probe must be reported, never propagated (teardown semantics)"
        );
        assert!(
            after.contains("applied_stages.push(StageMarker::HostFirewallAdmitted);"),
            "a failed probe must record the marker so the next apply / shutdown \
             retries the withdrawal"
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

    /// QH-46/QH-53 behavioural twins of
    /// `linux_firewall_admit_runs_after_backend_start_and_never_in_the_killswitch`:
    /// drive the real `admit_host_firewall_forwarding` stage through the
    /// helper protocol with a scripted firewalld posture and prove it FAILS
    /// CLOSED when the host firewall would discard forwarded tunnel traffic.
    ///
    /// Driving the stage directly is equivalent to the production path only
    /// while `ensure_host_firewall_admits_forwarding` reads nothing the
    /// killswitch prelude sets up — today it reads `interface_name` and the
    /// privileged client alone. If it ever grows such a dependency, these
    /// twins silently diverge from production; re-check this note then.
    ///
    /// Every log assertion goes through `LINUX_FIREWALLD_ZONE_PROGRAM` (the
    /// same constant `as_str()` returns), never a string literal, so a program
    /// rename breaks the presence asserts loudly instead of leaving the
    /// absence assert vacuously green.
    ///
    /// The harness tuple: (command log, stop flag, helper thread, system
    /// under test). Named because CI's clippy (unlike the pinned local
    /// toolchain's) rejects the inline four-tuple as type_complexity.
    #[cfg(target_os = "linux")]
    type ScriptedFirewalldHarness = (
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        LinuxCommandSystem,
    );

    #[cfg(target_os = "linux")]
    fn firewalld_scripted_system(
        socket_path: &Path,
        interface: &str,
        posture_stdout: &str,
    ) -> ScriptedFirewalldHarness {
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            socket_path,
            vec![(
                crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM.to_owned(),
                PrivilegedCommandOutput {
                    status: 0,
                    stdout: posture_stdout.to_owned(),
                    stderr: String::new(),
                },
            )],
        );
        let system = firewalld_client_system(socket_path, interface);
        (commands, stop, helper_thread, system)
    }

    // ── QH-60: management-bypass anchoring ──────────────────────────────
    #[test]
    fn v4_cidr_overlap_matrix() {
        use std::net::Ipv4Addr;
        let ip = |s: &str| s.parse::<Ipv4Addr>().expect("ipv4");
        // /32 inside a connected /24 — the admin-workstation pin — overlaps.
        assert!(super::v4_cidrs_overlap(
            ip("192.168.64.5"),
            32,
            ip("192.168.64.20"),
            24
        ));
        // Disjoint /24s (the QH-57 wedge) do not.
        assert!(!super::v4_cidrs_overlap(
            ip("192.168.18.0"),
            24,
            ip("192.168.64.20"),
            24
        ));
        // A /0 overlaps everything.
        assert!(super::v4_cidrs_overlap(
            ip("0.0.0.0"),
            0,
            ip("10.1.2.3"),
            24
        ));
        // Identical prefixes overlap.
        assert!(super::v4_cidrs_overlap(
            ip("10.0.7.0"),
            24,
            ip("10.0.7.9"),
            24
        ));
        // Adjacent /25 halves of one /24 do not.
        assert!(!super::v4_cidrs_overlap(
            ip("10.0.7.0"),
            25,
            ip("10.0.7.128"),
            25
        ));
    }

    #[test]
    fn parse_connected_v4_prefixes_reads_inet_tokens_not_columns() {
        let out = "2: enp0s9    inet 192.168.64.20/24 brd 192.168.64.255 scope global dynamic enp0s9\n\
                   2: enp0s9    inet6 fe80::1/64 scope link\n\
                   3: enp0s9    inet 10.0.7.9/16 scope global secondary enp0s9:0\n\
                   garbage line without keyword\n";
        let parsed = super::parse_connected_v4_prefixes(out);
        assert_eq!(
            parsed,
            vec![
                ("192.168.64.20".parse().expect("ip"), 24),
                ("10.0.7.9".parse().expect("ip"), 16),
            ]
        );
        assert!(super::parse_connected_v4_prefixes("").is_empty());
    }

    /// Scripted system for the anchoring tests: fail-closed SSH allow is ON
    /// with the given CIDRs, and the egress address observation answers with
    /// the given `ip -o addr show` output.
    /// The scripted-helper handle set `anchoring_system` returns: the recorded
    /// commands, the stop flag, the helper thread, and the system under test.
    #[cfg(target_os = "linux")]
    type AnchoringSystemParts = (
        Arc<Mutex<Vec<String>>>,
        Arc<AtomicBool>,
        std::thread::JoinHandle<()>,
        LinuxCommandSystem,
    );

    #[cfg(target_os = "linux")]
    fn anchoring_system(
        socket_path: &Path,
        cidrs: &[&str],
        engaged: bool,
        addr_show_stdout: &str,
        addr_show_status: i32,
    ) -> AnchoringSystemParts {
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            socket_path,
            vec![(
                "addr show".to_owned(),
                PrivilegedCommandOutput {
                    status: addr_show_status,
                    stdout: addr_show_stdout.to_owned(),
                    stderr: if addr_show_status == 0 {
                        String::new()
                    } else {
                        "scripted observation failure".to_owned()
                    },
                },
            )],
        );
        let client =
            PrivilegedCommandClient::new(socket_path.to_path_buf(), Duration::from_secs(2))
                .expect("privileged client should initialize");
        let parsed = cidrs
            .iter()
            .map(|c| c.parse::<ManagementCidr>().expect("management cidr"))
            .collect::<Vec<_>>();
        let mut system = LinuxCommandSystem::new(
            "rustynet0",
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            true,
            parsed,
        )
        .expect("linux command system should initialize");
        DataplaneSystem::set_generation(&mut system, 1);
        DataplaneSystem::set_full_tunnel_engaged(&mut system, engaged);
        (commands, stop, helper_thread, system)
    }

    #[cfg(target_os = "linux")]
    fn run_anchoring_case(
        prefix: &str,
        cidrs: &[&str],
        engaged: bool,
        stdout: &str,
        status: i32,
    ) -> (Result<(), SystemError>, Vec<String>) {
        let socket_path = phase10_test_socket_path(prefix);
        let (commands, stop, helper_thread, mut system) =
            anchoring_system(&socket_path, cidrs, engaged, stdout, status);
        let result = DataplaneSystem::apply_routes(&mut system, &[]);
        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);
        let log = commands.lock().expect("command log should lock").clone();
        (result, log)
    }

    #[cfg(target_os = "linux")]
    const QH60_CONNECTED: &str =
        "2: enp0s9    inet 192.168.64.20/24 brd 192.168.64.255 scope global dynamic enp0s9\n";

    #[cfg(target_os = "linux")]
    #[test]
    fn full_tunnel_apply_refuses_unanchored_management_cidrs() {
        // The QH-57 byte-for-byte scenario: configured 192.168.18.0/24, live
        // LAN 192.168.64.0/24, full-tunnel engaging.
        let (result, log) =
            run_anchoring_case("q60a", &["192.168.18.0/24"], true, QH60_CONNECTED, 0);
        match result {
            Err(SystemError::RouteApplyFailed(message)) => {
                assert!(message.contains("QH-60"), "{message}");
                assert!(message.contains("192.168.18.0/24"), "{message}");
                assert!(message.contains("192.168.64.20/24"), "{message}");
                assert!(message.contains("recoverable"), "{message}");
            }
            other => panic!("unanchored full-tunnel apply must refuse: {other:?}"),
        }
        assert!(
            !log.iter()
                .any(|cmd| cmd.contains("route replace 192.168.18.0/24")),
            "no bypass route may install after refusal: {log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn full_tunnel_apply_accepts_anchored_management_cidrs() {
        let (result, log) =
            run_anchoring_case("q60b", &["192.168.64.0/24"], true, QH60_CONNECTED, 0);
        result.expect("anchored full-tunnel apply should succeed");
        assert!(
            log.iter()
                .any(|cmd| cmd.contains("route replace 192.168.64.0/24")),
            "the bypass route must install: {log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn admin_workstation_slash32_inside_connected_prefix_anchors() {
        // The review's blocking case: a /32 pin inside the on-link /24
        // contains no local address but overlaps the connected prefix.
        let (result, _log) =
            run_anchoring_case("q60c", &["192.168.64.5/32"], true, QH60_CONNECTED, 0);
        result.expect("a /32 inside the connected prefix must anchor");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn off_mode_unanchored_warns_and_installs() {
        // Without full-tunnel the rule-51820 lookup never engages; a wrong
        // list is inert and refusal would brick mesh-join for exit-less
        // nodes. Mutation target: removing the full_tunnel gate makes this
        // test fail.
        let (result, log) =
            run_anchoring_case("q60d", &["192.168.18.0/24"], false, QH60_CONNECTED, 0);
        result.expect("off-mode apply must warn, not refuse");
        assert!(
            log.iter()
                .any(|cmd| cmd.contains("route replace 192.168.18.0/24")),
            "off-mode still installs the (inert) route: {log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn partial_anchor_installs_all_routes() {
        let (result, log) = run_anchoring_case(
            "q60e",
            &["192.168.18.0/24", "192.168.64.0/24"],
            true,
            QH60_CONNECTED,
            0,
        );
        result.expect("a partially anchored list should succeed");
        assert!(
            log.iter()
                .any(|cmd| cmd.contains("route replace 192.168.18.0/24"))
        );
        assert!(
            log.iter()
                .any(|cmd| cmd.contains("route replace 192.168.64.0/24"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn empty_address_output_classifies_as_unanchored_not_observation_error() {
        // The DHCP race: device up, no address yet — exit 0, empty stdout.
        let (result, _log) = run_anchoring_case("q60f", &["192.168.64.0/24"], true, "", 0);
        match result {
            Err(SystemError::RouteApplyFailed(message)) => {
                assert!(
                    message.contains("connected: []"),
                    "must land in the no-anchor arm naming zero addresses: {message}"
                );
                assert!(
                    !message.contains("observation"),
                    "must not be classified as an observation failure: {message}"
                );
            }
            other => panic!("empty address output under full-tunnel must refuse: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observation_error_fails_closed() {
        let (result, _log) = run_anchoring_case("q60g", &["192.168.64.0/24"], true, "", 1);
        match result {
            Err(SystemError::RouteApplyFailed(message)) => {
                assert!(message.contains("observation"), "{message}");
            }
            other => panic!("a failed observation must refuse the apply: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn v6_only_management_list_refuses_under_full_tunnel() {
        // v6 entries are excluded from the quorum while IPv6 parity is off
        // (the generation strips v6 addresses after the routes stage), so an
        // all-v6 list has an empty quorum and cannot anchor.
        let (result, _log) =
            run_anchoring_case("q60h", &["fd12:3456::/32"], true, QH60_CONNECTED, 0);
        assert!(
            matches!(result, Err(SystemError::RouteApplyFailed(_))),
            "an all-IPv6 management list must refuse under full-tunnel: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    fn firewalld_client_system(socket_path: &Path, interface: &str) -> LinuxCommandSystem {
        let client =
            PrivilegedCommandClient::new(socket_path.to_path_buf(), Duration::from_secs(2))
                .expect("privileged client should initialize");
        let mut system = LinuxCommandSystem::new(
            interface,
            "enp0s9",
            LinuxDataplaneMode::HybridNative,
            Some(client),
            false,
            Vec::new(),
        )
        .expect("linux command system should initialize");
        DataplaneSystem::set_generation(&mut system, 1);
        system
    }

    /// Helper that answers the firewalld builtin with a PROTOCOL error (the
    /// shape a busctl failure or refused request takes at the client), and
    /// every other command with empty success. Exercises the `?` on
    /// `run_capture` inside `ensure_host_firewall_admits_forwarding`, which the
    /// posture-scripting tests never can (their fake always answers success).
    #[cfg(target_os = "linux")]
    fn spawn_privileged_firewalld_error_helper(
        socket_path: &Path,
    ) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        if socket_path.exists() {
            let _ = std::fs::remove_file(socket_path);
        }
        let listener = UnixListener::bind(socket_path).unwrap_or_else(|err| {
            panic!(
                "test helper socket should bind at {}: {err}",
                socket_path.display()
            )
        });
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))
            .unwrap_or_else(|err| {
                panic!(
                    "test helper socket permissions should be settable at {}: {err}",
                    socket_path.display()
                )
            });
        listener
            .set_nonblocking(true)
            .expect("test helper socket should be non-blocking");

        let stop = Arc::new(AtomicBool::new(false));
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
                        let response = if request
                            .program
                            .contains(crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM)
                        {
                            crate::privileged_helper::HelperResponse::error(
                                "scripted firewalld builtin failure".to_owned(),
                            )
                        } else {
                            crate::privileged_helper::HelperResponse::success(
                                0,
                                String::new(),
                                String::new(),
                            )
                        };
                        let _ = crate::privileged_helper::write_response(&mut stream, response);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        (stop, handle)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_fails_closed_when_firewalld_leaves_tunnel_unbound() {
        let socket_path = phase10_test_socket_path("fwzu");
        let (commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rustynet0",
            "presence=running default_zone=public bound=false",
        );
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                // The :904 obstruction branch specifically — not the :902 parse
                // branch — so deleting only the forwarding_unobstructed() check
                // cannot hide behind a parse error from another test.
                message.contains("host firewall would discard forwarded tunnel traffic"),
                "the failure must come from the obstruction verdict: {message}"
            ),
            other => panic!(
                "firewall apply must fail closed when firewalld leaves the tunnel unbound: {other:?}"
            ),
        }
        let command_log = commands.lock().expect("command log should lock").clone();
        let bind_command = format!(
            "{} op=bind interface=rustynet0",
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        assert!(
            command_log.iter().any(|cmd| cmd.contains(&bind_command)),
            "the apply must have asked the builtin to bind the tunnel interface: {command_log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_fails_closed_on_unparseable_posture() {
        // An empty or garbled posture line must surface as a failed apply,
        // never as "firewalld absent, nothing to do".
        let socket_path = phase10_test_socket_path("fwzg");
        let (_commands, stop, helper_thread, mut system) =
            firewalld_scripted_system(&socket_path, "rustynet0", "");
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                // The :902 parse branch specifically — replacing the parse
                // failure with a defaulted posture is a distinct mutation from
                // deleting the obstruction check, and each branch has its own
                // detecting test.
                message.contains("firewalld posture"),
                "the failure must come from the posture parse: {message}"
            ),
            other => {
                panic!("an unparseable firewalld posture must fail the apply closed: {other:?}")
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_fails_closed_when_binding_state_is_unknown() {
        // The real builtin emits `presence=running` with NO bound token when
        // the zone query itself fails. Unknown binding state must read as
        // obstructed — mapping it to "clear" is precisely the fail-open class
        // QH-46 exists to prevent.
        let socket_path = phase10_test_socket_path("fwzq");
        let (_commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rustynet0",
            "presence=running default_zone=public",
        );
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                message.contains("host firewall would discard forwarded tunnel traffic"),
                "unknown binding state must fail via the obstruction verdict: {message}"
            ),
            other => panic!(
                "firewall apply must fail closed when the binding state is unknown: {other:?}"
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_fails_closed_when_firewalld_builtin_errors() {
        // A transport/builtin failure (busctl missing, helper refusal) reaches
        // the daemon as a client Err, not a posture line. Swallowing that Err
        // and returning Ok would be the canonical fail-open; this is the only
        // test that ever makes the firewalld request itself fail.
        let socket_path = phase10_test_socket_path("fwze");
        let (stop, helper_thread) = spawn_privileged_firewalld_error_helper(&socket_path);
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        // Deliberately variant-agnostic: today this surfaces as SystemError::Io
        // from the client; pinning that shape would couple the test to
        // transport plumbing. What must hold is that the apply FAILS.
        assert!(
            result.is_err(),
            "a failed firewalld builtin request must fail the apply closed: {result:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_passes_when_tunnel_bound_to_default_zone() {
        // Non-default interface name on purpose: with the production-default
        // `rustynet0` this assert could not distinguish the interface FIELD
        // from a hardcoded literal in the enforcement code.
        let socket_path = phase10_test_socket_path("fwzb");
        let (commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rnqh46",
            "presence=running default_zone=public bound=true",
        );
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("firewall apply should succeed once the tunnel is bound");
        // This log assertion is the test's entire M1-detection value (under a
        // deleted call the apply still returns Ok) — do not "simplify" it away.
        let command_log = commands.lock().expect("command log should lock").clone();
        let bind_command = format!(
            "{} op=bind interface=rnqh46",
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        assert!(
            command_log.iter().any(|cmd| cmd.contains(&bind_command)),
            "the apply must bind the CONFIGURED tunnel interface, not a hardcoded one: \
             {command_log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_admit_passes_when_firewalld_absent() {
        let socket_path = phase10_test_socket_path("fwza");
        let (_commands, stop, helper_thread, mut system) =
            firewalld_scripted_system(&socket_path, "rustynet0", "presence=absent");
        let result = DataplaneSystem::admit_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("firewall apply should succeed with no firewalld to coexist with");
    }

    // ── QH-52: the withdrawal direction, over the same scripted builtin ──

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_withdrawal_issues_the_unbind_for_the_configured_interface() {
        // Non-default interface name for the same reason the bind test uses
        // one: it distinguishes the interface FIELD from a hardcoded literal.
        let socket_path = phase10_test_socket_path("fwzw");
        let (commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rnqh52",
            "presence=running default_zone=public bound=false",
        );
        let result = DataplaneSystem::withdraw_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("a confirmed-unbound posture must report the withdrawal complete");
        // The whole M1-detection value: with the call deleted the function
        // still returns Ok.
        let command_log = commands.lock().expect("command log should lock").clone();
        let unbind_command = format!(
            "{} op=unbind interface=rnqh52",
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        assert!(
            command_log.iter().any(|cmd| cmd.contains(&unbind_command)),
            "demotion must ask the builtin to unbind the CONFIGURED tunnel interface: \
             {command_log:?}"
        );
        assert!(
            !command_log.iter().any(|cmd| cmd.contains("op=bind")),
            "the withdrawal must never re-bind: {command_log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_withdrawal_is_satisfied_when_firewalld_is_absent() {
        // The presence gate lives in exactly one place for both directions:
        // inside the builtin. A host with no firewalld never had a binding, so
        // the withdrawal has nothing to remove and must not report residue —
        // the mirror of `forwarding_admit_passes_when_firewalld_absent`.
        let socket_path = phase10_test_socket_path("fwzx");
        let (_commands, stop, helper_thread, mut system) =
            firewalld_scripted_system(&socket_path, "rustynet0", "presence=absent");
        let result = DataplaneSystem::withdraw_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("with no firewalld there is no binding to give back");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_withdrawal_reports_a_binding_that_survived_demotion() {
        let socket_path = phase10_test_socket_path("fwzs");
        let (_commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rustynet0",
            "presence=running default_zone=public bound=true",
        );
        let result = DataplaneSystem::withdraw_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                message.contains("host firewall zone binding survived role demotion"),
                "the failure must come from the withdrawal verdict: {message}"
            ),
            other => panic!("a surviving zone binding must be reported as residue: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_withdrawal_reports_residue_when_binding_state_is_unknown() {
        // `presence=running` with no `bound` token is what the builtin emits
        // when the zone query itself fails. "I could not tell" must record
        // possible residue, never a completed removal.
        let socket_path = phase10_test_socket_path("fwzy");
        let (_commands, stop, helper_thread, mut system) = firewalld_scripted_system(
            &socket_path,
            "rustynet0",
            "presence=running default_zone=public",
        );
        let result = DataplaneSystem::withdraw_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                message.contains("host firewall zone binding survived role demotion"),
                "unknown binding state must report residue via the withdrawal verdict: {message}"
            ),
            other => panic!("an unreadable binding state must not read as removed: {other:?}"),
        }
    }

    // ── QH-52 residual: the crash-restart reconcile, over the same builtin ──
    //
    // These need per-op scripting (the probe must QUERY first and only then
    // decide to unbind), so they drive `spawn_privileged_scripted_helper`
    // directly with `op=`-token needles instead of the single-posture
    // `firewalld_scripted_system` the direction tests above use.

    /// The defect itself, live over the builtin: a stale binding (what a
    /// crashed predecessor left) is cleared — query first, then unbind, never
    /// a bind.
    #[cfg(target_os = "linux")]
    #[test]
    fn crash_reconcile_clears_a_stale_binding_query_first() {
        let socket_path = phase10_test_socket_path("fwzr");
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "op=query".to_owned(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "presence=running default_zone=public bound=true".to_owned(),
                        stderr: String::new(),
                    },
                ),
                (
                    "op=unbind".to_owned(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "presence=running default_zone=public bound=false".to_owned(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let mut system = firewalld_client_system(&socket_path, "rnqh52");
        let result = DataplaneSystem::reconcile_firewalld_zone_residue(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("a cleared stale binding must report the reconcile complete");
        let command_log = commands.lock().expect("command log should lock").clone();
        let query_command = format!(
            "{} op=query interface=rnqh52",
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        let unbind_command = format!(
            "{} op=unbind interface=rnqh52",
            crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM
        );
        assert!(
            command_log.iter().any(|cmd| cmd.contains(&query_command)),
            "the reconcile must probe before mutating: {command_log:?}"
        );
        assert!(
            command_log.iter().any(|cmd| cmd.contains(&unbind_command)),
            "a probe that finds the interface still bound must unbind the CONFIGURED \
             tunnel interface: {command_log:?}"
        );
        assert!(
            !command_log.iter().any(|cmd| cmd.contains("op=bind")),
            "a reconcile must never re-bind: {command_log:?}"
        );
    }

    /// A node whose posture is already withdrawn pays the probe and nothing
    /// more: no mutation on the plain-client path, which is what makes the
    /// once-per-process probe affordable on hosts that never served.
    #[cfg(target_os = "linux")]
    #[test]
    fn crash_reconcile_is_a_noop_when_the_posture_is_already_withdrawn() {
        let socket_path = phase10_test_socket_path("fwzn");
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![(
                "op=query".to_owned(),
                PrivilegedCommandOutput {
                    status: 0,
                    stdout: "presence=absent".to_owned(),
                    stderr: String::new(),
                },
            )],
        );
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        let result = DataplaneSystem::reconcile_firewalld_zone_residue(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("no firewalld means no residue and a clean reconcile");
        let command_log = commands.lock().expect("command log should lock").clone();
        assert!(
            command_log.iter().any(|cmd| cmd.contains("op=query")),
            "the reconcile must probe even on a firewalld-less host: {command_log:?}"
        );
        assert!(
            !command_log.iter().any(|cmd| cmd.contains("op=unbind")),
            "an already-withdrawn posture must not be mutated: {command_log:?}"
        );
    }

    /// The fail-closed middle case: the probe ran but the posture could not
    /// be read (empty stdout). "I could not tell" must attempt the idempotent
    /// withdrawal — the same posture-unreadable rule the withdrawal direction
    /// tests pin — and an unconfirmable result is reported, never read as
    /// success.
    #[cfg(target_os = "linux")]
    #[test]
    fn crash_reconcile_attempts_the_unbind_when_the_posture_is_unreadable() {
        let socket_path = phase10_test_socket_path("fwzu");
        // Default response (no needle matched) is empty stdout, which the
        // posture parser rejects — exactly the unreadable case, for BOTH the
        // query and the follow-up unbind's re-read.
        let (commands, stop, helper_thread) =
            spawn_privileged_scripted_helper(&socket_path, Vec::new());
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        let result = DataplaneSystem::reconcile_firewalld_zone_residue(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        assert!(
            matches!(result, Err(SystemError::FirewallApplyFailed(_))),
            "an unreadable posture must not read as a completed reconcile: {result:?}"
        );
        let command_log = commands.lock().expect("command log should lock").clone();
        assert!(
            command_log.iter().any(|cmd| cmd.contains("op=unbind")),
            "an unreadable posture must still attempt the idempotent withdrawal: \
             {command_log:?}"
        );
    }

    /// The no-busctl hazard, live: when the probe could not run AT ALL (the
    /// builtin answers with a protocol error — helper refused, binary
    /// missing), the reconcile must report Ok so the controller does not
    /// re-record the marker and manufacture withdrawal churn on every apply
    /// of a host that simply lacks the diagnostic tool.
    #[cfg(target_os = "linux")]
    #[test]
    fn crash_reconcile_tolerates_an_unavailable_probe() {
        let socket_path = phase10_test_socket_path("fwzv");
        let (stop, helper_thread) = spawn_privileged_firewalld_error_helper(&socket_path);
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        let result = DataplaneSystem::reconcile_firewalld_zone_residue(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("an unavailable probe is a diagnostic gap, not residue evidence");
    }

    /// A binding that survives the reconcile's own unbind is residue, exactly
    /// as at demotion time — reported through the same verdict message.
    #[cfg(target_os = "linux")]
    #[test]
    fn crash_reconcile_reports_a_binding_that_survived_the_reconcile() {
        let socket_path = phase10_test_socket_path("fwzb2");
        let (commands, stop, helper_thread) = spawn_privileged_scripted_helper(
            &socket_path,
            vec![
                (
                    "op=query".to_owned(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "presence=running default_zone=public bound=true".to_owned(),
                        stderr: String::new(),
                    },
                ),
                (
                    "op=unbind".to_owned(),
                    PrivilegedCommandOutput {
                        status: 0,
                        stdout: "presence=running default_zone=public bound=true".to_owned(),
                        stderr: String::new(),
                    },
                ),
            ],
        );
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        let result = DataplaneSystem::reconcile_firewalld_zone_residue(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                message.contains("host firewall zone binding survived role demotion"),
                "the failure must come from the withdrawal verdict: {message}"
            ),
            other => panic!("a surviving zone binding must be reported as residue: {other:?}"),
        }
        let command_log = commands.lock().expect("command log should lock").clone();
        assert!(
            command_log.iter().any(|cmd| cmd.contains("op=unbind")),
            "the reconcile must have attempted the removal before reporting: {command_log:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forwarding_withdrawal_reports_an_unparseable_posture() {
        let socket_path = phase10_test_socket_path("fwzp");
        let (_commands, stop, helper_thread, mut system) =
            firewalld_scripted_system(&socket_path, "rustynet0", "");
        let result = DataplaneSystem::withdraw_host_firewall_forwarding(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        match result {
            Err(SystemError::FirewallApplyFailed(message)) => assert!(
                message.contains("firewalld posture"),
                "the failure must come from the posture parse: {message}"
            ),
            other => panic!("an unparseable posture must not read as a removed binding: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn firewall_killswitch_apply_never_drives_the_firewalld_builtin() {
        // QH-53 regression lock, behavioural layer: even with relay forwarding
        // enabled, the pre-start killswitch must not touch firewalld — the
        // tunnel interface does not exist at killswitch time on a cold
        // bootstrap, so a bind there fails every forwarding node on a
        // firewalld host. The bind belongs to admit_host_firewall_forwarding,
        // which the controller runs after backend start.
        //
        // Deliberately uses the all-success capture helper with NO scripted
        // firewalld response: if the bind is ever moved back, the unscripted
        // firewalld command comes back with an empty posture and the apply
        // FAILS on the parse — so this test detects the regression twice, via
        // the Ok expectation and via the absence assert.
        let socket_path = phase10_test_socket_path("fwzn");
        let (commands, stop, helper_thread) = spawn_privileged_capture_helper(&socket_path);
        let mut system = firewalld_client_system(&socket_path, "rustynet0");
        DataplaneSystem::set_relay_forwarding(&mut system, true);

        let result = DataplaneSystem::apply_firewall_killswitch(&mut system);

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        result.expect("the killswitch apply should succeed without firewalld involvement");
        let command_log = commands.lock().expect("command log should lock").clone();
        assert!(
            !command_log
                .iter()
                .any(|cmd| cmd.contains(crate::linux_firewalld_zone::LINUX_FIREWALLD_ZONE_PROGRAM)),
            "the pre-start killswitch must never drive the firewalld zone builtin: {command_log:?}"
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

        // Three commands: the D-6c tandem-anchor probe (`pfctl -s Anchors`,
        // read-only, no tandem anchors in the captured output so nothing
        // further is flushed), the fixed NAT-anchor flush, and the forwarding
        // reset.
        assert_eq!(
            after_not_serving, 3,
            "not-serving reconcile must probe tandem anchors, flush the NAT anchor AND reset forwarding; got: {command_log:?}"
        );
        assert_eq!(
            command_log.len(),
            3,
            "serving reconcile must issue no command; got: {command_log:?}"
        );
        assert!(
            command_log
                .iter()
                .any(|c| c.contains("pfctl") && c.contains("-s") && c.contains("Anchors")),
            "must probe the tandem-owned anchors before flushing; got: {command_log:?}"
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

    /// POL-14: a REFUSED LAN-route grant must leave no residue.
    ///
    /// The daemon's `LanAccessOn` handler mutates (`set_lan_access`,
    /// `set_lan_route_acl`, `advertise_lan_route`) and only THEN evaluates the
    /// gate, because `ensure_lan_route_allowed` is a post-condition check over
    /// exactly those three pieces of state. So a denial has to be unwound rather
    /// than prevented -- and the unwind has to be complete, or a refused grant
    /// leaves behind precisely the entries that let a later attempt through.
    ///
    /// This pins the controller half: `withdraw_lan_route` is the exact inverse
    /// of `advertise_lan_route`, and after the full revert the gate denies again.
    #[test]
    fn withdrawing_a_lan_route_leaves_no_residue_for_the_next_grant() {
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

        let request = || RouteGrantRequest {
            user: "user:alice".to_owned(),
            cidr: "192.168.1.0/24".to_owned(),
            protocol: Protocol::Tcp,
            context: TrafficContext::SharedExit,
        };

        // Establish the full granted state and confirm the gate passes, so the
        // denial below is caused by the revert and not by never having passed.
        controller.set_lan_access(true);
        controller.advertise_lan_route(exit_node.clone(), "192.168.1.0/24");
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);
        controller
            .ensure_lan_route_allowed(request())
            .expect("the fully granted state must pass, or this test proves nothing");

        // The exact revert the daemon performs on a refused grant.
        controller.withdraw_lan_route(&exit_node, "192.168.1.0/24");
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", false);
        controller.set_lan_access(false);

        assert_eq!(
            controller.ensure_lan_route_allowed(request()).err(),
            Some(Phase10Error::LanAccessDenied),
            "after the revert the gate must deny again"
        );

        // Residue check, ISOLATED to the advertised set. Restore BOTH the toggle
        // and the ACL, so the only remaining difference from the passing state
        // above is whether the route is still advertised. Without restoring the
        // ACL the ACL check denies first and masks the thing under test -- which
        // it did, until a mutation test showed a no-op `withdraw_lan_route`
        // passing this assertion.
        controller.set_lan_access(true);
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);
        assert_eq!(
            controller.ensure_lan_route_allowed(request()).err(),
            Some(Phase10Error::LanAccessDenied),
            "a withdrawn route must be indistinguishable from one never advertised"
        );

        // And re-advertising restores the pass, proving the denial above came
        // from the withdraw and not from some unrelated state the reverts broke.
        controller.advertise_lan_route(exit_node.clone(), "192.168.1.0/24");
        controller
            .ensure_lan_route_allowed(request())
            .expect("re-advertising must restore the grant");
    }

    /// `withdraw_lan_route` must be safe and inert on inputs that were never
    /// advertised, because the daemon calls the revert from failure points that
    /// occur BEFORE any route is advertised.
    #[test]
    fn withdrawing_an_unadvertised_lan_route_is_inert() {
        let policy = allow_shared_exit_policy();
        let mut controller = Phase10Controller::new(
            RecordingBackend::default(),
            DryRunSystem::default(),
            policy,
            TrustPolicy::default(),
        );
        let exit_node = NodeId::new("exit-1").expect("node id should parse");
        let other = NodeId::new("exit-2").expect("node id should parse");

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

        // Never advertised at all.
        controller.withdraw_lan_route(&exit_node, "192.168.1.0/24");
        // Advertised, then withdrawn for a DIFFERENT cidr and a different node.
        controller.advertise_lan_route(exit_node.clone(), "192.168.1.0/24");
        controller.withdraw_lan_route(&exit_node, "10.0.0.0/8");
        controller.withdraw_lan_route(&other, "192.168.1.0/24");

        controller.set_lan_access(true);
        controller.set_lan_route_acl("user:alice", "192.168.1.0/24", true);
        controller
            .set_exit_node(exit_node.clone(), "user:alice", Protocol::Tcp)
            .expect("policy should allow selecting exit");
        controller
            .ensure_lan_route_allowed(RouteGrantRequest {
                user: "user:alice".to_owned(),
                cidr: "192.168.1.0/24".to_owned(),
                protocol: Protocol::Tcp,
                context: TrafficContext::SharedExit,
            })
            .expect("an unrelated withdraw must not remove the advertised route");
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
        // The phase10 runtime does not implement `handshake_endpoint`, so this
        // race is unattributed and must not report the attributed reason.
        assert_eq!(
            report.reason,
            TraversalProbeReason::UnattributedHandshakeObserved
        );
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

    /// iproute2 renders the default route as `default`, so the killswitch's
    /// own bypass-route assertion could never match a `0.0.0.0/0` management
    /// allow-CIDR. It failed on every reconcile, restricting the daemon until
    /// every mutating command (route advertise, exit setup) was refused.
    ///
    /// The `output=` strings below are the verbatim `ip route show table
    /// 51820` output from a lab guest after
    /// `ip route replace 0.0.0.0/0 dev enp0s1 table 51820`.
    #[test]
    fn expected_bypass_route_matches_the_default_route_iproute2_actually_renders() {
        let route =
            LinuxCommandSystem::expected_bypass_route("0.0.0.0/0".to_owned(), "enp0s1".to_owned());
        assert!(
            LinuxCommandSystem::line_matches_expected_bypass_route(
                "default dev enp0s1 scope link ",
                &route
            ),
            "we install 0.0.0.0/0 and the kernel renders it back as `default`"
        );
        // The v6 default renders the same way.
        let v6 = LinuxCommandSystem::expected_bypass_route("::/0".to_owned(), "enp0s1".to_owned());
        assert!(LinuxCommandSystem::line_matches_expected_bypass_route(
            "default dev enp0s1 metric 1024 pref medium",
            &v6
        ));

        // `default` must still be matched against the RIGHT interface, so the
        // assertion cannot be satisfied by an unrelated default route.
        assert!(
            !LinuxCommandSystem::line_matches_expected_bypass_route(
                "default dev eth9 scope link",
                &route
            ),
            "a default route on another interface is not our owned bypass route"
        );
        // And a non-default destination must not be satisfied by `default`.
        let lan = LinuxCommandSystem::expected_bypass_route(
            "192.168.64.0/24".to_owned(),
            "enp0s1".to_owned(),
        );
        assert!(!LinuxCommandSystem::line_matches_expected_bypass_route(
            "default dev enp0s1 scope link",
            &lan
        ));
        assert!(LinuxCommandSystem::line_matches_expected_bypass_route(
            "192.168.64.0/24 dev enp0s1 scope link",
            &lan
        ));
    }

    /// The other rendering quirk, already handled: a host route drops its /32.
    #[test]
    fn expected_bypass_route_matches_a_host_route_rendered_without_its_prefix() {
        let route = LinuxCommandSystem::expected_bypass_route(
            "10.0.0.7/32".to_owned(),
            "enp0s1".to_owned(),
        );
        assert!(LinuxCommandSystem::line_matches_expected_bypass_route(
            "10.0.0.7 dev enp0s1 scope link",
            &route
        ));
        assert!(!LinuxCommandSystem::line_matches_expected_bypass_route(
            "10.0.0.8 dev enp0s1 scope link",
            &route
        ));
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

    /// QH-29: generator↔matcher agreement for the NAT table. Drives the REAL
    /// `apply_nat_forwarding` emitter through the privileged-capture helper,
    /// then checks that every shared token builder the runtime matcher
    /// (`assert_nat_forwarding`) matches with is present in the rendered
    /// `nft add rule` argv — including the relay-with-upstream hairpin rule
    /// emitted with its observability-only `counter` token, which the matcher
    /// deliberately does NOT require. If the emitter and the matcher ever
    /// drift apart, this fails loudly instead of the fail-closed assertion
    /// silently matching nothing on a live node.
    #[cfg(target_os = "linux")]
    #[test]
    fn nat_rule_tokens_agree_with_emitted_nft_argv() {
        let socket_path = phase10_test_socket_path("nat");
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
        DataplaneSystem::set_relay_forwarding(&mut system, true);

        // The killswitch egress-allow rule is only emitted while a firewall
        // table exists (`apply_nat_forwarding` keys it off `firewall_table`),
        // exactly as a live apply orders the stages: killswitch first, NAT
        // afterwards. Without this the third expectation below can never be
        // met, and the test would be asserting an ordering no node uses.
        DataplaneSystem::apply_firewall_killswitch(&mut system)
            .expect("killswitch apply should succeed against the capture helper");
        DataplaneSystem::apply_nat_forwarding(
            &mut system,
            false,
            ExitMode::FullTunnel,
            false,
            "10.6.0.0/16",
        )
        .expect("nat apply should succeed against the capture helper");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        // Matcher-side expectations (the SAME builders assert_nat_forwarding
        // consumes) must each match some emitted argv line.
        let egress_masquerade = LinuxCommandSystem::nat_egress_masquerade_tokens("enp0s9");
        let hairpin_masquerade = LinuxCommandSystem::nat_hairpin_masquerade_tokens("rustynet0");
        let egress_allow = LinuxCommandSystem::killswitch_egress_allow_tokens("enp0s9");
        for (name, tokens) in [
            ("egress masquerade", egress_masquerade),
            ("hairpin masquerade", hairpin_masquerade),
            ("killswitch egress allow", egress_allow),
        ] {
            let borrowed: Vec<&str> = tokens.iter().map(String::as_str).collect();
            assert!(
                LinuxCommandSystem::chain_contains_all_tokens(&command_log, &borrowed),
                "matcher token set for the {name} rule must appear in the emitted nft argv: \
                 tokens={borrowed:?} log={command_log:?}"
            );
        }
        // Negative control: a mutated token must NOT match, proving the
        // agreement check above is not vacuously true.
        assert!(
            !LinuxCommandSystem::chain_contains_all_tokens(
                &command_log,
                &["oifname", "enp0s9", "masqueradee"]
            ),
            "mutated token must not match any emitted rule"
        );
    }

    /// QH-29: generator↔matcher agreement for the inet fail-closed table.
    /// Drives the REAL `apply_firewall_killswitch` → `apply_nat_forwarding` →
    /// `apply_dns_protection` emitter chain through the privileged-capture
    /// helper, then checks that every shared token builder the runtime
    /// matcher (`assert_firewall_ruleset`) matches with — loopback,
    /// established/related, tunnel accept, both WireGuard port rules, both
    /// DNS fail-closed drops, both DNS allows, forward tun→egress, forward
    /// hairpin, and the NAT-activated killswitch egress allow — is present
    /// in the rendered `nft add rule` argv.
    #[cfg(target_os = "linux")]
    #[test]
    fn killswitch_and_dns_rule_tokens_agree_with_emitted_nft_argv() {
        let socket_path = phase10_test_socket_path("ks");
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
        .expect("linux command system should initialize")
        .with_wg_listen_port(51820)
        // apply_dns_protection refuses to take loopback DNS ownership without a
        // configured resolver port (fail-closed); the capture helper only records
        // argv, so any non-zero port exercises the emitted rule tokens.
        .with_dns_resolver_port(53535);
        DataplaneSystem::set_relay_forwarding(&mut system, true);

        DataplaneSystem::apply_firewall_killswitch(&mut system)
            .expect("killswitch apply should succeed against the capture helper");
        DataplaneSystem::apply_nat_forwarding(
            &mut system,
            false,
            ExitMode::FullTunnel,
            false,
            "10.6.0.0/16",
        )
        .expect("nat apply should succeed against the capture helper");
        DataplaneSystem::apply_dns_protection(&mut system)
            .expect("dns apply should succeed against the capture helper");
        let command_log = commands.lock().expect("command log should lock").clone();

        stop.store(true, Ordering::Relaxed);
        helper_thread
            .join()
            .expect("helper thread should join cleanly");
        let _ = std::fs::remove_file(&socket_path);

        // Matcher-side expectations (the SAME builders assert_firewall_ruleset
        // consumes), paired with the chain the matcher searches for them in.
        let expectations: Vec<(&str, Vec<String>)> = vec![
            ("killswitch", LinuxCommandSystem::loopback_accept_tokens()),
            (
                "killswitch",
                LinuxCommandSystem::established_related_accept_tokens(),
            ),
            (
                "killswitch",
                LinuxCommandSystem::tunnel_interface_accept_tokens("rustynet0"),
            ),
            (
                "killswitch",
                LinuxCommandSystem::wg_listen_port_allow_tokens("dport", "enp0s9", 51820),
            ),
            (
                "killswitch",
                LinuxCommandSystem::wg_listen_port_allow_tokens("sport", "enp0s9", 51820),
            ),
            (
                "killswitch",
                LinuxCommandSystem::killswitch_egress_allow_tokens("enp0s9"),
            ),
            (
                "killswitch",
                LinuxCommandSystem::dns_off_tunnel_drop_tokens("udp", "rustynet0"),
            ),
            (
                "killswitch",
                LinuxCommandSystem::dns_off_tunnel_drop_tokens("tcp", "rustynet0"),
            ),
            ("killswitch", LinuxCommandSystem::dns_accept_tokens("udp")),
            ("killswitch", LinuxCommandSystem::dns_accept_tokens("tcp")),
            (
                "forward",
                LinuxCommandSystem::established_related_accept_tokens(),
            ),
            (
                "forward",
                LinuxCommandSystem::forward_tunnel_to_egress_tokens("rustynet0", "enp0s9"),
            ),
            (
                "forward",
                LinuxCommandSystem::forward_hairpin_accept_tokens("rustynet0"),
            ),
        ];
        for (chain, tokens) in expectations {
            let chain_argv: Vec<String> = command_log
                .iter()
                .filter(|cmd| {
                    cmd.contains(" add rule inet ") && cmd.contains(&format!(" {chain} "))
                })
                .cloned()
                .collect();
            let borrowed: Vec<&str> = tokens.iter().map(String::as_str).collect();
            assert!(
                LinuxCommandSystem::chain_contains_all_tokens(&chain_argv, &borrowed),
                "matcher token set must appear in the emitted {chain}-chain nft argv: \
                 tokens={borrowed:?} chain_argv={chain_argv:?}"
            );
        }
    }

    /// QH-29 regression pin for the 2026-08-29 live-lab failure: a shared
    /// builder may NEVER emit a token carrying internal whitespace. The
    /// emitters splice these tokens into a real `nft add rule` argv, where
    /// each element must be ONE nft keyword — the privileged helper's
    /// allowlist matches per-token literals, and a phrase-shaped element
    /// (`"ct state established,related"`) is refused even though its
    /// `join(" ")` rendering looks byte-identical to the accepted spelling
    /// in any log. The substring-based pairing test above cannot see this
    /// class of defect (the joined phrase still matches as a substring),
    /// which is exactly how `established_related_accept_tokens` shipped a
    /// phrase token and broke every Linux dataplane apply live.
    #[test]
    fn nft_rule_builder_tokens_never_carry_internal_whitespace() {
        let builder_sets: Vec<(&str, Vec<String>)> = vec![
            ("loopback", LinuxCommandSystem::loopback_accept_tokens()),
            (
                "established_related",
                LinuxCommandSystem::established_related_accept_tokens(),
            ),
            (
                "tunnel_interface",
                LinuxCommandSystem::tunnel_interface_accept_tokens("rustynet0"),
            ),
            (
                "egress_allow",
                LinuxCommandSystem::killswitch_egress_allow_tokens("enp0s9"),
            ),
            (
                "wg_dport",
                LinuxCommandSystem::wg_listen_port_allow_tokens("dport", "enp0s9", 51820),
            ),
            (
                "wg_sport",
                LinuxCommandSystem::wg_listen_port_allow_tokens("sport", "enp0s9", 51820),
            ),
            (
                "dns_off_tunnel_drop_udp",
                LinuxCommandSystem::dns_off_tunnel_drop_tokens("udp", "rustynet0"),
            ),
            (
                "dns_off_tunnel_drop_tcp",
                LinuxCommandSystem::dns_off_tunnel_drop_tokens("tcp", "rustynet0"),
            ),
            (
                "dns_accept_udp",
                LinuxCommandSystem::dns_accept_tokens("udp"),
            ),
            (
                "dns_accept_tcp",
                LinuxCommandSystem::dns_accept_tokens("tcp"),
            ),
            (
                "forward_tunnel_to_egress",
                LinuxCommandSystem::forward_tunnel_to_egress_tokens("rustynet0", "enp0s9"),
            ),
            (
                "forward_hairpin",
                LinuxCommandSystem::forward_hairpin_accept_tokens("rustynet0"),
            ),
            (
                "nat_egress_masquerade",
                LinuxCommandSystem::nat_egress_masquerade_tokens("enp0s9"),
            ),
            (
                "nat_hairpin_masquerade",
                LinuxCommandSystem::nat_hairpin_masquerade_tokens("rustynet0"),
            ),
        ];
        for (name, tokens) in builder_sets {
            for token in tokens {
                assert!(
                    !token.chars().any(char::is_whitespace),
                    "nft rule builder {name} emitted a token with internal \
                     whitespace ({token:?}); the privileged-helper argv \
                     allowlist matches per-token nft keywords and would \
                     refuse the rule"
                );
            }
        }
    }

    /// Pins the established/related killswitch rule's FULL argv to the exact
    /// shape the privileged-helper allowlist accepts, so an emitter-side
    /// regression fails this test instead of every Linux reconcile apply.
    #[test]
    fn established_related_rule_argv_is_helper_allowlist_shaped() {
        let argv = LinuxCommandSystem::nft_add_rule_argv(
            "inet",
            "rustynet_g1",
            "killswitch",
            &LinuxCommandSystem::established_related_accept_tokens(),
            &[],
        );
        assert_eq!(
            argv,
            vec![
                "add",
                "rule",
                "inet",
                "rustynet_g1",
                "killswitch",
                "ct",
                "state",
                "established,related",
                "accept"
            ]
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

    // iproute2 >= 6.19 (e.g. ubuntu 26.04) exits 2 with "Error: ipv4: FIB
    // table does not exist." on `ip route show table 51820` when the table
    // has no routes yet, instead of the pre-6.19 behavior of printing
    // nothing and exiting 0. Confirmed by direct A/B on live lab guests
    // (ubuntu-utm-1 iproute2 6.19.0 vs debian-2 iproute2 6.15.0); see
    // documents/operations/active/LiveLabFindings_2026-07-12.md
    // ("iproute2-6.19 FIB-table regression"). `route_table_output` must
    // interpret this exact condition as an empty table, not a killswitch
    // reconcile failure. Pin the matching predicate directly (no privileged-
    // helper transport involved) so the test is fast, portable, and exercises
    // exactly the security-relevant fail-closed boundary described in the
    // finding: only exit code 2 with this specific stderr text is forgiven.
    #[test]
    fn is_empty_fib_table_error_matches_iproute2_6_19_ipv4_message() {
        let output = PrivilegedCommandOutput {
            status: 2,
            stdout: String::new(),
            stderr: "Error: ipv4: FIB table does not exist.\n".to_string(),
        };
        assert!(LinuxCommandSystem::is_empty_fib_table_error(&output));
    }

    // Same handling applies to the IPv6 show path's stderr wording.
    #[test]
    fn is_empty_fib_table_error_matches_iproute2_6_19_ipv6_message() {
        let output = PrivilegedCommandOutput {
            status: 2,
            stdout: String::new(),
            stderr: "Error: ipv6: FIB table does not exist.\n".to_string(),
        };
        assert!(LinuxCommandSystem::is_empty_fib_table_error(&output));
    }

    // Matching is case-insensitive on the message text.
    #[test]
    fn is_empty_fib_table_error_is_case_insensitive() {
        let output = PrivilegedCommandOutput {
            status: 2,
            stdout: String::new(),
            stderr: "ERROR: IPV4: FIB TABLE DOES NOT EXIST.\n".to_string(),
        };
        assert!(LinuxCommandSystem::is_empty_fib_table_error(&output));
    }

    // Negative/fail-closed pin: a different exit-2 stderr (e.g. a permissions
    // error) must NOT be treated as an empty table — only the exact
    // FIB-table-missing condition is forgiven, every other stderr stays a
    // hard failure.
    #[test]
    fn is_empty_fib_table_error_rejects_other_exit_2_errors() {
        let output = PrivilegedCommandOutput {
            status: 2,
            stdout: String::new(),
            stderr: "RTNETLINK answers: Operation not permitted\n".to_string(),
        };
        assert!(!LinuxCommandSystem::is_empty_fib_table_error(&output));
    }

    // Negative/fail-closed pin: the FIB-missing wording at any *other* exit
    // code must not be forgiven either — only exit code 2 qualifies.
    #[test]
    fn is_empty_fib_table_error_rejects_matching_text_at_other_exit_codes() {
        let output = PrivilegedCommandOutput {
            status: 1,
            stdout: String::new(),
            stderr: "Error: ipv4: FIB table does not exist.\n".to_string(),
        };
        assert!(!LinuxCommandSystem::is_empty_fib_table_error(&output));
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

        // Under a root test runner the file just written IS root-owned and
        // the ownership rejection cannot fire; chown it to nobody (which
        // root may do) so the same assertion holds in every environment.
        if nix::unistd::Uid::effective().is_root() {
            std::os::unix::fs::chown(&target, Some(65534), Some(65534))
                .expect("root can chown the target to nobody");
        }

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

    /// QH-29: generator↔matcher agreement for the macOS killswitch anchor.
    /// Renders the REAL pf ruleset via `render_pf_rules` and checks it
    /// satisfies every expectation `MacosCommandSystem::assert_killswitch`
    /// enforces against the LIVE `pfctl -s rules` output: the shared
    /// `MACOS_PF_TERMINAL_BLOCK_RULE` constant (used verbatim by BOTH the
    /// renderer and the matcher) must be the LAST rule, the loopback pass
    /// must exist, and the DNS matcher (`ruleset_contains_dns_rule` with the
    /// matcher's exact argument shapes) must accept the rendered dns_protected
    /// pass/block pairs. A renderer change that breaks the matcher now fails
    /// this test instead of silently weakening a live fail-closed check.
    #[test]
    fn macos_rendered_rules_satisfy_assert_killswitch_expectations() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");

        let last_line = rules.lines().last().expect("rendered rules are non-empty");
        assert_eq!(
            last_line, MACOS_PF_TERMINAL_BLOCK_RULE,
            "the terminal default-deny rule must be the LAST rule in the anchor"
        );
        assert!(
            rules.contains("pass quick on lo0 all"),
            "loopback pass rule must render"
        );
        for proto in ["udp", "tcp"] {
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(
                    &rules,
                    "pass out quick",
                    proto,
                    Some("utun9"),
                ),
                "matcher must accept the rendered on-tunnel {proto} :53 pass rule"
            );
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(
                    &rules,
                    "block drop out quick",
                    proto,
                    None,
                ),
                "matcher must accept the rendered off-tunnel {proto} :53 block rule"
            );
        }
        // Negative control: a direction the renderer never emits must not match.
        assert!(
            !MacosCommandSystem::ruleset_contains_dns_rule(
                &rules,
                "pass in quick",
                "udp",
                Some("utun9"),
            ),
            "mutated action token must not match any rendered rule"
        );
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

    /// Owner decision 2026-08-27 (24): the macOS pf DNS floor must hold at
    /// Linux-nft parity (`udp/tcp dport 53 oifname != <tunnel> drop`, inet
    /// covering v4+v6) for EVERY knob combination — no egress-interface
    /// allowance, no IPv6 posture, and no other renderer input may ever
    /// produce a `:53` pass rule scoped to anything but the tunnel. This
    /// pins the no-exclusion invariant: an operator-facing knob can
    /// strengthen the floor (strict mode renders no `:53` egress at all)
    /// but can never weaken it into a non-tunnel DNS escape.
    #[test]
    fn macos_render_pf_rules_dns_pass_is_tunnel_scoped_for_every_knob_combination() {
        for allow_egress in [false, true] {
            for ipv6_blocked in [false, true] {
                let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
                    .expect("macos system should construct");
                system.dns_protected = true;
                system.allow_egress_interface = allow_egress;
                system.ipv6_blocked = ipv6_blocked;

                let rules = system
                    .render_pf_rules(false)
                    .expect("rule render should succeed");
                for line in rules.lines() {
                    if line.contains("port 53") && line.starts_with("pass ") {
                        assert!(
                            line.contains("on utun9"),
                            "a :53 pass rule scoped away from the tunnel is a DNS exclusion \
                             hatch (allow_egress={allow_egress}, ipv6_blocked={ipv6_blocked}): {line}"
                        );
                    }
                }
                // The interface-agnostic drops must render whenever the DNS
                // rules do: off-tunnel v4 :53 is denied by explicit rule.
                assert!(
                    rules.contains("block drop out quick inet proto udp to any port 53"),
                    "udp/53 off-tunnel block must render (allow_egress={allow_egress}, \
                     ipv6_blocked={ipv6_blocked})"
                );
                assert!(
                    rules.contains("block drop out quick inet proto tcp to any port 53"),
                    "tcp/53 off-tunnel block must render (allow_egress={allow_egress}, \
                     ipv6_blocked={ipv6_blocked})"
                );

                // Strict mode is stronger than parity: no :53 egress pass
                // exists at all, and the terminal default-deny holds the
                // floor for every interface and family.
                let strict = system
                    .render_pf_rules(true)
                    .expect("strict rule render should succeed");
                assert!(
                    !strict.contains("port 53"),
                    "strict mode must render no :53 pass at all \
                     (allow_egress={allow_egress}, ipv6_blocked={ipv6_blocked}): {strict}"
                );
            }
        }
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_killswitch_spec_latches_dns_floor_while_fully_protected() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;
        // The full posture implies live loopback pins: the spec must keep the
        // DNS-block floor without re-enumerating the system configuration
        // (short-circuit, deterministic on every host).
        assert!(system.killswitch_spec().dns_protected);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_untouched_posture_apply_is_a_no_op() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        assert_eq!(system.dns_posture, DnsPosture::Untouched);
        DataplaneSystem::apply_dns_protection_for_posture(&mut system, DnsPosture::Untouched)
            .expect("the untouched posture is an explicit opt-out and must not fail");
        assert_eq!(system.dns_posture, DnsPosture::Untouched);
        assert!(!system.dns_protected);
        let err = DataplaneSystem::assert_dns_protection(&mut system)
            .expect_err("nothing was applied; the assert must fail closed");
        assert!(err.to_string().contains("DNS protection is not active"));
    }

    /// The probe targets the fixed loopback port 53535. Tests that BIND that
    /// port and tests that require it to be FREE must not race each other
    /// inside one test binary, so they share this lock.
    #[cfg(target_os = "macos")]
    fn dns_probe_port_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// M1 (MacosClientResolverNotServingDiagnosisReview_2026-09-02 §3.3): a
    /// `FullyProtected`-equivalent bootstrap-time probe IS answered when the
    /// daemon's hoisted resolver socket is drained through the probe servicer
    /// — the shared `build_dns_response` responder, zone not yet loaded
    /// (SERVFAIL still proves a live listener). Ordering alone must never
    /// fail an in-bootstrap protected-DNS apply.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_probe_answered_via_bootstrap_servicer() {
        let _guard = dns_probe_port_lock()
            .lock()
            .expect("dns probe port lock poisoned");
        let socket = std::sync::Arc::new(
            std::net::UdpSocket::bind("127.0.0.1:53535")
                .expect("hoisted resolver bind should succeed (test process owns the probe port)"),
        );
        socket
            .set_nonblocking(true)
            .expect("hoisted resolver nonblocking should succeed");
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_probe_servicer =
            Some(std::sync::Arc::new(crate::daemon::DnsProbeServicer::new(
                socket,
                crate::daemon::DnsResponderState::new_unresolved("rustynet"),
            )));
        system
            .verify_loopback_resolver_live()
            .expect("the bootstrap-time probe must be answered through the servicer");
    }

    /// M1 negative control: a servicer whose socket does NOT own the probe
    /// port answers nothing, so the probe still fails closed under its
    /// existing 2 s bound — the servicer adds servicing, never success by
    /// fiat.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_probe_servicer_cannot_answer_without_the_port() {
        let _guard = dns_probe_port_lock()
            .lock()
            .expect("dns probe port lock poisoned");
        // Bound to an EPHEMERAL port, never :53535: the servicer drains a
        // socket no probe can reach.
        let socket =
            std::sync::Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").expect("ephemeral bind"));
        socket
            .set_nonblocking(true)
            .expect("nonblocking should succeed");
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_probe_servicer =
            Some(std::sync::Arc::new(crate::daemon::DnsProbeServicer::new(
                socket,
                crate::daemon::DnsResponderState::new_unresolved("rustynet"),
            )));
        let err = system
            .verify_loopback_resolver_live()
            .expect_err("a servicer that owns no listener must not answer the probe");
        assert!(
            err.to_string().contains("127.0.0.1:53535"),
            "the error must name the unanswerable resolver endpoint: {err}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_scoped_posture_fails_closed_without_live_resolver() {
        let _guard = dns_probe_port_lock()
            .lock()
            .expect("dns probe port lock poisoned");
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        // No daemon is bound on 127.0.0.1:53535 in the test process, so the
        // apply-time probe must fail BEFORE any mutation (review A6): the
        // scoped resolver file must not be written to point at a dead
        // listener, and the posture must stay untouched.
        let err = DataplaneSystem::apply_dns_protection_for_posture(
            &mut system,
            DnsPosture::ScopedResolverOnly,
        )
        .expect_err("scoped posture without a live loopback resolver must fail closed");
        assert!(
            err.to_string().contains("127.0.0.1:53535"),
            "the error must name the unanswerable resolver endpoint: {err}"
        );
        assert_eq!(system.dns_posture, DnsPosture::Untouched);
        assert!(!system.dns_protected);
    }

    // The active-protection half resolves the real networksetup binary by its
    // absolute macOS path; on Linux the file does not exist and on Windows the
    // path is not even absolute, so on both the prerequisite check fails
    // before the drift assertion under test is reached. macOS-host only.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_assert_dns_protection_requires_active_dns_rules() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");

        let err = DataplaneSystem::assert_dns_protection(&mut system)
            .expect_err("inactive macOS DNS protection must fail closed");
        assert!(err.to_string().contains("DNS protection is not active"));

        system.dns_protected = true;
        // M2: the assert dispatches on the INSTALLED posture; simulating an
        // active full-protection posture requires both flags.
        system.dns_posture = DnsPosture::FullyProtected;
        // The pf half of the assertion is host-independent: the rendered
        // ruleset must contain, for both protocols, the tunnel-scoped :53
        // pass and the interface-agnostic :53 block.
        let rules = system
            .render_pf_rules(false)
            .expect("rule render should succeed");
        for proto in ["udp", "tcp"] {
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(&rules, "pass", proto, Some("utun9"),),
                "active macOS DNS protection must render the on-tunnel {proto} :53 pass rule"
            );
            assert!(
                MacosCommandSystem::ruleset_contains_dns_rule(&rules, "block", proto, None),
                "active macOS DNS protection must render the off-tunnel {proto} :53 block rule"
            );
        }
        // The system-configuration half runs against the LIVE host, so it can
        // only expect Ok when every enabled service is already pinned to
        // loopback. What must hold on EVERY host — including hosts with
        // disabled services, whose `-listallnetworkservices` output carries
        // the legend disclaimer — is that the legend line is never mistaken
        // for a service name. (That regression fabricated a phantom service
        // and failed the assert with `networksetup -getdnsservers '<legend>'
        // failed: status=4` instead of a meaningful result.) Any residual
        // failure must therefore be genuine drift about a real, enumerable
        // service — never a getdnsservers failure against the disclaimer.
        match DataplaneSystem::assert_dns_protection(&mut system) {
            Ok(()) => {}
            Err(SystemError::DnsApplyFailed(msg)) => {
                assert!(
                    !msg.contains("asterisk") && !msg.contains("denotes that a network service"),
                    "the -listallnetworkservices legend leaked through as a service: {msg}"
                );
                assert!(
                    msg.contains("drifted"),
                    "active protection must either pass or report real service drift, got: {msg}"
                );
            }
            Err(err) => panic!("unexpected assert_dns_protection error shape: {err}"),
        }
    }

    /// A redirect decision for the tests below: active managed redirect for
    /// all clients using this exit, service at 100.64.0.7.
    fn tandem_redirect_decision() -> TandemDnsRedirectDecision {
        TandemDnsRedirectDecision::Redirect {
            mode: rustynet_control::tandem_dns::TandemMode::ManagedRedirect,
            scope: rustynet_control::tandem_dns::TandemScope::AllClientsUsingExit,
            service_address: std::net::Ipv4Addr::new(100, 64, 0, 7),
            egress_block: TandemDnsEgressBlockPolicy::always_on(),
        }
    }

    fn tandem_mesh_prefix() -> MeshIpv4Prefix {
        MeshIpv4Prefix::new(std::net::Ipv4Addr::new(100, 64, 0, 0), 10)
            .expect("mesh prefix should build")
    }

    /// Ordering pin (§10.7 / design §7.2): the redirect can never activate
    /// before the base DNS fail-closed posture is live. The refusal returns
    /// BEFORE any pf execution, so this test never invokes pfctl.
    #[test]
    fn macos_tandem_redirect_requires_base_dns_failclosed_posture_first() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = false;

        let err = system
            .activate_tandem_dns_redirect(&tandem_redirect_decision(), &tandem_mesh_prefix())
            .expect_err("activation without the base DNS posture must fail closed");
        let SystemError::FirewallApplyFailed(message) = err else {
            panic!("expected FirewallApplyFailed, got {err:?}");
        };
        assert!(
            message.contains("base DNS fail-closed posture is not active"),
            "unexpected refusal: {message}"
        );
        assert!(system.tandem_dns_anchor.is_none());
    }

    /// A blind exit never hosts the tandem DNS service; activation refuses
    /// before any pf execution.
    #[test]
    fn macos_tandem_redirect_refuses_blind_exit() {
        let mut system = MacosCommandSystem::new("rustynet0", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.blind_exit_pf_config =
            Some(MacosBlindExitPfConfig::new("rustynet0", "en0", "100.64.0.0/10").unwrap());
        system.dns_protected = true;

        let err = system
            .activate_tandem_dns_redirect(&tandem_redirect_decision(), &tandem_mesh_prefix())
            .expect_err("activation under blind exit must fail closed");
        let SystemError::FirewallApplyFailed(message) = err else {
            panic!("expected FirewallApplyFailed, got {err:?}");
        };
        assert!(
            message.contains("blind exit"),
            "unexpected refusal: {message}"
        );
        assert!(system.tandem_dns_anchor.is_none());
    }

    /// Contained / off tandem phases must never install a redirect rule: the
    /// decision bridge refuses and the base posture remains the only DNS
    /// behavior. The refusal returns BEFORE any pf execution.
    #[test]
    fn macos_tandem_redirect_refuses_contained_and_off_decisions() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system.dns_protected = true;

        let off = TandemDnsRedirectDecision::NoRedirect { reason: None };
        let err = system
            .activate_tandem_dns_redirect(&off, &tandem_mesh_prefix())
            .expect_err("an off decision must never install a redirect rule");
        let SystemError::FirewallApplyFailed(message) = err else {
            panic!("expected FirewallApplyFailed, got {err:?}");
        };
        assert!(message.contains("decision is NoRedirect"));

        let contained = TandemDnsRedirectDecision::ContainNoRedirect {
            reason: rustynet_control::tandem_dns::TandemReasonCode::Residue,
        };
        let err = system
            .activate_tandem_dns_redirect(&contained, &tandem_mesh_prefix())
            .expect_err("a contained decision must never install a redirect rule");
        let SystemError::FirewallApplyFailed(message) = err else {
            panic!("expected FirewallApplyFailed, got {err:?}");
        };
        assert!(message.contains("decision is ContainNoRedirect"));
        assert!(system.tandem_dns_anchor.is_none());
    }

    /// Teardown without an owned tandem anchor is an exact no-op (no pf
    /// execution, no state change).
    #[test]
    fn macos_tandem_teardown_without_anchor_is_a_noop() {
        let mut system = MacosCommandSystem::new("utun9", "en0", None, false, Vec::new())
            .expect("macos system should construct");
        system
            .teardown_tandem_dns_redirect()
            .expect("teardown with no anchor must be a no-op");
        assert!(system.tandem_dns_anchor.is_none());
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

    // ---- QH-47: conntrack invalidation on NAT generation change ----

    /// Drive one apply and return the operations it recorded.
    fn apply_and_capture(
        controller: &mut Phase10Controller<WireguardBackend, DryRunSystem>,
        options: ApplyOptions,
    ) -> Vec<String> {
        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                Vec::new(),
                Vec::new(),
                options,
            )
            .expect("apply should succeed");
        controller.system.operations[start..].to_vec()
    }

    fn conntrack_flushes(ops: &[String]) -> Vec<&String> {
        ops.iter()
            .filter(|op| op.starts_with("flush_nat_conntrack:"))
            .collect()
    }

    fn exit_controller() -> Phase10Controller<WireguardBackend, DryRunSystem> {
        Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default(),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        )
    }

    /// The defect QH-47 records: a masquerade installed while traffic is
    /// already flowing never applies to those flows, because their conntrack
    /// binding is fixed and every packet refreshes it. Installing NAT must
    /// therefore invalidate the mesh-sourced entries.
    #[test]
    fn installing_masquerade_flushes_mesh_sourced_conntrack() {
        let mut controller = exit_controller();
        let ops = apply_and_capture(
            &mut controller,
            ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                ..ApplyOptions::default()
            },
        );

        assert_eq!(
            conntrack_flushes(&ops),
            vec![&"flush_nat_conntrack:masquerade_installed:100.64.0.0/10".to_owned()],
            "installing a masquerade must flush exactly the mesh source; ops={ops:?}"
        );
    }

    /// The flush must land AFTER the nat table exists. Issued before, the next
    /// packet of a steady stream re-creates the entry against the OLD ruleset
    /// and the flush accomplishes nothing.
    #[test]
    fn the_flush_follows_the_nat_apply_rather_than_preceding_it() {
        let mut controller = exit_controller();
        let ops = apply_and_capture(
            &mut controller,
            ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                ..ApplyOptions::default()
            },
        );

        let nat_at = ops
            .iter()
            .position(|op| op == "apply_nat_forwarding")
            .expect("the NAT stage must run");
        let flush_at = ops
            .iter()
            .position(|op| op.starts_with("flush_nat_conntrack:"))
            .expect("the flush must run");
        assert!(
            nat_at < flush_at,
            "the conntrack flush must follow the NAT apply; ops={ops:?}"
        );
    }

    /// The reconcile loop re-applies constantly. An identical generation
    /// invalidates no binding, and flushing on it would repeatedly destroy
    /// healthy mesh flows for no reason.
    #[test]
    fn reapplying_an_identical_generation_does_not_flush_conntrack() {
        let mut controller = exit_controller();
        let options = ApplyOptions {
            exit_mode: ExitMode::FullTunnel,
            ..ApplyOptions::default()
        };
        let first = apply_and_capture(&mut controller, options);
        assert_eq!(conntrack_flushes(&first).len(), 1, "ops={first:?}");

        for round in 0..3 {
            let again = apply_and_capture(&mut controller, options);
            assert!(
                conntrack_flushes(&again).is_empty(),
                "identical re-apply {round} must not flush conntrack; ops={again:?}"
            );
        }
    }

    /// Withdrawing the masquerade is the §10.7 direction: flows holding a NAT
    /// binding would otherwise keep egressing through a host that has stopped
    /// serving the exit.
    #[test]
    fn withdrawing_masquerade_in_place_flushes_conntrack() {
        let mut controller = exit_controller();
        apply_and_capture(
            &mut controller,
            ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                ..ApplyOptions::default()
            },
        );

        let demotion = apply_and_capture(&mut controller, ApplyOptions::default());
        assert_eq!(
            conntrack_flushes(&demotion),
            vec![&"flush_nat_conntrack:masquerade_withdrawn:100.64.0.0/10".to_owned()],
            "an in-place demotion must invalidate the bindings it leaves behind; ops={demotion:?}"
        );
        let rollback_at = demotion
            .iter()
            .position(|op| op == "rollback_nat_forwarding")
            .expect("the demotion must roll the NAT back");
        let flush_at = demotion
            .iter()
            .position(|op| op.starts_with("flush_nat_conntrack:"))
            .expect("the demotion must flush");
        assert!(
            rollback_at < flush_at,
            "the flush must follow the NAT removal; ops={demotion:?}"
        );
    }

    /// A generation that never installs NAT has nothing to invalidate, so a
    /// plain client must never pay the cost of a flush.
    #[test]
    fn client_generations_never_flush_conntrack() {
        let mut controller = exit_controller();
        for round in 0..3 {
            let ops = apply_and_capture(&mut controller, ApplyOptions::default());
            assert!(
                conntrack_flushes(&ops).is_empty(),
                "client apply {round} must not flush conntrack; ops={ops:?}"
            );
        }
    }

    /// `blind_exit` forwards without translating, so promoting into it WITHDRAWS
    /// a masquerade rather than installing one — and demoting a blind_exit that
    /// never translated must not flush at all.
    #[test]
    fn blind_exit_transitions_flush_only_in_the_withdrawing_direction() {
        let mut controller = exit_controller();
        apply_and_capture(
            &mut controller,
            ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                ..ApplyOptions::default()
            },
        );

        let to_blind = apply_and_capture(
            &mut controller,
            ApplyOptions {
                serve_exit_node: true,
                blind_exit: true,
                ..ApplyOptions::default()
            },
        );
        assert_eq!(
            conntrack_flushes(&to_blind),
            vec![&"flush_nat_conntrack:masquerade_withdrawn:100.64.0.0/10".to_owned()],
            "promoting into blind_exit removes the masquerade; ops={to_blind:?}"
        );

        let blind_again = apply_and_capture(
            &mut controller,
            ApplyOptions {
                serve_exit_node: true,
                blind_exit: true,
                ..ApplyOptions::default()
            },
        );
        assert!(
            conntrack_flushes(&blind_again).is_empty(),
            "an identical blind_exit re-apply must not flush; ops={blind_again:?}"
        );
    }

    /// A changed mesh CIDR invalidates bindings exactly as a changed rule does,
    /// so the posture carries it and a mesh renumber counts as a transition.
    #[test]
    fn a_changed_mesh_cidr_counts_as_a_nat_transition() {
        let mut controller = exit_controller();
        let options = ApplyOptions {
            exit_mode: ExitMode::FullTunnel,
            ..ApplyOptions::default()
        };
        apply_and_capture(&mut controller, options);

        let start = controller.system.operations.len();
        controller
            .apply_dataplane_generation(
                trust_ok(),
                RuntimeContext {
                    mesh_cidr: "10.42.0.0/16".to_owned(),
                    ..test_runtime_context()
                },
                Vec::new(),
                Vec::new(),
                options,
            )
            .expect("renumbered apply should succeed");
        let ops = controller.system.operations[start..].to_vec();

        assert_eq!(
            conntrack_flushes(&ops),
            vec![&"flush_nat_conntrack:masquerade_installed:10.42.0.0/16".to_owned()],
            "a mesh renumber must flush against the NEW source network; ops={ops:?}"
        );
    }

    /// A fail-closed unwind must not leave the previous generation's
    /// translations alive. The flush runs after the NAT rollback, under the
    /// withdrawal reason.
    #[test]
    fn a_failed_apply_flushes_conntrack_while_unwinding_the_nat_stage() {
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_dns_protection"),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        );

        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                Vec::new(),
                Vec::new(),
                ApplyOptions {
                    exit_mode: ExitMode::FullTunnel,
                    ..ApplyOptions::default()
                },
            )
            .expect_err("the seeded DNS failure must fail the apply");

        let ops = &controller.system.operations;
        let rollback_at = ops
            .iter()
            .position(|op| op == "rollback_nat_forwarding")
            .expect("the unwind must roll the NAT back");
        let flush_at = ops
            .iter()
            .position(|op| op == "flush_nat_conntrack:masquerade_withdrawn:100.64.0.0/10")
            .expect("the unwind must flush the bindings the NAT left behind");
        assert!(
            rollback_at < flush_at,
            "the unwind flush must follow the NAT removal; ops={ops:?}"
        );
    }

    /// After an unwind the committed posture is gone, so the NEXT apply must be
    /// treated as a transition — erring toward one extra flush, never toward a
    /// missed one.
    #[test]
    fn the_apply_after_an_unwind_is_treated_as_a_transition() {
        let mut controller = Phase10Controller::new(
            WireguardBackend::default(),
            DryRunSystem::default().fail_on("apply_dns_protection"),
            allow_shared_exit_policy(),
            TrustPolicy::default(),
        );
        let options = ApplyOptions {
            exit_mode: ExitMode::FullTunnel,
            ..ApplyOptions::default()
        };
        controller
            .apply_dataplane_generation(
                trust_ok(),
                test_runtime_context(),
                Vec::new(),
                Vec::new(),
                options,
            )
            .expect_err("the seeded DNS failure must fail the apply");

        controller.system.fail_operation = None;
        let recovery = apply_and_capture(&mut controller, options);
        assert_eq!(
            conntrack_flushes(&recovery),
            vec![&"flush_nat_conntrack:masquerade_installed:100.64.0.0/10".to_owned()],
            "the recovery apply must re-flush; ops={recovery:?}"
        );
    }

    /// The posture is the whole no-op guard, so pin its decision table directly
    /// rather than only through the controller.
    #[test]
    fn nat_posture_distinguishes_translating_from_non_translating_generations() {
        let client = NatPosture::for_generation(ApplyOptions::default(), "100.64.0.0/10");
        assert_eq!(client, None, "a client generation runs no NAT stage");
        assert!(!NatPosture::translates(client.as_ref()));

        let blind = NatPosture::for_generation(
            ApplyOptions {
                serve_exit_node: true,
                blind_exit: true,
                ..ApplyOptions::default()
            },
            "100.64.0.0/10",
        )
        .expect("a blind exit runs the NAT stage");
        assert!(!blind.masquerade, "blind_exit installs no masquerade");
        assert!(!blind.hairpin);
        assert!(!NatPosture::translates(Some(&blind)));

        let relay = NatPosture::for_generation(
            ApplyOptions {
                exit_mode: ExitMode::FullTunnel,
                serve_exit_node: true,
                ..ApplyOptions::default()
            },
            "100.64.0.0/10",
        )
        .expect("a relay-with-upstream runs the NAT stage");
        assert!(relay.masquerade && relay.hairpin);
        assert!(NatPosture::translates(Some(&relay)));

        let terminal_exit = NatPosture::for_generation(
            ApplyOptions {
                serve_exit_node: true,
                ..ApplyOptions::default()
            },
            "100.64.0.0/10",
        )
        .expect("a terminal exit runs the NAT stage");
        assert!(terminal_exit.masquerade && !terminal_exit.hairpin);
        assert_ne!(
            terminal_exit, relay,
            "gaining the hairpin SNAT is a real transition, not a no-op re-apply"
        );
    }

    /// Mutation proof for the QH-47 wiring: the shapes a plausible edit would
    /// quietly remove.
    #[test]
    fn the_conntrack_flush_keeps_its_audited_shape() {
        let source = include_str!("phase10.rs");
        let code = &source[..source.find("\nmod tests {").unwrap_or(source.len())];

        // (a) The production dispatch must forward the Linux arm — a missing or
        // stubbed arm would silently no-op the flush on the real daemon while
        // every DryRun-driven test stayed green.
        assert!(
            code.contains(
                "RuntimeSystem::Linux(system) => system.flush_nat_conntrack(mesh_cidr, reason)"
            ),
            "the RuntimeSystem Linux arm must dispatch flush_nat_conntrack"
        );

        // (b) The no-op guard: without the posture comparison the flush would
        // fire on every reconcile re-apply and repeatedly kill healthy flows.
        assert!(
            code.contains("next_nat_posture != self.current_nat_posture"),
            "the flush must be gated on a real posture transition"
        );

        // (c) The daemon must not be able to name a conntrack operation: the
        // selector is built from the validated spec, never assembled here.
        let body_at = code
            .find("/// QH-47. The one privileged builtin that can invalidate conntrack")
            .expect("the Linux flush arm must exist");
        let body: String = code[body_at..].chars().take(1400).collect();
        assert!(
            body.contains("ConntrackFlushSpec::for_mesh_source"),
            "the Linux arm must build the argv from the validated spec"
        );
        for forbidden in ["\"-D\"", "\"-F\"", "\"--orig-src\"", "conntrack_argv"] {
            assert!(
                !body.contains(forbidden),
                "the daemon must not construct conntrack arguments ({forbidden}); \
                 the helper owns the argv"
            );
        }

        // (d) An absent tool must surface. A flush that silently did not happen
        // is the exact invisibility QH-47 exists to remove.
        let report_at = code
            .find("fn report_nat_conntrack_flush")
            .expect("the reporting wrapper must exist");
        let rest = &code[report_at..];
        let report_end = rest[1..]
            .find("\n    fn ")
            .map(|offset| offset + 1)
            .unwrap_or(rest.len());
        let report = &rest[..report_end];
        assert!(
            report.contains("ConntrackFlushOutcome::ToolAbsent) => {")
                && report.contains("log::warn!"),
            "an absent conntrack binary must be logged, never silently skipped"
        );
        assert!(
            !report.contains("return Err"),
            "a flush failure must never fail an otherwise-healthy generation"
        );
    }
}
