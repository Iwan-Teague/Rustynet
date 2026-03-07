#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::num::{NonZeroU32, NonZeroU64, NonZeroUsize};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ipc::{IpcCommand, IpcResponse, parse_command, validate_cidr};
#[cfg(target_os = "macos")]
use crate::key_material::read_passphrase_file;
use crate::key_material::{
    apply_interface_private_key, decrypt_private_key, encrypt_private_key,
    generate_wireguard_keypair, remove_file_if_present, set_interface_down, write_public_key,
    write_runtime_private_key,
};
#[cfg(target_os = "macos")]
use crate::phase10::MacosCommandSystem;
use crate::phase10::{
    ApplyOptions, DataplaneState, DataplaneSystem, ManagementCidr, Phase10Controller,
    RouteGrantRequest, RuntimeSystem, TrustEvidence, TrustPolicy,
};
#[cfg(target_os = "linux")]
use crate::phase10::{LinuxCommandSystem, LinuxDataplaneMode};
use crate::privileged_helper::{
    DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH as HELPER_DEFAULT_SOCKET_PATH,
    DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS as HELPER_DEFAULT_TIMEOUT_MS, PrivilegedCommandClient,
    PrivilegedCommandProgram,
};
use crate::resilience::{
    ResilienceError, SessionStateSnapshot, load_session_snapshot, persist_session_snapshot,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use nix::sys::socket::getsockopt;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
use nix::sys::socket::sockopt::LocalPeerCred;
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::sockopt::PeerCredentials;
use nix::unistd::Uid;
use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RouteKind,
    RuntimeContext, TunnelBackend, TunnelStats,
};
#[cfg(target_os = "linux")]
use rustynet_backend_wireguard::LinuxWireguardBackend;
#[cfg(target_os = "macos")]
use rustynet_backend_wireguard::MacosWireguardBackend;
use rustynet_backend_wireguard::WireguardBackend;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustynet_backend_wireguard::WireguardCommandRunner;
use rustynet_control::membership::{
    MembershipNodeStatus, MembershipState, load_membership_log, load_membership_snapshot,
    replay_membership_snapshot_and_log,
};
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet, Decision,
    MembershipDirectory, MembershipStatus, Protocol, RuleAction, TrafficContext,
};
use sha2::{Digest, Sha256};

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";
pub const DEFAULT_TRUST_EVIDENCE_PATH: &str = "/var/lib/rustynet/rustynetd.trust";
pub const DEFAULT_TRUST_VERIFIER_KEY_PATH: &str = "/etc/rustynet/trust-evidence.pub";
pub const DEFAULT_TRUST_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.trust.watermark";
pub const DEFAULT_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
pub const DEFAULT_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
pub const DEFAULT_MEMBERSHIP_WATERMARK_PATH: &str = "/var/lib/rustynet/membership.watermark";
pub const DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH: &str = "/etc/rustynet/membership.owner.key";
pub const DEFAULT_AUTO_TUNNEL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
pub const DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH: &str = "/etc/rustynet/assignment.pub";
pub const DEFAULT_AUTO_TUNNEL_WATERMARK_PATH: &str =
    "/var/lib/rustynet/rustynetd.assignment.watermark";
pub const DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS: u64 = 300;
pub const DEFAULT_TRAVERSAL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.traversal";
pub const DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH: &str = "/etc/rustynet/traversal.pub";
pub const DEFAULT_TRAVERSAL_WATERMARK_PATH: &str =
    "/var/lib/rustynet/rustynetd.traversal.watermark";
pub const DEFAULT_TRAVERSAL_MAX_AGE_SECS: u64 = 120;
pub const DEFAULT_WG_INTERFACE: &str = "rustynet0";
pub const DEFAULT_WG_LISTEN_PORT: u16 = 51820;
pub const DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH: &str = "/run/rustynet/wireguard.key";
pub const DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.key.enc";
pub const DEFAULT_WG_KEY_PASSPHRASE_PATH: &str = "/var/lib/rustynet/keys/wireguard.passphrase";
pub const DEFAULT_WG_PUBLIC_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";
pub const DEFAULT_EGRESS_INTERFACE: &str = "eth0";
pub const DEFAULT_RECONCILE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_RECONCILE_FAILURES: u32 = 5;
pub const DEFAULT_AUTO_PORT_FORWARD_EXIT: bool = false;
pub const DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS: u32 = 1_200;
pub const DEFAULT_NODE_ID: &str = "daemon-local";
pub const DEFAULT_FAIL_CLOSED_SSH_ALLOW: bool = false;
pub const DEFAULT_TRUSTED_HELPER_SOCKET_PATH: &str = HELPER_DEFAULT_SOCKET_PATH;
pub const DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS: u64 = HELPER_DEFAULT_TIMEOUT_MS;
const BLIND_EXIT_DEFAULT_ROUTE_CIDR: &str = "0.0.0.0/0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaemonDataplaneMode {
    #[default]
    Shell,
    HybridNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonBackendMode {
    InMemory,
    LinuxWireguard,
    MacosWireguard,
}

#[allow(clippy::derivable_impls)]
impl Default for DaemonBackendMode {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            return DaemonBackendMode::LinuxWireguard;
        }
        #[cfg(target_os = "macos")]
        {
            return DaemonBackendMode::MacosWireguard;
        }
        #[allow(unreachable_code)]
        DaemonBackendMode::LinuxWireguard
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeRole {
    #[default]
    Admin,
    Client,
    BlindExit,
}

impl NodeRole {
    fn as_str(self) -> &'static str {
        match self {
            NodeRole::Admin => "admin",
            NodeRole::Client => "client",
            NodeRole::BlindExit => "blind_exit",
        }
    }

    fn is_blind_exit(self) -> bool {
        matches!(self, NodeRole::BlindExit)
    }

    fn is_admin(self) -> bool {
        matches!(self, NodeRole::Admin)
    }

    fn allows_command(self, command: &IpcCommand) -> bool {
        match self {
            NodeRole::Admin => true,
            NodeRole::Client => matches!(
                command,
                IpcCommand::Status
                    | IpcCommand::Netcheck
                    | IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::DnsInspect
            ),
            NodeRole::BlindExit => matches!(
                command,
                IpcCommand::Status | IpcCommand::Netcheck | IpcCommand::DnsInspect
            ),
        }
    }
}

impl std::str::FromStr for NodeRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(NodeRole::Admin),
            "client" => Ok(NodeRole::Client),
            "blind_exit" | "blind-exit" => Ok(NodeRole::BlindExit),
            _ => Err("invalid node role: expected admin, client, or blind_exit".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub node_id: String,
    pub node_role: NodeRole,
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub trust_evidence_path: PathBuf,
    pub trust_verifier_key_path: PathBuf,
    pub trust_watermark_path: PathBuf,
    pub membership_snapshot_path: PathBuf,
    pub membership_log_path: PathBuf,
    pub membership_watermark_path: PathBuf,
    pub auto_tunnel_enforce: bool,
    pub auto_tunnel_bundle_path: Option<PathBuf>,
    pub auto_tunnel_verifier_key_path: Option<PathBuf>,
    pub auto_tunnel_watermark_path: Option<PathBuf>,
    pub auto_tunnel_max_age_secs: NonZeroU64,
    pub traversal_bundle_path: PathBuf,
    pub traversal_verifier_key_path: PathBuf,
    pub traversal_watermark_path: PathBuf,
    pub traversal_max_age_secs: NonZeroU64,
    pub backend_mode: DaemonBackendMode,
    pub wg_interface: String,
    pub wg_listen_port: u16,
    pub wg_private_key_path: Option<PathBuf>,
    pub wg_encrypted_private_key_path: Option<PathBuf>,
    pub wg_key_passphrase_path: Option<PathBuf>,
    pub wg_public_key_path: Option<PathBuf>,
    pub egress_interface: String,
    pub auto_port_forward_exit: bool,
    pub auto_port_forward_lease_secs: NonZeroU32,
    pub dataplane_mode: DaemonDataplaneMode,
    pub privileged_helper_socket_path: Option<PathBuf>,
    pub privileged_helper_timeout_ms: NonZeroU64,
    pub reconcile_interval_ms: NonZeroU64,
    pub max_reconcile_failures: NonZeroU32,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    pub max_requests: Option<NonZeroUsize>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            node_id: DEFAULT_NODE_ID.to_string(),
            node_role: NodeRole::default(),
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            trust_evidence_path: PathBuf::from(DEFAULT_TRUST_EVIDENCE_PATH),
            trust_verifier_key_path: PathBuf::from(DEFAULT_TRUST_VERIFIER_KEY_PATH),
            trust_watermark_path: PathBuf::from(DEFAULT_TRUST_WATERMARK_PATH),
            membership_snapshot_path: PathBuf::from(DEFAULT_MEMBERSHIP_SNAPSHOT_PATH),
            membership_log_path: PathBuf::from(DEFAULT_MEMBERSHIP_LOG_PATH),
            membership_watermark_path: PathBuf::from(DEFAULT_MEMBERSHIP_WATERMARK_PATH),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_BUNDLE_PATH)),
            auto_tunnel_verifier_key_path: Some(PathBuf::from(
                DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH,
            )),
            auto_tunnel_watermark_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_WATERMARK_PATH)),
            auto_tunnel_max_age_secs: NonZeroU64::new(DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)
                .expect("default auto tunnel max age must be non-zero"),
            traversal_bundle_path: PathBuf::from(DEFAULT_TRAVERSAL_BUNDLE_PATH),
            traversal_verifier_key_path: PathBuf::from(DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH),
            traversal_watermark_path: PathBuf::from(DEFAULT_TRAVERSAL_WATERMARK_PATH),
            traversal_max_age_secs: NonZeroU64::new(DEFAULT_TRAVERSAL_MAX_AGE_SECS)
                .expect("default traversal max age must be non-zero"),
            backend_mode: DaemonBackendMode::default(),
            wg_interface: DEFAULT_WG_INTERFACE.to_string(),
            wg_listen_port: DEFAULT_WG_LISTEN_PORT,
            wg_private_key_path: Some(PathBuf::from(DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH)),
            wg_encrypted_private_key_path: Some(PathBuf::from(
                DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            )),
            wg_key_passphrase_path: Some(PathBuf::from(DEFAULT_WG_KEY_PASSPHRASE_PATH)),
            wg_public_key_path: Some(PathBuf::from(DEFAULT_WG_PUBLIC_KEY_PATH)),
            egress_interface: DEFAULT_EGRESS_INTERFACE.to_string(),
            auto_port_forward_exit: DEFAULT_AUTO_PORT_FORWARD_EXIT,
            auto_port_forward_lease_secs: NonZeroU32::new(DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS)
                .expect("default auto port-forward lease must be non-zero"),
            dataplane_mode: DaemonDataplaneMode::default(),
            privileged_helper_socket_path: Some(PathBuf::from(DEFAULT_TRUSTED_HELPER_SOCKET_PATH)),
            privileged_helper_timeout_ms: NonZeroU64::new(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS)
                .expect("default privileged helper timeout must be non-zero"),
            reconcile_interval_ms: NonZeroU64::new(DEFAULT_RECONCILE_INTERVAL_MS)
                .expect("default reconcile interval must be non-zero"),
            max_reconcile_failures: NonZeroU32::new(DEFAULT_MAX_RECONCILE_FAILURES)
                .expect("default max reconcile failures must be non-zero"),
            fail_closed_ssh_allow: DEFAULT_FAIL_CLOSED_SSH_ALLOW,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            max_requests: None,
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Io(String),
    InvalidConfig(String),
    State(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Io(message) => write!(f, "i/o error: {message}"),
            DaemonError::InvalidConfig(message) => write!(f, "invalid config: {message}"),
            DaemonError::State(message) => write!(f, "state error: {message}"),
        }
    }
}

impl std::error::Error for DaemonError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustBootstrapError {
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
}

impl fmt::Display for TrustBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustBootstrapError::Missing => f.write_str("trust evidence is missing"),
            TrustBootstrapError::Io(message) => write!(f, "trust evidence io failure: {message}"),
            TrustBootstrapError::InvalidFormat(message) => {
                write!(f, "trust evidence invalid format: {message}")
            }
            TrustBootstrapError::KeyInvalid => {
                f.write_str("trust evidence verifier key is invalid")
            }
            TrustBootstrapError::SignatureInvalid => {
                f.write_str("trust evidence signature verification failed")
            }
            TrustBootstrapError::ReplayDetected => f.write_str("trust evidence replay detected"),
            TrustBootstrapError::FutureDated => {
                f.write_str("trust evidence timestamp exceeds allowable clock skew")
            }
            TrustBootstrapError::Stale => f.write_str("trust evidence is stale"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustWatermark {
    updated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustEvidenceEnvelope {
    evidence: TrustEvidence,
    watermark: TrustWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AutoTunnelBootstrapError {
    Disabled,
    MissingConfig(&'static str),
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
    WrongNode,
    PolicyDenied(String),
}

impl fmt::Display for AutoTunnelBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutoTunnelBootstrapError::Disabled => f.write_str("auto-tunnel is disabled"),
            AutoTunnelBootstrapError::MissingConfig(field) => {
                write!(f, "auto-tunnel missing config: {field}")
            }
            AutoTunnelBootstrapError::Missing => f.write_str("auto-tunnel bundle is missing"),
            AutoTunnelBootstrapError::Io(message) => {
                write!(f, "auto-tunnel bundle io failure: {message}")
            }
            AutoTunnelBootstrapError::InvalidFormat(message) => {
                write!(f, "auto-tunnel bundle invalid format: {message}")
            }
            AutoTunnelBootstrapError::KeyInvalid => {
                f.write_str("auto-tunnel verifier key is invalid")
            }
            AutoTunnelBootstrapError::SignatureInvalid => {
                f.write_str("auto-tunnel signature verification failed")
            }
            AutoTunnelBootstrapError::ReplayDetected => {
                f.write_str("auto-tunnel bundle replay detected")
            }
            AutoTunnelBootstrapError::FutureDated => {
                f.write_str("auto-tunnel bundle is future dated")
            }
            AutoTunnelBootstrapError::Stale => f.write_str("auto-tunnel bundle is stale"),
            AutoTunnelBootstrapError::WrongNode => {
                f.write_str("auto-tunnel bundle node id does not match local node")
            }
            AutoTunnelBootstrapError::PolicyDenied(reason) => {
                write!(f, "auto-tunnel bundle denied by local policy: {reason}")
            }
        }
    }
}

impl std::error::Error for AutoTunnelBootstrapError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AutoTunnelWatermark {
    generated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct AutoTunnelBundleEnvelope {
    bundle: AutoTunnelBundle,
    watermark: AutoTunnelWatermark,
}

#[derive(Debug, Clone)]
struct AutoTunnelBundle {
    node_id: String,
    mesh_cidr: String,
    assigned_cidr: String,
    peers: Vec<PeerConfig>,
    routes: Vec<Route>,
    selected_exit_node: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalCandidateType {
    Host,
    ServerReflexive,
    Relay,
}

impl TraversalCandidateType {
    fn as_str(self) -> &'static str {
        match self {
            TraversalCandidateType::Host => "host",
            TraversalCandidateType::ServerReflexive => "srflx",
            TraversalCandidateType::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalCandidate {
    candidate_type: TraversalCandidateType,
    endpoint: std::net::SocketAddr,
    relay_id: Option<String>,
    priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalBundle {
    source_node_id: String,
    target_node_id: String,
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
    candidates: Vec<TraversalCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraversalWatermark {
    generated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalBundleEnvelope {
    bundle: TraversalBundle,
    watermark: TraversalWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraversalBootstrapError {
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
}

impl fmt::Display for TraversalBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraversalBootstrapError::Missing => f.write_str("traversal bundle is missing"),
            TraversalBootstrapError::Io(message) => {
                write!(f, "traversal bundle io failure: {message}")
            }
            TraversalBootstrapError::InvalidFormat(message) => {
                write!(f, "traversal bundle invalid format: {message}")
            }
            TraversalBootstrapError::KeyInvalid => f.write_str("traversal verifier key is invalid"),
            TraversalBootstrapError::SignatureInvalid => {
                f.write_str("traversal signature verification failed")
            }
            TraversalBootstrapError::ReplayDetected => {
                f.write_str("traversal bundle replay detected")
            }
            TraversalBootstrapError::FutureDated => f.write_str("traversal bundle is future dated"),
            TraversalBootstrapError::Stale => f.write_str("traversal bundle is stale"),
        }
    }
}

impl std::error::Error for TraversalBootstrapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MembershipBootstrapError {
    MissingSnapshot,
    MissingLog,
    SnapshotLoad(String),
    LogLoad(String),
    Replay(String),
    InvalidRoot,
    WatermarkReplay,
    LocalNodeNotActive,
    ExitNodeNotActive(String),
    Io(String),
}

impl fmt::Display for MembershipBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembershipBootstrapError::MissingSnapshot => {
                f.write_str("membership snapshot is missing")
            }
            MembershipBootstrapError::MissingLog => f.write_str("membership log is missing"),
            MembershipBootstrapError::SnapshotLoad(msg) => {
                write!(f, "membership snapshot load failed: {msg}")
            }
            MembershipBootstrapError::LogLoad(msg) => {
                write!(f, "membership log load failed: {msg}")
            }
            MembershipBootstrapError::Replay(msg) => {
                write!(f, "membership replay failed: {msg}")
            }
            MembershipBootstrapError::InvalidRoot => {
                f.write_str("membership root verification failed")
            }
            MembershipBootstrapError::WatermarkReplay => {
                f.write_str("membership replay/rollback detected by watermark")
            }
            MembershipBootstrapError::LocalNodeNotActive => {
                f.write_str("local node is not active in membership state")
            }
            MembershipBootstrapError::ExitNodeNotActive(node_id) => {
                write!(f, "selected exit node is not active: {node_id}")
            }
            MembershipBootstrapError::Io(msg) => write!(f, "membership io failure: {msg}"),
        }
    }
}

impl std::error::Error for MembershipBootstrapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MembershipWatermark {
    epoch: u64,
    state_root: String,
}

enum DaemonBackend {
    #[allow(dead_code)]
    InMemory(WireguardBackend),
    #[cfg(target_os = "linux")]
    Linux(LinuxWireguardBackend<PrivilegedHelperWireguardRunner>),
    #[cfg(target_os = "macos")]
    Macos(MacosWireguardBackend<PrivilegedHelperWireguardRunner>),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct PrivilegedHelperWireguardRunner {
    helper_client: PrivilegedCommandClient,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PrivilegedHelperWireguardRunner {
    fn new(helper_client: PrivilegedCommandClient) -> Self {
        Self { helper_client }
    }

    fn helper_program_for(program: &str) -> Result<PrivilegedCommandProgram, BackendError> {
        match program {
            "ip" => Ok(PrivilegedCommandProgram::Ip),
            "wg" => Ok(PrivilegedCommandProgram::Wg),
            "ifconfig" => Ok(PrivilegedCommandProgram::Ifconfig),
            "route" => Ok(PrivilegedCommandProgram::Route),
            "wireguard-go" => Ok(PrivilegedCommandProgram::WireguardGo),
            "kill" => Ok(PrivilegedCommandProgram::Kill),
            _ => Err(BackendError::invalid_input(
                "unsupported privileged wireguard backend command",
            )),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl WireguardCommandRunner for PrivilegedHelperWireguardRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
        let helper_program = Self::helper_program_for(program)?;
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self
            .helper_client
            .run_capture(helper_program, &arg_refs)
            .map_err(|err| {
                BackendError::internal(format!(
                    "privileged helper {program} invocation failed: {err}"
                ))
            })?;

        if output.success() {
            return Ok(());
        }

        let stderr = output.stderr.trim();
        if stderr.is_empty() {
            return Err(BackendError::internal(format!(
                "privileged helper {program} exited with status {}",
                output.status
            )));
        }

        Err(BackendError::internal(format!(
            "privileged helper {program} exited with status {}: {stderr}",
            output.status
        )))
    }
}

impl DaemonBackend {
    fn from_config(config: &DaemonConfig) -> Result<Self, DaemonError> {
        match config.backend_mode {
            DaemonBackendMode::InMemory => {
                #[cfg(test)]
                {
                    Ok(Self::InMemory(WireguardBackend::default()))
                }
                #[cfg(not(test))]
                {
                    Err(DaemonError::InvalidConfig(
                        "in-memory backend is disabled in production daemon paths".to_string(),
                    ))
                }
            }
            DaemonBackendMode::LinuxWireguard => {
                #[cfg(target_os = "linux")]
                {
                    let helper_socket = config
                        .privileged_helper_socket_path
                        .as_ref()
                        .ok_or_else(|| {
                            DaemonError::InvalidConfig(
                                "privileged helper socket path is required for linux-wireguard backend"
                                    .to_string(),
                            )
                        })?;
                    let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                        DaemonError::InvalidConfig(
                            "wg private key path is required for linux-wireguard backend"
                                .to_string(),
                        )
                    })?;
                    validate_private_key_permissions(private_key)?;
                    let helper_client = PrivilegedCommandClient::new(
                        helper_socket.clone(),
                        Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                    )
                    .map_err(DaemonError::InvalidConfig)?;
                    let backend = LinuxWireguardBackend::new(
                        PrivilegedHelperWireguardRunner::new(helper_client),
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.wg_listen_port,
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::Linux(backend))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Err(DaemonError::InvalidConfig(
                        "linux-wireguard backend is only supported on linux".to_string(),
                    ))
                }
            }
            DaemonBackendMode::MacosWireguard => {
                #[cfg(target_os = "macos")]
                {
                    let helper_socket = config
                        .privileged_helper_socket_path
                        .as_ref()
                        .ok_or_else(|| {
                            DaemonError::InvalidConfig(
                                "privileged helper socket path is required for macos-wireguard backend"
                                    .to_string(),
                            )
                        })?;
                    let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                        DaemonError::InvalidConfig(
                            "wg private key path is required for macos-wireguard backend"
                                .to_string(),
                        )
                    })?;
                    validate_private_key_permissions(private_key)?;
                    let helper_client = PrivilegedCommandClient::new(
                        helper_socket.clone(),
                        Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                    )
                    .map_err(DaemonError::InvalidConfig)?;
                    let backend = MacosWireguardBackend::new(
                        PrivilegedHelperWireguardRunner::new(helper_client),
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.egress_interface.clone(),
                        config.wg_listen_port,
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::Macos(backend))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Err(DaemonError::InvalidConfig(
                        "macos-wireguard backend is only supported on macos".to_string(),
                    ))
                }
            }
        }
    }
}

impl TunnelBackend for DaemonBackend {
    fn name(&self) -> &'static str {
        match self {
            DaemonBackend::InMemory(backend) => backend.name(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.name(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.name(),
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        match self {
            DaemonBackend::InMemory(backend) => backend.capabilities(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.capabilities(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.capabilities(),
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.start(context),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.start(context),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.start(context),
        }
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.configure_peer(peer),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.configure_peer(peer),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.configure_peer(peer),
        }
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.remove_peer(node_id),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.remove_peer(node_id),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.remove_peer(node_id),
        }
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.apply_routes(routes),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.apply_routes(routes),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.apply_routes(routes),
        }
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.set_exit_mode(mode),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.set_exit_mode(mode),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.set_exit_mode(mode),
        }
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.stats(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.stats(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.stats(),
        }
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.shutdown(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.shutdown(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.shutdown(),
        }
    }
}

struct DaemonRuntime {
    controller: Phase10Controller<DaemonBackend, RuntimeSystem>,
    policy: ContextualPolicySet,
    backend_mode: DaemonBackendMode,
    node_role: NodeRole,
    local_node_id: String,
    wg_interface: String,
    #[cfg(target_os = "linux")]
    wg_listen_port: u16,
    wg_private_key_path: Option<PathBuf>,
    wg_encrypted_private_key_path: Option<PathBuf>,
    wg_key_passphrase_path: Option<PathBuf>,
    wg_public_key_path: Option<PathBuf>,
    privileged_helper_client: Option<PrivilegedCommandClient>,
    #[cfg(target_os = "linux")]
    egress_interface: String,
    state_path: PathBuf,
    trust_evidence_path: PathBuf,
    trust_verifier_key_path: PathBuf,
    trust_watermark_path: PathBuf,
    membership_snapshot_path: PathBuf,
    membership_log_path: PathBuf,
    membership_watermark_path: PathBuf,
    auto_tunnel_enforce: bool,
    auto_tunnel_bundle_path: Option<PathBuf>,
    auto_tunnel_verifier_key_path: Option<PathBuf>,
    auto_tunnel_watermark_path: Option<PathBuf>,
    auto_tunnel_max_age_secs: u64,
    traversal_bundle_path: PathBuf,
    traversal_verifier_key_path: PathBuf,
    traversal_watermark_path: PathBuf,
    traversal_max_age_secs: u64,
    trust_policy: TrustPolicy,
    selected_exit_node: Option<String>,
    lan_access_enabled: bool,
    advertised_routes: BTreeSet<String>,
    restriction_mode: RestrictionMode,
    bootstrap_error: Option<String>,
    reconcile_attempts: u64,
    reconcile_failures: u64,
    last_reconcile_unix: Option<u64>,
    last_reconcile_error: Option<String>,
    last_applied_assignment: Option<AutoTunnelWatermark>,
    local_route_reconcile_pending: bool,
    max_reconcile_failures: u32,
    membership_state: Option<MembershipState>,
    membership_directory: MembershipDirectory,
    traversal_hint: Option<TraversalBundleEnvelope>,
    traversal_hint_error: Option<String>,
    auto_port_forward_exit: bool,
    #[cfg(target_os = "linux")]
    auto_port_forward_lease_secs: u32,
    exit_port_forward_last_error: Option<String>,
    #[cfg(target_os = "linux")]
    exit_port_forward_lease: Option<ExitPortForwardLease>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExitPortForwardLease {
    gateway: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lease_secs: u32,
    renewed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestrictionMode {
    None,
    Recoverable,
    Permanent,
}

impl DaemonRuntime {
    fn new(config: &DaemonConfig) -> Result<Self, DaemonError> {
        NodeId::new(config.node_id.clone())
            .map_err(|err| DaemonError::InvalidConfig(format!("invalid node id: {err}")))?;
        let policy = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh, TrafficContext::SharedExit],
            }],
        };
        let trust_policy = TrustPolicy::default();
        let backend = DaemonBackend::from_config(config)?;
        let controller = Phase10Controller::new(
            backend,
            daemon_system(config)?,
            policy.clone(),
            trust_policy,
        );
        let privileged_helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        Ok(Self {
            controller,
            policy,
            backend_mode: config.backend_mode,
            node_role: config.node_role,
            local_node_id: config.node_id.clone(),
            wg_interface: config.wg_interface.clone(),
            #[cfg(target_os = "linux")]
            wg_listen_port: config.wg_listen_port,
            wg_private_key_path: config.wg_private_key_path.clone(),
            wg_encrypted_private_key_path: config.wg_encrypted_private_key_path.clone(),
            wg_key_passphrase_path: config.wg_key_passphrase_path.clone(),
            wg_public_key_path: config.wg_public_key_path.clone(),
            privileged_helper_client,
            #[cfg(target_os = "linux")]
            egress_interface: config.egress_interface.clone(),
            state_path: config.state_path.clone(),
            trust_evidence_path: config.trust_evidence_path.clone(),
            trust_verifier_key_path: config.trust_verifier_key_path.clone(),
            trust_watermark_path: config.trust_watermark_path.clone(),
            membership_snapshot_path: config.membership_snapshot_path.clone(),
            membership_log_path: config.membership_log_path.clone(),
            membership_watermark_path: config.membership_watermark_path.clone(),
            auto_tunnel_enforce: config.auto_tunnel_enforce,
            auto_tunnel_bundle_path: config.auto_tunnel_bundle_path.clone(),
            auto_tunnel_verifier_key_path: config.auto_tunnel_verifier_key_path.clone(),
            auto_tunnel_watermark_path: config.auto_tunnel_watermark_path.clone(),
            auto_tunnel_max_age_secs: config.auto_tunnel_max_age_secs.get(),
            traversal_bundle_path: config.traversal_bundle_path.clone(),
            traversal_verifier_key_path: config.traversal_verifier_key_path.clone(),
            traversal_watermark_path: config.traversal_watermark_path.clone(),
            traversal_max_age_secs: config.traversal_max_age_secs.get(),
            trust_policy,
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_routes: BTreeSet::new(),
            restriction_mode: RestrictionMode::None,
            bootstrap_error: None,
            reconcile_attempts: 0,
            reconcile_failures: 0,
            last_reconcile_unix: None,
            last_reconcile_error: None,
            last_applied_assignment: None,
            local_route_reconcile_pending: false,
            max_reconcile_failures: config.max_reconcile_failures.get(),
            membership_state: None,
            membership_directory: MembershipDirectory::default(),
            traversal_hint: None,
            traversal_hint_error: None,
            auto_port_forward_exit: config.auto_port_forward_exit,
            #[cfg(target_os = "linux")]
            auto_port_forward_lease_secs: config.auto_port_forward_lease_secs.get(),
            exit_port_forward_last_error: None,
            #[cfg(target_os = "linux")]
            exit_port_forward_lease: None,
        })
    }

    fn load_verified_trust(&self) -> Result<TrustEvidence, TrustBootstrapError> {
        let previous_watermark = load_trust_watermark(&self.trust_watermark_path)?;
        let envelope = load_trust_evidence(
            &self.trust_evidence_path,
            &self.trust_verifier_key_path,
            self.trust_policy,
            previous_watermark,
        )?;
        persist_trust_watermark(&self.trust_watermark_path, envelope.watermark)?;
        Ok(envelope.evidence)
    }

    fn load_verified_membership(&self) -> Result<MembershipState, MembershipBootstrapError> {
        if !self.membership_snapshot_path.exists() {
            return Err(MembershipBootstrapError::MissingSnapshot);
        }
        if !self.membership_log_path.exists() {
            return Err(MembershipBootstrapError::MissingLog);
        }

        let snapshot = load_membership_snapshot(&self.membership_snapshot_path)
            .map_err(|err| MembershipBootstrapError::SnapshotLoad(err.to_string()))?;
        let entries = load_membership_log(&self.membership_log_path)
            .map_err(|err| MembershipBootstrapError::LogLoad(err.to_string()))?;
        let replayed = replay_membership_snapshot_and_log(&snapshot, &entries, unix_now())
            .map_err(|err| MembershipBootstrapError::Replay(err.to_string()))?;
        let state_root = replayed
            .state_root_hex()
            .map_err(|_| MembershipBootstrapError::InvalidRoot)?;
        let watermark = MembershipWatermark {
            epoch: replayed.epoch,
            state_root: state_root.clone(),
        };
        let previous = load_membership_watermark(&self.membership_watermark_path)
            .map_err(|err| MembershipBootstrapError::Io(err.to_string()))?;
        if let Some(previous) = previous {
            if watermark.epoch < previous.epoch
                || (watermark.epoch == previous.epoch
                    && watermark.state_root != previous.state_root)
            {
                return Err(MembershipBootstrapError::WatermarkReplay);
            }
        }
        persist_membership_watermark(&self.membership_watermark_path, &watermark)
            .map_err(|err| MembershipBootstrapError::Io(err.to_string()))?;

        let local_active = replayed.nodes.iter().any(|node| {
            node.node_id == self.local_node_id && node.status == MembershipNodeStatus::Active
        });
        if !local_active {
            return Err(MembershipBootstrapError::LocalNodeNotActive);
        }
        if let Some(exit_node) = self.selected_exit_node.as_deref() {
            let exit_active = replayed.nodes.iter().any(|node| {
                node.node_id == exit_node && node.status == MembershipNodeStatus::Active
            });
            if !exit_active {
                return Err(MembershipBootstrapError::ExitNodeNotActive(
                    exit_node.to_string(),
                ));
            }
        }

        Ok(replayed)
    }

    fn auto_tunnel_paths(&self) -> Result<(&Path, &Path, &Path), AutoTunnelBootstrapError> {
        if !self.auto_tunnel_enforce {
            return Err(AutoTunnelBootstrapError::Disabled);
        }
        let bundle_path = self.auto_tunnel_bundle_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_bundle_path"),
        )?;
        let verifier_path = self.auto_tunnel_verifier_key_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_verifier_key_path"),
        )?;
        let watermark_path = self.auto_tunnel_watermark_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_watermark_path"),
        )?;
        Ok((bundle_path, verifier_path, watermark_path))
    }

    fn load_verified_auto_tunnel(
        &self,
        membership_directory: &MembershipDirectory,
    ) -> Result<AutoTunnelBundleEnvelope, AutoTunnelBootstrapError> {
        let (bundle_path, verifier_path, watermark_path) = self.auto_tunnel_paths()?;
        let previous_watermark = load_auto_tunnel_watermark(watermark_path)?;
        let envelope = load_auto_tunnel_bundle(
            bundle_path,
            verifier_path,
            self.auto_tunnel_max_age_secs,
            self.trust_policy,
            previous_watermark,
        )?;
        if envelope.bundle.node_id != self.local_node_id {
            return Err(AutoTunnelBootstrapError::WrongNode);
        }
        self.policy_gate_auto_tunnel(&envelope.bundle, membership_directory)?;
        persist_auto_tunnel_watermark(watermark_path, envelope.watermark)?;
        Ok(envelope)
    }

    fn policy_gate_auto_tunnel(
        &self,
        bundle: &AutoTunnelBundle,
        membership_directory: &MembershipDirectory,
    ) -> Result<(), AutoTunnelBootstrapError> {
        let subject = "user:local";

        for peer in &bundle.peers {
            let decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: format!("node:{}", peer.node_id.as_str()),
                    protocol: Protocol::Any,
                    context: TrafficContext::Mesh,
                },
                membership_directory,
            );
            if decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "peer {} denied",
                    peer.node_id
                )));
            }
        }

        for route in &bundle.routes {
            let context = match route.kind {
                RouteKind::Mesh => TrafficContext::Mesh,
                RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan => TrafficContext::SharedExit,
            };
            let cidr_decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: route.destination_cidr.clone(),
                    protocol: Protocol::Any,
                    context,
                },
                membership_directory,
            );
            if cidr_decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "route {} denied",
                    route.destination_cidr
                )));
            }
            let via_decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: format!("node:{}", route.via_node.as_str()),
                    protocol: Protocol::Any,
                    context,
                },
                membership_directory,
            );
            if via_decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "route via node {} denied",
                    route.via_node
                )));
            }
        }

        Ok(())
    }

    fn refresh_traversal_hint_state(&mut self) {
        let previous_watermark = match load_traversal_watermark(&self.traversal_watermark_path) {
            Ok(value) => value,
            Err(err) => {
                self.traversal_hint = None;
                self.traversal_hint_error = Some(err.to_string());
                return;
            }
        };
        match load_traversal_bundle(
            &self.traversal_bundle_path,
            &self.traversal_verifier_key_path,
            self.traversal_max_age_secs,
            self.trust_policy,
            previous_watermark,
        ) {
            Ok(envelope) => {
                if let Err(err) =
                    persist_traversal_watermark(&self.traversal_watermark_path, envelope.watermark)
                {
                    self.traversal_hint = None;
                    self.traversal_hint_error = Some(err.to_string());
                    return;
                }
                self.traversal_hint = Some(envelope);
                self.traversal_hint_error = None;
            }
            Err(TraversalBootstrapError::Missing) => {
                self.traversal_hint = None;
                self.traversal_hint_error = None;
            }
            Err(err) => {
                self.traversal_hint = None;
                self.traversal_hint_error = Some(err.to_string());
            }
        }
    }

    fn netcheck_response_line(&self) -> String {
        let (path_mode, path_reason) = match self.controller.state() {
            DataplaneState::FailClosed => ("fail_closed", "fail_closed"),
            DataplaneState::ExitActive => ("direct_preferred_relay_fallback", "exit_active"),
            DataplaneState::DataplaneApplied => {
                ("direct_preferred_relay_fallback", "dataplane_applied")
            }
            DataplaneState::ControlTrusted => {
                ("direct_preferred_relay_fallback", "control_trusted")
            }
            DataplaneState::Init => ("initializing", "init"),
        };

        let now = unix_now();
        let (traversal_status, source, target, generated_at, expires_at, age_secs, remaining_secs) =
            if let Some(envelope) = self.traversal_hint.as_ref() {
                let age = now.saturating_sub(envelope.bundle.generated_at_unix);
                let remaining = envelope.bundle.expires_at_unix.saturating_sub(now);
                (
                    "valid",
                    envelope.bundle.source_node_id.as_str(),
                    envelope.bundle.target_node_id.as_str(),
                    envelope.bundle.generated_at_unix.to_string(),
                    envelope.bundle.expires_at_unix.to_string(),
                    age.to_string(),
                    remaining.to_string(),
                )
            } else if self.traversal_hint_error.is_some() {
                (
                    "invalid",
                    "none",
                    "none",
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                )
            } else {
                (
                    "missing",
                    "none",
                    "none",
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                )
            };

        let mut host_candidates = 0usize;
        let mut srflx_candidates = 0usize;
        let mut relay_candidates = 0usize;
        let mut candidate_count = 0usize;
        let mut max_candidate_priority: Option<u32> = None;
        if let Some(envelope) = self.traversal_hint.as_ref() {
            candidate_count = envelope.bundle.candidates.len();
            for candidate in &envelope.bundle.candidates {
                max_candidate_priority =
                    Some(max_candidate_priority.unwrap_or(0).max(candidate.priority));
                match candidate.candidate_type {
                    TraversalCandidateType::Host => {
                        host_candidates = host_candidates.saturating_add(1)
                    }
                    TraversalCandidateType::ServerReflexive => {
                        srflx_candidates = srflx_candidates.saturating_add(1)
                    }
                    TraversalCandidateType::Relay => {
                        relay_candidates = relay_candidates.saturating_add(1)
                    }
                }
            }
        }

        let traversal_error = self
            .traversal_hint_error
            .as_deref()
            .map(sanitize_netcheck_value)
            .unwrap_or_else(|| "none".to_string());
        let max_candidate_priority = max_candidate_priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        format!(
            "netcheck: path_mode={path_mode} path_reason={path_reason} traversal_status={traversal_status} traversal_source={source} traversal_target={target} traversal_generated_at_unix={generated_at} traversal_expires_at_unix={expires_at} traversal_age_secs={age_secs} traversal_remaining_secs={remaining_secs} candidate_count={candidate_count} host_candidates={host_candidates} srflx_candidates={srflx_candidates} relay_candidates={relay_candidates} max_candidate_priority={max_candidate_priority} traversal_error={traversal_error}",
        )
    }

    fn bootstrap(&mut self) {
        match self.restore_state() {
            Ok(()) => {}
            Err(_err) => {
                self.restrict_permanent("state restore failed integrity checks".to_string());
                let _ = self
                    .controller
                    .force_fail_closed("state_restore_integrity_failed");
                return;
            }
        }
        if let Err(err) = self.enforce_blind_exit_invariants() {
            self.restrict_permanent(format!(
                "blind-exit role invariants failed during bootstrap: {err}"
            ));
            let _ = self
                .controller
                .force_fail_closed("blind_exit_invariants_failed");
            return;
        }

        let trust = match self.load_verified_trust() {
            Ok(evidence) => evidence,
            Err(err) => {
                self.restrict_recoverable(err.to_string());
                let _ = self.controller.force_fail_closed("trust_bootstrap_failed");
                return;
            }
        };

        let membership_state = match self.load_verified_membership() {
            Ok(state) => state,
            Err(err) => {
                self.restrict_recoverable(err.to_string());
                let _ = self
                    .controller
                    .force_fail_closed("membership_bootstrap_failed");
                return;
            }
        };
        let membership_directory = membership_directory_from_state(&membership_state);

        let auto_bundle = if self.auto_tunnel_enforce {
            match self.load_verified_auto_tunnel(&membership_directory) {
                Ok(bundle) => Some(bundle),
                Err(err) => {
                    self.restrict_recoverable(err.to_string());
                    let _ = self
                        .controller
                        .force_fail_closed("auto_tunnel_bootstrap_failed");
                    return;
                }
            }
        } else {
            None
        };

        let (mesh_cidr, local_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
            if let Some(envelope) = auto_bundle {
                let lan_enabled = envelope
                    .bundle
                    .routes
                    .iter()
                    .any(|route| route.kind == RouteKind::ExitNodeLan);
                (
                    envelope.bundle.mesh_cidr,
                    envelope.bundle.assigned_cidr,
                    envelope.bundle.peers,
                    envelope.bundle.routes,
                    envelope.bundle.selected_exit_node,
                    lan_enabled,
                    Some(envelope.watermark),
                )
            } else {
                (
                    "100.64.0.0/10".to_string(),
                    "100.64.0.1/32".to_string(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    false,
                    None,
                )
            };
        if let Err(err) = self.validate_blind_exit_assignment(auto_exit.as_deref(), auto_lan_access)
        {
            self.restrict_recoverable(err);
            let _ = self
                .controller
                .force_fail_closed("blind_exit_assignment_rejected");
            return;
        }

        self.refresh_traversal_hint_state();

        let local_node = match NodeId::new(self.local_node_id.clone()) {
            Ok(node_id) => node_id,
            Err(err) => {
                self.restrict_permanent(format!("invalid local node id in runtime: {err}"));
                let _ = self.controller.force_fail_closed("invalid_local_node_id");
                return;
            }
        };

        if let Err(err) = self.ensure_runtime_private_key_material() {
            self.restrict_recoverable(format!("runtime key preparation failed: {err}"));
            let _ = self
                .controller
                .force_fail_closed("runtime_key_prepare_failed");
            return;
        }

        let serve_exit_node = if self.node_role.is_blind_exit() {
            true
        } else if self.auto_tunnel_enforce {
            self.is_serving_exit_node(auto_exit.as_deref())
        } else {
            self.is_serving_exit_node(self.selected_exit_node.as_deref())
        };

        let apply_result = self.controller.apply_dataplane_generation(
            trust,
            RuntimeContext {
                local_node,
                mesh_cidr,
                local_cidr,
            },
            peers,
            routes,
            ApplyOptions {
                protected_dns: true,
                ipv6_parity_supported: false,
                serve_exit_node,
                exit_mode: if self.node_role.is_blind_exit() {
                    ExitMode::Off
                } else if self.auto_tunnel_enforce {
                    if auto_exit.is_some() {
                        ExitMode::FullTunnel
                    } else {
                        ExitMode::Off
                    }
                } else {
                    self.desired_exit_mode()
                },
            },
        );
        let cleanup_result = self.scrub_runtime_private_key_material();
        match (apply_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(err), Ok(())) => {
                self.restrict_recoverable(format!("dataplane bootstrap apply failed: {err}"));
                let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
                return;
            }
            (Err(err), Err(cleanup_err)) => {
                self.restrict_recoverable(format!(
                    "dataplane bootstrap apply failed: {err}; runtime key cleanup failed: {cleanup_err}"
                ));
                let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
                return;
            }
            (Ok(()), Err(cleanup_err)) => {
                self.restrict_recoverable(format!(
                    "runtime key cleanup failed after bootstrap apply: {cleanup_err}"
                ));
                let _ = self
                    .controller
                    .force_fail_closed("runtime_key_cleanup_failed");
                return;
            }
        }
        self.membership_state = Some(membership_state);
        self.membership_directory = membership_directory;

        if self.auto_tunnel_enforce {
            if self.node_role.is_blind_exit() {
                self.selected_exit_node = None;
                self.lan_access_enabled = false;
                self.controller.set_lan_access(false);
            } else {
                self.selected_exit_node = auto_exit;
                self.lan_access_enabled = auto_lan_access;
                self.controller.set_lan_access(auto_lan_access);
            }
            self.last_applied_assignment = auto_watermark;
        } else if let Some(exit_node) = &self.selected_exit_node {
            if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                let _ = self
                    .controller
                    .set_exit_node(node_id, "user:local", Protocol::Any);
            }
        }

        self.restriction_mode = RestrictionMode::None;
        self.bootstrap_error = None;
        self.refresh_traversal_hint_state();
        self.maintain_exit_port_forward(
            self.is_serving_exit_node(self.selected_exit_node.as_deref()),
        );
    }

    fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        if !self.node_role.allows_command(&command) {
            return IpcResponse::err(
                "command denied: current node role does not permit this operation",
            );
        }
        if self.is_restricted() && command.is_mutating() {
            return IpcResponse::err("daemon is in restricted-safe mode");
        }
        let auto_tunnel_route_advertise_allowed = matches!(
            &command,
            IpcCommand::RouteAdvertise(cidr)
                if self.allow_auto_tunnel_exit_advertisement(cidr)
        );
        if self.auto_tunnel_enforce
            && matches!(
                &command,
                IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::RouteAdvertise(_)
            )
            && !auto_tunnel_route_advertise_allowed
        {
            return IpcResponse::err(
                "manual route and exit mutations are disabled while auto-tunnel is enforced (except route advertise 0.0.0.0/0 for exit-serving nodes)",
            );
        }

        match command {
            IpcCommand::Status => {
                let last_assignment = self
                    .last_applied_assignment
                    .map(|watermark| format!("{}:{}", watermark.generated_at_unix, watermark.nonce))
                    .unwrap_or_else(|| "none".to_string());
                let membership_epoch = self
                    .membership_state
                    .as_ref()
                    .map(|state| state.epoch.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let membership_active_nodes = self
                    .membership_state
                    .as_ref()
                    .map(|state| state.active_nodes().len().to_string())
                    .unwrap_or_else(|| "none".to_string());
                let port_forward_external_port = self
                    .exit_port_forward_external_port()
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let port_forward_error = self
                    .exit_port_forward_last_error
                    .as_deref()
                    .unwrap_or("none");
                let serving_exit_node =
                    if self.is_serving_exit_node(self.selected_exit_node.as_deref()) {
                        "true"
                    } else {
                        "false"
                    };
                IpcResponse::ok(format!(
                    "node_id={} node_role={} state={:?} generation={} exit_node={} serving_exit_node={} lan_access={} restricted_safe_mode={} restriction_mode={:?} bootstrap_error={} reconcile_attempts={} reconcile_failures={} last_reconcile_unix={} last_reconcile_error={} encrypted_key_store={} auto_tunnel_enforce={} auto_port_forward_exit={} port_forward_external_port={} port_forward_error={} last_assignment={} membership_epoch={} membership_active_nodes={}",
                    self.local_node_id,
                    self.node_role.as_str(),
                    self.controller.state(),
                    self.controller.generation(),
                    self.selected_exit_node.as_deref().unwrap_or("none"),
                    serving_exit_node,
                    if self.lan_access_enabled { "on" } else { "off" },
                    if self.is_restricted() {
                        "true"
                    } else {
                        "false"
                    },
                    self.restriction_mode,
                    self.bootstrap_error.as_deref().unwrap_or("none"),
                    self.reconcile_attempts,
                    self.reconcile_failures,
                    self.last_reconcile_unix
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    self.last_reconcile_error.as_deref().unwrap_or("none"),
                    if self.wg_encrypted_private_key_path.is_some() {
                        "true"
                    } else {
                        "false"
                    },
                    if self.auto_tunnel_enforce {
                        "true"
                    } else {
                        "false"
                    },
                    if self.auto_port_forward_exit {
                        "true"
                    } else {
                        "false"
                    },
                    port_forward_external_port,
                    port_forward_error,
                    last_assignment,
                    membership_epoch,
                    membership_active_nodes
                ))
            }
            IpcCommand::Netcheck => {
                self.refresh_traversal_hint_state();
                IpcResponse::ok(self.netcheck_response_line())
            }
            IpcCommand::ExitNodeSelect(node) => {
                let node_id = match NodeId::new(node.clone()) {
                    Ok(value) => value,
                    Err(err) => return IpcResponse::err(format!("invalid node: {err}")),
                };
                if self.membership_directory.node_status(node.as_str()) != MembershipStatus::Active
                {
                    return IpcResponse::err(
                        "exit-node selection denied: node is not active in membership state",
                    );
                }
                match self
                    .controller
                    .set_exit_node(node_id, "user:local", Protocol::Any)
                {
                    Ok(()) => {
                        self.selected_exit_node = Some(node.clone());
                        if let Err(err) = self.persist_state() {
                            return IpcResponse::err(format!("persist failed: {err}"));
                        }
                        IpcResponse::ok(format!("exit-node selected: {node}"))
                    }
                    Err(err) => IpcResponse::err(err.to_string()),
                }
            }
            IpcCommand::ExitNodeOff => match self.controller.clear_exit_node() {
                Ok(()) => {
                    self.selected_exit_node = None;
                    if let Err(err) = self.persist_state() {
                        return IpcResponse::err(format!("persist failed: {err}"));
                    }
                    IpcResponse::ok("exit-node disabled")
                }
                Err(err) => IpcResponse::err(err.to_string()),
            },
            IpcCommand::LanAccessOn => {
                self.controller.set_lan_access(true);
                self.lan_access_enabled = true;
                if let Some(exit_node) = &self.selected_exit_node {
                    if self.membership_directory.node_status(exit_node.as_str())
                        != MembershipStatus::Active
                    {
                        return IpcResponse::err(
                            "lan-access denied: selected exit node is not active in membership state",
                        );
                    }
                    self.controller
                        .set_lan_route_acl("user:local", "192.168.1.0/24", true);
                    if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                        self.controller
                            .advertise_lan_route(node_id, "192.168.1.0/24");
                    }
                    let _ = self.controller.ensure_lan_route_allowed(RouteGrantRequest {
                        user: "user:local".to_string(),
                        cidr: "192.168.1.0/24".to_string(),
                        protocol: Protocol::Any,
                        context: TrafficContext::SharedExit,
                    });
                }
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                IpcResponse::ok("lan-access enabled")
            }
            IpcCommand::LanAccessOff => {
                self.controller.set_lan_access(false);
                self.lan_access_enabled = false;
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                IpcResponse::ok("lan-access disabled")
            }
            IpcCommand::DnsInspect => {
                IpcResponse::ok("dns inspect: protected=true resolver=rustynet")
            }
            IpcCommand::RouteAdvertise(cidr) => {
                if self.auto_tunnel_enforce && !self.allow_auto_tunnel_exit_advertisement(&cidr) {
                    return IpcResponse::err(
                        "manual route and exit mutations are disabled while auto-tunnel is enforced (except route advertise 0.0.0.0/0 for exit-serving nodes)",
                    );
                }
                if !validate_cidr(&cidr) {
                    return IpcResponse::err("invalid cidr format");
                }
                if let Some(exit_node) = &self.selected_exit_node {
                    if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                        if self.membership_directory.node_status(exit_node.as_str())
                            != MembershipStatus::Active
                        {
                            return IpcResponse::err(
                                "route advertise denied: selected exit node is not active in membership state",
                            );
                        }
                        self.controller.advertise_lan_route(node_id, &cidr);
                        self.controller.set_lan_route_acl("user:local", &cidr, true);
                    }
                }
                self.advertised_routes.insert(cidr.clone());
                self.local_route_reconcile_pending = true;
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                if self.auto_tunnel_enforce && cidr == "0.0.0.0/0" {
                    // Apply exit-serving dataplane/NAT immediately after advertised default route changes
                    // (including relay-with-upstream-exit mode) so status and forwarding reflect the
                    // requested fail-closed policy without waiting for the periodic reconcile interval.
                    self.reconcile();
                }
                IpcResponse::ok(format!("route advertised: {cidr}"))
            }
            IpcCommand::KeyRotate => match self.rotate_local_key_material() {
                Ok(message) => IpcResponse::ok(message),
                Err(err) => IpcResponse::err(err),
            },
            IpcCommand::KeyRevoke => match self.revoke_local_key_material() {
                Ok(message) => IpcResponse::ok(message),
                Err(err) => IpcResponse::err(err),
            },
            IpcCommand::Unknown(raw) => IpcResponse::err(format!("unknown command: {raw}")),
        }
    }

    fn apply_interface_private_key_runtime(&self, runtime_key_path: &Path) -> Result<(), String> {
        if let Some(client) = self.privileged_helper_client.as_ref() {
            let runtime_path = runtime_key_path
                .to_str()
                .ok_or_else(|| "runtime key path must be valid utf-8".to_string())?;
            let output = client.run_capture(
                PrivilegedCommandProgram::Wg,
                &[
                    "set",
                    self.wg_interface.as_str(),
                    "private-key",
                    runtime_path,
                ],
            )?;
            if output.success() {
                return Ok(());
            }
            return Err(format!(
                "wg set private-key failed for {}: status={} stderr={}",
                self.wg_interface, output.status, output.stderr
            ));
        }
        apply_interface_private_key(&self.wg_interface, runtime_key_path)
    }

    fn set_interface_down_runtime(&self) -> Result<(), String> {
        if let Some(client) = self.privileged_helper_client.as_ref() {
            let output = match self.backend_mode {
                DaemonBackendMode::LinuxWireguard => client.run_capture(
                    PrivilegedCommandProgram::Ip,
                    &["link", "set", "down", "dev", self.wg_interface.as_str()],
                )?,
                DaemonBackendMode::MacosWireguard => client.run_capture(
                    PrivilegedCommandProgram::Ifconfig,
                    &[self.wg_interface.as_str(), "down"],
                )?,
                DaemonBackendMode::InMemory => {
                    return Err("interface down is not supported for in-memory backend".to_string());
                }
            };
            if output.success() {
                return Ok(());
            }
            let command_label = match self.backend_mode {
                DaemonBackendMode::LinuxWireguard => "ip link set down",
                DaemonBackendMode::MacosWireguard => "ifconfig down",
                DaemonBackendMode::InMemory => "interface down",
            };
            return Err(format!(
                "{command_label} failed for {}: status={} stderr={}",
                self.wg_interface, output.status, output.stderr
            ));
        }
        set_interface_down(&self.wg_interface)
    }

    fn rotate_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(
            self.backend_mode,
            DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
        ) {
            return Err(
                "key rotation is only supported for linux-wireguard or macos-wireguard backend"
                    .to_string(),
            );
        }
        let runtime_path = self
            .wg_private_key_path
            .clone()
            .ok_or_else(|| "wg private key path is not configured".to_string())?;

        let mut old_runtime = fs::read(&runtime_path).ok();
        let mut old_encrypted = self
            .wg_encrypted_private_key_path
            .as_ref()
            .and_then(|path| fs::read(path).ok());
        let old_public = self
            .wg_public_key_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());

        let result = (|| -> Result<String, String> {
            let (mut new_private, new_public) = generate_wireguard_keypair()?;

            if let Some(encrypted_path) = self.wg_encrypted_private_key_path.as_ref() {
                let passphrase_path = self.wg_key_passphrase_path.as_ref().ok_or_else(|| {
                    "wg key passphrase path is required when encrypted key storage is configured"
                        .to_string()
                })?;
                if let Err(err) = encrypt_private_key(&new_private, encrypted_path, passphrase_path)
                {
                    new_private.fill(0);
                    return Err(err);
                }
            }

            if let Err(err) = write_runtime_private_key(&runtime_path, &new_private) {
                new_private.fill(0);
                return Err(err);
            }
            if let Some(public_path) = self.wg_public_key_path.as_ref() {
                if let Err(err) = write_public_key(public_path, &new_public) {
                    new_private.fill(0);
                    return Err(err);
                }
            }

            if let Err(err) = self.apply_interface_private_key_runtime(&runtime_path) {
                let _ = self.restore_key_backups(
                    old_runtime.as_deref(),
                    old_encrypted.as_deref(),
                    old_public.as_deref(),
                );
                new_private.fill(0);
                return Err(format!("rotate apply failed and rollback attempted: {err}"));
            }

            new_private.fill(0);

            if let Err(err) = self.persist_state() {
                return Err(format!("persist failed after key rotation: {err}"));
            }
            if let Err(err) = self.scrub_runtime_private_key_file() {
                return Err(format!(
                    "key rotation completed but runtime key cleanup failed: {err}"
                ));
            }

            let bundle = format!("rotation:{}:{}", self.local_node_id, new_public);
            Ok(format!(
                "key rotated: node_id={} public_key={} rotation_bundle={}",
                self.local_node_id, new_public, bundle
            ))
        })();

        zeroize_optional_bytes(&mut old_runtime);
        zeroize_optional_bytes(&mut old_encrypted);
        result
    }

    fn restore_key_backups(
        &self,
        old_runtime: Option<&[u8]>,
        old_encrypted: Option<&[u8]>,
        old_public: Option<&str>,
    ) -> Result<(), String> {
        if let (Some(path), Some(bytes)) = (self.wg_private_key_path.as_ref(), old_runtime) {
            write_runtime_private_key(path, bytes)?;
            let _ = self.apply_interface_private_key_runtime(path);
        }
        if let (Some(path), Some(bytes)) =
            (self.wg_encrypted_private_key_path.as_ref(), old_encrypted)
        {
            write_runtime_private_key(path, bytes)?;
        }
        if let (Some(path), Some(value)) = (self.wg_public_key_path.as_ref(), old_public) {
            write_public_key(path, value.trim())?;
        }
        Ok(())
    }

    fn revoke_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(
            self.backend_mode,
            DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
        ) {
            return Err(
                "key revoke is only supported for linux-wireguard or macos-wireguard backend"
                    .to_string(),
            );
        }
        self.restrict_permanent("local key revoked".to_string());
        let _ = self.controller.force_fail_closed("local_key_revoked");

        let mut failures = Vec::new();
        if let Err(err) = self.set_interface_down_runtime() {
            failures.push(format!("interface down failed: {err}"));
        }
        if let Some(path) = self.wg_private_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }
        if let Some(path) = self.wg_encrypted_private_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }
        if let Some(path) = self.wg_public_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }

        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.release_exit_port_forward();
        self.clear_exit_port_forward_state();

        if let Err(err) = self.persist_state() {
            failures.push(format!("persist failed after revoke: {err}"));
        }

        if failures.is_empty() {
            Ok("local key revoked: interface disabled and key material removed".to_string())
        } else {
            Err(format!(
                "key revoke completed with errors: {}",
                failures.join("; ")
            ))
        }
    }

    fn scrub_runtime_private_key_file(&self) -> Result<(), String> {
        if self.wg_encrypted_private_key_path.is_none() {
            return Ok(());
        }
        if let Some(path) = self.wg_private_key_path.as_ref() {
            remove_file_if_present(path)?;
        }
        Ok(())
    }

    fn ensure_runtime_private_key_material(&self) -> Result<(), String> {
        prepare_runtime_wireguard_key_material(
            self.backend_mode,
            self.wg_private_key_path.as_deref(),
            self.wg_encrypted_private_key_path.as_deref(),
            self.wg_key_passphrase_path.as_deref(),
        )
    }

    fn scrub_runtime_private_key_material(&self) -> Result<(), String> {
        scrub_runtime_wireguard_key_material(
            self.backend_mode,
            self.wg_private_key_path.as_deref(),
            self.wg_encrypted_private_key_path.as_deref(),
        )
    }

    fn persist_state(&mut self) -> Result<(), String> {
        let snapshot = SessionStateSnapshot {
            timestamp_unix: unix_now(),
            peer_ids: self.advertised_routes.iter().cloned().collect::<Vec<_>>(),
            selected_exit_node: self.selected_exit_node.clone(),
            lan_access_enabled: self.lan_access_enabled,
        };
        persist_session_snapshot(&snapshot, &self.state_path).map_err(|err| {
            self.restrict_permanent("state persist failure".to_string());
            let _ = self.controller.force_fail_closed("state_persist_failure");
            err.to_string()
        })
    }

    fn restore_state(&mut self) -> Result<(), ResilienceError> {
        if !self.state_path.exists() {
            return Ok(());
        }

        let snapshot = load_session_snapshot(&self.state_path)?;
        self.selected_exit_node = snapshot.selected_exit_node;
        self.lan_access_enabled = snapshot.lan_access_enabled;
        self.advertised_routes = snapshot.peer_ids.into_iter().collect::<BTreeSet<_>>();
        self.controller.set_lan_access(self.lan_access_enabled);

        if let Some(selected) = &self.selected_exit_node {
            if let Ok(node_id) = NodeId::new(selected.clone()) {
                for route in &self.advertised_routes {
                    self.controller.advertise_lan_route(node_id.clone(), route);
                }
            }
        }

        Ok(())
    }

    fn reconcile(&mut self) {
        self.reconcile_attempts = self.reconcile_attempts.saturating_add(1);
        self.last_reconcile_unix = Some(unix_now());
        if let Err(err) = self.enforce_blind_exit_invariants() {
            self.reconcile_failures = self.reconcile_failures.saturating_add(1);
            let message = format!("blind-exit role invariants failed during reconcile: {err}");
            self.last_reconcile_error = Some(message.clone());
            self.restrict_permanent(message);
            let _ = self
                .controller
                .force_fail_closed("blind_exit_invariants_failed");
            return;
        }

        let trust = match self.load_verified_trust() {
            Ok(evidence) => evidence,
            Err(err) => {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("trust reconcile failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self.controller.force_fail_closed("trust_reconcile_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }
        };

        let membership_state = match self.load_verified_membership() {
            Ok(state) => state,
            Err(err) => {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("membership reconcile failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self
                    .controller
                    .force_fail_closed("membership_reconcile_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }
        };
        let membership_directory = membership_directory_from_state(&membership_state);

        let auto_bundle = if self.auto_tunnel_enforce {
            match self.load_verified_auto_tunnel(&membership_directory) {
                Ok(bundle) => Some(bundle),
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("auto-tunnel reconcile failed: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self
                        .controller
                        .force_fail_closed("auto_tunnel_reconcile_failed");
                    self.promote_to_permanent_if_over_limit();
                    return;
                }
            }
        } else {
            None
        };

        let assignment_changed = auto_bundle
            .as_ref()
            .map(|envelope| Some(envelope.watermark) != self.last_applied_assignment)
            .unwrap_or(false);
        let membership_changed = self
            .membership_state
            .as_ref()
            .map(|current| current.epoch != membership_state.epoch)
            .unwrap_or(true);

        self.last_reconcile_error = None;

        if self.controller.state() == DataplaneState::FailClosed
            || self.restriction_mode == RestrictionMode::Recoverable
            || assignment_changed
            || membership_changed
            || self.local_route_reconcile_pending
        {
            let (mesh_cidr, local_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
                if let Some(envelope) = auto_bundle {
                    let lan_enabled = envelope
                        .bundle
                        .routes
                        .iter()
                        .any(|route| route.kind == RouteKind::ExitNodeLan);
                    (
                        envelope.bundle.mesh_cidr,
                        envelope.bundle.assigned_cidr,
                        envelope.bundle.peers,
                        envelope.bundle.routes,
                        envelope.bundle.selected_exit_node,
                        lan_enabled,
                        Some(envelope.watermark),
                    )
                } else {
                    (
                        "100.64.0.0/10".to_string(),
                        "100.64.0.1/32".to_string(),
                        Vec::new(),
                        Vec::new(),
                        None,
                        false,
                        None,
                    )
                };
            if let Err(err) =
                self.validate_blind_exit_assignment(auto_exit.as_deref(), auto_lan_access)
            {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                self.last_reconcile_error = Some(err.clone());
                self.restrict_recoverable(err);
                let _ = self
                    .controller
                    .force_fail_closed("blind_exit_assignment_rejected");
                self.promote_to_permanent_if_over_limit();
                return;
            }
            let local_node = match NodeId::new(self.local_node_id.clone()) {
                Ok(node_id) => node_id,
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("invalid local node id in runtime: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_permanent(message);
                    let _ = self.controller.force_fail_closed("invalid_local_node_id");
                    return;
                }
            };

            if let Err(err) = self.ensure_runtime_private_key_material() {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("runtime key preparation failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self
                    .controller
                    .force_fail_closed("runtime_key_prepare_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }

            let serve_exit_node = if self.node_role.is_blind_exit() {
                true
            } else if self.auto_tunnel_enforce {
                self.is_serving_exit_node(auto_exit.as_deref())
            } else {
                self.is_serving_exit_node(self.selected_exit_node.as_deref())
            };

            let apply_result = self.controller.apply_dataplane_generation(
                trust,
                RuntimeContext {
                    local_node,
                    mesh_cidr,
                    local_cidr,
                },
                peers,
                routes,
                ApplyOptions {
                    protected_dns: true,
                    ipv6_parity_supported: false,
                    serve_exit_node,
                    exit_mode: if self.node_role.is_blind_exit() {
                        ExitMode::Off
                    } else if self.auto_tunnel_enforce {
                        if auto_exit.is_some() {
                            ExitMode::FullTunnel
                        } else {
                            ExitMode::Off
                        }
                    } else {
                        self.desired_exit_mode()
                    },
                },
            );
            let cleanup_result = self.scrub_runtime_private_key_material();

            match (apply_result, cleanup_result) {
                (Ok(()), Ok(())) => {
                    self.membership_state = Some(membership_state);
                    self.membership_directory = membership_directory;
                    if self.auto_tunnel_enforce {
                        if self.node_role.is_blind_exit() {
                            self.selected_exit_node = None;
                            self.lan_access_enabled = false;
                            self.controller.set_lan_access(false);
                        } else {
                            self.selected_exit_node = auto_exit;
                            self.lan_access_enabled = auto_lan_access;
                            self.controller.set_lan_access(auto_lan_access);
                        }
                        self.last_applied_assignment = auto_watermark;
                    }
                    self.restriction_mode = RestrictionMode::None;
                    self.bootstrap_error = None;
                    self.reconcile_failures = 0;
                    self.local_route_reconcile_pending = false;
                }
                (Err(err), Ok(())) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("reconcile dataplane apply failed: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self.controller.force_fail_closed("reconcile_apply_failed");
                    self.promote_to_permanent_if_over_limit();
                }
                (Err(err), Err(cleanup_err)) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!(
                        "reconcile dataplane apply failed: {err}; runtime key cleanup failed: {cleanup_err}"
                    );
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self.controller.force_fail_closed("reconcile_apply_failed");
                    self.promote_to_permanent_if_over_limit();
                }
                (Ok(()), Err(cleanup_err)) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message =
                        format!("runtime key cleanup failed after reconcile apply: {cleanup_err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self
                        .controller
                        .force_fail_closed("runtime_key_cleanup_failed");
                    self.promote_to_permanent_if_over_limit();
                }
            }
        }

        self.maintain_exit_port_forward(
            self.is_serving_exit_node(self.selected_exit_node.as_deref()),
        );
    }

    fn enforce_blind_exit_invariants(&mut self) -> Result<(), String> {
        if !self.node_role.is_blind_exit() {
            return Ok(());
        }
        let mut changed = false;
        if self.selected_exit_node.take().is_some() {
            changed = true;
        }
        if self.lan_access_enabled {
            self.lan_access_enabled = false;
            self.controller.set_lan_access(false);
            changed = true;
        }
        if !self
            .advertised_routes
            .contains(BLIND_EXIT_DEFAULT_ROUTE_CIDR)
        {
            self.advertised_routes
                .insert(BLIND_EXIT_DEFAULT_ROUTE_CIDR.to_string());
            self.local_route_reconcile_pending = true;
            changed = true;
        }
        if changed {
            self.persist_state()?;
        }
        Ok(())
    }

    fn validate_blind_exit_assignment(
        &self,
        selected_exit_node: Option<&str>,
        lan_access_enabled: bool,
    ) -> Result<(), String> {
        if !self.node_role.is_blind_exit() {
            return Ok(());
        }
        if selected_exit_node.is_some() {
            eprintln!("rustynetd: ignoring selected_exit_node assignment for blind_exit role");
        }
        if lan_access_enabled {
            eprintln!("rustynetd: ignoring LAN route assignment for blind_exit role");
        }
        Ok(())
    }

    fn desired_exit_mode(&self) -> ExitMode {
        if self.selected_exit_node.is_some() {
            ExitMode::FullTunnel
        } else {
            ExitMode::Off
        }
    }

    fn is_serving_exit_node(&self, _selected_exit_node: Option<&str>) -> bool {
        self.node_role.is_blind_exit()
            || (self.node_role.is_admin()
                && self
                    .advertised_routes
                    .contains(BLIND_EXIT_DEFAULT_ROUTE_CIDR))
    }

    fn allow_auto_tunnel_exit_advertisement(&self, cidr: &str) -> bool {
        self.node_role.is_admin() && cidr == BLIND_EXIT_DEFAULT_ROUTE_CIDR
    }

    fn is_restricted(&self) -> bool {
        self.restriction_mode != RestrictionMode::None
    }

    fn restrict_recoverable(&mut self, message: String) {
        if self.restriction_mode == RestrictionMode::Permanent {
            return;
        }
        self.restriction_mode = RestrictionMode::Recoverable;
        self.bootstrap_error = Some(message);
    }

    fn restrict_permanent(&mut self, message: String) {
        self.restriction_mode = RestrictionMode::Permanent;
        self.bootstrap_error = Some(message);
    }

    fn promote_to_permanent_if_over_limit(&mut self) {
        if self.reconcile_failures >= u64::from(self.max_reconcile_failures) {
            self.restrict_permanent(format!(
                "reconcile failure threshold exceeded: {}",
                self.reconcile_failures
            ));
        }
    }

    fn maintain_exit_port_forward(&mut self, should_serve_exit: bool) {
        if !self.auto_port_forward_exit {
            self.release_exit_port_forward();
            self.clear_exit_port_forward_state();
            return;
        }

        #[cfg(target_os = "linux")]
        {
            if !should_serve_exit {
                self.release_exit_port_forward();
                self.clear_exit_port_forward_state();
                return;
            }

            let now_unix = unix_now();
            if let Some(current) = self.exit_port_forward_lease {
                let refresh_at = current
                    .renewed_at_unix
                    .saturating_add(u64::from(current.lease_secs.max(60) / 2));
                if now_unix < refresh_at {
                    return;
                }
            }

            let gateway =
                match detect_ipv4_default_gateway_for_interface(self.egress_interface.as_str()) {
                    Ok(value) => value,
                    Err(err) => {
                        self.exit_port_forward_last_error = Some(err);
                        self.exit_port_forward_lease = None;
                        return;
                    }
                };

            match nat_pmp_map_udp_port(
                gateway,
                self.wg_listen_port,
                self.wg_listen_port,
                self.auto_port_forward_lease_secs,
            ) {
                Ok((external_port, granted_lease_secs)) => {
                    if external_port != self.wg_listen_port {
                        let _ =
                            nat_pmp_delete_udp_port(gateway, self.wg_listen_port, external_port);
                        self.exit_port_forward_last_error = Some(format!(
                            "router mapped unexpected external port {external_port}; expected {}",
                            self.wg_listen_port
                        ));
                        self.exit_port_forward_lease = None;
                        return;
                    }
                    self.exit_port_forward_lease = Some(ExitPortForwardLease {
                        gateway,
                        internal_port: self.wg_listen_port,
                        external_port,
                        lease_secs: granted_lease_secs,
                        renewed_at_unix: now_unix,
                    });
                    self.exit_port_forward_last_error = None;
                }
                Err(err) => {
                    self.exit_port_forward_last_error = Some(err);
                    self.exit_port_forward_lease = None;
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = should_serve_exit;
            self.exit_port_forward_last_error =
                Some("auto port forward is supported only on Linux".to_string());
        }
    }

    fn release_exit_port_forward(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(lease) = self.exit_port_forward_lease {
                if let Err(err) =
                    nat_pmp_delete_udp_port(lease.gateway, lease.internal_port, lease.external_port)
                {
                    self.exit_port_forward_last_error =
                        Some(format!("auto port-forward release failed: {err}"));
                }
            }
        }
    }

    fn clear_exit_port_forward_state(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.exit_port_forward_lease = None;
        }
        self.exit_port_forward_last_error = None;
    }

    fn exit_port_forward_external_port(&self) -> Option<u16> {
        #[cfg(target_os = "linux")]
        {
            self.exit_port_forward_lease
                .map(|lease| lease.external_port)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_ipv4_default_gateway_for_interface(interface: &str) -> Result<Ipv4Addr, String> {
    let routes = fs::read_to_string("/proc/net/route")
        .map_err(|err| format!("read /proc/net/route failed: {err}"))?;
    for (index, line) in routes.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        if fields[0] != interface {
            continue;
        }
        if fields[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(fields[3], 16)
            .map_err(|err| format!("parse route flags failed: {err}"))?;
        let route_is_up = (flags & 0x1) != 0;
        let has_gateway = (flags & 0x2) != 0;
        if !route_is_up || !has_gateway {
            continue;
        }
        let gateway_u32 = u32::from_str_radix(fields[2], 16)
            .map_err(|err| format!("parse default gateway failed: {err}"))?;
        let octets = gateway_u32.to_le_bytes();
        return Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
    }
    Err(format!(
        "no IPv4 default gateway found for interface {interface}"
    ))
}

#[cfg(target_os = "linux")]
fn nat_pmp_map_udp_port(
    gateway: Ipv4Addr,
    internal_port: u16,
    requested_external_port: u16,
    requested_lease_secs: u32,
) -> Result<(u16, u32), String> {
    let mut request = [0u8; 12];
    request[0] = 0;
    request[1] = 1;
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&requested_external_port.to_be_bytes());
    request[8..12].copy_from_slice(&requested_lease_secs.to_be_bytes());
    let response = nat_pmp_round_trip(gateway, &request)?;
    if response.len() < 16 {
        return Err("nat-pmp mapping response too short".to_string());
    }
    if response[0] != 0 || response[1] != 129 {
        return Err("nat-pmp mapping response opcode mismatch".to_string());
    }
    let result_code = u16::from_be_bytes([response[2], response[3]]);
    if result_code != 0 {
        return Err(format!(
            "nat-pmp mapping rejected by gateway (code {result_code})"
        ));
    }
    let returned_internal = u16::from_be_bytes([response[8], response[9]]);
    if returned_internal != internal_port {
        return Err(format!(
            "nat-pmp internal port mismatch: expected {internal_port}, got {returned_internal}"
        ));
    }
    let mapped_external = u16::from_be_bytes([response[10], response[11]]);
    let granted_lease =
        u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    if mapped_external == 0 {
        return Err("nat-pmp gateway returned invalid external port".to_string());
    }
    if granted_lease == 0 {
        return Err("nat-pmp gateway returned zero lease".to_string());
    }
    Ok((mapped_external, granted_lease))
}

#[cfg(target_os = "linux")]
fn nat_pmp_delete_udp_port(
    gateway: Ipv4Addr,
    internal_port: u16,
    current_external_port: u16,
) -> Result<(), String> {
    let mut request = [0u8; 12];
    request[0] = 0;
    request[1] = 1;
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&current_external_port.to_be_bytes());
    request[8..12].copy_from_slice(&0u32.to_be_bytes());
    let response = nat_pmp_round_trip(gateway, &request)?;
    if response.len() < 16 {
        return Err("nat-pmp delete response too short".to_string());
    }
    if response[0] != 0 || response[1] != 129 {
        return Err("nat-pmp delete response opcode mismatch".to_string());
    }
    let result_code = u16::from_be_bytes([response[2], response[3]]);
    if result_code != 0 {
        return Err(format!(
            "nat-pmp delete rejected by gateway (code {result_code})"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn nat_pmp_round_trip(gateway: Ipv4Addr, request: &[u8]) -> Result<Vec<u8>, String> {
    let gateway_addr = SocketAddrV4::new(gateway, 5351);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|err| format!("nat-pmp socket bind failed: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("nat-pmp read-timeout setup failed: {err}"))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("nat-pmp write-timeout setup failed: {err}"))?;
    socket
        .send_to(request, gateway_addr)
        .map_err(|err| format!("nat-pmp request send failed: {err}"))?;
    let mut response = [0u8; 64];
    let (len, from) = socket
        .recv_from(&mut response)
        .map_err(|err| format!("nat-pmp response receive failed: {err}"))?;
    if from.ip() != gateway {
        return Err(format!(
            "nat-pmp response source mismatch: expected {gateway}, got {}",
            from.ip()
        ));
    }
    if from.port() != 5351 {
        return Err(format!(
            "nat-pmp response source port mismatch: expected 5351, got {}",
            from.port()
        ));
    }
    Ok(response[..len].to_vec())
}

fn zeroize_optional_bytes(value: &mut Option<Vec<u8>>) {
    if let Some(bytes) = value.as_mut() {
        bytes.fill(0);
    }
}

fn daemon_system(config: &DaemonConfig) -> Result<RuntimeSystem, DaemonError> {
    #[cfg(target_os = "linux")]
    {
        // In test mode, the in-memory backend uses DryRunSystem to avoid modifying
        // host network state (nftables killswitch, ip rules, sysctl) which would sever
        // the network connection running the tests.
        #[cfg(test)]
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            return Ok(RuntimeSystem::DryRun(
                crate::phase10::DryRunSystem::default(),
            ));
        }

        let mode = match config.dataplane_mode {
            DaemonDataplaneMode::Shell => LinuxDataplaneMode::Shell,
            DaemonDataplaneMode::HybridNative => LinuxDataplaneMode::HybridNative,
        };
        let helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        let system = LinuxCommandSystem::new(
            config.wg_interface.clone(),
            config.egress_interface.clone(),
            mode,
            helper_client,
            config.fail_closed_ssh_allow,
            config.fail_closed_ssh_allow_cidrs.clone(),
        )
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        Ok(RuntimeSystem::Linux(system))
    }
    #[cfg(target_os = "macos")]
    {
        #[cfg(test)]
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            return Ok(RuntimeSystem::DryRun(
                crate::phase10::DryRunSystem::default(),
            ));
        }

        let helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        let system = MacosCommandSystem::new(
            config.wg_interface.clone(),
            config.egress_interface.clone(),
            helper_client,
            config.fail_closed_ssh_allow,
            config.fail_closed_ssh_allow_cidrs.clone(),
        )
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        Ok(RuntimeSystem::Macos(system))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            #[cfg(test)]
            {
                return Ok(RuntimeSystem::DryRun(
                    crate::phase10::DryRunSystem::default(),
                ));
            }
        }
        Err(DaemonError::InvalidConfig(
            "daemon dataplane requires a linux or macos host with a supported wireguard backend"
                .to_string(),
        ))
    }
}

pub fn run_daemon(config: DaemonConfig) -> Result<(), DaemonError> {
    if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
        return Err(DaemonError::InvalidConfig(
            "in-memory backend is disabled in production daemon paths".to_string(),
        ));
    }
    if config.socket_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "socket path must not be empty".to_string(),
        ));
    }
    validate_daemon_config(&config)?;
    prepare_runtime_wireguard_key(&config)?;
    if let Err(err) = run_preflight_checks(&config) {
        let _ = scrub_runtime_wireguard_key_after_bootstrap(&config);
        return Err(err);
    }

    let mut runtime = match DaemonRuntime::new(&config) {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = scrub_runtime_wireguard_key_after_bootstrap(&config);
            return Err(err);
        }
    };
    runtime.bootstrap();
    scrub_runtime_wireguard_key_after_bootstrap(&config)?;

    if let Some(parent) = config.socket_path.parent() {
        fs::create_dir_all(parent).map_err(|err| DaemonError::Io(err.to_string()))?;
        match fs::set_permissions(parent, fs::Permissions::from_mode(0o700)) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                let metadata = fs::metadata(parent).map_err(|meta_err| {
                    DaemonError::Io(format!(
                        "inspect socket parent after chmod denial failed: {meta_err}"
                    ))
                })?;
                let mode = metadata.permissions().mode() & 0o777;
                let owner_uid = metadata.uid();
                let expected_uid = Uid::effective().as_raw();
                let root_managed_shared_runtime = owner_uid == 0 && mode == 0o770;
                if !root_managed_shared_runtime || owner_uid == expected_uid {
                    return Err(DaemonError::Io(err.to_string()));
                }
            }
            Err(err) => {
                return Err(DaemonError::Io(err.to_string()));
            }
        }
    }

    if config.socket_path.exists() {
        fs::remove_file(&config.socket_path).map_err(|err| DaemonError::Io(err.to_string()))?;
    }

    let listener = UnixListener::bind(&config.socket_path)
        .map_err(|err| DaemonError::Io(format!("bind failed: {err}")))?;
    fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| DaemonError::Io(err.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| DaemonError::Io(format!("socket nonblocking failed: {err}")))?;

    let socket_owner_uid = socket_owner_uid(&config.socket_path)?;

    let mut processed = 0usize;
    let reconcile_interval = Duration::from_millis(config.reconcile_interval_ms.get().max(100));
    let mut next_reconcile = Instant::now() + reconcile_interval;

    loop {
        let mut processed_command = false;
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|err| DaemonError::Io(format!("socket read-timeout failed: {err}")))?;
                let command = read_command(&stream).map_err(DaemonError::Io)?;
                let parsed = parse_command(&command);

                let authorized = if parsed.is_mutating() {
                    match peer_uid(&stream) {
                        Some(peer_uid) => peer_uid == 0 || peer_uid == socket_owner_uid,
                        None => false,
                    }
                } else {
                    true
                };

                let response = if authorized {
                    runtime.handle_command(parsed)
                } else {
                    IpcResponse::err("unauthorized mutation request")
                };

                write_response(stream, response).map_err(DaemonError::Io)?;
                processed = processed.saturating_add(1);
                processed_command = true;
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {}
            Err(err) => return Err(DaemonError::Io(format!("accept failed: {err}"))),
        }

        let now = Instant::now();
        if now >= next_reconcile {
            runtime.reconcile();
            next_reconcile = now + reconcile_interval;
        }

        if config
            .max_requests
            .map(|max| processed >= max.get())
            .unwrap_or(false)
        {
            break;
        }

        if !processed_command {
            let sleep_for = next_reconcile
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(25));
            if !sleep_for.is_zero() {
                sleep(sleep_for);
            }
        }
    }

    scrub_runtime_wireguard_key_after_bootstrap(&config)?;
    Ok(())
}

fn scrub_runtime_wireguard_key_after_bootstrap(config: &DaemonConfig) -> Result<(), DaemonError> {
    scrub_runtime_wireguard_key_material(
        config.backend_mode,
        config.wg_private_key_path.as_deref(),
        config.wg_encrypted_private_key_path.as_deref(),
    )
    .map_err(|err| DaemonError::InvalidConfig(format!("runtime private key cleanup failed: {err}")))
}

fn scrub_runtime_wireguard_key_material(
    backend_mode: DaemonBackendMode,
    runtime_path: Option<&Path>,
    encrypted_private_key_path: Option<&Path>,
) -> Result<(), String> {
    if !matches!(
        backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) {
        return Ok(());
    }
    if encrypted_private_key_path.is_none() {
        return Ok(());
    }
    let Some(runtime_path) = runtime_path else {
        return Ok(());
    };
    if !runtime_path.exists() {
        return Ok(());
    }
    remove_file_if_present(runtime_path)
}

fn prepare_runtime_wireguard_key(config: &DaemonConfig) -> Result<(), DaemonError> {
    prepare_runtime_wireguard_key_material(
        config.backend_mode,
        config.wg_private_key_path.as_deref(),
        config.wg_encrypted_private_key_path.as_deref(),
        config.wg_key_passphrase_path.as_deref(),
    )
    .map_err(DaemonError::InvalidConfig)
}

fn prepare_runtime_wireguard_key_material(
    backend_mode: DaemonBackendMode,
    runtime_path: Option<&Path>,
    encrypted_private_key_path: Option<&Path>,
    passphrase_path: Option<&Path>,
) -> Result<(), String> {
    if !matches!(
        backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) {
        return Ok(());
    }

    let runtime_path = runtime_path.ok_or_else(|| {
        "wg private key path is required for linux-wireguard or macos-wireguard backend".to_string()
    })?;

    if let Some(encrypted_path) = encrypted_private_key_path {
        let passphrase_path = passphrase_path.ok_or_else(|| {
            "wg key passphrase path is required when encrypted key path is configured".to_string()
        })?;
        let mut decrypted = decrypt_private_key(encrypted_path, passphrase_path)
            .map_err(|err| format!("wg key decrypt failed: {err}"))?;
        let write_result = write_runtime_private_key(runtime_path, &decrypted);
        decrypted.fill(0);
        if let Err(err) = write_result {
            let _ = remove_file_if_present(runtime_path);
            return Err(format!("wg runtime key write failed: {err}"));
        }
        return Ok(());
    }

    validate_private_key_permissions(runtime_path).map_err(|err| err.to_string())
}

fn validate_daemon_config(config: &DaemonConfig) -> Result<(), DaemonError> {
    if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
        return Err(DaemonError::InvalidConfig(
            "in-memory backend is disabled in production daemon paths".to_string(),
        ));
    }

    NodeId::new(config.node_id.clone())
        .map_err(|err| DaemonError::InvalidConfig(format!("node id is invalid: {err}")))?;

    if !config.socket_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "socket path must be absolute".to_string(),
        ));
    }
    if !config.state_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "state path must be absolute".to_string(),
        ));
    }
    if let Some(path) = config.privileged_helper_socket_path.as_ref() {
        if !path.is_absolute() {
            return Err(DaemonError::InvalidConfig(
                "privileged helper socket path must be absolute".to_string(),
            ));
        }
    }
    if !config.trust_evidence_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "trust evidence path must be absolute".to_string(),
        ));
    }
    if !config.trust_verifier_key_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "trust verifier key path must be absolute".to_string(),
        ));
    }
    if !config.trust_watermark_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "trust watermark path must be absolute".to_string(),
        ));
    }
    if !config.membership_snapshot_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "membership snapshot path must be absolute".to_string(),
        ));
    }
    if !config.membership_log_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "membership log path must be absolute".to_string(),
        ));
    }
    if !config.membership_watermark_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "membership watermark path must be absolute".to_string(),
        ));
    }
    if let Some(path) = config.auto_tunnel_bundle_path.as_ref() {
        if !path.is_absolute() {
            return Err(DaemonError::InvalidConfig(
                "auto tunnel bundle path must be absolute".to_string(),
            ));
        }
    }
    if let Some(path) = config.auto_tunnel_verifier_key_path.as_ref() {
        if !path.is_absolute() {
            return Err(DaemonError::InvalidConfig(
                "auto tunnel verifier key path must be absolute".to_string(),
            ));
        }
    }
    if let Some(path) = config.auto_tunnel_watermark_path.as_ref() {
        if !path.is_absolute() {
            return Err(DaemonError::InvalidConfig(
                "auto tunnel watermark path must be absolute".to_string(),
            ));
        }
    }
    if !config.traversal_bundle_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "traversal bundle path must be absolute".to_string(),
        ));
    }
    if !config.traversal_verifier_key_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "traversal verifier key path must be absolute".to_string(),
        ));
    }
    if !config.traversal_watermark_path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "traversal watermark path must be absolute".to_string(),
        ));
    }
    if config.wg_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "wireguard interface must not be empty".to_string(),
        ));
    }
    if config.wg_listen_port == 0 {
        return Err(DaemonError::InvalidConfig(
            "wireguard listen port must be in range 1-65535".to_string(),
        ));
    }
    if config.egress_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "egress interface must not be empty".to_string(),
        ));
    }
    if config.auto_port_forward_lease_secs.get() < 60 {
        return Err(DaemonError::InvalidConfig(
            "auto port-forward lease must be at least 60 seconds".to_string(),
        ));
    }
    if config.auto_port_forward_exit
        && !matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard)
    {
        return Err(DaemonError::InvalidConfig(
            "auto port-forward exit is supported only with linux-wireguard backend".to_string(),
        ));
    }
    if config.trust_evidence_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust evidence path must not be empty".to_string(),
        ));
    }
    if config.trust_verifier_key_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust verifier key path must not be empty".to_string(),
        ));
    }
    if config.trust_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust watermark path must not be empty".to_string(),
        ));
    }
    if config.membership_snapshot_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership snapshot path must not be empty".to_string(),
        ));
    }
    if config.membership_log_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership log path must not be empty".to_string(),
        ));
    }
    if config.membership_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership watermark path must not be empty".to_string(),
        ));
    }
    if config.traversal_bundle_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal bundle path must not be empty".to_string(),
        ));
    }
    if config.traversal_verifier_key_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal verifier key path must not be empty".to_string(),
        ));
    }
    if config.traversal_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal watermark path must not be empty".to_string(),
        ));
    }
    if config.auto_tunnel_enforce
        && (config.auto_tunnel_bundle_path.is_none()
            || config.auto_tunnel_verifier_key_path.is_none()
            || config.auto_tunnel_watermark_path.is_none())
    {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel enforce requires bundle, verifier key, and watermark paths".to_string(),
        ));
    }
    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) {
        if let Some(path) = config.wg_private_key_path.as_ref() {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfig(
                    "wg private key path must be absolute".to_string(),
                ));
            }
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref() {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfig(
                    "wg encrypted private key path must be absolute".to_string(),
                ));
            }
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref() {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfig(
                    "wg key passphrase path must be absolute".to_string(),
                ));
            }
        }
        if let Some(path) = config.wg_public_key_path.as_ref() {
            if !path.is_absolute() {
                return Err(DaemonError::InvalidConfig(
                    "wg public key path must be absolute".to_string(),
                ));
            }
        }
        if config.wg_encrypted_private_key_path.is_some() && config.wg_key_passphrase_path.is_none()
        {
            return Err(DaemonError::InvalidConfig(
                "wg key passphrase path is required when encrypted key path is set".to_string(),
            ));
        }
        if config.wg_key_passphrase_path.is_some() && config.wg_encrypted_private_key_path.is_none()
        {
            return Err(DaemonError::InvalidConfig(
                "wg encrypted private key path is required when passphrase path is set".to_string(),
            ));
        }
    }

    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) && config.wg_private_key_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(
            "wg private key path is required for linux-wireguard or macos-wireguard backend"
                .to_string(),
        ));
    }
    if config.fail_closed_ssh_allow {
        if config.fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(DaemonError::InvalidConfig(
                "fail-closed ssh allow requires at least one management cidr".to_string(),
            ));
        }
    }
    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) && config.privileged_helper_socket_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(
            "privileged helper socket path is required for linux-wireguard or macos-wireguard backend"
                .to_string(),
        ));
    }

    Ok(())
}

fn run_preflight_checks(config: &DaemonConfig) -> Result<(), DaemonError> {
    if let Some(parent) = config.state_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("state directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.trust_evidence_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("trust directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.trust_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("trust watermark directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.membership_snapshot_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "membership snapshot directory create failed: {err}"
            ))
        })?;
    }
    if let Some(parent) = config.membership_log_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("membership log directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.membership_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "membership watermark directory create failed: {err}"
            ))
        })?;
    }
    if config.auto_tunnel_enforce {
        if let Some(path) = config.auto_tunnel_bundle_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    DaemonError::InvalidConfig(format!(
                        "auto tunnel bundle directory create failed: {err}"
                    ))
                })?;
            }
        }
    }
    if config.auto_tunnel_enforce {
        if let Some(path) = config.auto_tunnel_watermark_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    DaemonError::InvalidConfig(format!(
                        "auto tunnel watermark directory create failed: {err}"
                    ))
                })?;
            }
        }
    }
    if let Some(parent) = config.traversal_bundle_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("traversal bundle directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.traversal_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "traversal watermark directory create failed: {err}"
            ))
        })?;
    }

    validate_trust_evidence_permissions(&config.trust_evidence_path)?;
    validate_trust_verifier_key_permissions(&config.trust_verifier_key_path)?;
    validate_membership_snapshot_permissions(&config.membership_snapshot_path)?;
    validate_membership_log_permissions(&config.membership_log_path)?;
    if config.traversal_bundle_path.exists() {
        validate_traversal_verifier_key_permissions(&config.traversal_verifier_key_path)?;
        validate_traversal_bundle_permissions(&config.traversal_bundle_path)?;
    }
    if config.auto_tunnel_enforce {
        let bundle_path = config.auto_tunnel_bundle_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires bundle path".to_string())
        })?;
        let verifier_key_path = config
            .auto_tunnel_verifier_key_path
            .as_ref()
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "auto tunnel enforce requires verifier key path".to_string(),
                )
            })?;
        validate_auto_tunnel_bundle_permissions(bundle_path)?;
        validate_auto_tunnel_verifier_key_permissions(verifier_key_path)?;
    }
    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
    ) {
        if let Some(path) = config.wg_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref() {
            validate_passphrase_permissions(path)?;
        }
        if let Some(path) = config.wg_public_key_path.as_ref() {
            validate_public_key_permissions(path)?;
        }
    }

    let watermark = load_trust_watermark(&config.trust_watermark_path).map_err(|err| {
        DaemonError::InvalidConfig(format!("trust watermark preflight failed: {err}"))
    })?;
    let _ = load_trust_evidence(
        &config.trust_evidence_path,
        &config.trust_verifier_key_path,
        TrustPolicy::default(),
        watermark,
    )
    .map_err(|err| DaemonError::InvalidConfig(format!("trust preflight failed: {err}")))?;
    let membership_snapshot =
        load_membership_snapshot(&config.membership_snapshot_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("membership snapshot preflight failed: {err}"))
        })?;
    let membership_entries = load_membership_log(&config.membership_log_path).map_err(|err| {
        DaemonError::InvalidConfig(format!("membership log preflight failed: {err}"))
    })?;
    let _ =
        replay_membership_snapshot_and_log(&membership_snapshot, &membership_entries, unix_now())
            .map_err(|err| {
            DaemonError::InvalidConfig(format!("membership replay preflight failed: {err}"))
        })?;

    if config.auto_tunnel_enforce {
        let bundle_path = config.auto_tunnel_bundle_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires bundle path".to_string())
        })?;
        let verifier_key_path = config
            .auto_tunnel_verifier_key_path
            .as_ref()
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "auto tunnel enforce requires verifier key path".to_string(),
                )
            })?;
        let watermark_path = config.auto_tunnel_watermark_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires watermark path".to_string())
        })?;
        let watermark = load_auto_tunnel_watermark(watermark_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel watermark preflight failed: {err}"))
        })?;
        let _ = load_auto_tunnel_bundle(
            bundle_path,
            verifier_key_path,
            config.auto_tunnel_max_age_secs.get(),
            TrustPolicy::default(),
            watermark,
        )
        .map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel preflight failed: {err}"))
        })?;
    }

    let traversal_watermark =
        load_traversal_watermark(&config.traversal_watermark_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("traversal watermark preflight failed: {err}"))
        })?;
    if config.traversal_bundle_path.exists() {
        let _ = load_traversal_bundle(
            &config.traversal_bundle_path,
            &config.traversal_verifier_key_path,
            config.traversal_max_age_secs.get(),
            TrustPolicy::default(),
            traversal_watermark,
        )
        .map_err(|err| DaemonError::InvalidConfig(format!("traversal preflight failed: {err}")))?;
    }

    let mut system = daemon_system(config)?;
    system
        .check_prerequisites()
        .map_err(|err| DaemonError::InvalidConfig(format!("dataplane preflight failed: {err}")))?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077, false)
}

#[cfg(not(target_os = "linux"))]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077, false)
}

fn validate_passphrase_permissions(path: &Path) -> Result<(), DaemonError> {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT")
            .ok()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            read_passphrase_file(path).map_err(|err| {
                DaemonError::InvalidConfig(format!(
                    "wireguard key passphrase source invalid: {err}"
                ))
            })?;
            return Ok(());
        }
    }

    let allow_root_owner = is_systemd_runtime_credential_path(path);
    let disallowed_mode_mask = passphrase_disallowed_mode_mask(path);
    validate_file_security(
        path,
        "wireguard key passphrase credential",
        disallowed_mode_mask,
        allow_root_owner,
    )
}

fn is_systemd_runtime_credential_path(path: &Path) -> bool {
    path.starts_with("/run/credentials/")
}

fn passphrase_disallowed_mode_mask(path: &Path) -> u32 {
    if is_systemd_runtime_credential_path(path) {
        // systemd runtime credentials are typically provisioned as 0440 root:<service-group>
        // and should still reject any write/execute bit or any "other" access.
        0o337
    } else {
        0o077
    }
}

#[cfg(target_os = "linux")]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022, false)
}

#[cfg(not(target_os = "linux"))]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022, false)
}

#[cfg(target_os = "linux")]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o037, true)
}

fn load_trust_evidence(
    path: &Path,
    verifier_key_path: &Path,
    trust_policy: TrustPolicy,
    previous_watermark: Option<TrustWatermark>,
) -> Result<TrustEvidenceEnvelope, TrustBootstrapError> {
    if !path.exists() {
        return Err(TrustBootstrapError::Missing);
    }

    let verifying_key = load_verifying_key(verifier_key_path)?;
    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut tls13_valid: Option<bool> = None;
    let mut signed_control_valid: Option<bool> = None;
    let mut signed_data_age_secs: Option<u64> = None;
    let mut clock_skew_secs: Option<u64> = None;
    let mut updated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut signature_hex: Option<String> = None;

    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TrustBootstrapError::InvalidFormat(
                "line missing key/value separator".to_string(),
            ));
        };

        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "tls13_valid" => {
                tls13_valid = parse_bool(value);
            }
            "signed_control_valid" => {
                signed_control_valid = parse_bool(value);
            }
            "signed_data_age_secs" => {
                signed_data_age_secs = value.parse::<u64>().ok();
            }
            "clock_skew_secs" => {
                clock_skew_secs = value.parse::<u64>().ok();
            }
            "updated_at_unix" => {
                updated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "signature" => {
                signature_hex = Some(value.to_string());
            }
            _ => {
                return Err(TrustBootstrapError::InvalidFormat(format!(
                    "unknown key {key}"
                )));
            }
        }
    }

    if version != Some(2) {
        return Err(TrustBootstrapError::InvalidFormat(
            "unsupported trust evidence version".to_string(),
        ));
    }

    let record = TrustEvidenceRecord {
        tls13_valid: tls13_valid
            .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing tls13_valid".to_string()))?,
        signed_control_valid: signed_control_valid.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing signed_control_valid".to_string())
        })?,
        signed_data_age_secs: signed_data_age_secs.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing signed_data_age_secs".to_string())
        })?,
        clock_skew_secs: clock_skew_secs.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing clock_skew_secs".to_string())
        })?,
        updated_at_unix: updated_at_unix.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing updated_at_unix".to_string())
        })?,
        nonce: nonce
            .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing nonce".to_string()))?,
    };

    let signature_hex = signature_hex.ok_or_else(|| {
        TrustBootstrapError::InvalidFormat("missing trust evidence signature".to_string())
    })?;
    let signature_bytes = decode_hex_to_fixed::<64>(&signature_hex).map_err(|_| {
        TrustBootstrapError::InvalidFormat("invalid signature encoding".to_string())
    })?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = trust_evidence_payload(&record);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TrustBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if record.updated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(TrustBootstrapError::FutureDated);
    }

    let age = now.saturating_sub(record.updated_at_unix);
    if age > trust_policy.max_signed_data_age_secs {
        return Err(TrustBootstrapError::Stale);
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = TrustWatermark {
        updated_at_unix: record.updated_at_unix,
        nonce: record.nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match compare_trust_watermark_generation(&watermark, &existing) {
            std::cmp::Ordering::Less => return Err(TrustBootstrapError::ReplayDetected),
            std::cmp::Ordering::Equal => {
                if existing.payload_digest != Some(payload_digest) {
                    return Err(TrustBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    Ok(TrustEvidenceEnvelope {
        evidence: TrustEvidence {
            tls13_valid: record.tls13_valid,
            signed_control_valid: record.signed_control_valid,
            signed_data_age_secs: record.signed_data_age_secs,
            clock_skew_secs: record.clock_skew_secs,
        },
        watermark,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustEvidenceRecord {
    tls13_valid: bool,
    signed_control_valid: bool,
    signed_data_age_secs: u64,
    clock_skew_secs: u64,
    updated_at_unix: u64,
    nonce: u64,
}

fn trust_evidence_payload(record: &TrustEvidenceRecord) -> String {
    format!(
        "version=2\ntls13_valid={}\nsigned_control_valid={}\nsigned_data_age_secs={}\nclock_skew_secs={}\nupdated_at_unix={}\nnonce={}\n",
        if record.tls13_valid { "true" } else { "false" },
        if record.signed_control_valid {
            "true"
        } else {
            "false"
        },
        record.signed_data_age_secs,
        record.clock_skew_secs,
        record.updated_at_unix,
        record.nonce
    )
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn compare_trust_watermark_generation(
    incoming: &TrustWatermark,
    existing: &TrustWatermark,
) -> std::cmp::Ordering {
    (incoming.updated_at_unix, incoming.nonce).cmp(&(existing.updated_at_unix, existing.nonce))
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], TrustBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(TrustBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_hex_nibble(raw[index * 2])?;
        let lo = decode_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, TrustBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TrustBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, TrustBootstrapError> {
    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing verifier key".to_string()))?;
    let key_bytes = decode_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| TrustBootstrapError::KeyInvalid)
}

fn load_trust_watermark(path: &Path) -> Result<Option<TrustWatermark>, TrustBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut updated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TrustBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "updated_at_unix" => {
                updated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "payload_digest_sha256" => {
                payload_digest = Some(decode_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(TrustBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let version = version.ok_or_else(|| {
        TrustBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(TrustBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    Ok(Some(TrustWatermark {
        updated_at_unix: updated_at_unix.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark updated_at_unix".to_string())
        })?,
        nonce: nonce.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark nonce".to_string())
        })?,
        payload_digest: Some(payload_digest.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat(
                "missing watermark payload_digest_sha256".to_string(),
            )
        })?),
    }))
}

fn persist_trust_watermark(
    path: &Path,
    watermark: TrustWatermark,
) -> Result<(), TrustBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload = format!(
        "version=2\nupdated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.updated_at_unix,
        watermark.nonce,
        encode_hex(&watermark.payload_digest.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat(
                "watermark payload digest must be present".to_string(),
            )
        })?)
    );
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn load_membership_watermark(path: &Path) -> Result<Option<MembershipWatermark>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut version: Option<u8> = None;
    let mut epoch: Option<u64> = None;
    let mut state_root: Option<String> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("membership watermark line missing key/value separator".to_string());
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "epoch" => {
                epoch = value.parse::<u64>().ok();
            }
            "state_root" => {
                state_root = Some(value.to_string());
            }
            _ => return Err(format!("unknown membership watermark key {key}")),
        }
    }
    if version != Some(1) {
        return Err("unsupported membership watermark version".to_string());
    }
    Ok(Some(MembershipWatermark {
        epoch: epoch.ok_or_else(|| "missing membership watermark epoch".to_string())?,
        state_root: state_root
            .ok_or_else(|| "missing membership watermark state_root".to_string())?,
    }))
}

fn persist_membership_watermark(
    path: &Path,
    watermark: &MembershipWatermark,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
        }
    }
    let payload = format!(
        "version=1\nepoch={}\nstate_root={}\n",
        watermark.epoch, watermark.state_root
    );
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options.open(&temp_path).map_err(|err| err.to_string())?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    if let Some(parent) = path.parent() {
        let parent_dir = fs::File::open(parent).map_err(|err| err.to_string())?;
        parent_dir.sync_all().map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn load_auto_tunnel_bundle(
    path: &Path,
    verifier_key_path: &Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<AutoTunnelWatermark>,
) -> Result<AutoTunnelBundleEnvelope, AutoTunnelBootstrapError> {
    if !path.exists() {
        return Err(AutoTunnelBootstrapError::Missing);
    }

    let verifying_key = load_auto_tunnel_verifying_key(verifier_key_path)?;
    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;

    let mut payload = String::new();
    let mut signature_hex: Option<String> = None;
    let mut fields = std::collections::HashMap::new();

    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(AutoTunnelBootstrapError::InvalidFormat(
                "line missing key/value separator".to_string(),
            ));
        };
        if key == "signature" {
            signature_hex = Some(value.to_string());
            continue;
        }
        payload.push_str(line);
        payload.push('\n');
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "duplicate key {key}"
            )));
        }
    }

    let version = fields
        .get("version")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing version".to_string()))?;
    if version != "1" {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unsupported bundle version".to_string(),
        ));
    }

    let node_id = fields
        .get("node_id")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing node_id".to_string()))?
        .to_string();
    NodeId::new(node_id.clone())
        .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;

    let mesh_cidr = fields
        .get("mesh_cidr")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing mesh_cidr".to_string()))?
        .to_string();
    if !is_valid_ipv4_or_ipv6_cidr(&mesh_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid mesh_cidr".to_string(),
        ));
    }

    let assigned_cidr = fields
        .get("assigned_cidr")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing assigned_cidr".to_string())
        })?
        .to_string();
    if !is_valid_ipv4_or_ipv6_cidr(&assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid assigned_cidr".to_string(),
        ));
    }
    if !is_host_cidr(&assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "assigned_cidr must be a host cidr".to_string(),
        ));
    }
    if !cidr_contains(&mesh_cidr, &assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "assigned_cidr is outside mesh_cidr".to_string(),
        ));
    }

    let generated_at_unix = fields
        .get("generated_at_unix")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing generated_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat("invalid generated_at_unix".to_string())
        })?;
    let expires_at_unix = fields
        .get("expires_at_unix")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing expires_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat("invalid expires_at_unix".to_string())
        })?;
    if generated_at_unix >= expires_at_unix {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
        ));
    }

    let nonce = fields
        .get("nonce")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing nonce".to_string()))?
        .parse::<u64>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid nonce".to_string()))?;

    let signature_hex = signature_hex.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing bundle signature".to_string())
    })?;
    let signature_bytes = decode_auto_tunnel_hex_to_fixed::<64>(&signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| AutoTunnelBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if generated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(AutoTunnelBootstrapError::FutureDated);
    }
    if now > expires_at_unix || now.saturating_sub(generated_at_unix) > max_age_secs {
        return Err(AutoTunnelBootstrapError::Stale);
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = AutoTunnelWatermark {
        generated_at_unix,
        nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match auto_tunnel_watermark_ordering(&watermark, &existing) {
            std::cmp::Ordering::Less => {
                return Err(AutoTunnelBootstrapError::ReplayDetected);
            }
            std::cmp::Ordering::Equal => {
                let existing_digest = existing
                    .payload_digest
                    .ok_or(AutoTunnelBootstrapError::ReplayDetected)?;
                if existing_digest != payload_digest {
                    return Err(AutoTunnelBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    let peer_count = fields
        .get("peer_count")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing peer_count".to_string()))?
        .parse::<usize>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid peer_count".to_string()))?;
    let mut peers = Vec::with_capacity(peer_count);
    for index in 0..peer_count {
        let node_id_key = format!("peer.{index}.node_id");
        let endpoint_key = format!("peer.{index}.endpoint");
        let public_key_key = format!("peer.{index}.public_key_hex");
        let allowed_ips_key = format!("peer.{index}.allowed_ips");

        let peer_node = fields.get(&node_id_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {node_id_key}"))
        })?;
        let peer_node_id = NodeId::new(peer_node.clone())
            .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;

        let endpoint_raw = fields.get(&endpoint_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {endpoint_key}"))
        })?;
        let endpoint = endpoint_raw.parse::<std::net::SocketAddr>().map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat(format!("invalid endpoint {endpoint_key}"))
        })?;

        let public_key_hex = fields.get(&public_key_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {public_key_key}"))
        })?;
        let public_key = decode_auto_tunnel_hex_to_fixed::<32>(public_key_hex)?;

        let allowed_ips_raw = fields.get(&allowed_ips_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {allowed_ips_key}"))
        })?;
        let allowed_ips = allowed_ips_raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if allowed_ips.is_empty()
            || allowed_ips
                .iter()
                .any(|cidr| !is_valid_ipv4_or_ipv6_cidr(cidr))
        {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "invalid allowed_ips for peer {index}"
            )));
        }

        peers.push(PeerConfig {
            node_id: peer_node_id,
            endpoint: rustynet_backend_api::SocketEndpoint {
                addr: endpoint.ip(),
                port: endpoint.port(),
            },
            public_key,
            allowed_ips,
        });
    }

    let route_count = fields
        .get("route_count")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing route_count".to_string()))?
        .parse::<usize>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid route_count".to_string()))?;
    let mut routes = Vec::with_capacity(route_count);
    let mut selected_exit_node: Option<String> = None;
    for index in 0..route_count {
        let destination_key = format!("route.{index}.destination_cidr");
        let via_node_key = format!("route.{index}.via_node");
        let kind_key = format!("route.{index}.kind");

        let destination_cidr = fields.get(&destination_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {destination_key}"))
        })?;
        if !is_valid_ipv4_or_ipv6_cidr(destination_cidr) {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "invalid destination cidr for route {index}"
            )));
        }
        let via_node_raw = fields.get(&via_node_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {via_node_key}"))
        })?;
        let via_node = NodeId::new(via_node_raw.clone())
            .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;
        let kind = match fields.get(&kind_key).map(String::as_str) {
            Some("mesh") => RouteKind::Mesh,
            Some("exit_lan") => RouteKind::ExitNodeLan,
            Some("exit_default") => RouteKind::ExitNodeDefault,
            _ => {
                return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                    "invalid route kind for route {index}"
                )));
            }
        };
        if matches!(kind, RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan) {
            let via = via_node.as_str().to_string();
            if let Some(existing) = selected_exit_node.as_deref() {
                if existing != via {
                    return Err(AutoTunnelBootstrapError::InvalidFormat(
                        "exit routes reference multiple exit nodes".to_string(),
                    ));
                }
            }
            selected_exit_node = Some(via);
        }

        routes.push(Route {
            destination_cidr: destination_cidr.clone(),
            via_node,
            kind,
        });
    }

    Ok(AutoTunnelBundleEnvelope {
        bundle: AutoTunnelBundle {
            node_id,
            mesh_cidr,
            assigned_cidr,
            peers,
            routes,
            selected_exit_node,
        },
        watermark,
    })
}

fn load_auto_tunnel_verifying_key(path: &Path) -> Result<VerifyingKey, AutoTunnelBootstrapError> {
    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing verifier key".to_string())
        })?;
    let key_bytes = decode_auto_tunnel_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| AutoTunnelBootstrapError::KeyInvalid)
}

fn decode_auto_tunnel_hex_to_fixed<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], AutoTunnelBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_auto_tunnel_hex_nibble(raw[index * 2])?;
        let lo = decode_auto_tunnel_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_auto_tunnel_hex_nibble(value: u8) -> Result<u8, AutoTunnelBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn auto_tunnel_watermark_ordering(
    current: &AutoTunnelWatermark,
    previous: &AutoTunnelWatermark,
) -> std::cmp::Ordering {
    current
        .generated_at_unix
        .cmp(&previous.generated_at_unix)
        .then(current.nonce.cmp(&previous.nonce))
}

fn load_auto_tunnel_watermark(
    path: &Path,
) -> Result<Option<AutoTunnelWatermark>, AutoTunnelBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut generated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(AutoTunnelBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "generated_at_unix" => {
                generated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "payload_digest_sha256" => {
                payload_digest = Some(decode_auto_tunnel_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let generated_at_unix = generated_at_unix.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark generated_at_unix".to_string())
    })?;
    let nonce = nonce.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark nonce".to_string())
    })?;
    let version = version.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    let payload_digest = Some(payload_digest.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat(
            "missing watermark payload_digest_sha256".to_string(),
        )
    })?);
    Ok(Some(AutoTunnelWatermark {
        generated_at_unix,
        nonce,
        payload_digest,
    }))
}

fn persist_auto_tunnel_watermark(
    path: &Path,
    watermark: AutoTunnelWatermark,
) -> Result<(), AutoTunnelBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload_digest = watermark
        .payload_digest
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(
                "watermark payload digest is required".to_string(),
            )
        })
        .map(|digest| encode_hex(&digest))?;
    let payload = format!(
        "version=2\ngenerated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.generated_at_unix, watermark.nonce, payload_digest
    );
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn load_traversal_bundle(
    path: &Path,
    verifier_key_path: &Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<TraversalWatermark>,
) -> Result<TraversalBundleEnvelope, TraversalBootstrapError> {
    if !path.exists() {
        return Err(TraversalBootstrapError::Missing);
    }

    let verifying_key = load_traversal_verifying_key(verifier_key_path)?;
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;

    let mut payload = String::new();
    let mut signature_hex: Option<String> = None;
    let mut fields = std::collections::HashMap::new();

    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TraversalBootstrapError::InvalidFormat(
                "line missing key/value separator".to_string(),
            ));
        };
        if key == "signature" {
            signature_hex = Some(value.to_string());
            continue;
        }
        payload.push_str(line);
        payload.push('\n');
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "duplicate key {key}"
            )));
        }
    }

    let version = fields
        .get("version")
        .ok_or_else(|| TraversalBootstrapError::InvalidFormat("missing version".to_string()))?;
    if version != "1" {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported traversal version".to_string(),
        ));
    }
    if fields.get("path_policy").map(String::as_str) != Some("direct_preferred_relay_allowed") {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported traversal path_policy".to_string(),
        ));
    }

    let source_node_id = fields
        .get("source_node_id")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing source_node_id".to_string())
        })?
        .to_string();
    NodeId::new(source_node_id.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;
    let target_node_id = fields
        .get("target_node_id")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing target_node_id".to_string())
        })?
        .to_string();
    NodeId::new(target_node_id.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;

    let generated_at_unix = fields
        .get("generated_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing generated_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid generated_at_unix".to_string())
        })?;
    let expires_at_unix = fields
        .get("expires_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing expires_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid expires_at_unix".to_string())
        })?;
    if generated_at_unix >= expires_at_unix {
        return Err(TraversalBootstrapError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
        ));
    }
    let nonce = fields
        .get("nonce")
        .ok_or_else(|| TraversalBootstrapError::InvalidFormat("missing nonce".to_string()))?
        .parse::<u64>()
        .map_err(|_| TraversalBootstrapError::InvalidFormat("invalid nonce".to_string()))?;

    let signature_hex = signature_hex.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing traversal signature".to_string())
    })?;
    let signature_bytes = decode_traversal_hex_to_fixed::<64>(&signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TraversalBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if generated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(TraversalBootstrapError::FutureDated);
    }
    if now > expires_at_unix || now.saturating_sub(generated_at_unix) > max_age_secs {
        return Err(TraversalBootstrapError::Stale);
    }

    let candidate_count = fields
        .get("candidate_count")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing candidate_count".to_string())
        })?
        .parse::<usize>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid candidate_count".to_string())
        })?;
    if candidate_count == 0 || candidate_count > 8 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "candidate_count must be between 1 and 8".to_string(),
        ));
    }

    let mut candidates = Vec::with_capacity(candidate_count);
    let mut seen = std::collections::HashSet::new();
    for index in 0..candidate_count {
        let candidate_type_key = format!("candidate.{index}.type");
        let addr_key = format!("candidate.{index}.addr");
        let port_key = format!("candidate.{index}.port");
        let family_key = format!("candidate.{index}.family");
        let relay_id_key = format!("candidate.{index}.relay_id");
        let priority_key = format!("candidate.{index}.priority");

        let candidate_type = match fields.get(&candidate_type_key).map(String::as_str) {
            Some("host") => TraversalCandidateType::Host,
            Some("srflx") => TraversalCandidateType::ServerReflexive,
            Some("relay") => TraversalCandidateType::Relay,
            _ => {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate type for index {index}"
                )));
            }
        };

        let ip = fields
            .get(&addr_key)
            .ok_or_else(|| TraversalBootstrapError::InvalidFormat(format!("missing {addr_key}")))?
            .parse::<std::net::IpAddr>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate addr for index {index}"
                ))
            })?;
        validate_traversal_candidate_ip(candidate_type, ip, index)?;
        let family = fields.get(&family_key).ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(format!("missing {family_key}"))
        })?;
        if (ip.is_ipv4() && family != "ipv4") || (ip.is_ipv6() && family != "ipv6") {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "candidate family mismatch for index {index}"
            )));
        }
        let port = fields
            .get(&port_key)
            .ok_or_else(|| TraversalBootstrapError::InvalidFormat(format!("missing {port_key}")))?
            .parse::<u16>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate port for index {index}"
                ))
            })?;
        if port == 0 {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "candidate port must be non-zero for index {index}"
            )));
        }

        let relay_id_raw = fields.get(&relay_id_key).ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(format!("missing {relay_id_key}"))
        })?;
        let relay_id = if relay_id_raw.trim().is_empty() {
            None
        } else {
            Some(relay_id_raw.trim().to_string())
        };
        if matches!(candidate_type, TraversalCandidateType::Relay) && relay_id.is_none() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "relay candidate missing relay_id for index {index}"
            )));
        }
        if !matches!(candidate_type, TraversalCandidateType::Relay) && relay_id.is_some() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "relay_id is only allowed for relay candidates (index {index})"
            )));
        }

        let priority = fields
            .get(&priority_key)
            .ok_or_else(|| {
                TraversalBootstrapError::InvalidFormat(format!("missing {priority_key}"))
            })?
            .parse::<u32>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate priority for index {index}"
                ))
            })?;
        let dedupe = format!(
            "{}|{}|{}|{}",
            candidate_type.as_str(),
            ip,
            port,
            relay_id.as_deref().unwrap_or("")
        );
        if !seen.insert(dedupe) {
            return Err(TraversalBootstrapError::InvalidFormat(
                "duplicate traversal candidate tuple".to_string(),
            ));
        }

        candidates.push(TraversalCandidate {
            candidate_type,
            endpoint: std::net::SocketAddr::new(ip, port),
            relay_id,
            priority,
        });
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = TraversalWatermark {
        generated_at_unix,
        nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match traversal_watermark_ordering(&watermark, &existing) {
            std::cmp::Ordering::Less => {
                return Err(TraversalBootstrapError::ReplayDetected);
            }
            std::cmp::Ordering::Equal => {
                let existing_digest = existing
                    .payload_digest
                    .ok_or(TraversalBootstrapError::ReplayDetected)?;
                if existing_digest != payload_digest {
                    return Err(TraversalBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    Ok(TraversalBundleEnvelope {
        bundle: TraversalBundle {
            source_node_id,
            target_node_id,
            generated_at_unix,
            expires_at_unix,
            nonce,
            candidates,
        },
        watermark,
    })
}

fn validate_traversal_candidate_ip(
    candidate_type: TraversalCandidateType,
    ip: std::net::IpAddr,
    index: usize,
) -> Result<(), TraversalBootstrapError> {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "candidate index {index} uses disallowed special address"
        )));
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_link_local() || v4.is_broadcast() {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "candidate index {index} uses disallowed special address"
                )));
            }
            if matches!(candidate_type, TraversalCandidateType::ServerReflexive)
                && !is_global_unicast_ipv4(v4)
            {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "srflx candidate index {index} must use global unicast address"
                )));
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() || v6.is_unique_local() {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "candidate index {index} uses disallowed special address"
                )));
            }
            if matches!(candidate_type, TraversalCandidateType::ServerReflexive)
                && !is_global_unicast_ipv6(v6)
            {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "srflx candidate index {index} must use global unicast address"
                )));
            }
        }
    }
    Ok(())
}

fn is_global_unicast_ipv4(value: std::net::Ipv4Addr) -> bool {
    if value.is_private()
        || value.is_loopback()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || value.is_unspecified()
        || value.is_documentation()
    {
        return false;
    }
    let octets = value.octets();
    // Shared Address Space (100.64.0.0/10) and benchmarking space (198.18.0.0/15).
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    true
}

fn is_global_unicast_ipv6(value: std::net::Ipv6Addr) -> bool {
    if value.is_unspecified()
        || value.is_loopback()
        || value.is_multicast()
        || value.is_unicast_link_local()
        || value.is_unique_local()
    {
        return false;
    }
    // Documentation range 2001:db8::/32.
    let segments = value.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    true
}

fn load_traversal_verifying_key(path: &Path) -> Result<VerifyingKey, TraversalBootstrapError> {
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing verifier key".to_string())
        })?;
    let key_bytes = decode_traversal_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| TraversalBootstrapError::KeyInvalid)
}

fn decode_traversal_hex_to_fixed<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], TraversalBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_traversal_hex_nibble(raw[index * 2])?;
        let lo = decode_traversal_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_traversal_hex_nibble(value: u8) -> Result<u8, TraversalBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TraversalBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn traversal_watermark_ordering(
    current: &TraversalWatermark,
    previous: &TraversalWatermark,
) -> std::cmp::Ordering {
    current
        .generated_at_unix
        .cmp(&previous.generated_at_unix)
        .then(current.nonce.cmp(&previous.nonce))
}

fn load_traversal_watermark(
    path: &Path,
) -> Result<Option<TraversalWatermark>, TraversalBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut generated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TraversalBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => version = value.parse::<u8>().ok(),
            "generated_at_unix" => generated_at_unix = value.parse::<u64>().ok(),
            "nonce" => nonce = value.parse::<u64>().ok(),
            "payload_digest_sha256" => {
                payload_digest = Some(decode_traversal_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let generated_at_unix = generated_at_unix.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark generated_at_unix".to_string())
    })?;
    let nonce = nonce.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark nonce".to_string())
    })?;
    let version = version.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    let payload_digest = Some(payload_digest.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat(
            "missing watermark payload_digest_sha256".to_string(),
        )
    })?);
    Ok(Some(TraversalWatermark {
        generated_at_unix,
        nonce,
        payload_digest,
    }))
}

fn persist_traversal_watermark(
    path: &Path,
    watermark: TraversalWatermark,
) -> Result<(), TraversalBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload_digest = watermark
        .payload_digest
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(
                "watermark payload digest is required".to_string(),
            )
        })
        .map(|digest| encode_hex(&digest))?;
    let payload = format!(
        "version=2\ngenerated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.generated_at_unix, watermark.nonce, payload_digest
    );
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn is_valid_ipv4_or_ipv6_cidr(value: &str) -> bool {
    parse_cidr(value).is_some()
}

fn is_host_cidr(value: &str) -> bool {
    match parse_cidr(value) {
        Some((std::net::IpAddr::V4(_), prefix)) => prefix == 32,
        Some((std::net::IpAddr::V6(_), prefix)) => prefix == 128,
        None => false,
    }
}

fn cidr_contains(container: &str, candidate: &str) -> bool {
    let Some((container_ip, container_prefix)) = parse_cidr(container) else {
        return false;
    };
    let Some((candidate_ip, candidate_prefix)) = parse_cidr(candidate) else {
        return false;
    };
    if candidate_prefix < container_prefix {
        return false;
    }
    match (container_ip, candidate_ip) {
        (std::net::IpAddr::V4(container_v4), std::net::IpAddr::V4(candidate_v4)) => {
            let mask = if container_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - container_prefix)
            };
            (u32::from(container_v4) & mask) == (u32::from(candidate_v4) & mask)
        }
        (std::net::IpAddr::V6(container_v6), std::net::IpAddr::V6(candidate_v6)) => {
            let container_raw = u128::from_be_bytes(container_v6.octets());
            let candidate_raw = u128::from_be_bytes(candidate_v6.octets());
            let mask = if container_prefix == 0 {
                0
            } else {
                u128::MAX << (128 - container_prefix)
            };
            (container_raw & mask) == (candidate_raw & mask)
        }
        _ => false,
    }
}

fn parse_cidr(value: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip_part, prefix_part) = value.split_once('/')?;
    let ip = ip_part.parse::<std::net::IpAddr>().ok()?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    let valid = match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    };
    if valid { Some((ip, prefix)) } else { None }
}

#[cfg(target_os = "linux")]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_traversal_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal bundle", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_traversal_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal bundle", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_traversal_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_traversal_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022, true)
}

fn validate_file_security(
    path: &Path,
    label: &str,
    disallowed_mode_mask: u32,
    allow_root_owner: bool,
) -> Result<(), DaemonError> {
    let link_metadata = fs::symlink_metadata(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("{label} metadata read failed: {err}"))
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must not be a symlink"
        )));
    }
    if !link_metadata.file_type().is_file() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must be a regular file"
        )));
    }

    let metadata = fs::metadata(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("{label} metadata read failed: {err}"))
    })?;
    let mode = metadata.permissions().mode();
    if mode & disallowed_mode_mask != 0 {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} has insecure permissions: mode {:o}",
            mode & 0o777
        )));
    }

    let owner_uid = metadata.uid();
    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid && !(allow_root_owner && owner_uid == 0) {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} owner uid mismatch: expected {expected_uid}, got {owner_uid}"
        )));
    }
    fs::File::open(path).map_err(|err| {
        DaemonError::InvalidConfig(format!(
            "{label} is not readable by runtime user (uid {expected_uid}): {err}"
        ))
    })?;
    Ok(())
}

fn read_command(stream: &UnixStream) -> Result<String, String> {
    let reader = BufReader::new(stream);
    let mut limited = reader.take(4097);
    let mut bytes = Vec::new();
    limited
        .read_until(b'\n', &mut bytes)
        .map_err(|err| format!("read failed: {err}"))?;
    if bytes.len() > 4096 {
        return Err("command too long".to_string());
    }
    if bytes.contains(&b'\0') {
        return Err("command contains null byte".to_string());
    }
    let line = String::from_utf8(bytes).map_err(|_| "command is not valid utf-8".to_string())?;
    Ok(line.trim().to_string())
}

fn write_response(mut stream: UnixStream, response: IpcResponse) -> Result<(), String> {
    stream
        .write_all(format!("{}\n", response.to_wire()).as_bytes())
        .map_err(|err| format!("write failed: {err}"))
}

fn socket_owner_uid(path: &Path) -> Result<u32, DaemonError> {
    let metadata = fs::metadata(path).map_err(|err| DaemonError::Io(err.to_string()))?;
    Ok(metadata.uid())
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return getsockopt(stream, PeerCredentials)
            .ok()
            .map(|cred| cred.uid());
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return getsockopt(stream, LocalPeerCred)
            .ok()
            .map(|cred| cred.uid());
    }

    #[allow(unreachable_code)]
    None
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sanitize_netcheck_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | ':' | '.' | '/' | '+' => ch,
            _ => '_',
        })
        .collect()
}

fn membership_directory_from_state(state: &MembershipState) -> MembershipDirectory {
    let mut directory = MembershipDirectory::default();
    for node in &state.nodes {
        let status = match node.status {
            MembershipNodeStatus::Active => MembershipStatus::Active,
            MembershipNodeStatus::Revoked | MembershipNodeStatus::Quarantined => {
                MembershipStatus::Revoked
            }
        };
        directory.set_node_status(node.node_id.clone(), status);
    }
    directory
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::num::NonZeroU32;
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
        persist_membership_snapshot,
    };

    use super::{
        AutoTunnelWatermark, DEFAULT_TRAVERSAL_MAX_AGE_SECS, DaemonBackendMode, DaemonConfig,
        DaemonRuntime, IpcCommand, NodeRole, TrustEvidenceRecord, TrustPolicy, TrustWatermark,
        load_auto_tunnel_bundle, load_auto_tunnel_watermark, load_traversal_bundle,
        load_traversal_watermark, load_trust_evidence, load_trust_watermark,
        passphrase_disallowed_mode_mask, persist_auto_tunnel_watermark,
        persist_traversal_watermark, persist_trust_watermark,
        prepare_runtime_wireguard_key_material, run_daemon, run_preflight_checks,
        scrub_runtime_wireguard_key_material, sha256_digest, trust_evidence_payload, unix_now,
        validate_daemon_config, zeroize_optional_bytes,
    };

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn passphrase_permission_mask_accepts_systemd_runtime_credential_mode() {
        assert_eq!(
            passphrase_disallowed_mode_mask(Path::new(
                "/run/credentials/rustynetd.service/wg_key_passphrase"
            )),
            0o337
        );
        assert_eq!(
            passphrase_disallowed_mode_mask(Path::new(
                "/var/lib/rustynet/keys/wireguard.passphrase"
            )),
            0o077
        );
    }

    fn write_trust_file(path: &Path, verifier_path: &Path, nonce: u64) {
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce,
        };
        write_trust_file_with_record(path, verifier_path, record);
    }

    fn write_trust_file_with_record(
        path: &Path,
        verifier_path: &Path,
        record: TrustEvidenceRecord,
    ) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("verifier key permissions should be secure");
        }
        let body = trust_evidence_payload(&record);
        let signature = signing_key.sign(body.as_bytes());
        std::fs::write(
            path,
            format!("{body}signature={}\n", hex_encode(&signature.to_bytes())),
        )
        .expect("trust file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("trust evidence permissions should be secure");
        }
    }

    fn write_auto_tunnel_file(
        path: &Path,
        verifier_path: &Path,
        node_id: &str,
        nonce: u64,
        tamper_after_sign: bool,
    ) {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("auto tunnel verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(300);
        let peer_public = hex_encode(&[9u8; 32]);
        let payload = format!(
            "version=1\nnode_id={node_id}\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npeer_count=1\npeer.0.node_id=node-exit\npeer.0.endpoint=203.0.113.20:51820\npeer.0.public_key_hex={peer_public}\npeer.0.allowed_ips=100.64.0.2/32\nroute_count=1\nroute.0.destination_cidr=0.0.0.0/0\nroute.0.via_node=node-exit\nroute.0.kind=exit_default\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if tamper_after_sign {
            body = body.replace("route_count=1", "route_count=2");
        }
        std::fs::write(path, body).expect("auto tunnel file should be written");
    }

    fn write_auto_tunnel_file_exitless(
        path: &Path,
        verifier_path: &Path,
        node_id: &str,
        nonce: u64,
    ) {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("auto tunnel verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(300);
        let peer_public = hex_encode(&[9u8; 32]);
        let payload = format!(
            "version=1\nnode_id={node_id}\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npeer_count=1\npeer.0.node_id=node-exit\npeer.0.endpoint=203.0.113.21:51820\npeer.0.public_key_hex={peer_public}\npeer.0.allowed_ips=100.64.0.2/32\nroute_count=0\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("auto tunnel file should be written");
    }

    fn write_traversal_file_with_srflx(
        path: &Path,
        verifier_path: &Path,
        nonce: u64,
        srflx_addr: &str,
        tamper_after_sign: bool,
    ) {
        let signing_key = SigningKey::from_bytes(&[29u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(DEFAULT_TRAVERSAL_MAX_AGE_SECS);
        let payload = format!(
            "version=1\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npath_policy=direct_preferred_relay_allowed\ncandidate_count=3\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.10\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=900\ncandidate.1.type=srflx\ncandidate.1.addr={srflx_addr}\ncandidate.1.port=62000\ncandidate.1.family=ipv4\ncandidate.1.relay_id=\ncandidate.1.priority=850\ncandidate.2.type=relay\ncandidate.2.addr=198.51.100.40\ncandidate.2.port=51820\ncandidate.2.family=ipv4\ncandidate.2.relay_id=relay-eu-1\ncandidate.2.priority=700\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if tamper_after_sign {
            body = body.replace("candidate.2.priority=700", "candidate.2.priority=701");
        }
        std::fs::write(path, body).expect("traversal file should be written");
    }

    fn write_traversal_file(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        tamper_after_sign: bool,
    ) {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.77\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-1\ncandidate.1.priority=20\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if tamper_after_sign {
            body = body.replace("candidate_count=2", "candidate_count=3");
        }
        std::fs::write(path, body).expect("traversal file should be written");
    }

    fn write_membership_files(snapshot_path: &Path, log_path: &Path, local_node_id: &str) {
        write_membership_files_with_exit_status(
            snapshot_path,
            log_path,
            local_node_id,
            MembershipNodeStatus::Active,
        );
    }

    fn write_membership_files_with_exit_status(
        snapshot_path: &Path,
        log_path: &Path,
        local_node_id: &str,
        exit_status: MembershipNodeStatus,
    ) {
        let owner_signing = SigningKey::from_bytes(&[7; 32]);
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-test".to_string(),
            epoch: 1,
            nodes: vec![
                MembershipNode {
                    node_id: local_node_id.to_string(),
                    node_pubkey_hex: hex_encode(&[9; 32]),
                    owner: "owner@example.local".to_string(),
                    status: MembershipNodeStatus::Active,
                    roles: vec!["tag:servers".to_string()],
                    joined_at_unix: 100,
                    updated_at_unix: 100,
                },
                MembershipNode {
                    node_id: "node-exit".to_string(),
                    node_pubkey_hex: hex_encode(&[11; 32]),
                    owner: "owner@example.local".to_string(),
                    status: exit_status,
                    roles: vec!["tag:exit".to_string()],
                    joined_at_unix: 100,
                    updated_at_unix: 100,
                },
            ],
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_string(),
                approver_pubkey_hex: hex_encode(owner_signing.verifying_key().as_bytes()),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        persist_membership_snapshot(snapshot_path, &state)
            .expect("membership snapshot should be written");
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).expect("membership log parent should exist");
        }
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(log_path)
            .expect("membership log should be opened");
        file.write_all(b"version=1\n")
            .expect("membership log should be written");
    }

    fn secure_test_dir(prefix: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{unique}"));
        std::fs::create_dir_all(&dir).expect("secure test directory should be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("secure test directory permissions should be set");
        }
        dir
    }

    #[test]
    fn run_daemon_rejects_in_memory_backend_mode() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let err = run_daemon(config).expect_err("in-memory backend must be rejected");
        assert!(err.to_string().contains("in-memory backend is disabled"));
    }

    #[test]
    fn validate_daemon_config_rejects_fail_closed_ssh_allow_without_cidrs() {
        let config = DaemonConfig {
            fail_closed_ssh_allow: true,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("fail-closed ssh allow must require management cidrs");
        assert!(err.to_string().contains("at least one management cidr"));
    }

    #[test]
    fn validate_daemon_config_rejects_auto_port_forward_short_lease() {
        let config = DaemonConfig {
            auto_port_forward_lease_secs: NonZeroU32::new(59)
                .expect("non-zero auto port-forward lease for test"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("short auto port-forward lease should be rejected");
        assert!(err.to_string().contains("at least 60 seconds"));
    }

    #[test]
    fn validate_daemon_config_rejects_auto_port_forward_on_non_linux_backend() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::MacosWireguard,
            auto_port_forward_exit: true,
            auto_port_forward_lease_secs: NonZeroU32::new(1200)
                .expect("non-zero auto port-forward lease for test"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("auto port-forward should be linux-wireguard only");
        assert!(
            err.to_string()
                .contains("supported only with linux-wireguard backend")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_relative_traversal_paths() {
        let config = DaemonConfig {
            traversal_bundle_path: std::path::PathBuf::from("relative.traversal"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("relative traversal bundle path must be rejected");
        assert!(
            err.to_string()
                .contains("traversal bundle path must be absolute")
        );
    }

    #[test]
    fn zeroize_optional_bytes_scrubs_sensitive_buffer() {
        let mut value = Some(vec![7u8, 9u8, 13u8, 17u8]);
        zeroize_optional_bytes(&mut value);
        assert_eq!(value, Some(vec![0u8, 0u8, 0u8, 0u8]));
    }

    #[test]
    fn runtime_key_prepare_requires_plaintext_key_when_encrypted_store_disabled() {
        let test_dir = secure_test_dir("rustynetd-runtime-key-prepare-plaintext");
        let runtime_key_path = test_dir.join("wireguard.key");

        let err = prepare_runtime_wireguard_key_material(
            DaemonBackendMode::LinuxWireguard,
            Some(runtime_key_path.as_path()),
            None,
            None,
        )
        .expect_err("missing plaintext runtime key must be rejected");
        assert!(err.contains("wireguard private key"));

        std::fs::write(&runtime_key_path, b"private-key\n")
            .expect("runtime key should be writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&runtime_key_path, std::fs::Permissions::from_mode(0o600))
                .expect("runtime key permissions should be restrictive");
        }

        prepare_runtime_wireguard_key_material(
            DaemonBackendMode::LinuxWireguard,
            Some(runtime_key_path.as_path()),
            None,
            None,
        )
        .expect("existing plaintext runtime key should be accepted");

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn runtime_key_scrub_only_removes_ephemeral_file_when_encrypted_store_is_used() {
        let test_dir = secure_test_dir("rustynetd-runtime-key-scrub");
        let runtime_key_path = test_dir.join("wireguard.key");
        let encrypted_key_path = test_dir.join("wireguard.key.enc");
        std::fs::write(&runtime_key_path, b"private-key\n")
            .expect("runtime key should be writable");

        scrub_runtime_wireguard_key_material(
            DaemonBackendMode::LinuxWireguard,
            Some(runtime_key_path.as_path()),
            None,
        )
        .expect("plaintext key mode should not scrub runtime key");
        assert!(runtime_key_path.exists());

        scrub_runtime_wireguard_key_material(
            DaemonBackendMode::LinuxWireguard,
            Some(runtime_key_path.as_path()),
            Some(encrypted_key_path.as_path()),
        )
        .expect("encrypted key mode should scrub runtime key");
        assert!(!runtime_key_path.exists());

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn trust_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-trust-watermark-round-trip");
        let watermark_path = test_dir.join("trust.watermark");
        let expected = TrustWatermark {
            updated_at_unix: 123,
            nonce: 9,
            payload_digest: Some([0x5au8; 32]),
        };
        persist_trust_watermark(&watermark_path, expected).expect("watermark should persist");
        let loaded = load_trust_watermark(&watermark_path)
            .expect("watermark should load")
            .expect("watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path).expect("watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_watermark_rejects_legacy_version_without_digest() {
        let test_dir = secure_test_dir("rustynetd-trust-watermark-v1");
        let watermark_path = test_dir.join("trust.watermark");
        std::fs::write(&watermark_path, "version=1\nupdated_at_unix=100\nnonce=7\n")
            .expect("legacy watermark should be written");
        let err = load_trust_watermark(&watermark_path)
            .expect_err("legacy watermark format must fail closed");
        assert!(matches!(err, super::TrustBootstrapError::InvalidFormat(_)));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_allows_equal_watermark_when_payload_digest_matches() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-match");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 41,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: Some(sha256_digest(trust_evidence_payload(&record).as_bytes())),
        };
        let envelope = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect("matching digest for equal watermark should be accepted");
        assert_eq!(envelope.watermark, previous);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_rejects_equal_watermark_when_payload_digest_differs() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-mismatch");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 42,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let tampered_record = TrustEvidenceRecord {
            signed_control_valid: false,
            ..record
        };
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: Some(sha256_digest(
                trust_evidence_payload(&tampered_record).as_bytes(),
            )),
        };
        let err = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect_err("mismatched digest for equal watermark must be rejected");
        assert!(matches!(err, super::TrustBootstrapError::ReplayDetected));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_rejects_equal_watermark_when_legacy_digest_missing() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-legacy");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 43,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: None,
        };
        let err = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect_err("legacy equal watermark without digest must fail closed");
        assert!(matches!(err, super::TrustBootstrapError::ReplayDetected));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn auto_tunnel_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-round-trip");
        let watermark_path = test_dir.join("assignment.watermark");
        let expected = AutoTunnelWatermark {
            generated_at_unix: 100,
            nonce: 9,
            payload_digest: Some([0x33u8; 32]),
        };
        persist_auto_tunnel_watermark(&watermark_path, expected)
            .expect("auto tunnel watermark should persist");
        let loaded = load_auto_tunnel_watermark(&watermark_path)
            .expect("auto tunnel watermark should load")
            .expect("auto tunnel watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path)
            .expect("auto tunnel watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_watermark_rejects_legacy_version_without_digest() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-v1");
        let watermark_path = test_dir.join("assignment.watermark");
        std::fs::write(
            &watermark_path,
            "version=1\ngenerated_at_unix=10\nnonce=2\n",
        )
        .expect("legacy auto tunnel watermark should be written");
        let err = load_auto_tunnel_watermark(&watermark_path)
            .expect_err("legacy auto tunnel watermark format must fail closed");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_allows_equal_watermark_when_payload_digest_matches() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-equal-match");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            7,
            false,
        );
        let first = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect("first auto tunnel load should succeed");
        let second = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            Some(first.watermark),
        )
        .expect("equal watermark should be accepted when digest matches");
        assert_eq!(second.watermark, first.watermark);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_equal_watermark_when_payload_digest_differs() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-equal-mismatch");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            8,
            false,
        );
        let envelope = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect("first auto tunnel load should succeed");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            Some(AutoTunnelWatermark {
                generated_at_unix: envelope.watermark.generated_at_unix,
                nonce: envelope.watermark.nonce,
                payload_digest: Some([0x44u8; 32]),
            }),
        )
        .expect_err("equal watermark with mismatched payload digest must fail");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::ReplayDetected
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn traversal_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-traversal-watermark-round-trip");
        let watermark_path = test_dir.join("traversal.watermark");
        let expected = super::TraversalWatermark {
            generated_at_unix: 200,
            nonce: 13,
            payload_digest: Some([0x55u8; 32]),
        };
        persist_traversal_watermark(&watermark_path, expected)
            .expect("traversal watermark should persist");
        let loaded = load_traversal_watermark(&watermark_path)
            .expect("traversal watermark should load")
            .expect("traversal watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path)
            .expect("traversal watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_rejects_tampered_signature_and_replay() {
        let test_dir = secure_test_dir("rustynetd-traversal-tamper-replay");
        let traversal_path = test_dir.join("traversal.bundle");
        let verifier_path = test_dir.join("traversal.verifier.pub");

        write_traversal_file(&traversal_path, &verifier_path, "node-a", "node-b", 1, true);
        let tampered = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("tampered traversal bundle must fail signature verification");
        assert!(matches!(
            tampered,
            super::TraversalBootstrapError::SignatureInvalid
        ));

        write_traversal_file(
            &traversal_path,
            &verifier_path,
            "node-a",
            "node-b",
            2,
            false,
        );
        let first = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("first traversal bundle load should succeed");
        let replay = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            Some(super::TraversalWatermark {
                generated_at_unix: first.watermark.generated_at_unix,
                nonce: first.watermark.nonce,
                payload_digest: Some([0x42u8; 32]),
            }),
        )
        .expect_err("equal traversal watermark with mismatched digest must fail");
        assert!(matches!(
            replay,
            super::TraversalBootstrapError::ReplayDetected
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn netcheck_reports_structured_traversal_diagnostics() {
        let test_dir = secure_test_dir("rustynetd-netcheck-traversal-diagnostics");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            5,
            false,
        );

        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::InMemory,
            node_id: "daemon-local".to_string(),
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            membership_snapshot_path,
            membership_log_path,
            auto_tunnel_enforce: false,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should initialize");
        runtime.traversal_bundle_path = traversal_path;
        runtime.traversal_verifier_key_path = traversal_verifier_path;
        runtime.traversal_watermark_path = traversal_watermark_path;
        runtime.refresh_traversal_hint_state();
        let output = runtime.netcheck_response_line();
        assert!(output.contains("path_mode=initializing"));
        assert!(output.contains("traversal_status=valid"));
        assert!(output.contains("candidate_count=2"));
        assert!(output.contains("host_candidates=1"));
        assert!(output.contains("relay_candidates=1"));
        assert!(output.contains("srflx_candidates=0"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_assigned_cidr_outside_mesh() {
        let test_dir = secure_test_dir("rustynetd-auto-assigned-outside-mesh");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            9,
            false,
        );
        let body = std::fs::read_to_string(&assignment_path)
            .expect("auto tunnel bundle should be readable");
        let tampered = body.replace("assigned_cidr=100.64.0.1/32", "assigned_cidr=10.0.0.1/32");
        std::fs::write(&assignment_path, tampered).expect("tampered bundle should be writable");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("assigned cidr outside mesh must be rejected");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("outside mesh"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_non_host_assigned_cidr() {
        let test_dir = secure_test_dir("rustynetd-auto-assigned-not-host");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            10,
            false,
        );
        let body = std::fs::read_to_string(&assignment_path)
            .expect("auto tunnel bundle should be readable");
        let tampered = body.replace("assigned_cidr=100.64.0.1/32", "assigned_cidr=100.64.0.0/10");
        std::fs::write(&assignment_path, tampered).expect("tampered bundle should be writable");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("non-host assigned cidr must be rejected");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("host cidr"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_rejects_private_srflx_candidate() {
        let test_dir = secure_test_dir("rustynetd-traversal-private-srflx");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file_with_srflx(
            &traversal_path,
            &traversal_verifier_path,
            1,
            "10.10.10.10",
            false,
        );

        let err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("private srflx candidate must be rejected");
        assert!(matches!(
            err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("srflx candidate"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn preflight_allows_missing_traversal_bundle_without_verifier_key() {
        let test_dir = secure_test_dir("rustynetd-preflight-traversal-optional");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_bundle_path = test_dir.join("missing.traversal.bundle");
        let traversal_verifier_path = test_dir.join("missing.traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_bundle_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        run_preflight_checks(&config)
            .expect("preflight should pass when traversal bundle is absent");

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn preflight_rejects_present_traversal_bundle_when_verifier_key_missing() {
        let test_dir = secure_test_dir("rustynetd-preflight-traversal-requires-verifier");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_bundle_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("missing.traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        std::fs::write(&traversal_bundle_path, "version=1\n")
            .expect("traversal bundle marker should be writable");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_bundle_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let err = run_preflight_checks(&config)
            .expect_err("preflight must fail when traversal bundle exists without verifier key");
        assert!(
            err.to_string()
                .contains("traversal verifier key metadata read failed"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_bundle_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_netcheck_uses_configured_traversal_paths() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-netcheck");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_traversal_file_with_srflx(
            &traversal_path,
            &traversal_verifier_path,
            9,
            "1.1.1.1",
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("traversal_status=valid"));
        assert!(netcheck.message.contains("candidate_count=3"));
        assert!(netcheck.message.contains("srflx_candidates=1"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_handles_status_and_mutating_commands() {
        let test_dir = secure_test_dir("rustynetd-runtime-test");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("state="));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(select.ok);
        assert!(select.message.contains("exit-node selected"));

        let route =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(route.ok);
        assert!(route.message.contains("route advertised"));

        let invalid_route =
            runtime.handle_command(IpcCommand::RouteAdvertise("bad-route".to_string()));
        assert!(!invalid_route.ok);

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_client_role_blocks_admin_mutations() {
        let test_dir = secure_test_dir("rustynetd-runtime-client-role");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Client,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=client"));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(select.ok);

        let route =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(!route.ok);
        assert!(route.message.contains("node role"));

        let key_rotate = runtime.handle_command(IpcCommand::KeyRotate);
        assert!(!key_rotate.ok);
        assert!(key_rotate.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_client_role_never_reports_exit_serving() {
        let test_dir = secure_test_dir("rustynetd-runtime-client-no-exit-serving");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Client,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        runtime.advertised_routes.insert("0.0.0.0/0".to_string());
        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=client"));
        assert!(status.message.contains("serving_exit_node=false"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_blind_exit_role_is_least_privilege() {
        let test_dir = secure_test_dir("rustynetd-runtime-blind-exit-role");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::BlindExit,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=blind_exit"));
        assert!(status.message.contains("serving_exit_node=true"));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!select.ok);
        assert!(select.message.contains("node role"));

        let exit_off = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!exit_off.ok);
        assert!(exit_off.message.contains("node role"));

        let lan_on = runtime.handle_command(IpcCommand::LanAccessOn);
        assert!(!lan_on.ok);
        assert!(lan_on.message.contains("node role"));

        let route = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(!route.ok);
        assert!(route.message.contains("node role"));

        let key_rotate = runtime.handle_command(IpcCommand::KeyRotate);
        assert!(!key_rotate.ok);
        assert!(key_rotate.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_blind_exit_ignores_client_assignment_fields() {
        let test_dir = secure_test_dir("rustynetd-runtime-blind-exit-assignment");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        // Includes an exit-default route that would map to selected_exit_node for clients.
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            9,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::BlindExit,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=blind_exit"));
        assert!(status.message.contains("serving_exit_node=true"));
        assert!(status.message.contains("exit_node=none"));
        assert!(status.message.contains("restricted_safe_mode=false"));

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(denied.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_enters_restricted_safe_mode_without_trust_evidence() {
        let test_dir = secure_test_dir("rustynetd-runtime-restricted");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("missing.trust");
        let trust_verifier_path = test_dir.join("missing.trust.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let response = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!response.ok);
        assert!(response.message.contains("restricted-safe"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_denies_exit_selection_for_revoked_membership_node() {
        let test_dir = secure_test_dir("rustynetd-runtime-membership-revoked");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files_with_exit_status(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
            MembershipNodeStatus::Revoked,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(denied.message.contains("not active in membership state"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_rejects_replayed_trust_evidence() {
        let test_dir = secure_test_dir("rustynetd-runtime-replay");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 2);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        persist_trust_watermark(
            &trust_watermark_path,
            TrustWatermark {
                updated_at_unix: unix_now(),
                nonce: 3,
                payload_digest: Some([0u8; 32]),
            },
        )
        .expect("watermark should be persisted");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let response = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!response.ok);
        assert!(response.message.contains("restricted-safe"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_enforcement_applies_and_blocks_manual_mutations() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("auto_tunnel_enforce=true"));
        assert!(status.message.contains("last_assignment="));

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(
            denied
                .message
                .contains("disabled while auto-tunnel is enforced")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_allows_exit_service_advertise_only() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-exit-service");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file_exitless(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let allowed = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(allowed.ok);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("serving_exit_node=true"));

        let denied =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(!denied.ok);
        assert!(
            denied
                .message
                .contains("disabled while auto-tunnel is enforced")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_allows_relay_exit_with_upstream_exit() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-relay-with-upstream");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        // Includes an exit-default route, so selected_exit_node is present in assignment state.
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            5,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Admin,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let enabled = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(enabled.ok);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("exit_node=node-exit"));
        assert!(status.message.contains("serving_exit_node=true"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_tamper_and_replay_fail_closed() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-reject");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            true,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));

        let denied = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!denied.ok);
        assert!(denied.message.contains("restricted-safe"));

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            2,
            false,
        );
        persist_auto_tunnel_watermark(
            &assignment_watermark_path,
            AutoTunnelWatermark {
                generated_at_unix: unix_now().saturating_add(10),
                nonce: 99,
                payload_digest: Some([0xabu8; 32]),
            },
        )
        .expect("assignment watermark should be persisted");
        let mut replay_runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        replay_runtime.bootstrap();

        let replay_status = replay_runtime.handle_command(IpcCommand::Status);
        assert!(replay_status.ok);
        assert!(replay_status.message.contains("restricted_safe_mode=true"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }
}
