#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ipc::{IpcCommand, IpcResponse, parse_command, validate_cidr};
use crate::key_material::{
    apply_interface_private_key, decrypt_private_key, encrypt_private_key,
    generate_wireguard_keypair, remove_file_if_present, set_interface_down, write_public_key,
    write_runtime_private_key,
};
use crate::phase10::{
    ApplyOptions, DataplaneState, DataplaneSystem, Phase10Controller, RouteGrantRequest,
    RuntimeSystem, TrustEvidence, TrustPolicy,
};
#[cfg(target_os = "linux")]
use crate::phase10::{LinuxCommandSystem, LinuxDataplaneMode};
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
use rustynet_backend_wireguard::WireguardBackend;
#[cfg(target_os = "linux")]
use rustynet_backend_wireguard::{LinuxCommandRunner, LinuxWireguardBackend};
use rustynet_control::membership::{
    MembershipNodeStatus, MembershipState, load_membership_log, load_membership_snapshot,
    replay_membership_snapshot_and_log,
};
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet, Decision,
    MembershipDirectory, MembershipStatus, Protocol, RuleAction, TrafficContext,
};

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";
pub const DEFAULT_TRUST_EVIDENCE_PATH: &str = "/var/lib/rustynet/rustynetd.trust";
pub const DEFAULT_TRUST_VERIFIER_KEY_PATH: &str = "/etc/rustynet/trust-evidence.pub";
pub const DEFAULT_TRUST_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.trust.watermark";
pub const DEFAULT_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
pub const DEFAULT_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
pub const DEFAULT_MEMBERSHIP_WATERMARK_PATH: &str = "/var/lib/rustynet/membership.watermark";
pub const DEFAULT_AUTO_TUNNEL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
pub const DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH: &str = "/etc/rustynet/assignment.pub";
pub const DEFAULT_AUTO_TUNNEL_WATERMARK_PATH: &str =
    "/var/lib/rustynet/rustynetd.assignment.watermark";
pub const DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS: u64 = 300;
pub const DEFAULT_WG_INTERFACE: &str = "rustynet0";
pub const DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH: &str = "/run/rustynet/wireguard.key";
pub const DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str = "/etc/rustynet/wireguard.key.enc";
pub const DEFAULT_WG_KEY_PASSPHRASE_PATH: &str = "/etc/rustynet/wireguard.passphrase";
pub const DEFAULT_WG_PUBLIC_KEY_PATH: &str = "/etc/rustynet/wireguard.pub";
pub const DEFAULT_EGRESS_INTERFACE: &str = "eth0";
pub const DEFAULT_RECONCILE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_RECONCILE_FAILURES: u32 = 5;
pub const DEFAULT_NODE_ID: &str = "daemon-local";

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
}

#[allow(clippy::derivable_impls)]
impl Default for DaemonBackendMode {
    fn default() -> Self {
        DaemonBackendMode::LinuxWireguard
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub node_id: String,
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
    pub auto_tunnel_max_age_secs: u64,
    pub backend_mode: DaemonBackendMode,
    pub wg_interface: String,
    pub wg_private_key_path: Option<PathBuf>,
    pub wg_encrypted_private_key_path: Option<PathBuf>,
    pub wg_key_passphrase_path: Option<PathBuf>,
    pub wg_public_key_path: Option<PathBuf>,
    pub egress_interface: String,
    pub dataplane_mode: DaemonDataplaneMode,
    pub reconcile_interval_ms: u64,
    pub max_reconcile_failures: u32,
    pub max_requests: Option<usize>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            node_id: DEFAULT_NODE_ID.to_string(),
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            trust_evidence_path: PathBuf::from(DEFAULT_TRUST_EVIDENCE_PATH),
            trust_verifier_key_path: PathBuf::from(DEFAULT_TRUST_VERIFIER_KEY_PATH),
            trust_watermark_path: PathBuf::from(DEFAULT_TRUST_WATERMARK_PATH),
            membership_snapshot_path: PathBuf::from(DEFAULT_MEMBERSHIP_SNAPSHOT_PATH),
            membership_log_path: PathBuf::from(DEFAULT_MEMBERSHIP_LOG_PATH),
            membership_watermark_path: PathBuf::from(DEFAULT_MEMBERSHIP_WATERMARK_PATH),
            auto_tunnel_enforce: false,
            auto_tunnel_bundle_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_BUNDLE_PATH)),
            auto_tunnel_verifier_key_path: Some(PathBuf::from(
                DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH,
            )),
            auto_tunnel_watermark_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_WATERMARK_PATH)),
            auto_tunnel_max_age_secs: DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            backend_mode: DaemonBackendMode::default(),
            wg_interface: DEFAULT_WG_INTERFACE.to_string(),
            wg_private_key_path: Some(PathBuf::from(DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH)),
            wg_encrypted_private_key_path: Some(PathBuf::from(
                DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            )),
            wg_key_passphrase_path: Some(PathBuf::from(DEFAULT_WG_KEY_PASSPHRASE_PATH)),
            wg_public_key_path: Some(PathBuf::from(DEFAULT_WG_PUBLIC_KEY_PATH)),
            egress_interface: DEFAULT_EGRESS_INTERFACE.to_string(),
            dataplane_mode: DaemonDataplaneMode::default(),
            reconcile_interval_ms: DEFAULT_RECONCILE_INTERVAL_MS,
            max_reconcile_failures: DEFAULT_MAX_RECONCILE_FAILURES,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TrustWatermark {
    updated_at_unix: u64,
    nonce: u64,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct AutoTunnelWatermark {
    generated_at_unix: u64,
    nonce: u64,
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
    peers: Vec<PeerConfig>,
    routes: Vec<Route>,
    selected_exit_node: Option<String>,
}

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
    Linux(LinuxWireguardBackend<LinuxCommandRunner>),
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
                    let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                        DaemonError::InvalidConfig(
                            "wg private key path is required for linux-wireguard backend"
                                .to_string(),
                        )
                    })?;
                    validate_private_key_permissions(private_key)?;
                    let backend = LinuxWireguardBackend::new(
                        LinuxCommandRunner,
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
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
        }
    }
}

impl TunnelBackend for DaemonBackend {
    fn name(&self) -> &'static str {
        match self {
            DaemonBackend::InMemory(backend) => backend.name(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.name(),
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        match self {
            DaemonBackend::InMemory(backend) => backend.capabilities(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.capabilities(),
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.start(context),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.start(context),
        }
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.configure_peer(peer),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.configure_peer(peer),
        }
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.remove_peer(node_id),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.remove_peer(node_id),
        }
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.apply_routes(routes),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.apply_routes(routes),
        }
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.set_exit_mode(mode),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.set_exit_mode(mode),
        }
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.stats(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.stats(),
        }
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.shutdown(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.shutdown(),
        }
    }
}

struct DaemonRuntime {
    controller: Phase10Controller<DaemonBackend, RuntimeSystem>,
    policy: ContextualPolicySet,
    backend_mode: DaemonBackendMode,
    local_node_id: String,
    wg_interface: String,
    wg_private_key_path: Option<PathBuf>,
    wg_encrypted_private_key_path: Option<PathBuf>,
    wg_key_passphrase_path: Option<PathBuf>,
    wg_public_key_path: Option<PathBuf>,
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
    max_reconcile_failures: u32,
    membership_state: Option<MembershipState>,
    membership_directory: MembershipDirectory,
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
        Ok(Self {
            controller,
            policy,
            backend_mode: config.backend_mode,
            local_node_id: config.node_id.clone(),
            wg_interface: config.wg_interface.clone(),
            wg_private_key_path: config.wg_private_key_path.clone(),
            wg_encrypted_private_key_path: config.wg_encrypted_private_key_path.clone(),
            wg_key_passphrase_path: config.wg_key_passphrase_path.clone(),
            wg_public_key_path: config.wg_public_key_path.clone(),
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
            auto_tunnel_max_age_secs: config.auto_tunnel_max_age_secs,
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
            max_reconcile_failures: config.max_reconcile_failures,
            membership_state: None,
            membership_directory: MembershipDirectory::default(),
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
        if let Some(previous) = previous
            && (watermark.epoch < previous.epoch
                || (watermark.epoch == previous.epoch
                    && watermark.state_root != previous.state_root))
        {
            return Err(MembershipBootstrapError::WatermarkReplay);
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

        let (mesh_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
            if let Some(envelope) = auto_bundle {
                let lan_enabled = envelope
                    .bundle
                    .routes
                    .iter()
                    .any(|route| route.kind == RouteKind::ExitNodeLan);
                (
                    envelope.bundle.mesh_cidr,
                    envelope.bundle.peers,
                    envelope.bundle.routes,
                    envelope.bundle.selected_exit_node,
                    lan_enabled,
                    Some(envelope.watermark),
                )
            } else {
                (
                    "100.64.0.0/10".to_string(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    false,
                    None,
                )
            };

        let apply = self.controller.apply_dataplane_generation(
            trust,
            RuntimeContext {
                local_node: NodeId::new(self.local_node_id.clone()).expect("valid local node"),
                mesh_cidr,
            },
            peers,
            routes,
            ApplyOptions {
                protected_dns: true,
                ipv6_parity_supported: false,
                exit_mode: if self.auto_tunnel_enforce {
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
        if apply.is_err() {
            self.restrict_recoverable("dataplane bootstrap apply failed".to_string());
            let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
            return;
        }
        self.membership_state = Some(membership_state);
        self.membership_directory = membership_directory;

        if self.auto_tunnel_enforce {
            self.selected_exit_node = auto_exit;
            self.lan_access_enabled = auto_lan_access;
            self.controller.set_lan_access(auto_lan_access);
            self.last_applied_assignment = auto_watermark;
        } else if let Some(exit_node) = &self.selected_exit_node
            && let Ok(node_id) = NodeId::new(exit_node.clone())
        {
            let _ = self
                .controller
                .set_exit_node(node_id, "user:local", Protocol::Any);
        }

        self.restriction_mode = RestrictionMode::None;
        self.bootstrap_error = None;
    }

    fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        if self.is_restricted() && command.is_mutating() {
            return IpcResponse::err("daemon is in restricted-safe mode");
        }
        if self.auto_tunnel_enforce
            && matches!(
                command,
                IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::RouteAdvertise(_)
            )
        {
            return IpcResponse::err(
                "manual route and exit mutations are disabled while auto-tunnel is enforced",
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
                IpcResponse::ok(format!(
                    "node_id={} state={:?} generation={} exit_node={} lan_access={} restricted_safe_mode={} restriction_mode={:?} bootstrap_error={} reconcile_attempts={} reconcile_failures={} last_reconcile_unix={} last_reconcile_error={} encrypted_key_store={} auto_tunnel_enforce={} last_assignment={} membership_epoch={} membership_active_nodes={}",
                    self.local_node_id,
                    self.controller.state(),
                    self.controller.generation(),
                    self.selected_exit_node.as_deref().unwrap_or("none"),
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
                    last_assignment,
                    membership_epoch,
                    membership_active_nodes
                ))
            }
            IpcCommand::Netcheck => {
                let transport = if self.controller.state() == DataplaneState::FailClosed {
                    "fail-closed"
                } else {
                    "direct-preferred relay-fallback"
                };
                IpcResponse::ok(format!("netcheck: path={transport}"))
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
                if !validate_cidr(&cidr) {
                    return IpcResponse::err("invalid cidr format");
                }
                if let Some(exit_node) = &self.selected_exit_node
                    && let Ok(node_id) = NodeId::new(exit_node.clone())
                {
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
                self.advertised_routes.insert(cidr.clone());
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
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

    fn rotate_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(self.backend_mode, DaemonBackendMode::LinuxWireguard) {
            return Err("key rotation is only supported for linux-wireguard backend".to_string());
        }
        let runtime_path = self
            .wg_private_key_path
            .clone()
            .ok_or_else(|| "wg private key path is not configured".to_string())?;

        let old_runtime = fs::read(&runtime_path).ok();
        let old_encrypted = self
            .wg_encrypted_private_key_path
            .as_ref()
            .and_then(|path| fs::read(path).ok());
        let old_public = self
            .wg_public_key_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());

        let (mut new_private, new_public) = generate_wireguard_keypair()?;

        if let Some(encrypted_path) = self.wg_encrypted_private_key_path.as_ref() {
            let passphrase_path = self.wg_key_passphrase_path.as_ref().ok_or_else(|| {
                "wg key passphrase path is required when encrypted key storage is configured"
                    .to_string()
            })?;
            encrypt_private_key(&new_private, encrypted_path, passphrase_path)?;
        }

        if let Err(err) = write_runtime_private_key(&runtime_path, &new_private) {
            new_private.fill(0);
            return Err(err);
        }
        if let Some(public_path) = self.wg_public_key_path.as_ref()
            && let Err(err) = write_public_key(public_path, &new_public)
        {
            new_private.fill(0);
            return Err(err);
        }

        if let Err(err) = apply_interface_private_key(&self.wg_interface, &runtime_path) {
            let _ = self.restore_key_backups(old_runtime, old_encrypted, old_public);
            new_private.fill(0);
            return Err(format!("rotate apply failed and rollback attempted: {err}"));
        }

        new_private.fill(0);

        if let Err(err) = self.persist_state() {
            return Err(format!("persist failed after key rotation: {err}"));
        }

        let bundle = format!("rotation:{}:{}", self.local_node_id, new_public);
        Ok(format!(
            "key rotated: node_id={} public_key={} rotation_bundle={}",
            self.local_node_id, new_public, bundle
        ))
    }

    fn restore_key_backups(
        &self,
        old_runtime: Option<Vec<u8>>,
        old_encrypted: Option<Vec<u8>>,
        old_public: Option<String>,
    ) -> Result<(), String> {
        if let (Some(path), Some(bytes)) = (self.wg_private_key_path.as_ref(), old_runtime) {
            write_runtime_private_key(path, &bytes)?;
            let _ = apply_interface_private_key(&self.wg_interface, path);
        }
        if let (Some(path), Some(bytes)) =
            (self.wg_encrypted_private_key_path.as_ref(), old_encrypted)
        {
            write_runtime_private_key(path, &bytes)?;
        }
        if let (Some(path), Some(value)) = (self.wg_public_key_path.as_ref(), old_public) {
            write_public_key(path, value.trim())?;
        }
        Ok(())
    }

    fn revoke_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(self.backend_mode, DaemonBackendMode::LinuxWireguard) {
            return Err("key revoke is only supported for linux-wireguard backend".to_string());
        }
        self.restrict_permanent("local key revoked".to_string());
        let _ = self.controller.force_fail_closed("local_key_revoked");

        let mut failures = Vec::new();
        if let Err(err) = set_interface_down(&self.wg_interface) {
            failures.push(format!("interface down failed: {err}"));
        }
        if let Some(path) = self.wg_private_key_path.as_ref()
            && let Err(err) = remove_file_if_present(path)
        {
            failures.push(err);
        }
        if let Some(path) = self.wg_encrypted_private_key_path.as_ref()
            && let Err(err) = remove_file_if_present(path)
        {
            failures.push(err);
        }
        if let Some(path) = self.wg_public_key_path.as_ref()
            && let Err(err) = remove_file_if_present(path)
        {
            failures.push(err);
        }

        self.selected_exit_node = None;
        self.lan_access_enabled = false;

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

        if let Some(selected) = &self.selected_exit_node
            && let Ok(node_id) = NodeId::new(selected.clone())
        {
            for route in &self.advertised_routes {
                self.controller.advertise_lan_route(node_id.clone(), route);
            }
        }

        Ok(())
    }

    fn reconcile(&mut self) {
        self.reconcile_attempts = self.reconcile_attempts.saturating_add(1);
        self.last_reconcile_unix = Some(unix_now());

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
        {
            let (mesh_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
                if let Some(envelope) = auto_bundle {
                    let lan_enabled = envelope
                        .bundle
                        .routes
                        .iter()
                        .any(|route| route.kind == RouteKind::ExitNodeLan);
                    (
                        envelope.bundle.mesh_cidr,
                        envelope.bundle.peers,
                        envelope.bundle.routes,
                        envelope.bundle.selected_exit_node,
                        lan_enabled,
                        Some(envelope.watermark),
                    )
                } else {
                    (
                        "100.64.0.0/10".to_string(),
                        Vec::new(),
                        Vec::new(),
                        None,
                        false,
                        None,
                    )
                };
            let apply = self.controller.apply_dataplane_generation(
                trust,
                RuntimeContext {
                    local_node: NodeId::new(self.local_node_id.clone()).expect("valid local node"),
                    mesh_cidr,
                },
                peers,
                routes,
                ApplyOptions {
                    protected_dns: true,
                    ipv6_parity_supported: false,
                    exit_mode: if self.auto_tunnel_enforce {
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

            match apply {
                Ok(()) => {
                    self.membership_state = Some(membership_state);
                    self.membership_directory = membership_directory;
                    if self.auto_tunnel_enforce {
                        self.selected_exit_node = auto_exit;
                        self.lan_access_enabled = auto_lan_access;
                        self.controller.set_lan_access(auto_lan_access);
                        self.last_applied_assignment = auto_watermark;
                    }
                    self.restriction_mode = RestrictionMode::None;
                    self.bootstrap_error = None;
                    self.reconcile_failures = 0;
                }
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("reconcile dataplane apply failed: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self.controller.force_fail_closed("reconcile_apply_failed");
                    self.promote_to_permanent_if_over_limit();
                }
            }
        }
    }

    fn desired_exit_mode(&self) -> ExitMode {
        if self.selected_exit_node.is_some() {
            ExitMode::FullTunnel
        } else {
            ExitMode::Off
        }
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
}

fn daemon_system(config: &DaemonConfig) -> Result<RuntimeSystem, DaemonError> {
    #[cfg(target_os = "linux")]
    {
        let mode = match config.dataplane_mode {
            DaemonDataplaneMode::Shell => LinuxDataplaneMode::Shell,
            DaemonDataplaneMode::HybridNative => LinuxDataplaneMode::HybridNative,
        };
        let system = LinuxCommandSystem::new(
            config.wg_interface.clone(),
            config.egress_interface.clone(),
            mode,
        )
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        return Ok(RuntimeSystem::Linux(system));
    }
    #[cfg(not(target_os = "linux"))]
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
            "daemon dataplane requires a linux host and linux-wireguard backend".to_string(),
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
    run_preflight_checks(&config)?;

    let mut runtime = DaemonRuntime::new(&config)?;
    runtime.bootstrap();

    if let Some(parent) = config.socket_path.parent() {
        fs::create_dir_all(parent).map_err(|err| DaemonError::Io(err.to_string()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|err| DaemonError::Io(err.to_string()))?;
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
    let reconcile_interval = Duration::from_millis(config.reconcile_interval_ms.max(100));
    let mut next_reconcile = Instant::now() + reconcile_interval;

    loop {
        let mut processed_command = false;
        match listener.accept() {
            Ok((stream, _)) => {
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
            .map(|max| processed >= max)
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

    Ok(())
}

fn prepare_runtime_wireguard_key(config: &DaemonConfig) -> Result<(), DaemonError> {
    if !matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard) {
        return Ok(());
    }

    let Some(runtime_path) = config.wg_private_key_path.as_ref() else {
        return Ok(());
    };
    let Some(encrypted_path) = config.wg_encrypted_private_key_path.as_ref() else {
        return Ok(());
    };
    let passphrase_path = config.wg_key_passphrase_path.as_ref().ok_or_else(|| {
        DaemonError::InvalidConfig(
            "wg key passphrase path is required when encrypted key path is configured".to_string(),
        )
    })?;

    let mut decrypted = decrypt_private_key(encrypted_path, passphrase_path)
        .map_err(|err| DaemonError::InvalidConfig(format!("wg key decrypt failed: {err}")))?;
    write_runtime_private_key(runtime_path, &decrypted)
        .map_err(|err| DaemonError::InvalidConfig(format!("wg runtime key write failed: {err}")))?;
    decrypted.fill(0);
    Ok(())
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
    if let Some(path) = config.auto_tunnel_bundle_path.as_ref()
        && !path.is_absolute()
    {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel bundle path must be absolute".to_string(),
        ));
    }
    if let Some(path) = config.auto_tunnel_verifier_key_path.as_ref()
        && !path.is_absolute()
    {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel verifier key path must be absolute".to_string(),
        ));
    }
    if let Some(path) = config.auto_tunnel_watermark_path.as_ref()
        && !path.is_absolute()
    {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel watermark path must be absolute".to_string(),
        ));
    }
    if config.wg_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "wireguard interface must not be empty".to_string(),
        ));
    }
    if config.egress_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "egress interface must not be empty".to_string(),
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
    if config.auto_tunnel_max_age_secs == 0 {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel max age must be greater than 0".to_string(),
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
    if matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard) {
        if let Some(path) = config.wg_private_key_path.as_ref()
            && !path.is_absolute()
        {
            return Err(DaemonError::InvalidConfig(
                "wg private key path must be absolute".to_string(),
            ));
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref()
            && !path.is_absolute()
        {
            return Err(DaemonError::InvalidConfig(
                "wg encrypted private key path must be absolute".to_string(),
            ));
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref()
            && !path.is_absolute()
        {
            return Err(DaemonError::InvalidConfig(
                "wg key passphrase path must be absolute".to_string(),
            ));
        }
        if let Some(path) = config.wg_public_key_path.as_ref()
            && !path.is_absolute()
        {
            return Err(DaemonError::InvalidConfig(
                "wg public key path must be absolute".to_string(),
            ));
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

    if matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard)
        && config.wg_private_key_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(
            "wg private key path is required for linux-wireguard backend".to_string(),
        ));
    }
    if config.reconcile_interval_ms == 0 {
        return Err(DaemonError::InvalidConfig(
            "reconcile interval must be greater than 0".to_string(),
        ));
    }
    if config.max_reconcile_failures == 0 {
        return Err(DaemonError::InvalidConfig(
            "max reconcile failures must be greater than 0".to_string(),
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
    if config.auto_tunnel_enforce
        && let Some(path) = config.auto_tunnel_bundle_path.as_ref()
        && let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel bundle directory create failed: {err}"))
        })?;
    }
    if config.auto_tunnel_enforce
        && let Some(path) = config.auto_tunnel_watermark_path.as_ref()
        && let Some(parent) = path.parent()
    {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "auto tunnel watermark directory create failed: {err}"
            ))
        })?;
    }

    validate_trust_evidence_permissions(&config.trust_evidence_path)?;
    validate_trust_verifier_key_permissions(&config.trust_verifier_key_path)?;
    validate_membership_snapshot_permissions(&config.membership_snapshot_path)?;
    validate_membership_log_permissions(&config.membership_log_path)?;
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
    if matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard) {
        if let Some(path) = config.wg_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref() {
            validate_private_key_permissions(path)?;
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
            config.auto_tunnel_max_age_secs,
            TrustPolicy::default(),
            watermark,
        )
        .map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel preflight failed: {err}"))
        })?;
    }

    let mut system = daemon_system(config)?;
    system
        .check_prerequisites()
        .map_err(|err| DaemonError::InvalidConfig(format!("dataplane preflight failed: {err}")))?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077)
}

#[cfg(not(target_os = "linux"))]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077)
}

#[cfg(target_os = "linux")]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022)
}

#[cfg(not(target_os = "linux"))]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022)
}

#[cfg(target_os = "linux")]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o077)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o077)
}

#[cfg(target_os = "linux")]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o077)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o077)
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
    verifying_key
        .verify(trust_evidence_payload(&record).as_bytes(), &signature)
        .map_err(|_| TrustBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if record.updated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(TrustBootstrapError::FutureDated);
    }

    let age = now.saturating_sub(record.updated_at_unix);
    if age > trust_policy.max_signed_data_age_secs {
        return Err(TrustBootstrapError::Stale);
    }

    let watermark = TrustWatermark {
        updated_at_unix: record.updated_at_unix,
        nonce: record.nonce,
    };
    if previous_watermark
        .map(|existing| watermark < existing)
        .unwrap_or(false)
    {
        return Err(TrustBootstrapError::ReplayDetected);
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
            _ => {
                return Err(TrustBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    if version != Some(1) {
        return Err(TrustBootstrapError::InvalidFormat(
            "unsupported watermark version".to_string(),
        ));
    }
    Ok(Some(TrustWatermark {
        updated_at_unix: updated_at_unix.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark updated_at_unix".to_string())
        })?,
        nonce: nonce.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark nonce".to_string())
        })?,
    }))
}

fn persist_trust_watermark(
    path: &Path,
    watermark: TrustWatermark,
) -> Result<(), TrustBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    }
    let payload = format!(
        "version=1\nupdated_at_unix={}\nnonce={}\n",
        watermark.updated_at_unix, watermark.nonce
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
    temp.write_all(payload.as_bytes())
        .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    temp.sync_all()
        .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    fs::rename(&temp_path, path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
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
    temp.write_all(payload.as_bytes())
        .map_err(|err| err.to_string())?;
    temp.sync_all().map_err(|err| err.to_string())?;
    fs::rename(&temp_path, path).map_err(|err| err.to_string())?;
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

    let assigned_cidr = fields.get("assigned_cidr").ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing assigned_cidr".to_string())
    })?;
    if !is_valid_ipv4_or_ipv6_cidr(assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid assigned_cidr".to_string(),
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

    let watermark = AutoTunnelWatermark {
        generated_at_unix,
        nonce,
    };
    if previous_watermark
        .map(|existing| watermark <= existing)
        .unwrap_or(false)
    {
        return Err(AutoTunnelBootstrapError::ReplayDetected);
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
            if let Some(existing) = selected_exit_node.as_deref()
                && existing != via
            {
                return Err(AutoTunnelBootstrapError::InvalidFormat(
                    "exit routes reference multiple exit nodes".to_string(),
                ));
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
            _ => {
                return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    if version != Some(1) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unsupported watermark version".to_string(),
        ));
    }
    Ok(Some(AutoTunnelWatermark {
        generated_at_unix: generated_at_unix.ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(
                "missing watermark generated_at_unix".to_string(),
            )
        })?,
        nonce: nonce.ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing watermark nonce".to_string())
        })?,
    }))
}

fn persist_auto_tunnel_watermark(
    path: &Path,
    watermark: AutoTunnelWatermark,
) -> Result<(), AutoTunnelBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    }
    let payload = format!(
        "version=1\ngenerated_at_unix={}\nnonce={}\n",
        watermark.generated_at_unix, watermark.nonce
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
    temp.write_all(payload.as_bytes())
        .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    temp.sync_all()
        .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    fs::rename(&temp_path, path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    Ok(())
}

fn is_valid_ipv4_or_ipv6_cidr(value: &str) -> bool {
    let Some((ip_part, prefix_part)) = value.split_once('/') else {
        return false;
    };
    if ip_part.parse::<std::net::IpAddr>().is_err() {
        return false;
    }
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    if ip_part.contains(':') {
        prefix <= 128
    } else {
        prefix <= 32
    }
}

#[cfg(target_os = "linux")]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o077)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o077)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022)
}

#[cfg(target_os = "linux")]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022)
}

fn validate_file_security(
    path: &Path,
    label: &str,
    disallowed_mode_mask: u32,
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
    if owner_uid != expected_uid {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} owner uid mismatch: expected {expected_uid}, got {owner_uid}"
        )));
    }
    Ok(())
}

fn read_command(stream: &UnixStream) -> Result<String, String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|err| format!("read failed: {err}"))?;
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
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
        persist_membership_snapshot,
    };

    use super::{
        AutoTunnelWatermark, DaemonBackendMode, DaemonConfig, DaemonRuntime, IpcCommand,
        TrustEvidenceRecord, TrustWatermark, persist_auto_tunnel_watermark,
        persist_trust_watermark, run_daemon, trust_evidence_payload, unix_now,
    };

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    fn write_trust_file(path: &Path, verifier_path: &Path, nonce: u64) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("verifier key should be written");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce,
        };
        let body = trust_evidence_payload(&record);
        let signature = signing_key.sign(body.as_bytes());
        std::fs::write(
            path,
            format!("{body}signature={}\n", hex_encode(&signature.to_bytes())),
        )
        .expect("trust file should be written");
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
    fn daemon_runtime_handles_status_and_mutating_commands() {
        let unique = format!(
            "rustynetd-runtime-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.trust.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));
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
    }

    #[test]
    fn daemon_runtime_enters_restricted_safe_mode_without_trust_evidence() {
        let unique = format!(
            "rustynetd-runtime-restricted-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.missing.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.missing.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));
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
    }

    #[test]
    fn daemon_runtime_denies_exit_selection_for_revoked_membership_node() {
        let unique = format!(
            "rustynetd-runtime-membership-revoked-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.trust.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));

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
    }

    #[test]
    fn daemon_runtime_rejects_replayed_trust_evidence() {
        let unique = format!(
            "rustynetd-runtime-replay-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.trust.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));
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
    }

    #[test]
    fn daemon_runtime_auto_tunnel_enforcement_applies_and_blocks_manual_mutations() {
        let unique = format!(
            "rustynetd-runtime-auto-tunnel-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.trust.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.trust.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));
        let assignment_path = std::env::temp_dir().join(format!("{unique}.assignment"));
        let assignment_verifier_path =
            std::env::temp_dir().join(format!("{unique}.assignment.pub"));
        let assignment_watermark_path =
            std::env::temp_dir().join(format!("{unique}.assignment.watermark"));

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
    }

    #[test]
    fn daemon_runtime_auto_tunnel_tamper_and_replay_fail_closed() {
        let unique = format!(
            "rustynetd-runtime-auto-tunnel-reject-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let state_path = std::env::temp_dir().join(format!("{unique}.state"));
        let trust_path = std::env::temp_dir().join(format!("{unique}.trust"));
        let trust_verifier_path = std::env::temp_dir().join(format!("{unique}.trust.pub"));
        let trust_watermark_path = std::env::temp_dir().join(format!("{unique}.trust.watermark"));
        let membership_snapshot_path =
            std::env::temp_dir().join(format!("{unique}.membership.snapshot"));
        let membership_log_path = std::env::temp_dir().join(format!("{unique}.membership.log"));
        let membership_watermark_path =
            std::env::temp_dir().join(format!("{unique}.membership.watermark"));
        let assignment_path = std::env::temp_dir().join(format!("{unique}.assignment"));
        let assignment_verifier_path =
            std::env::temp_dir().join(format!("{unique}.assignment.pub"));
        let assignment_watermark_path =
            std::env::temp_dir().join(format!("{unique}.assignment.watermark"));

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
    }
}
