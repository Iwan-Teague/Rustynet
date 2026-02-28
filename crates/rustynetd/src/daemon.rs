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
use crate::phase10::{
    ApplyOptions, DataplaneState, DataplaneSystem, DryRunSystem, Phase10Controller,
    RouteGrantRequest, RuntimeSystem, TrustEvidence, TrustPolicy,
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
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    TunnelBackend, TunnelStats,
};
use rustynet_backend_wireguard::WireguardBackend;
#[cfg(target_os = "linux")]
use rustynet_backend_wireguard::{LinuxCommandRunner, LinuxWireguardBackend};
use rustynet_policy::{
    ContextualPolicyRule, ContextualPolicySet, Protocol, RuleAction, TrafficContext,
};

pub const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
pub const DEFAULT_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";
pub const DEFAULT_TRUST_EVIDENCE_PATH: &str = "/var/lib/rustynet/rustynetd.trust";
pub const DEFAULT_TRUST_VERIFIER_KEY_PATH: &str = "/etc/rustynet/trust-evidence.pub";
pub const DEFAULT_TRUST_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.trust.watermark";
pub const DEFAULT_WG_INTERFACE: &str = "rustynet0";
pub const DEFAULT_EGRESS_INTERFACE: &str = "eth0";
pub const DEFAULT_RECONCILE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_RECONCILE_FAILURES: u32 = 5;

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
        #[cfg(target_os = "linux")]
        {
            return DaemonBackendMode::LinuxWireguard;
        }

        #[allow(unreachable_code)]
        DaemonBackendMode::InMemory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub trust_evidence_path: PathBuf,
    pub trust_verifier_key_path: PathBuf,
    pub trust_watermark_path: PathBuf,
    pub backend_mode: DaemonBackendMode,
    pub wg_interface: String,
    pub wg_private_key_path: Option<PathBuf>,
    pub egress_interface: String,
    pub dataplane_mode: DaemonDataplaneMode,
    pub reconcile_interval_ms: u64,
    pub max_reconcile_failures: u32,
    pub max_requests: Option<usize>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            trust_evidence_path: PathBuf::from(DEFAULT_TRUST_EVIDENCE_PATH),
            trust_verifier_key_path: PathBuf::from(DEFAULT_TRUST_VERIFIER_KEY_PATH),
            trust_watermark_path: PathBuf::from(DEFAULT_TRUST_WATERMARK_PATH),
            backend_mode: DaemonBackendMode::default(),
            wg_interface: DEFAULT_WG_INTERFACE.to_string(),
            wg_private_key_path: None,
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

enum DaemonBackend {
    InMemory(WireguardBackend),
    #[cfg(target_os = "linux")]
    Linux(LinuxWireguardBackend<LinuxCommandRunner>),
}

impl DaemonBackend {
    fn from_config(config: &DaemonConfig) -> Result<Self, DaemonError> {
        match config.backend_mode {
            DaemonBackendMode::InMemory => Ok(Self::InMemory(WireguardBackend::default())),
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
    state_path: PathBuf,
    trust_evidence_path: PathBuf,
    trust_verifier_key_path: PathBuf,
    trust_watermark_path: PathBuf,
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
    max_reconcile_failures: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestrictionMode {
    None,
    Recoverable,
    Permanent,
}

impl DaemonRuntime {
    fn new(config: &DaemonConfig) -> Result<Self, DaemonError> {
        let policy = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedExit],
            }],
        };
        let trust_policy = TrustPolicy::default();
        let backend = DaemonBackend::from_config(config)?;
        let controller =
            Phase10Controller::new(backend, daemon_system(config)?, policy, trust_policy);
        Ok(Self {
            controller,
            state_path: config.state_path.clone(),
            trust_evidence_path: config.trust_evidence_path.clone(),
            trust_verifier_key_path: config.trust_verifier_key_path.clone(),
            trust_watermark_path: config.trust_watermark_path.clone(),
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
            max_reconcile_failures: config.max_reconcile_failures,
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

        let apply = self.controller.apply_dataplane_generation(
            trust,
            RuntimeContext {
                local_node: NodeId::new("daemon-local").expect("valid local node"),
                mesh_cidr: "100.64.0.0/10".to_string(),
            },
            Vec::new(),
            Vec::new(),
            ApplyOptions {
                protected_dns: true,
                ipv6_parity_supported: false,
                exit_mode: self.desired_exit_mode(),
            },
        );
        if apply.is_err() {
            self.restrict_recoverable("dataplane bootstrap apply failed".to_string());
            let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
            return;
        }

        if let Some(exit_node) = &self.selected_exit_node
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

        match command {
            IpcCommand::Status => IpcResponse::ok(format!(
                "state={:?} generation={} exit_node={} lan_access={} restricted_safe_mode={} restriction_mode={:?} bootstrap_error={} reconcile_attempts={} reconcile_failures={} last_reconcile_unix={} last_reconcile_error={}",
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
                self.last_reconcile_error.as_deref().unwrap_or("none")
            )),
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
                self.advertised_routes.insert(cidr.clone());
                if let Some(exit_node) = &self.selected_exit_node
                    && let Ok(node_id) = NodeId::new(exit_node.clone())
                {
                    self.controller.advertise_lan_route(node_id, &cidr);
                    self.controller.set_lan_route_acl("user:local", &cidr, true);
                }
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                IpcResponse::ok(format!("route advertised: {cidr}"))
            }
            IpcCommand::Unknown(raw) => IpcResponse::err(format!("unknown command: {raw}")),
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

        self.last_reconcile_error = None;

        if self.controller.state() == DataplaneState::FailClosed
            || self.restriction_mode == RestrictionMode::Recoverable
        {
            let apply = self.controller.apply_dataplane_generation(
                trust,
                RuntimeContext {
                    local_node: NodeId::new("daemon-local").expect("valid local node"),
                    mesh_cidr: "100.64.0.0/10".to_string(),
                },
                Vec::new(),
                Vec::new(),
                ApplyOptions {
                    protected_dns: true,
                    ipv6_parity_supported: false,
                    exit_mode: self.desired_exit_mode(),
                },
            );

            match apply {
                Ok(()) => {
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

fn daemon_system(_config: &DaemonConfig) -> Result<RuntimeSystem, DaemonError> {
    #[cfg(target_os = "linux")]
    {
        let mode = match _config.dataplane_mode {
            DaemonDataplaneMode::Shell => LinuxDataplaneMode::Shell,
            DaemonDataplaneMode::HybridNative => LinuxDataplaneMode::HybridNative,
        };
        let system = LinuxCommandSystem::new(
            _config.wg_interface.clone(),
            _config.egress_interface.clone(),
            mode,
        )
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        return Ok(RuntimeSystem::Linux(system));
    }
    #[allow(unreachable_code)]
    Ok(RuntimeSystem::DryRun(DryRunSystem::default()))
}

pub fn run_daemon(config: DaemonConfig) -> Result<(), DaemonError> {
    if config.socket_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "socket path must not be empty".to_string(),
        ));
    }
    validate_daemon_config(&config)?;
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

fn validate_daemon_config(config: &DaemonConfig) -> Result<(), DaemonError> {
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

    validate_trust_evidence_permissions(&config.trust_evidence_path)?;
    validate_trust_verifier_key_permissions(&config.trust_verifier_key_path)?;
    if let Some(path) = config.wg_private_key_path.as_ref() {
        validate_private_key_permissions(path)?;
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

#[cfg(target_os = "linux")]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022)
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use ed25519_dalek::{Signer, SigningKey};

    use super::{
        DaemonBackendMode, DaemonConfig, DaemonRuntime, IpcCommand, TrustEvidenceRecord,
        TrustWatermark, persist_trust_watermark, trust_evidence_payload, unix_now,
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
        write_trust_file(&trust_path, &trust_verifier_path, 1);

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
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
        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let response = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!response.ok);
        assert!(response.message.contains("restricted-safe"));

        let _ = std::fs::remove_file(state_path);
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
        write_trust_file(&trust_path, &trust_verifier_path, 2);
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
    }
}
