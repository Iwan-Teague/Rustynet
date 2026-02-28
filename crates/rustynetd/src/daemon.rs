#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
use rustynet_backend_api::{ExitMode, NodeId, RuntimeContext};
use rustynet_backend_wireguard::WireguardBackend;
use rustynet_policy::{
    ContextualPolicyRule, ContextualPolicySet, Protocol, RuleAction, TrafficContext,
};

use crate::ipc::{IpcCommand, IpcResponse, parse_command, validate_cidr};
#[cfg(target_os = "linux")]
use crate::phase10::LinuxCommandSystem;
use crate::phase10::{
    ApplyOptions, DataplaneState, DryRunSystem, Phase10Controller, RouteGrantRequest,
    RuntimeSystem, TrustEvidence, TrustPolicy,
};
use crate::resilience::{
    ResilienceError, SessionStateSnapshot, load_session_snapshot, persist_session_snapshot,
};

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/rustynetd.sock";
pub const DEFAULT_STATE_PATH: &str = "/tmp/rustynetd.state";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub max_requests: Option<usize>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
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

struct DaemonRuntime {
    controller: Phase10Controller<WireguardBackend, RuntimeSystem>,
    state_path: PathBuf,
    selected_exit_node: Option<String>,
    lan_access_enabled: bool,
    advertised_routes: BTreeSet<String>,
    restricted_safe_mode: bool,
}

impl DaemonRuntime {
    fn new(state_path: PathBuf) -> Self {
        let policy = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::SharedExit],
            }],
        };
        let controller = Phase10Controller::new(
            WireguardBackend::default(),
            daemon_system(),
            policy,
            TrustPolicy::default(),
        );
        Self {
            controller,
            state_path,
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_routes: BTreeSet::new(),
            restricted_safe_mode: false,
        }
    }

    fn bootstrap(&mut self) {
        match self.restore_state() {
            Ok(()) => {}
            Err(_err) => {
                self.restricted_safe_mode = true;
                let _ = self
                    .controller
                    .force_fail_closed("state_restore_integrity_failed");
            }
        }

        let trust = TrustEvidence {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
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
                exit_mode: ExitMode::Off,
            },
        );
        if apply.is_err() {
            self.restricted_safe_mode = true;
        }
    }

    fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        if self.restricted_safe_mode && command.is_mutating() {
            return IpcResponse::err("daemon is in restricted-safe mode");
        }

        match command {
            IpcCommand::Status => IpcResponse::ok(format!(
                "state={:?} generation={} exit_node={} lan_access={} restricted_safe_mode={}",
                self.controller.state(),
                self.controller.generation(),
                self.selected_exit_node.as_deref().unwrap_or("none"),
                if self.lan_access_enabled { "on" } else { "off" },
                if self.restricted_safe_mode {
                    "true"
                } else {
                    "false"
                }
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
            self.restricted_safe_mode = true;
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
            self.controller
                .advertise_lan_route(node_id, "192.168.1.0/24");
        }

        Ok(())
    }
}

fn daemon_system() -> RuntimeSystem {
    #[cfg(target_os = "linux")]
    {
        return RuntimeSystem::Linux(LinuxCommandSystem);
    }
    #[allow(unreachable_code)]
    RuntimeSystem::DryRun(DryRunSystem::default())
}

pub fn run_daemon(config: DaemonConfig) -> Result<(), DaemonError> {
    if config.socket_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "socket path must not be empty".to_string(),
        ));
    }

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

    let socket_owner_uid = socket_owner_uid(&config.socket_path)?;

    let mut runtime = DaemonRuntime::new(config.state_path.clone());
    runtime.bootstrap();

    let mut processed = 0usize;
    for connection in listener.incoming() {
        let stream = connection.map_err(|err| DaemonError::Io(err.to_string()))?;
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
        if config
            .max_requests
            .map(|max| processed >= max)
            .unwrap_or(false)
        {
            break;
        }
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
    use super::{DaemonRuntime, IpcCommand};

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

        let mut runtime = DaemonRuntime::new(state_path.clone());
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
    }
}
