use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::process::Command;

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};

use crate::linux_command::{
    WireguardCommandRunner, encode_wg_public_key_base64, parse_peer_latest_handshake_unix,
    validate_interface_name, validate_listen_port, validate_private_key_path,
};

const MACOS_ROUTE_BINARY: &str = "/sbin/route";
const MACOS_PS_BINARY: &str = "/bin/ps";

#[derive(Debug)]
pub struct MacosWireguardBackend<R: WireguardCommandRunner> {
    runner: R,
    interface_name: String,
    private_key_path: String,
    egress_interface: String,
    listen_port: u16,
    running: bool,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    context: Option<RuntimeContext>,
    exit_mode: ExitMode,
    default_gateway: Option<String>,
    endpoint_bypass_hosts: BTreeSet<String>,
}

impl<R: WireguardCommandRunner> MacosWireguardBackend<R> {
    pub fn new(
        runner: R,
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        egress_interface: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        let interface_name = interface_name.into();
        let private_key_path = private_key_path.into();
        let egress_interface = egress_interface.into();
        validate_macos_interface_name(&interface_name)?;
        validate_private_key_path(&private_key_path)?;
        validate_interface_name(&egress_interface)?;
        validate_listen_port(listen_port)?;
        Ok(Self {
            runner,
            interface_name,
            private_key_path,
            egress_interface,
            listen_port,
            running: false,
            peers: BTreeMap::new(),
            routes: Vec::new(),
            context: None,
            exit_mode: ExitMode::Off,
            default_gateway: None,
            endpoint_bypass_hosts: BTreeSet::new(),
        })
    }

    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }
        Err(BackendError::not_running(
            "macos wireguard backend is not running",
        ))
    }

    fn ensure_cidr(value: &str) -> Result<(), BackendError> {
        if value.is_empty() || !value.contains('/') {
            return Err(BackendError::invalid_input("invalid cidr value"));
        }
        if !value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == ':' || ch == '/')
        {
            return Err(BackendError::invalid_input(
                "cidr contains invalid characters",
            ));
        }
        Ok(())
    }

    fn configure_interface(&mut self, context: &RuntimeContext) -> Result<(), BackendError> {
        Self::ensure_cidr(&context.local_cidr)?;
        let local_ip = extract_ip_from_cidr(&context.local_cidr)?;

        if self
            .runner
            .run("wireguard-go", std::slice::from_ref(&self.interface_name))
            .is_err()
        {
            let _ = self.remove_interface();
            self.runner
                .run("wireguard-go", std::slice::from_ref(&self.interface_name))?;
        }

        if let Err(err) = self.runner.run(
            "wg",
            &[
                "set".to_string(),
                self.interface_name.clone(),
                "private-key".to_string(),
                self.private_key_path.clone(),
                "listen-port".to_string(),
                self.listen_port.to_string(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }

        if let Err(err) = self.runner.run(
            "ifconfig",
            &[
                self.interface_name.clone(),
                "inet".to_string(),
                local_ip.clone(),
                local_ip,
                "netmask".to_string(),
                "255.255.255.255".to_string(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }

        if let Err(err) = self
            .runner
            .run("ifconfig", &[self.interface_name.clone(), "up".to_string()])
        {
            let _ = self.remove_interface();
            return Err(err);
        }

        Ok(())
    }

    fn remove_interface(&mut self) -> Result<(), BackendError> {
        let _ = self.runner.run(
            "ifconfig",
            &[self.interface_name.clone(), "down".to_string()],
        );
        self.restore_default_route();
        self.endpoint_bypass_hosts.clear();
        self.terminate_wireguard_go_processes()
    }

    fn apply_route_reconciliation(&mut self, next_routes: &[Route]) -> Result<(), BackendError> {
        for route in &self.routes {
            if route.destination_cidr == "0.0.0.0/0" || route.destination_cidr == "::/0" {
                continue;
            }
            if !next_routes.iter().any(|candidate| candidate == route) {
                let args = route_delete_args(&route.destination_cidr)?;
                self.runner.run("route", &args)?;
            }
        }

        for route in next_routes {
            if route.destination_cidr == "0.0.0.0/0" || route.destination_cidr == "::/0" {
                continue;
            }
            Self::ensure_cidr(&route.destination_cidr)?;
            let args = route_add_args(&route.destination_cidr, &self.interface_name)?;
            self.runner.run("route", &args)?;
        }

        self.routes = next_routes.to_vec();
        Ok(())
    }

    fn capture_default_gateway(&self) -> Result<String, BackendError> {
        let output = Command::new(MACOS_ROUTE_BINARY)
            .args(["-n", "get", "default"])
            .output()
            .map_err(|err| BackendError::internal(format!("route get default failed: {err}")))?;
        if !output.status.success() {
            return Err(BackendError::internal(format!(
                "route get default exited with status {}",
                output.status
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let normalized = line.trim();
            if let Some(value) = normalized.strip_prefix("gateway:") {
                let gateway = value.trim();
                if !gateway.is_empty() {
                    return Ok(gateway.to_string());
                }
            }
        }
        Err(BackendError::internal(
            "default gateway not found in route output",
        ))
    }

    fn install_endpoint_bypass_routes(&mut self) -> Result<(), BackendError> {
        let gateway = self
            .default_gateway
            .as_ref()
            .ok_or_else(|| BackendError::internal("default gateway not captured"))?
            .clone();

        self.endpoint_bypass_hosts.clear();
        for peer in self.peers.values() {
            let endpoint = peer.endpoint.addr.to_string();
            let family = if peer.endpoint.addr.is_ipv4() {
                "-inet"
            } else {
                "-inet6"
            };
            self.runner.run(
                "route",
                &[
                    "-n".to_string(),
                    "add".to_string(),
                    family.to_string(),
                    "-host".to_string(),
                    endpoint.clone(),
                    gateway.clone(),
                    "-ifscope".to_string(),
                    self.egress_interface.clone(),
                ],
            )?;
            self.endpoint_bypass_hosts.insert(endpoint);
        }
        Ok(())
    }

    fn remove_endpoint_bypass_routes(&mut self) {
        for endpoint in self.endpoint_bypass_hosts.iter().cloned() {
            let is_ipv6 = endpoint.contains(':');
            let family = if is_ipv6 { "-inet6" } else { "-inet" };
            let _ = self.runner.run(
                "route",
                &[
                    "-n".to_string(),
                    "delete".to_string(),
                    family.to_string(),
                    "-host".to_string(),
                    endpoint,
                ],
            );
        }
        self.endpoint_bypass_hosts.clear();
    }

    fn apply_default_route_to_tunnel(&mut self) -> Result<(), BackendError> {
        let gateway = self.capture_default_gateway()?;
        self.default_gateway = Some(gateway);
        self.install_endpoint_bypass_routes()?;

        if self
            .runner
            .run(
                "route",
                &[
                    "-n".to_string(),
                    "change".to_string(),
                    "-inet".to_string(),
                    "default".to_string(),
                    "-interface".to_string(),
                    self.interface_name.clone(),
                ],
            )
            .is_err()
        {
            self.runner.run(
                "route",
                &[
                    "-n".to_string(),
                    "add".to_string(),
                    "-inet".to_string(),
                    "default".to_string(),
                    "-interface".to_string(),
                    self.interface_name.clone(),
                ],
            )?;
        }
        Ok(())
    }

    fn restore_default_route(&mut self) {
        let Some(gateway) = self.default_gateway.clone() else {
            return;
        };
        let _ = self.runner.run(
            "route",
            &[
                "-n".to_string(),
                "change".to_string(),
                "-inet".to_string(),
                "default".to_string(),
                gateway.clone(),
            ],
        );
        self.remove_endpoint_bypass_routes();
        self.default_gateway = None;
    }

    fn terminate_wireguard_go_processes(&mut self) -> Result<(), BackendError> {
        let mut last_error: Option<BackendError> = None;
        for pid in find_wireguard_go_pids(&self.interface_name)? {
            if let Err(err) = self
                .runner
                .run("kill", &["-TERM".to_string(), pid.to_string()])
            {
                last_error = Some(err);
            }
        }
        if let Some(err) = last_error {
            return Err(err);
        }
        Ok(())
    }

    fn set_exit_tables(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        match mode {
            ExitMode::Off => {
                self.restore_default_route();
                Ok(())
            }
            ExitMode::FullTunnel => self.apply_default_route_to_tunnel(),
        }
    }

    fn read_peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        let peer = self
            .peers
            .get(node_id)
            .ok_or_else(|| BackendError::invalid_input("peer is not configured"))?;
        let output = self.runner.run_capture(
            "wg",
            &[
                "show".to_string(),
                self.interface_name.clone(),
                "latest-handshakes".to_string(),
            ],
        )?;
        let public_key = encode_wg_public_key_base64(&peer.public_key);
        parse_peer_latest_handshake_unix(&output.stdout, &public_key, self.peers.len().max(1))
    }
}

impl<R: WireguardCommandRunner + Send + Sync> TunnelBackend for MacosWireguardBackend<R> {
    fn name(&self) -> &'static str {
        "wireguard-macos"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running(
                "macos wireguard backend already started",
            ));
        }
        self.configure_interface(&context)?;
        self.context = Some(context);
        self.running = true;
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        if peer.allowed_ips.is_empty() {
            return Err(BackendError::invalid_input(
                "peer allowed_ips must not be empty",
            ));
        }

        for cidr in &peer.allowed_ips {
            Self::ensure_cidr(cidr)?;
        }

        let allowed_ips = peer.allowed_ips.join(",");
        let endpoint = format!("{}:{}", peer.endpoint.addr, peer.endpoint.port);
        self.runner.run(
            "wg",
            &[
                "set".to_string(),
                self.interface_name.clone(),
                "peer".to_string(),
                encode_wg_public_key_base64(&peer.public_key),
                "endpoint".to_string(),
                endpoint,
                "allowed-ips".to_string(),
                allowed_ips,
            ],
        )?;

        self.peers.insert(peer.node_id.clone(), peer);
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        self.ensure_running()?;
        let Some(peer) = self.peers.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        let endpoint_value = format!("{}:{}", endpoint.addr, endpoint.port);
        self.runner.run(
            "wg",
            &[
                "set".to_string(),
                self.interface_name.clone(),
                "peer".to_string(),
                encode_wg_public_key_base64(&peer.public_key),
                "endpoint".to_string(),
                endpoint_value,
            ],
        )?;
        peer.endpoint = endpoint;
        Ok(())
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.ensure_running()?;
        Ok(self.peers.get(node_id).map(|peer| peer.endpoint))
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        self.ensure_running()?;
        self.read_peer_latest_handshake_unix(node_id)
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        let Some(peer) = self.peers.remove(node_id) else {
            return Ok(());
        };
        self.runner.run(
            "wg",
            &[
                "set".to_string(),
                self.interface_name.clone(),
                "peer".to_string(),
                encode_wg_public_key_base64(&peer.public_key),
                "remove".to_string(),
            ],
        )
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.apply_route_reconciliation(&routes)
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.set_exit_tables(mode)?;
        self.exit_mode = mode;
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_running()?;
        Ok(TunnelStats {
            peer_count: self.peers.len(),
            bytes_tx: 0,
            bytes_rx: 0,
            using_relay_path: false,
        })
    }

    fn transport_socket_identity_blocker(&self) -> Option<String> {
        Some(
            "macos wireguard backend is a command-only adapter over wireguard-go and its OS-managed UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_string(),
        )
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        let _ = self.set_exit_tables(ExitMode::Off);
        self.remove_interface()?;
        self.running = false;
        self.peers.clear();
        self.routes.clear();
        self.context = None;
        self.exit_mode = ExitMode::Off;
        Ok(())
    }
}

fn validate_macos_interface_name(name: &str) -> Result<(), BackendError> {
    validate_interface_name(name)?;
    if !name.starts_with("utun") {
        return Err(BackendError::invalid_input(
            "macos wireguard interface name must start with utun",
        ));
    }
    let suffix = &name[4..];
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(BackendError::invalid_input(
            "macos wireguard interface name must be utun followed by digits",
        ));
    }
    Ok(())
}

fn extract_ip_from_cidr(cidr: &str) -> Result<String, BackendError> {
    let (ip, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
    if ip.is_empty() || prefix.is_empty() {
        return Err(BackendError::invalid_input("invalid cidr value"));
    }
    if !ip
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == ':')
    {
        return Err(BackendError::invalid_input(
            "cidr contains invalid characters",
        ));
    }
    if !prefix.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(BackendError::invalid_input("invalid cidr prefix"));
    }
    Ok(ip.to_string())
}

fn route_add_args(cidr: &str, interface_name: &str) -> Result<Vec<String>, BackendError> {
    let (destination, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
    let prefix = prefix
        .parse::<u16>()
        .map_err(|_| BackendError::invalid_input("invalid cidr prefix"))?;
    if destination.contains(':') {
        if prefix > 128 {
            return Err(BackendError::invalid_input("invalid ipv6 prefix"));
        }
        return Ok(vec![
            "-n".to_string(),
            "add".to_string(),
            "-inet6".to_string(),
            "-net".to_string(),
            cidr.to_string(),
            "-interface".to_string(),
            interface_name.to_string(),
        ]);
    }
    if prefix > 32 {
        return Err(BackendError::invalid_input("invalid ipv4 prefix"));
    }
    Ok(vec![
        "-n".to_string(),
        "add".to_string(),
        "-inet".to_string(),
        "-net".to_string(),
        cidr.to_string(),
        "-interface".to_string(),
        interface_name.to_string(),
    ])
}

fn route_delete_args(cidr: &str) -> Result<Vec<String>, BackendError> {
    let (_destination, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
    let prefix = prefix
        .parse::<u16>()
        .map_err(|_| BackendError::invalid_input("invalid cidr prefix"))?;
    let is_ipv6 = cidr.contains(':');
    if is_ipv6 && prefix > 128 {
        return Err(BackendError::invalid_input("invalid ipv6 prefix"));
    }
    if !is_ipv6 && prefix > 32 {
        return Err(BackendError::invalid_input("invalid ipv4 prefix"));
    }
    Ok(vec![
        "-n".to_string(),
        "delete".to_string(),
        if is_ipv6 {
            "-inet6".to_string()
        } else {
            "-inet".to_string()
        },
        "-net".to_string(),
        cidr.to_string(),
    ])
}

fn find_wireguard_go_pids(interface_name: &str) -> Result<Vec<u32>, BackendError> {
    let output = match Command::new(MACOS_PS_BINARY)
        .args(["-axo", "pid=,command="])
        .output()
    {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            return Ok(Vec::new());
        }
        Err(err) => {
            return Err(BackendError::internal(format!("ps spawn failed: {err}")));
        }
    };
    if !output.status.success() {
        return Err(BackendError::internal(format!(
            "ps exited with status {}",
            output.status
        )));
    }
    let expected_suffix = format!("wireguard-go {interface_name}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut pids = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        let Some(pid_raw) = parts.next() else {
            continue;
        };
        let command = trimmed
            .strip_prefix(pid_raw)
            .map(str::trim_start)
            .unwrap_or_default();
        if command.is_empty() {
            continue;
        }
        if !command.trim_end().ends_with(expected_suffix.as_str()) {
            continue;
        }
        let pid = pid_raw
            .trim()
            .parse::<u32>()
            .map_err(|err| BackendError::internal(format!("invalid ps pid value: {err}")))?;
        pids.push(pid);
    }
    Ok(pids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_command::WireguardCommandOutput;

    #[derive(Debug, Default)]
    struct RecordingRunner;

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, _program: &str, _args: &[String]) -> Result<(), BackendError> {
            Ok(())
        }

        fn run_capture(
            &mut self,
            _program: &str,
            _args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            Ok(WireguardCommandOutput {
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    fn runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("local-node").expect("valid node id"),
            interface_name: "rustynet0".to_string(),
            mesh_cidr: "100.64.0.1/32".to_string(),
            local_cidr: "100.64.0.1/32".to_string(),
        }
    }

    fn sample_peer(name: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.10".parse().expect("valid ip"),
                port: 51820,
            },
            public_key: [7; 32],
            allowed_ips: vec!["100.64.1.0/24".to_string()],
        }
    }

    #[test]
    fn macos_backend_reports_transport_socket_identity_blocker() {
        let backend = MacosWireguardBackend::new(
            RecordingRunner,
            "utun9",
            "/tmp/rustynet-test.key",
            "en0",
            51820,
        )
        .expect("macos backend should be constructible");

        let blocker = backend
            .transport_socket_identity_blocker()
            .expect("macos backend should report transport blocker");
        assert!(blocker.contains("wireguard-go"));
        assert!(blocker.contains("command-only adapter"));
        assert!(blocker.contains("no authoritative packet-I/O handle"));
        assert!(blocker.contains("backend-owned datagram multiplexer"));
        assert!(blocker.contains("same-port daemon side socket is not authoritative"));
    }

    #[test]
    fn macos_backend_requires_utun_interface_name() {
        let err =
            MacosWireguardBackend::new(RecordingRunner, "rustynet0", "/tmp/wg.key", "en0", 51820)
                .expect_err("non-utun interface names must be rejected");
        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
    }

    #[test]
    fn macos_backend_reports_ipv6_not_supported_until_parity_is_implemented() {
        let backend =
            MacosWireguardBackend::new(RecordingRunner, "utun9", "/tmp/wg.key", "en0", 51820)
                .expect("backend should be constructed");
        assert!(!backend.capabilities().supports_ipv6);
    }

    #[test]
    fn macos_backend_accepts_basic_lifecycle_with_recording_runner() {
        let mut backend =
            MacosWireguardBackend::new(RecordingRunner, "utun9", "/tmp/wg.key", "en0", 51820)
                .expect("backend should be constructed");

        backend
            .start(runtime_context())
            .expect("start should execute runner calls");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "100.100.1.0/24".to_string(),
                via_node: NodeId::new("peer-a").expect("id should parse"),
                kind: rustynet_backend_api::RouteKind::Mesh,
            }])
            .expect("route apply should work");
        backend.shutdown().expect("shutdown should work");
    }
}
