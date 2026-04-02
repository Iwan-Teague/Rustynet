use std::collections::BTreeMap;
use std::process::Command;

use rustynet_backend_api::{
    BackendCapabilities, BackendError, BackendErrorKind, ExitMode, NodeId, PeerConfig, Route,
    RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};

pub(crate) const WG_LATEST_HANDSHAKES_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardCommandOutput {
    pub stdout: String,
    pub stderr: String,
}

pub trait WireguardCommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError>;

    fn run_capture(
        &mut self,
        program: &str,
        args: &[String],
    ) -> Result<WireguardCommandOutput, BackendError>;
}

#[derive(Debug, Default)]
pub struct LinuxCommandRunner;

impl WireguardCommandRunner for LinuxCommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
        let _ = self.run_capture(program, args)?;
        Ok(())
    }

    fn run_capture(
        &mut self,
        program: &str,
        args: &[String],
    ) -> Result<WireguardCommandOutput, BackendError> {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|err| BackendError::internal(format!("{program} spawn failed: {err}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if stderr.is_empty() {
                return Err(BackendError::internal(format!(
                    "{program} exited with status {}",
                    output.status
                )));
            }
            return Err(BackendError::internal(format!(
                "{program} exited with status {}: {stderr}",
                output.status
            )));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|_| BackendError::internal(format!("{program} produced non-utf8 stdout")))?;
        let stderr = String::from_utf8(output.stderr)
            .map_err(|_| BackendError::internal(format!("{program} produced non-utf8 stderr")))?;
        Ok(WireguardCommandOutput { stdout, stderr })
    }
}

#[derive(Debug)]
pub struct LinuxWireguardBackend<R: WireguardCommandRunner> {
    pub(crate) runner: R,
    interface_name: String,
    private_key_path: String,
    listen_port: u16,
    running: bool,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    context: Option<RuntimeContext>,
    exit_mode: ExitMode,
}

impl<R: WireguardCommandRunner> LinuxWireguardBackend<R> {
    pub fn new(
        runner: R,
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        let interface_name = interface_name.into();
        let private_key_path = private_key_path.into();
        validate_interface_name(&interface_name)?;
        validate_private_key_path(&private_key_path)?;
        validate_listen_port(listen_port)?;
        Ok(Self {
            runner,
            interface_name,
            private_key_path,
            listen_port,
            running: false,
            peers: BTreeMap::new(),
            routes: Vec::new(),
            context: None,
            exit_mode: ExitMode::Off,
        })
    }

    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }
        Err(BackendError::not_running(
            "linux wireguard backend is not running",
        ))
    }

    pub(crate) fn ensure_cidr(value: &str) -> Result<(), BackendError> {
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

    fn is_missing_ip_route_error(err: &BackendError) -> bool {
        if err.kind != BackendErrorKind::Internal {
            return false;
        }
        let message = err.message.to_ascii_lowercase();
        message.contains("rtnetlink answers: no such process")
            || message.contains("no such process")
            || message.contains("no such file or directory")
    }

    fn configure_interface(&mut self, context: &RuntimeContext) -> Result<(), BackendError> {
        Self::ensure_cidr(&context.local_cidr)?;
        let add_args = [
            "link".to_string(),
            "add".to_string(),
            "dev".to_string(),
            self.interface_name.clone(),
            "type".to_string(),
            "wireguard".to_string(),
        ];
        if self.runner.run("ip", &add_args).is_err() {
            let _ = self.remove_interface();
            self.runner.run("ip", &add_args)?;
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
            "ip",
            &[
                "address".to_string(),
                "add".to_string(),
                context.local_cidr.clone(),
                "dev".to_string(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_string(),
                "set".to_string(),
                "up".to_string(),
                "dev".to_string(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        Ok(())
    }

    fn remove_interface(&mut self) -> Result<(), BackendError> {
        self.runner.run(
            "ip",
            &[
                "link".to_string(),
                "del".to_string(),
                "dev".to_string(),
                self.interface_name.clone(),
            ],
        )
    }

    fn apply_route_reconciliation(&mut self, next_routes: &[Route]) -> Result<(), BackendError> {
        for route in &self.routes {
            if next_routes.iter().any(|candidate| candidate == route) {
                continue;
            }

            match self.runner.run(
                "ip",
                &[
                    "route".to_string(),
                    "del".to_string(),
                    route.destination_cidr.clone(),
                    "dev".to_string(),
                    self.interface_name.clone(),
                ],
            ) {
                Ok(()) => {}
                Err(err) => {
                    if !Self::is_missing_ip_route_error(&err) {
                        return Err(err);
                    }
                }
            }
        }

        for route in next_routes {
            Self::ensure_cidr(&route.destination_cidr)?;
            if matches!(route.kind, rustynet_backend_api::RouteKind::ExitNodeDefault) {
                continue;
            }
            self.runner.run(
                "ip",
                &[
                    "route".to_string(),
                    "replace".to_string(),
                    route.destination_cidr.clone(),
                    "dev".to_string(),
                    self.interface_name.clone(),
                ],
            )?;
        }

        self.routes = next_routes.to_vec();
        Ok(())
    }

    fn set_exit_tables(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        const EXIT_RULE_PRIORITY: &str = "10000";
        for _ in 0..64 {
            if self
                .runner
                .run(
                    "ip",
                    &[
                        "rule".to_string(),
                        "del".to_string(),
                        "table".to_string(),
                        "51820".to_string(),
                    ],
                )
                .is_err()
            {
                break;
            }
        }
        let delete_args = [
            "rule".to_string(),
            "del".to_string(),
            "priority".to_string(),
            EXIT_RULE_PRIORITY.to_string(),
            "table".to_string(),
            "51820".to_string(),
        ];
        match mode {
            ExitMode::Off => {
                let _ = self.runner.run("ip", &delete_args);
                Ok(())
            }
            ExitMode::FullTunnel => {
                let _ = self.runner.run("ip", &delete_args);
                self.runner.run(
                    "ip",
                    &[
                        "rule".to_string(),
                        "add".to_string(),
                        "priority".to_string(),
                        EXIT_RULE_PRIORITY.to_string(),
                        "table".to_string(),
                        "51820".to_string(),
                    ],
                )
            }
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

impl<R: WireguardCommandRunner + Send + Sync> TunnelBackend for LinuxWireguardBackend<R> {
    fn name(&self) -> &'static str {
        "wireguard-linux"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: true,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running(
                "linux wireguard backend already started",
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
            "linux wireguard backend is a command-only adapter over an OS-managed WireGuard UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_string(),
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

pub(crate) fn validate_interface_name(name: &str) -> Result<(), BackendError> {
    if name.is_empty() || name.len() > 15 {
        return Err(BackendError::invalid_input(
            "wireguard interface name length must be between 1 and 15",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
    {
        return Err(BackendError::invalid_input(
            "wireguard interface name contains invalid characters",
        ));
    }
    Ok(())
}

pub(crate) fn validate_private_key_path(path: &str) -> Result<(), BackendError> {
    if path.trim().is_empty() {
        return Err(BackendError::invalid_input(
            "wireguard private key path must not be empty",
        ));
    }
    if !path.starts_with('/') {
        return Err(BackendError::invalid_input(
            "wireguard private key path must be absolute",
        ));
    }
    if path.contains('\0') {
        return Err(BackendError::invalid_input(
            "wireguard private key path contains invalid characters",
        ));
    }
    Ok(())
}

pub(crate) fn validate_listen_port(port: u16) -> Result<(), BackendError> {
    if port == 0 {
        return Err(BackendError::invalid_input(
            "wireguard listen port must be in range 1-65535",
        ));
    }
    Ok(())
}

pub(crate) fn parse_peer_latest_handshake_unix(
    stdout: &str,
    expected_public_key: &str,
    max_lines: usize,
) -> Result<Option<u64>, BackendError> {
    if stdout.len() > WG_LATEST_HANDSHAKES_MAX_BYTES {
        return Err(BackendError::internal(format!(
            "wg latest-handshakes output exceeded {WG_LATEST_HANDSHAKES_MAX_BYTES} bytes"
        )));
    }

    let mut lines_seen = 0usize;
    let mut matched: Option<Option<u64>> = None;
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        lines_seen = lines_seen.saturating_add(1);
        if lines_seen > max_lines {
            return Err(BackendError::internal(
                "wg latest-handshakes output exceeded expected peer count",
            ));
        }
        let mut fields = line.split_whitespace();
        let public_key = fields.next().ok_or_else(|| {
            BackendError::internal("wg latest-handshakes line missing public key")
        })?;
        let handshake_raw = fields.next().ok_or_else(|| {
            BackendError::internal("wg latest-handshakes line missing handshake timestamp")
        })?;
        if fields.next().is_some() {
            return Err(BackendError::internal(
                "wg latest-handshakes line contains unexpected trailing data",
            ));
        }
        if public_key != expected_public_key {
            continue;
        }
        if matched.is_some() {
            return Err(BackendError::internal(
                "wg latest-handshakes output contained duplicate peer entries",
            ));
        }
        let handshake_unix = handshake_raw.parse::<u64>().map_err(|err| {
            BackendError::internal(format!(
                "wg latest-handshakes timestamp parse failed: {err}"
            ))
        })?;
        matched = Some((handshake_unix != 0).then_some(handshake_unix));
    }

    Ok(matched.flatten())
}

pub(crate) fn encode_wg_public_key_base64(value: &[u8; 32]) -> String {
    const BASE64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    let mut index = 0usize;
    while index + 3 <= value.len() {
        let chunk = ((value[index] as u32) << 16)
            | ((value[index + 1] as u32) << 8)
            | (value[index + 2] as u32);
        output.push(BASE64_TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[(chunk & 0x3f) as usize] as char);
        index += 3;
    }

    let remaining = value.len() - index;
    if remaining == 2 {
        let chunk = ((value[index] as u32) << 16) | ((value[index + 1] as u32) << 8);
        output.push(BASE64_TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        output.push('=');
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct RecordingRunner {
        calls: Vec<(String, Vec<String>)>,
        fail_program: Option<String>,
        capture_outputs: BTreeMap<(String, Vec<String>), WireguardCommandOutput>,
    }

    impl RecordingRunner {
        fn fail_on(mut self, program: &str) -> Self {
            self.fail_program = Some(program.to_string());
            self
        }

        fn capture_output(
            mut self,
            program: &str,
            args: &[String],
            stdout: &str,
            stderr: &str,
        ) -> Self {
            self.capture_outputs.insert(
                (program.to_string(), args.to_vec()),
                WireguardCommandOutput {
                    stdout: stdout.to_string(),
                    stderr: stderr.to_string(),
                },
            );
            self
        }
    }

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.calls.push((program.to_string(), args.to_vec()));
            if self
                .fail_program
                .as_ref()
                .map(|candidate| candidate == program)
                .unwrap_or(false)
            {
                return Err(BackendError::internal("injected failure"));
            }
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            self.run(program, args)?;
            Ok(self
                .capture_outputs
                .get(&(program.to_string(), args.to_vec()))
                .cloned()
                .unwrap_or(WireguardCommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                }))
        }
    }

    #[derive(Debug, Default)]
    struct MissingRouteDeleteRunner;

    impl WireguardCommandRunner for MissingRouteDeleteRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let is_route_delete = program == "ip"
                && args.first().map(String::as_str) == Some("route")
                && args.get(1).map(String::as_str) == Some("del");
            if is_route_delete {
                return Err(BackendError::internal(
                    "privileged helper ip exited with status 2: RTNETLINK answers: No such process",
                ));
            }
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            self.run(program, args)?;
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
    fn linux_backend_reports_transport_socket_identity_blocker() {
        let backend = LinuxWireguardBackend::new(
            RecordingRunner::default(),
            "rustynet0",
            "/tmp/rustynet-test.key",
            51820,
        )
        .expect("linux backend should be constructible");

        let blocker = backend
            .transport_socket_identity_blocker()
            .expect("linux backend should report transport blocker");
        assert!(blocker.contains("command-only adapter"));
        assert!(blocker.contains("OS-managed WireGuard UDP socket"));
        assert!(blocker.contains("no authoritative packet-I/O handle"));
        assert!(blocker.contains("backend-owned datagram multiplexer"));
        assert!(blocker.contains("same-port daemon side socket is not authoritative"));
    }

    #[test]
    fn linux_backend_executes_ip_and_wg_calls_through_runner() {
        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
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
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode should work");
        backend.shutdown().expect("shutdown should work");

        let stats = backend.stats();
        assert!(stats.is_err());
    }

    #[test]
    fn linux_backend_full_tunnel_rule_uses_fixed_priority() {
        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");

        backend
            .start(runtime_context())
            .expect("start should execute runner calls");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode should work");

        let delete_rule = vec![
            "rule".to_string(),
            "del".to_string(),
            "priority".to_string(),
            "10000".to_string(),
            "table".to_string(),
            "51820".to_string(),
        ];
        let add_rule = vec![
            "rule".to_string(),
            "add".to_string(),
            "priority".to_string(),
            "10000".to_string(),
            "table".to_string(),
            "51820".to_string(),
        ];

        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|(program, args)| program == "ip" && args == &delete_rule)
        );
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|(program, args)| program == "ip" && args == &add_rule)
        );
    }

    #[test]
    fn linux_backend_uses_base64_peer_key_for_wg_commands() {
        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");
        backend
            .remove_peer(&NodeId::new("peer-a").expect("valid node id"))
            .expect("peer remove should work");

        let expected_public_key = encode_wg_public_key_base64(&[7; 32]);
        let mut peer_key_args = backend
            .runner
            .calls
            .iter()
            .filter(|(program, args)| {
                program == "wg" && args.len() >= 4 && args[0] == "set" && args[2] == "peer"
            })
            .map(|(_, args)| args[3].clone())
            .collect::<Vec<_>>();
        peer_key_args.sort();
        assert_eq!(
            peer_key_args,
            vec![expected_public_key.clone(), expected_public_key]
        );
    }

    #[test]
    fn base64_encoder_matches_wireguard_key_format() {
        assert_eq!(
            encode_wg_public_key_base64(&[0u8; 32]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn linux_backend_validates_interface_and_cidr_inputs() {
        assert!(
            LinuxWireguardBackend::new(RecordingRunner::default(), "", "/tmp/wg.key", 51820)
                .is_err()
        );
        assert!(
            LinuxWireguardBackend::new(RecordingRunner::default(), "wg;rm", "/tmp/wg.key", 51820)
                .is_err()
        );
        assert!(
            LinuxWireguardBackend::new(
                RecordingRunner::default(),
                "rustynet0",
                "relative.key",
                51820
            )
            .is_err()
        );
        assert!(
            LinuxWireguardBackend::new(RecordingRunner::default(), "rustynet0", "/tmp/wg.key", 0)
                .is_err()
        );

        let mut backend = LinuxWireguardBackend::new(
            RecordingRunner::default(),
            "rustynet0",
            "/tmp/wg.key",
            51820,
        )
        .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should succeed");

        let mut peer = sample_peer("peer-a");
        peer.allowed_ips = vec!["0.0.0.0/0;rm".to_string()];
        let err = backend
            .configure_peer(peer)
            .expect_err("invalid cidr should be rejected");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    }

    #[test]
    fn linux_backend_propagates_runner_failures() {
        let runner = RecordingRunner::default().fail_on("ip");
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");

        let err = backend
            .start(runtime_context())
            .expect_err("runner failure should bubble");
        assert_eq!(err.kind, BackendErrorKind::Internal);
    }

    #[test]
    fn linux_backend_ignores_missing_route_delete_during_reconciliation() {
        let runner = MissingRouteDeleteRunner;
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        let peer = NodeId::new("peer-a").expect("id should parse");

        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "100.100.1.0/24".to_string(),
                via_node: peer.clone(),
                kind: rustynet_backend_api::RouteKind::Mesh,
            }])
            .expect("initial route apply should succeed");
        backend
            .apply_routes(Vec::new())
            .expect("missing route delete should be treated as idempotent");

        assert!(backend.routes.is_empty());
    }

    #[test]
    fn linux_backend_reads_latest_handshake_for_configured_peer() {
        let args = vec![
            "show".to_string(),
            "rustynet0".to_string(),
            "latest-handshakes".to_string(),
        ];
        let runner = RecordingRunner::default().capture_output(
            "wg",
            &args,
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\t12345\n",
            "",
        );
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        let node_id = NodeId::new("peer-a").expect("id should parse");
        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");

        let latest = backend
            .peer_latest_handshake_unix(&node_id)
            .expect("latest handshake should parse");
        assert_eq!(latest, Some(12_345));
    }

    #[test]
    fn latest_handshake_parser_rejects_oversized_or_malformed_output() {
        let oversized = "a".repeat(WG_LATEST_HANDSHAKES_MAX_BYTES + 1);
        let err = parse_peer_latest_handshake_unix(
            &oversized,
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            1,
        )
        .expect_err("oversized latest-handshakes output must fail");
        assert_eq!(err.kind, BackendErrorKind::Internal);

        let err = parse_peer_latest_handshake_unix(
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\tnot-a-number\n",
            "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            1,
        )
        .expect_err("malformed timestamp must fail");
        assert_eq!(err.kind, BackendErrorKind::Internal);
    }
}
