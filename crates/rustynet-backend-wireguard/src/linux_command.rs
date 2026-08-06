use std::collections::BTreeMap;
use std::process::Command;

use rustynet_backend_api::{
    BackendCapabilities, BackendError, BackendErrorKind, ExitMode, NodeId, PeerConfig, Route,
    RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};

pub(crate) const WG_LATEST_HANDSHAKES_MAX_BYTES: usize = 64 * 1024;

/// FIS-0027 Phase 2: the safe bring-up tunnel MTU the per-OS command adapters
/// set explicitly at interface configuration time.
///
/// Rustynet previously never set the tunnel MTU on any OS, leaving the value
/// to whatever the platform default happened to be (1500 on some kernels and
/// TUN paths — the never-set-MTU bug band-aided by a manual `ExecStartPost
/// ip link set mtu 1420` in the embedded-support runbook). 1420 is the widely
/// used WireGuard convention: 1500-byte Ethernet minus 80 bytes of worst-case
/// IPv6 + UDP + WireGuard encapsulation overhead, so a full-size inner packet
/// never fragments the outer frame on a clean 1500 underlay. FIS-0027's later
/// phases replace this static bring-up value with the per-path measured MTU
/// from the `rustynetd::path_mtu` DPLPMTUD search; until then this constant
/// makes bring-up deterministic instead of platform-default-dependent.
pub const SAFE_BRINGUP_TUNNEL_MTU: u16 = 1420;

/// Environment override for the bring-up tunnel MTU.
///
/// `SAFE_BRINGUP_TUNNEL_MTU` assumes a clean 1500-byte underlay. That
/// assumption fails on a NAT-traversed path, where the outer packet may ride a
/// carrier with a smaller MTU: a WireGuard datagram leaving over a 1280-byte
/// hop only has 1280 − 60 = 1220 bytes left for the inner packet, so a 1420
/// tunnel silently black-holes anything large while pings keep working.
/// Measured on a real cross-network path 2026-07-29 — ICMP succeeded to a
/// 1000-byte payload, failed from 1200 up, and bulk TCP stalled after 0.03 MB.
///
/// This is an interim operator escape hatch, not the answer. FIS-0027 Phase 3
/// replaces it with the per-path measured value from the
/// `rustynetd::path_mtu` DPLPMTUD search, whose state machine already exists
/// but has no consumer yet.
pub const TUNNEL_MTU_ENV: &str = "RUSTYNET_WG_TUNNEL_MTU";

/// Lower bound for the override. 1200 is the smallest tunnel MTU that still
/// clears a 1280-byte outer hop (the IPv6 minimum link MTU, and what tailscale
/// and most tunnel carriers use) after worst-case encapsulation overhead.
pub const MIN_BRINGUP_TUNNEL_MTU: u16 = 1200;

/// Resolve the bring-up tunnel MTU.
///
/// Returns `SAFE_BRINGUP_TUNNEL_MTU` unless `RUSTYNET_WG_TUNNEL_MTU` holds a
/// value inside `MIN_BRINGUP_TUNNEL_MTU..=SAFE_BRINGUP_TUNNEL_MTU`. Anything
/// absent, unparseable, or out of range falls back to the default: a bad
/// override must not silently produce an interface MTU nobody chose, and the
/// ceiling stays at the audited default so this can only ever make the tunnel
/// *more* conservative, never less.
pub fn bringup_tunnel_mtu() -> u16 {
    resolve_bringup_tunnel_mtu(std::env::var(TUNNEL_MTU_ENV).ok().as_deref())
}

/// Pure core of [`bringup_tunnel_mtu`], split out so the bounds are testable
/// without touching process environment.
pub fn resolve_bringup_tunnel_mtu(raw: Option<&str>) -> u16 {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return SAFE_BRINGUP_TUNNEL_MTU;
    };
    match raw.parse::<u16>() {
        Ok(value) if (MIN_BRINGUP_TUNNEL_MTU..=SAFE_BRINGUP_TUNNEL_MTU).contains(&value) => value,
        _ => SAFE_BRINGUP_TUNNEL_MTU,
    }
}

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
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
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
            "link".to_owned(),
            "add".to_owned(),
            "dev".to_owned(),
            self.interface_name.clone(),
            "type".to_owned(),
            "wireguard".to_owned(),
        ];
        if self.runner.run("ip", &add_args).is_err() {
            let _ = self.remove_interface();
            self.runner.run("ip", &add_args)?;
        }
        if let Err(err) = self.runner.run(
            "wg",
            &[
                "set".to_owned(),
                self.interface_name.clone(),
                "private-key".to_owned(),
                self.private_key_path.clone(),
                "listen-port".to_owned(),
                self.listen_port.to_string(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "address".to_owned(),
                "add".to_owned(),
                context.local_cidr.clone(),
                "dev".to_owned(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        // FIS-0027 Phase 2: pin the tunnel MTU explicitly (wg-quick order —
        // before link-up) instead of trusting the platform default, closing
        // the never-set-MTU gap.
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                "mtu".to_owned(),
                bringup_tunnel_mtu().to_string(),
                "dev".to_owned(),
                self.interface_name.clone(),
            ],
        ) {
            let _ = self.remove_interface();
            return Err(err);
        }
        if let Err(err) = self.runner.run(
            "ip",
            &[
                "link".to_owned(),
                "set".to_owned(),
                "up".to_owned(),
                "dev".to_owned(),
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
                "link".to_owned(),
                "del".to_owned(),
                "dev".to_owned(),
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
                    "route".to_owned(),
                    "del".to_owned(),
                    route.destination_cidr.clone(),
                    "dev".to_owned(),
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
                    "route".to_owned(),
                    "replace".to_owned(),
                    route.destination_cidr.clone(),
                    "dev".to_owned(),
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
                        "rule".to_owned(),
                        "del".to_owned(),
                        "table".to_owned(),
                        "51820".to_owned(),
                    ],
                )
                .is_err()
            {
                break;
            }
        }
        let delete_args = [
            "rule".to_owned(),
            "del".to_owned(),
            "priority".to_owned(),
            EXIT_RULE_PRIORITY.to_owned(),
            "table".to_owned(),
            "51820".to_owned(),
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
                        "rule".to_owned(),
                        "add".to_owned(),
                        "priority".to_owned(),
                        EXIT_RULE_PRIORITY.to_owned(),
                        "table".to_owned(),
                        "51820".to_owned(),
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
                "show".to_owned(),
                self.interface_name.clone(),
                "latest-handshakes".to_owned(),
            ],
        )?;
        let public_key = encode_wg_public_key_base64(&peer.public_key);
        parse_peer_latest_handshake_unix(&output.stdout, &public_key, self.peers.len().max(1))
    }

    /// I4/A3.2: report the endpoint the peer's latest handshake came from.
    ///
    /// Deliberately NOT `self.peers.get(node_id).map(|peer| peer.endpoint)` —
    /// that is the value we last configured, which during an ICE pair race is
    /// simply the last pair probed. Reading `wg show <iface> dump` reports what
    /// the kernel actually recorded for the peer, which after a successful
    /// handshake is the address the peer authenticated from.
    fn handshake_endpoint_observed(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        let peer = self
            .peers
            .get(node_id)
            .ok_or_else(|| BackendError::invalid_input("peer is not configured"))?;
        let public_key = encode_wg_public_key_base64(&peer.public_key);
        let output = self.runner.run_capture(
            "wg",
            &[
                "show".to_owned(),
                self.interface_name.clone(),
                "dump".to_owned(),
            ],
        )?;
        parse_peer_dump_handshake_endpoint(&output.stdout, &public_key, self.peers.len().max(1))
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
            supports_exit_client: true,
            supports_exit_serving: true,
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
        let mut args = vec![
            "set".to_owned(),
            self.interface_name.clone(),
            "peer".to_owned(),
            encode_wg_public_key_base64(&peer.public_key),
            "endpoint".to_owned(),
            endpoint,
            "allowed-ips".to_owned(),
            allowed_ips,
        ];
        // FIS-0015: only when configured — None preserves today's behavior
        // (no WG-native keepalive).
        if let Some(interval_secs) = peer.persistent_keepalive_secs {
            args.push("persistent-keepalive".to_owned());
            args.push(interval_secs.to_string());
        }
        self.runner.run("wg", &args)?;

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
                "set".to_owned(),
                self.interface_name.clone(),
                "peer".to_owned(),
                encode_wg_public_key_base64(&peer.public_key),
                "endpoint".to_owned(),
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

    fn handshake_endpoint(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.ensure_running()?;
        self.handshake_endpoint_observed(node_id)
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        let Some(peer) = self.peers.remove(node_id) else {
            return Ok(());
        };
        self.runner.run(
            "wg",
            &[
                "set".to_owned(),
                self.interface_name.clone(),
                "peer".to_owned(),
                encode_wg_public_key_base64(&peer.public_key),
                "remove".to_owned(),
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
            "linux wireguard backend is a command-only adapter over an OS-managed WireGuard UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned(),
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

/// I4/A3.2: extract the endpoint a peer's most recent handshake was observed
/// from, out of `wg show <iface> dump`.
///
/// `dump` is used rather than `latest-handshakes` because it reports the
/// endpoint and the handshake timestamp on the SAME line, read in one command
/// invocation. That atomicity is the whole point: the two values must describe
/// the same observation, or pairing them would reintroduce the misattribution
/// this exists to remove.
///
/// Fails closed to `Ok(None)` — meaning "unattributed" — whenever the peer is
/// absent, the endpoint column is `(none)`, or the handshake timestamp is zero.
/// The last case matters most: reporting an endpoint for a peer that has never
/// completed a handshake would attribute a handshake that never happened.
///
/// Peer lines carry 8 tab-separated fields (public-key, preshared-key,
/// endpoint, allowed-ips, latest-handshake, rx, tx, persistent-keepalive);
/// the leading interface line carries 4 (private-key, public-key, listen-port,
/// fwmark) and is skipped by field count rather than by position, so a future
/// extra interface line cannot silently shift the parse.
pub(crate) fn parse_peer_dump_handshake_endpoint(
    stdout: &str,
    expected_public_key: &str,
    max_lines: usize,
) -> Result<Option<SocketEndpoint>, BackendError> {
    if stdout.len() > WG_LATEST_HANDSHAKES_MAX_BYTES {
        return Err(BackendError::internal(format!(
            "wg dump output exceeded {WG_LATEST_HANDSHAKES_MAX_BYTES} bytes"
        )));
    }

    let mut lines_seen = 0usize;
    let mut matched: Option<Option<SocketEndpoint>> = None;
    for raw_line in stdout.lines() {
        let line = raw_line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            continue;
        }
        lines_seen = lines_seen.saturating_add(1);
        if lines_seen > max_lines.saturating_add(1) {
            return Err(BackendError::internal(
                "wg dump output exceeded expected peer count",
            ));
        }
        let fields: Vec<&str> = line.split('\t').collect();
        // The interface line has 4 fields; peer lines have 8. Anything else is
        // a format we did not expect, and guessing at it would be worse than
        // reporting nothing.
        if fields.len() == 4 {
            continue;
        }
        if fields.len() != 8 {
            return Err(BackendError::internal(
                "wg dump line did not carry the expected field count",
            ));
        }
        if fields[0] != expected_public_key {
            continue;
        }
        if matched.is_some() {
            return Err(BackendError::internal(
                "wg dump output contained duplicate peer entries",
            ));
        }
        let endpoint_raw = fields[2];
        let handshake_unix = fields[4].parse::<u64>().map_err(|err| {
            BackendError::internal(format!("wg dump timestamp parse failed: {err}"))
        })?;
        if handshake_unix == 0 || endpoint_raw == "(none)" {
            matched = Some(None);
            continue;
        }
        matched = Some(parse_wg_endpoint(endpoint_raw));
    }

    Ok(matched.flatten())
}

/// Parse WireGuard's endpoint rendering into a `SocketEndpoint`.
///
/// Delegates to the standard `SocketAddr` parser, which already handles both
/// `ADDR:PORT` and the bracketed `[V6]:PORT` form wireguard emits. An
/// unparseable value yields `None` (unattributed) rather than an error: a
/// backend that cannot read the endpoint must not fail the probe, it must
/// decline to attribute.
fn parse_wg_endpoint(value: &str) -> Option<SocketEndpoint> {
    value
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| SocketEndpoint {
            addr: addr.ip(),
            port: addr.port(),
        })
}

pub(crate) fn encode_wg_public_key_base64(value: &[u8; 32]) -> String {
    const BASE64_TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    let mut index = 0usize;
    while index + 3 <= value.len() {
        let chunk = (u32::from(value[index]) << 16)
            | (u32::from(value[index + 1]) << 8)
            | u32::from(value[index + 2]);
        output.push(BASE64_TABLE[((chunk >> 18) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 12) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[((chunk >> 6) & 0x3f) as usize] as char);
        output.push(BASE64_TABLE[(chunk & 0x3f) as usize] as char);
        index += 3;
    }

    let remaining = value.len() - index;
    if remaining == 2 {
        let chunk = (u32::from(value[index]) << 16) | (u32::from(value[index + 1]) << 8);
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
            self.fail_program = Some(program.to_owned());
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
                (program.to_owned(), args.to_vec()),
                WireguardCommandOutput {
                    stdout: stdout.to_owned(),
                    stderr: stderr.to_owned(),
                },
            );
            self
        }
    }

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.calls.push((program.to_owned(), args.to_vec()));
            if self
                .fail_program
                .as_ref()
                .is_some_and(|candidate| candidate == program)
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
                .get(&(program.to_owned(), args.to_vec()))
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
            interface_name: "rustynet0".to_owned(),
            mesh_cidr: "100.64.0.1/32".to_owned(),
            local_cidr: "100.64.0.1/32".to_owned(),
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
            allowed_ips: vec!["100.64.1.0/24".to_owned()],
            persistent_keepalive_secs: None,
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
                destination_cidr: "100.100.1.0/24".to_owned(),
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

    /// I4/A3.2. The dump line carries the endpoint the kernel recorded, which
    /// after a handshake is where the peer authenticated from — NOT the value
    /// we last configured. This is the whole point of the method.
    #[test]
    fn dump_parser_reports_the_endpoint_the_handshake_came_from() {
        let dump = "priv\tpub\t51820\toff\n\
                    peer-key\t(none)\t203.0.113.7:41641\t10.0.0.2/32\t1735689600\t0\t0\toff\n";
        let endpoint = parse_peer_dump_handshake_endpoint(dump, "peer-key", 4)
            .expect("dump should parse")
            .expect("a handshaked peer must report its endpoint");
        assert_eq!(endpoint.port, 41641);
        assert_eq!(endpoint.addr.to_string(), "203.0.113.7");
    }

    /// Fail closed: a peer that has never completed a handshake must report
    /// nothing. Reporting its configured endpoint here would attribute a
    /// handshake that never happened, which is the defect class this method
    /// exists to remove.
    #[test]
    fn dump_parser_reports_nothing_when_no_handshake_has_occurred() {
        let dump = "priv\tpub\t51820\toff\n\
                    peer-key\t(none)\t203.0.113.7:41641\t10.0.0.2/32\t0\t0\t0\toff\n";
        assert_eq!(
            parse_peer_dump_handshake_endpoint(dump, "peer-key", 4).expect("dump should parse"),
            None,
            "a zero handshake timestamp must not attribute an endpoint"
        );
    }

    /// A peer with no endpoint yet is likewise unattributed rather than an
    /// error: the probe must continue, it just may not credit anything.
    #[test]
    fn dump_parser_reports_nothing_for_an_absent_endpoint() {
        let dump = "priv\tpub\t51820\toff\n\
                    peer-key\t(none)\t(none)\t10.0.0.2/32\t1735689600\t0\t0\toff\n";
        assert_eq!(
            parse_peer_dump_handshake_endpoint(dump, "peer-key", 4).expect("dump should parse"),
            None
        );
    }

    /// IPv6 endpoints arrive bracketed; they must round-trip, or attribution
    /// would silently degrade to unattributed on every v6 path.
    #[test]
    fn dump_parser_handles_bracketed_ipv6_endpoints() {
        let dump = "priv\tpub\t51820\toff\n\
                    peer-key\t(none)\t[2001:db8::7]:41641\t10.0.0.2/32\t1735689600\t0\t0\toff\n";
        let endpoint = parse_peer_dump_handshake_endpoint(dump, "peer-key", 4)
            .expect("dump should parse")
            .expect("v6 endpoint must be attributed");
        assert_eq!(endpoint.port, 41641);
        assert_eq!(endpoint.addr.to_string(), "2001:db8::7");
    }

    /// Only the requested peer may be credited. Crediting a sibling peer's
    /// endpoint would be a cross-peer misattribution.
    #[test]
    fn dump_parser_selects_the_requested_peer_only() {
        let dump = "priv\tpub\t51820\toff\n\
                    other-key\t(none)\t198.51.100.1:1111\t10.0.0.3/32\t1735689600\t0\t0\toff\n\
                    peer-key\t(none)\t203.0.113.7:41641\t10.0.0.2/32\t1735689600\t0\t0\toff\n";
        let endpoint = parse_peer_dump_handshake_endpoint(dump, "peer-key", 4)
            .expect("dump should parse")
            .expect("requested peer must be found");
        assert_eq!(endpoint.port, 41641);
    }

    /// The per-backend proof the dispatch pin cannot give: this exercises the
    /// real `TunnelBackend::handshake_endpoint` on the Linux adapter through a
    /// programmed `wg show dump`. If this adapter ever silently falls back to
    /// the defaulted trait method it returns `None` and this fails — which is
    /// exactly the defaulted-method regression class a source-text dispatch
    /// pin cannot detect.
    #[test]
    fn linux_backend_handshake_endpoint_reads_the_live_dump_not_the_configured_value() {
        let dump = "priv\tpub\t51820\toff\n\
                    "
        .to_owned()
            + &encode_wg_public_key_base64(&sample_peer("peer-a").public_key)
            + "\t(none)\t203.0.113.7:41641\t10.0.0.2/32\t1735689600\t0\t0\toff\n";
        let runner = RecordingRunner::default().capture_output(
            "wg",
            &["show".to_owned(), "rustynet0".to_owned(), "dump".to_owned()],
            &dump,
            "",
        );
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");

        let observed = backend
            .handshake_endpoint(&NodeId::new("peer-a").expect("node id"))
            .expect("handshake endpoint read should succeed")
            .expect("a handshaked peer must attribute an endpoint");
        assert_eq!(
            observed.addr.to_string(),
            "203.0.113.7",
            "the adapter must report the endpoint from the live dump"
        );
        assert_ne!(
            observed,
            sample_peer("peer-a").endpoint,
            "reporting the CONFIGURED endpoint would defeat attribution entirely"
        );
    }

    #[test]
    fn linux_backend_wg_set_includes_persistent_keepalive_when_configured() {
        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");

        // Default (None): no persistent-keepalive arg — today's behavior.
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");
        assert!(
            !backend
                .runner
                .calls
                .iter()
                .any(|(_, args)| args.iter().any(|arg| arg == "persistent-keepalive")),
            "None must not emit persistent-keepalive"
        );

        // Some(n): the wg set call carries `persistent-keepalive n`.
        let mut peer = sample_peer("peer-b");
        peer.persistent_keepalive_secs = Some(21);
        backend
            .configure_peer(peer)
            .expect("peer configure should work");
        assert!(
            backend.runner.calls.iter().any(|(program, args)| {
                program == "wg"
                    && args
                        .windows(2)
                        .any(|pair| pair[0] == "persistent-keepalive" && pair[1] == "21")
            }),
            "Some(21) must emit `persistent-keepalive 21`"
        );
    }

    #[test]
    fn resolve_bringup_tunnel_mtu_bounds_the_override() {
        // Absent / empty / malformed all fall back to the audited default: a bad
        // override must never silently produce an MTU nobody chose.
        assert_eq!(resolve_bringup_tunnel_mtu(None), SAFE_BRINGUP_TUNNEL_MTU);
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("")),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("   ")),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("not-a-number")),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("-5")),
            SAFE_BRINGUP_TUNNEL_MTU
        );

        // The ceiling is the audited default, so an override can only ever make
        // the tunnel MORE conservative -- never grant a larger MTU.
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("9000")),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some(&(SAFE_BRINGUP_TUNNEL_MTU + 1).to_string())),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        // ...and below the floor is refused too, so a typo cannot cripple the link.
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some("576")),
            SAFE_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some(&(MIN_BRINGUP_TUNNEL_MTU - 1).to_string())),
            SAFE_BRINGUP_TUNNEL_MTU
        );

        // In-range values are honoured, including both endpoints. 1220 is the
        // value the measured 1280-byte cross-network path actually needs.
        assert_eq!(resolve_bringup_tunnel_mtu(Some("1220")), 1220);
        assert_eq!(resolve_bringup_tunnel_mtu(Some(" 1220 ")), 1220);
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some(&MIN_BRINGUP_TUNNEL_MTU.to_string())),
            MIN_BRINGUP_TUNNEL_MTU
        );
        assert_eq!(
            resolve_bringup_tunnel_mtu(Some(&SAFE_BRINGUP_TUNNEL_MTU.to_string())),
            SAFE_BRINGUP_TUNNEL_MTU
        );
    }

    #[test]
    fn linux_backend_sets_safe_bringup_mtu_before_link_up() {
        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");

        backend
            .start(runtime_context())
            .expect("start should execute runner calls");

        let expected_mtu_args = vec![
            "link".to_owned(),
            "set".to_owned(),
            "mtu".to_owned(),
            SAFE_BRINGUP_TUNNEL_MTU.to_string(),
            "dev".to_owned(),
            "rustynet0".to_owned(),
        ];
        let mtu_index = backend
            .runner
            .calls
            .iter()
            .position(|(program, args)| program == "ip" && args == &expected_mtu_args)
            .expect("start must set the safe bring-up MTU explicitly");
        let up_index = backend
            .runner
            .calls
            .iter()
            .position(|(program, args)| program == "ip" && args.iter().any(|arg| arg == "up"))
            .expect("start must bring the link up");
        assert!(
            mtu_index < up_index,
            "MTU must be pinned before the link comes up (wg-quick order)"
        );
    }

    #[derive(Debug, Default)]
    struct MtuSetFailureRunner {
        calls: Vec<(String, Vec<String>)>,
    }

    impl WireguardCommandRunner for MtuSetFailureRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.calls.push((program.to_owned(), args.to_vec()));
            if program == "ip" && args.iter().any(|arg| arg == "mtu") {
                return Err(BackendError::internal("injected mtu set failure"));
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

    #[test]
    fn linux_backend_start_rolls_back_interface_when_mtu_set_fails() {
        let runner = MtuSetFailureRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");

        let err = backend
            .start(runtime_context())
            .expect_err("mtu set failure must fail the start");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(!backend.running, "backend must not report running");
        assert!(
            backend.runner.calls.iter().any(|(program, args)| {
                program == "ip"
                    && args.first().map(String::as_str) == Some("link")
                    && args.get(1).map(String::as_str) == Some("del")
            }),
            "failed mtu set must tear the interface back down"
        );
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
            "rule".to_owned(),
            "del".to_owned(),
            "priority".to_owned(),
            "10000".to_owned(),
            "table".to_owned(),
            "51820".to_owned(),
        ];
        let add_rule = vec![
            "rule".to_owned(),
            "add".to_owned(),
            "priority".to_owned(),
            "10000".to_owned(),
            "table".to_owned(),
            "51820".to_owned(),
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
        peer.allowed_ips = vec!["0.0.0.0/0;rm".to_owned()];
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
                destination_cidr: "100.100.1.0/24".to_owned(),
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
            "show".to_owned(),
            "rustynet0".to_owned(),
            "latest-handshakes".to_owned(),
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
