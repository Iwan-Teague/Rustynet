use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};
#[cfg(windows)]
use rustynet_windows_native::{WindowsDpapiScope, dpapi_protect};

use crate::linux_command::{
    WireguardCommandOutput, WireguardCommandRunner, encode_wg_public_key_base64,
    parse_peer_latest_handshake_unix, validate_listen_port,
};

pub const DEFAULT_WINDOWS_WIREGUARD_EXE_PATH: &str = r"C:\Program Files\WireGuard\wireguard.exe";
pub const DEFAULT_WINDOWS_WG_EXE_PATH: &str = r"C:\Program Files\WireGuard\wg.exe";
pub const DEFAULT_WINDOWS_NETSH_EXE_PATH: &str = r"C:\Windows\System32\netsh.exe";

const WINDOWS_CONFIG_FILE_SUFFIX: &str = ".conf.dpapi";

#[derive(Debug)]
pub struct WindowsWireguardBackend<R: WireguardCommandRunner> {
    runner: R,
    tunnel_name: String,
    config_path: PathBuf,
    private_key_path: PathBuf,
    wireguard_exe_path: PathBuf,
    wg_exe_path: PathBuf,
    netsh_exe_path: PathBuf,
    listen_port: u16,
    running: bool,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    context: Option<RuntimeContext>,
    exit_mode: ExitMode,
}

impl<R: WireguardCommandRunner> WindowsWireguardBackend<R> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        runner: R,
        tunnel_name: impl Into<String>,
        config_path: impl Into<String>,
        private_key_path: impl Into<String>,
        wireguard_exe_path: impl Into<String>,
        wg_exe_path: impl Into<String>,
        netsh_exe_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        let tunnel_name = tunnel_name.into();
        let config_path = PathBuf::from(config_path.into());
        let private_key_path = PathBuf::from(private_key_path.into());
        let wireguard_exe_path = PathBuf::from(wireguard_exe_path.into());
        let wg_exe_path = PathBuf::from(wg_exe_path.into());
        let netsh_exe_path = PathBuf::from(netsh_exe_path.into());

        validate_windows_tunnel_name(&tunnel_name)?;
        validate_windows_config_path(config_path.as_path(), tunnel_name.as_str())?;
        validate_host_absolute_path(private_key_path.as_path(), "windows private key path")?;
        validate_host_absolute_path(wireguard_exe_path.as_path(), "windows wireguard.exe path")?;
        validate_host_absolute_path(wg_exe_path.as_path(), "windows wg.exe path")?;
        validate_host_absolute_path(netsh_exe_path.as_path(), "windows netsh.exe path")?;
        validate_listen_port(listen_port)?;

        Ok(Self {
            runner,
            tunnel_name,
            config_path,
            private_key_path,
            wireguard_exe_path,
            wg_exe_path,
            netsh_exe_path,
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
            "windows wireguard backend is not running",
        ))
    }

    fn ensure_prerequisites(&self) -> Result<(), BackendError> {
        ensure_host_file_exists(self.private_key_path.as_path(), "windows private key file")?;
        ensure_host_file_exists(
            self.wireguard_exe_path.as_path(),
            "windows wireguard.exe binary",
        )?;
        ensure_host_file_exists(self.wg_exe_path.as_path(), "windows wg.exe binary")?;
        ensure_host_file_exists(self.netsh_exe_path.as_path(), "windows netsh.exe binary")
    }

    fn sync_persistent_config(&self) -> Result<(), BackendError> {
        let bytes = protect_config_bytes(
            self.render_config()?.as_bytes(),
            self.tunnel_name.as_str(),
            self.config_path.as_path(),
        )?;
        write_config_atomically(self.config_path.as_path(), &bytes)
    }

    fn install_tunnel_service(&mut self) -> Result<(), BackendError> {
        self.runner.run(
            self.wireguard_exe_path.to_string_lossy().as_ref(),
            &[
                "/installtunnelservice".to_owned(),
                self.config_path.display().to_string(),
            ],
        )
    }

    /// Poll `wg show <tunnel>` until the wintun adapter is ready.
    ///
    /// `wireguard.exe /installtunnelservice` returns as soon as the SCM
    /// reports the service as Running, but the wintun adapter (e.g.
    /// `rustynet0`) may still be initialising at that point.  Subsequent
    /// apply steps that bind firewall rules to the interface alias (e.g.
    /// `New-NetFirewallRule -InterfaceAlias rustynet0`) fail immediately if
    /// the adapter is not yet enumerated by the OS.
    ///
    /// Non-empty stdout from `wg show <tunnel>` is the canonical signal that
    /// the adapter is present and WireGuard has attached to it.
    fn wait_for_tunnel_ready(&mut self) -> Result<(), BackendError> {
        const TUNNEL_READY_TIMEOUT_SECS: u64 = 30;
        const TUNNEL_READY_RETRY_INTERVAL_MS: u64 = 1000;
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(TUNNEL_READY_TIMEOUT_SECS);
        loop {
            let result = self.runner.run_capture(
                self.wg_exe_path.to_string_lossy().as_ref(),
                &["show".to_owned(), self.tunnel_name.clone()],
            );
            if let Ok(out) = result
                && !out.stdout.trim().is_empty()
            {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                return Err(BackendError::internal(format!(
                    "WireGuard tunnel '{}' did not become ready within {} seconds",
                    self.tunnel_name, TUNNEL_READY_TIMEOUT_SECS
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(
                TUNNEL_READY_RETRY_INTERVAL_MS,
            ));
        }
    }

    fn uninstall_tunnel_service(&mut self) -> Result<(), BackendError> {
        self.runner.run(
            self.wireguard_exe_path.to_string_lossy().as_ref(),
            &[
                "/uninstalltunnelservice".to_owned(),
                self.tunnel_name.clone(),
            ],
        )
    }

    fn apply_route_reconciliation(
        &mut self,
        next_routes: &[Route],
        next_exit_mode: ExitMode,
    ) -> Result<(), BackendError> {
        let current = effective_routes(&self.routes, self.exit_mode);
        let next = effective_routes(next_routes, next_exit_mode);

        for destination_cidr in current.difference(&next) {
            self.delete_os_route(destination_cidr)?;
        }
        for destination_cidr in next.difference(&current) {
            self.add_os_route(destination_cidr)?;
        }

        Ok(())
    }

    fn add_os_route(&mut self, destination_cidr: &str) -> Result<(), BackendError> {
        validate_cidr(destination_cidr)?;
        let (family, next_hop) = route_family_and_next_hop(destination_cidr)?;
        self.runner.run(
            self.netsh_exe_path.to_string_lossy().as_ref(),
            &[
                "interface".to_owned(),
                family.to_owned(),
                "add".to_owned(),
                "route".to_owned(),
                format!("prefix={destination_cidr}"),
                format!("interface={}", self.tunnel_name),
                next_hop.to_owned(),
                "store=active".to_owned(),
                // Use a low metric so WireGuard routes take precedence over the
                // physical NIC default route. Without this, the auto-calculated
                // interface metric (typically 200+) loses to the physical NIC
                // default route (typically metric 10–25), causing FullTunnel
                // traffic to bypass the WireGuard interface entirely.
                "metric=1".to_owned(),
            ],
        )
    }

    fn delete_os_route(&mut self, destination_cidr: &str) -> Result<(), BackendError> {
        validate_cidr(destination_cidr)?;
        let (family, _) = route_family_and_next_hop(destination_cidr)?;
        self.runner.run(
            self.netsh_exe_path.to_string_lossy().as_ref(),
            &[
                "interface".to_owned(),
                family.to_owned(),
                "delete".to_owned(),
                "route".to_owned(),
                format!("prefix={destination_cidr}"),
                format!("interface={}", self.tunnel_name),
                "store=active".to_owned(),
            ],
        )
    }

    fn render_config(&self) -> Result<String, BackendError> {
        let context = self.context.as_ref().ok_or_else(|| {
            BackendError::not_running("windows wireguard backend has no runtime context")
        })?;
        validate_cidr(context.local_cidr.as_str())?;
        let private_key = read_private_key_value(self.private_key_path.as_path())?;
        let mut rendered = String::new();
        rendered.push_str("[Interface]\n");
        rendered.push_str("PrivateKey = ");
        rendered.push_str(private_key.as_str());
        rendered.push('\n');
        rendered.push_str("Address = ");
        rendered.push_str(context.local_cidr.as_str());
        rendered.push('\n');
        rendered.push_str("ListenPort = ");
        rendered.push_str(&self.listen_port.to_string());
        rendered.push('\n');
        rendered.push('\n');

        for peer in self.peers.values() {
            let allowed_ips = self.merged_allowed_ips(peer)?;
            let endpoint = render_endpoint(peer.endpoint);
            rendered.push_str("[Peer]\n");
            rendered.push_str("PublicKey = ");
            rendered.push_str(encode_wg_public_key_base64(&peer.public_key).as_str());
            rendered.push('\n');
            rendered.push_str("Endpoint = ");
            rendered.push_str(endpoint.as_str());
            rendered.push('\n');
            rendered.push_str("AllowedIPs = ");
            rendered.push_str(allowed_ips.as_str());
            rendered.push('\n');
            rendered.push('\n');
        }

        Ok(rendered)
    }

    fn merged_allowed_ips(&self, peer: &PeerConfig) -> Result<String, BackendError> {
        if peer.allowed_ips.is_empty() {
            return Err(BackendError::invalid_input(
                "peer allowed_ips must not be empty",
            ));
        }
        let mut merged = BTreeSet::new();
        for cidr in &peer.allowed_ips {
            validate_cidr(cidr)?;
            merged.insert(cidr.clone());
        }
        for route in self
            .routes
            .iter()
            .filter(|route| route.via_node == peer.node_id)
        {
            validate_cidr(route.destination_cidr.as_str())?;
            merged.insert(route.destination_cidr.clone());
        }
        if matches!(self.exit_mode, ExitMode::Off) {
            merged.retain(|cidr| cidr != "0.0.0.0/0" && cidr != "::/0");
            for cidr in &peer.allowed_ips {
                merged.insert(cidr.clone());
            }
        }
        Ok(merged.into_iter().collect::<Vec<_>>().join(","))
    }

    fn apply_peer_runtime(&mut self, peer: &PeerConfig) -> Result<(), BackendError> {
        let allowed_ips = self.merged_allowed_ips(peer)?;
        let endpoint = render_endpoint(peer.endpoint);
        self.runner.run(
            self.wg_exe_path.to_string_lossy().as_ref(),
            &[
                "set".to_owned(),
                self.tunnel_name.clone(),
                "peer".to_owned(),
                encode_wg_public_key_base64(&peer.public_key),
                "endpoint".to_owned(),
                endpoint,
                "allowed-ips".to_owned(),
                allowed_ips,
            ],
        )
    }

    fn rewrite_runtime_peers(&mut self) -> Result<(), BackendError> {
        let peers = self.peers.values().cloned().collect::<Vec<_>>();
        for peer in peers {
            self.apply_peer_runtime(&peer)?;
        }
        Ok(())
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
            self.wg_exe_path.to_string_lossy().as_ref(),
            &[
                "show".to_owned(),
                self.tunnel_name.clone(),
                "latest-handshakes".to_owned(),
            ],
        )?;
        let public_key = encode_wg_public_key_base64(&peer.public_key);
        parse_peer_latest_handshake_unix(&output.stdout, &public_key, self.peers.len().max(1))
    }

    fn read_transfer_totals(&mut self) -> Result<(u64, u64), BackendError> {
        let output = self.runner.run_capture(
            self.wg_exe_path.to_string_lossy().as_ref(),
            &[
                "show".to_owned(),
                self.tunnel_name.clone(),
                "transfer".to_owned(),
            ],
        )?;
        parse_transfer_totals(&output, self.peers.values())
    }
}

impl<R: WireguardCommandRunner + Send + Sync + Clone> TunnelBackend for WindowsWireguardBackend<R> {
    fn name(&self) -> &'static str {
        "wireguard-windows"
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
                "windows wireguard backend already started",
            ));
        }
        if context.interface_name != self.tunnel_name {
            return Err(BackendError::invalid_input(
                "windows wireguard tunnel name must match runtime interface name",
            ));
        }
        self.ensure_prerequisites()?;
        self.context = Some(context);
        self.sync_persistent_config()?;
        if let Err(err) = self.install_tunnel_service() {
            self.context = None;
            return Err(err);
        }
        if let Err(err) = self.wait_for_tunnel_ready() {
            // The tunnel service started but the adapter never came up; tear
            // the service back down before returning so the system is left in
            // a clean state for the caller's rollback path.
            let _ = self.uninstall_tunnel_service();
            self.context = None;
            return Err(err);
        }
        self.running = true;
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        let peer_for_runtime = peer.clone();
        self.peers.insert(peer.node_id.clone(), peer);
        self.apply_peer_runtime(&peer_for_runtime)?;
        self.sync_persistent_config()
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
        peer.endpoint = endpoint;
        let peer_for_runtime = peer.clone();
        self.apply_peer_runtime(&peer_for_runtime)?;
        self.sync_persistent_config()
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
            self.wg_exe_path.to_string_lossy().as_ref(),
            &[
                "set".to_owned(),
                self.tunnel_name.clone(),
                "peer".to_owned(),
                encode_wg_public_key_base64(&peer.public_key),
                "remove".to_owned(),
            ],
        )?;
        self.sync_persistent_config()
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_running()?;
        for route in &routes {
            validate_cidr(route.destination_cidr.as_str())?;
            if !self.peers.contains_key(&route.via_node) {
                return Err(BackendError::invalid_input(
                    "route via_node must reference a configured peer",
                ));
            }
        }
        self.apply_route_reconciliation(&routes, self.exit_mode)?;
        self.routes = routes;
        self.rewrite_runtime_peers()?;
        self.sync_persistent_config()
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.apply_route_reconciliation(&self.routes.clone(), mode)?;
        self.exit_mode = mode;
        self.rewrite_runtime_peers()?;
        self.sync_persistent_config()
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_running()?;
        let mut cloned = self.clone_for_stats()?;
        let (bytes_rx, bytes_tx) = cloned.read_transfer_totals()?;
        Ok(TunnelStats {
            peer_count: self.peers.len(),
            bytes_tx,
            bytes_rx,
            using_relay_path: false,
        })
    }

    fn transport_socket_identity_blocker(&self) -> Option<String> {
        Some(
            "windows wireguard backend is a command-only adapter over the official WireGuard for Windows tunnel service and its OS-managed WireGuardNT UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned(),
        )
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        let route_cleanup = self.apply_route_reconciliation(&[], ExitMode::Off);
        let uninstall_result = self.uninstall_tunnel_service();
        let cleanup_result = remove_file_if_present(self.config_path.as_path());
        self.running = false;
        self.peers.clear();
        self.routes.clear();
        self.context = None;
        self.exit_mode = ExitMode::Off;
        route_cleanup?;
        uninstall_result?;
        cleanup_result?;
        Ok(())
    }
}

impl<R: WireguardCommandRunner + Clone> WindowsWireguardBackend<R> {
    fn clone_for_stats(&self) -> Result<Self, BackendError> {
        Ok(Self {
            runner: self.runner.clone(),
            tunnel_name: self.tunnel_name.clone(),
            config_path: self.config_path.clone(),
            private_key_path: self.private_key_path.clone(),
            wireguard_exe_path: self.wireguard_exe_path.clone(),
            wg_exe_path: self.wg_exe_path.clone(),
            netsh_exe_path: self.netsh_exe_path.clone(),
            listen_port: self.listen_port,
            running: self.running,
            peers: self.peers.clone(),
            routes: self.routes.clone(),
            context: self.context.clone(),
            exit_mode: self.exit_mode,
        })
    }
}

fn remove_file_if_present(path: &Path) -> Result<(), BackendError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(BackendError::internal(format!(
            "remove Windows tunnel config failed ({}): {err}",
            path.display()
        ))),
    }
}

fn write_config_atomically(path: &Path, bytes: &[u8]) -> Result<(), BackendError> {
    let parent = path.parent().ok_or_else(|| {
        BackendError::invalid_input(format!(
            "windows config path must include a parent directory: {}",
            path.display()
        ))
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        BackendError::internal(format!(
            "create Windows config directory failed ({}): {err}",
            parent.display()
        ))
    })?;
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let temp_path = path.with_extension(format!("tmp.{}.{}", std::process::id(), nanos));
    fs::write(&temp_path, bytes).map_err(|err| {
        BackendError::internal(format!(
            "write Windows tunnel config staging file failed ({}): {err}",
            temp_path.display()
        ))
    })?;
    fs::rename(&temp_path, path).map_err(|err| {
        let _ = fs::remove_file(&temp_path);
        BackendError::internal(format!(
            "persist Windows tunnel config failed ({}): {err}",
            path.display()
        ))
    })
}

fn protect_config_bytes(
    bytes: &[u8],
    tunnel_name: &str,
    path: &Path,
) -> Result<Vec<u8>, BackendError> {
    #[cfg(windows)]
    {
        // LocalMachine scope: any LocalSystem process (including the WireGuard
        // tunnel service, which runs as LocalSystem) can decrypt this blob.
        // CurrentUser scope would lock the blob to the daemon's logon session
        // and the tunnel service — a different security principal — could not
        // read the config, causing the Wintun adapter to start without an IP.
        return dpapi_protect(bytes, WindowsDpapiScope::LocalMachine, tunnel_name).map_err(|err| {
            BackendError::internal(format!(
                "DPAPI protect failed for Windows tunnel config {}: {err}",
                path.display()
            ))
        });
    }
    #[cfg(not(windows))]
    {
        let _ = tunnel_name;
        let _ = path;
        Ok(bytes.to_vec())
    }
}

fn read_private_key_value(path: &Path) -> Result<String, BackendError> {
    let contents = fs::read_to_string(path).map_err(|err| {
        BackendError::internal(format!(
            "read Windows private key file failed ({}): {err}",
            path.display()
        ))
    })?;
    let key = contents.trim();
    if key.is_empty() {
        return Err(BackendError::invalid_input(
            "windows private key file must not be empty",
        ));
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '='))
    {
        return Err(BackendError::invalid_input(
            "windows private key file contains invalid characters",
        ));
    }
    Ok(key.to_owned())
}

fn parse_transfer_totals(
    output: &WireguardCommandOutput,
    peers: impl Iterator<Item = impl std::borrow::Borrow<PeerConfig>>,
) -> Result<(u64, u64), BackendError> {
    let allowed_public_keys = peers
        .map(|peer| encode_wg_public_key_base64(&peer.borrow().public_key))
        .collect::<BTreeSet<_>>();
    let mut bytes_rx = 0u64;
    let mut bytes_tx = 0u64;
    for line in output.stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let fields = trimmed.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 3 {
            return Err(BackendError::internal(
                "wg show transfer produced an unexpected row shape",
            ));
        }
        if !allowed_public_keys.contains(fields[0]) {
            continue;
        }
        let peer_rx = fields[1].parse::<u64>().map_err(|_| {
            BackendError::internal("wg show transfer produced a non-numeric rx byte count")
        })?;
        let peer_tx = fields[2].parse::<u64>().map_err(|_| {
            BackendError::internal("wg show transfer produced a non-numeric tx byte count")
        })?;
        bytes_rx = bytes_rx.saturating_add(peer_rx);
        bytes_tx = bytes_tx.saturating_add(peer_tx);
    }
    Ok((bytes_rx, bytes_tx))
}

fn render_endpoint(endpoint: SocketEndpoint) -> String {
    if endpoint.addr.is_ipv6() {
        format!("[{}]:{}", endpoint.addr, endpoint.port)
    } else {
        format!("{}:{}", endpoint.addr, endpoint.port)
    }
}

fn validate_cidr(value: &str) -> Result<(), BackendError> {
    if value.is_empty() || !value.contains('/') {
        return Err(BackendError::invalid_input("invalid cidr value"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | ':' | '/'))
    {
        return Err(BackendError::invalid_input(
            "cidr contains invalid characters",
        ));
    }
    Ok(())
}

fn validate_windows_tunnel_name(name: &str) -> Result<(), BackendError> {
    // The tunnel name is interpolated into netsh argv values of the form
    // `interface=<name>` (see `add_os_route` / `delete_os_route`).  Allowing
    // `=` in the name would let a caller-supplied identifier collide with the
    // netsh `key=value` separator and turn `interface=foo=bar` into a value
    // netsh parses ambiguously, so we reject `=` here.  We also reject
    // control chars, non-ASCII, and whitespace for the same class of reasons
    // (corrupted log lines, ambiguous argv shape, mismatched DPAPI config
    // file names which are derived from this value).  Real WireGuard for
    // Windows tunnel names are short ASCII identifiers — this matches the
    // hardened `validate_windows_interface_alias` model in rustynetd's
    // phase10 system.
    const RESERVED_NAMES: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    if name.is_empty() || name.len() > 32 {
        return Err(BackendError::invalid_input(
            "windows tunnel name length must be between 1 and 32",
        ));
    }
    if !name.is_ascii() {
        return Err(BackendError::invalid_input(
            "windows tunnel name must be ASCII",
        ));
    }
    if name.chars().any(|ch| ch.is_ascii_control()) {
        return Err(BackendError::invalid_input(
            "windows tunnel name must not contain control characters",
        ));
    }
    if name.chars().any(|ch| ch.is_ascii_whitespace()) {
        return Err(BackendError::invalid_input(
            "windows tunnel name must not contain whitespace",
        ));
    }
    if name.contains('=') {
        return Err(BackendError::invalid_input(
            "windows tunnel name must not contain '='",
        ));
    }
    if RESERVED_NAMES
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(name))
    {
        return Err(BackendError::invalid_input(
            "windows tunnel name must not use a reserved device name",
        ));
    }
    if !name
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '+' | '.' | '-'))
    {
        return Err(BackendError::invalid_input(
            "windows tunnel name contains invalid characters",
        ));
    }
    Ok(())
}

fn validate_windows_config_path(path: &Path, tunnel_name: &str) -> Result<(), BackendError> {
    validate_host_absolute_path(path, "windows tunnel config path")?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            BackendError::invalid_input("windows tunnel config path must end in a file name")
        })?;
    let expected_name = format!("{tunnel_name}{WINDOWS_CONFIG_FILE_SUFFIX}");
    if file_name != expected_name {
        return Err(BackendError::invalid_input(format!(
            "windows tunnel config file name must be {expected_name}"
        )));
    }
    Ok(())
}

fn ensure_host_file_exists(path: &Path, label: &str) -> Result<(), BackendError> {
    let metadata = fs::metadata(path).map_err(|err| {
        BackendError::invalid_input(format!(
            "{label} is missing or unreadable ({}): {err}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(BackendError::invalid_input(format!(
            "{label} must be a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn effective_routes(routes: &[Route], exit_mode: ExitMode) -> BTreeSet<String> {
    routes
        .iter()
        .filter(|route| {
            matches!(exit_mode, ExitMode::FullTunnel)
                || !is_default_route(route.destination_cidr.as_str())
        })
        .map(|route| route.destination_cidr.clone())
        .collect()
}

fn is_default_route(destination_cidr: &str) -> bool {
    matches!(destination_cidr, "0.0.0.0/0" | "::/0")
}

fn route_family_and_next_hop(
    destination_cidr: &str,
) -> Result<(&'static str, &'static str), BackendError> {
    if destination_cidr.contains(':') {
        return Ok(("ipv6", "nexthop=::"));
    }
    Ok(("ipv4", "nexthop=0.0.0.0"))
}

fn validate_host_absolute_path(path: &Path, label: &str) -> Result<(), BackendError> {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy().replace('/', "\\");
        let bytes = text.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || bytes[2] != b'\\'
        {
            return Err(BackendError::invalid_input(format!(
                "{label} must be an absolute Windows path"
            )));
        }
    }
    #[cfg(not(windows))]
    {
        if !path.is_absolute() {
            return Err(BackendError::invalid_input(format!(
                "{label} must be absolute"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn ensure_prerequisites_covers_wg_exe_and_wireguard_service_availability() {
        let temp_dir = tempfile::TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);

        let runner = RecordingRunner::default();
        let backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        backend
            .ensure_prerequisites()
            .expect("prerequisites should be satisfied");

        std::fs::remove_file(&wg_path).expect("delete wg.exe");
        let err = backend
            .ensure_prerequisites()
            .expect_err("wg.exe missing should fail");
        assert!(
            err.to_string().contains("windows wg.exe binary"),
            "Error must reference missing wg.exe binary prep: {err}"
        );

        std::fs::write(&wg_path, "dummy").expect("dummy file");
        std::fs::remove_file(&wireguard_path).expect("delete wireguard.exe");
        let err2 = backend
            .ensure_prerequisites()
            .expect_err("wireguard.exe missing should fail");
        assert!(
            err2.to_string().contains("windows wireguard.exe binary"),
            "Error must reference missing wireguard.exe binary prep: {err2}"
        );
    }

    use super::*;
    use base64::prelude::*;
    use rustynet_backend_api::RouteKind;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    #[derive(Debug, Clone)]
    struct RecordingRunner {
        #[allow(clippy::type_complexity)]
        commands: Arc<Mutex<Vec<(String, Vec<String>)>>>,
        handshake_output: Arc<Mutex<String>>,
        transfer_output: Arc<Mutex<String>>,
        /// Stdout returned for plain `wg show <tunnel>` calls (the
        /// tunnel-readiness probe in `wait_for_tunnel_ready`).  Defaults to a
        /// non-empty interface summary so tests that do not exercise a slow-
        /// start scenario get an immediate pass through the readiness loop.
        show_interface_output: Arc<Mutex<String>>,
    }

    impl Default for RecordingRunner {
        fn default() -> Self {
            Self {
                commands: Arc::new(Mutex::new(Vec::new())),
                handshake_output: Arc::new(Mutex::new(String::new())),
                transfer_output: Arc::new(Mutex::new(String::new())),
                // Simulate a ready wintun adapter so `wait_for_tunnel_ready`
                // exits on the first poll in tests that don't model slow start.
                show_interface_output: Arc::new(Mutex::new(
                    "interface: rustynet0\n  public key: AAAA=\n  listening port: 51820\n"
                        .to_owned(),
                )),
            }
        }
    }

    impl RecordingRunner {
        fn recorded(&self) -> Vec<(String, Vec<String>)> {
            self.commands.lock().expect("commands").clone()
        }
    }

    impl WireguardCommandRunner for RecordingRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            self.commands
                .lock()
                .expect("commands")
                .push((program.to_owned(), args.to_vec()));
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            self.commands
                .lock()
                .expect("commands")
                .push((program.to_owned(), args.to_vec()));
            let stdout = if args.iter().any(|arg| arg == "latest-handshakes") {
                self.handshake_output.lock().expect("handshake").clone()
            } else if args.iter().any(|arg| arg == "transfer") {
                self.transfer_output.lock().expect("transfer").clone()
            } else if args.first().map(std::string::String::as_str) == Some("show") {
                // Plain `wg show <tunnel>` — the tunnel-readiness probe.
                self.show_interface_output
                    .lock()
                    .expect("show_interface_output")
                    .clone()
            } else {
                String::new()
            };
            Ok(WireguardCommandOutput {
                stdout,
                stderr: String::new(),
            })
        }
    }

    fn runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("local-node").expect("valid node id"),
            interface_name: "rustynet0".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
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
            allowed_ips: vec!["100.64.10.0/24".to_owned()],
        }
    }

    fn write_private_key(temp_dir: &TempDir) -> PathBuf {
        let path = temp_dir.path().join("wireguard.key");
        fs::write(&path, format!("{}\n", BASE64_STANDARD.encode([9u8; 32])))
            .expect("private key should be written");
        path
    }

    fn backend_paths(temp_dir: &TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf, PathBuf) {
        let config = temp_dir.path().join("rustynet0.conf.dpapi");
        let private_key = write_private_key(temp_dir);
        let wireguard = temp_dir.path().join("wireguard.exe");
        let wg = temp_dir.path().join("wg.exe");
        let netsh = temp_dir.path().join("netsh.exe");
        fs::write(&wireguard, b"").expect("wireguard path should exist");
        fs::write(&wg, b"").expect("wg path should exist");
        fs::write(&netsh, b"").expect("netsh path should exist");
        (config, private_key, wireguard, wg, netsh)
    }

    #[test]
    fn windows_backend_start_configures_tunnel_service_and_persists_dpapi_config_shape() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        backend
            .start(runtime_context())
            .expect("backend should start successfully");

        let written = fs::read_to_string(&config_path).expect("config should be written");
        assert!(written.contains("[Interface]"));
        assert!(written.contains("Address = 100.64.0.1/32"));
        assert!(written.contains("ListenPort = 51820"));

        let recorded = runner.recorded();
        // start() emits two commands: install_tunnel_service (via run) then
        // the first wait_for_tunnel_ready poll (via run_capture).
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0].0, wireguard_path.to_string_lossy());
        assert_eq!(
            recorded[0].1,
            vec![
                "/installtunnelservice".to_owned(),
                config_path.display().to_string()
            ]
        );
        // Second call must be the readiness probe: `wg show rustynet0`.
        assert_eq!(recorded[1].0, wg_path.to_string_lossy());
        assert_eq!(
            recorded[1].1,
            vec!["show".to_owned(), "rustynet0".to_owned()]
        );
    }

    #[test]
    fn windows_backend_capabilities_distinguish_exit_client_and_serving_roles() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let backend = WindowsWireguardBackend::new(
            RecordingRunner::default(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        let capabilities = backend.capabilities();
        assert!(capabilities.supports_exit_nodes);
        assert!(
            capabilities.supports_exit_client,
            "Windows WireGuardNT can consume an exit node through AllowedIPs/default routes"
        );
        assert!(
            capabilities.supports_exit_serving,
            "Windows exit serving is allowed only with Phase10 system NAT/forwarding preflight"
        );
    }

    #[test]
    fn windows_backend_route_lifecycle_rewrites_allowed_ips_for_configured_peer() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");
        let peer = sample_peer("peer-a");

        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");
        backend
            .apply_routes(vec![
                Route {
                    destination_cidr: "100.64.20.0/24".to_owned(),
                    via_node: peer.node_id.clone(),
                    kind: RouteKind::Mesh,
                },
                Route {
                    destination_cidr: "0.0.0.0/0".to_owned(),
                    via_node: peer.node_id.clone(),
                    kind: RouteKind::ExitNodeDefault,
                },
            ])
            .expect("routes should apply");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full-tunnel mode should apply");

        let written = fs::read_to_string(&config_path).expect("config should be readable");
        assert!(written.contains("AllowedIPs = 0.0.0.0/0,100.64.10.0/24,100.64.20.0/24"));
        let recorded = runner.recorded();
        assert!(
            recorded
                .iter()
                .any(|(_, args)| args.iter().any(|arg| arg == "allowed-ips")),
            "runtime peer rewrite should issue wg set allowed-ips"
        );
        assert!(
            recorded.iter().any(|(program, args)| {
                program == &netsh_path.to_string_lossy()
                    && args
                        == &vec![
                            "interface".to_owned(),
                            "ipv4".to_owned(),
                            "add".to_owned(),
                            "route".to_owned(),
                            "prefix=100.64.20.0/24".to_owned(),
                            "interface=rustynet0".to_owned(),
                            "nexthop=0.0.0.0".to_owned(),
                            "store=active".to_owned(),
                            "metric=1".to_owned(),
                        ]
            }),
            "mesh route should be installed through netsh"
        );
        assert!(
            recorded.iter().any(|(program, args)| {
                program == &netsh_path.to_string_lossy()
                    && args
                        == &vec![
                            "interface".to_owned(),
                            "ipv4".to_owned(),
                            "add".to_owned(),
                            "route".to_owned(),
                            "prefix=0.0.0.0/0".to_owned(),
                            "interface=rustynet0".to_owned(),
                            "nexthop=0.0.0.0".to_owned(),
                            "store=active".to_owned(),
                            "metric=1".to_owned(),
                        ]
            }),
            "default route should be installed only after exit mode enables it"
        );
    }

    #[test]
    fn windows_backend_stats_and_handshakes_are_read_from_wg_show() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let peer = sample_peer("peer-a");
        let peer_public_key = encode_wg_public_key_base64(&peer.public_key);
        *runner.handshake_output.lock().expect("handshake") = format!("{peer_public_key}\t123\n");
        *runner.transfer_output.lock().expect("transfer") = format!("{peer_public_key}\t11\t22\n");

        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");

        let stats = backend.stats().expect("stats should succeed");
        assert_eq!(stats.peer_count, 1);
        assert_eq!(stats.bytes_rx, 11);
        assert_eq!(stats.bytes_tx, 22);
        assert_eq!(
            backend
                .peer_latest_handshake_unix(&peer.node_id)
                .expect("handshake lookup should succeed"),
            Some(123)
        );
    }

    #[test]
    fn windows_backend_shutdown_uninstalls_service_and_removes_config() {
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        backend
            .start(runtime_context())
            .expect("backend should start successfully");
        backend.shutdown().expect("shutdown should succeed");

        assert!(
            !config_path.exists(),
            "shutdown should remove persisted tunnel config"
        );
        let recorded = runner.recorded();
        assert_eq!(
            recorded.last().expect("shutdown command").1,
            vec!["/uninstalltunnelservice".to_owned(), "rustynet0".to_owned()]
        );
    }

    #[test]
    fn windows_tunnel_name_validator_rejects_equals_and_unsafe_chars() {
        // The tunnel name is interpolated into a netsh argv value of the form
        // `interface=<tunnel_name>` and used to derive the DPAPI config file
        // name.  A name containing `=` would create an ambiguous netsh
        // `key=value` argument; whitespace, control characters, and non-ASCII
        // would corrupt log lines and the DPAPI filename.  Pin those rejects
        // so a future regression that loosens the validator fails CI in the
        // same way the parallel phase10 `validate_windows_interface_alias`
        // hardening did.
        let rejected = [
            "rustynet=0",
            "rustynet 0",
            "rustynet\t0",
            "rustynet\n0",
            "rustynet\u{0007}0",
            "rüstynet0",
            "",
        ];
        for bad in rejected {
            assert!(
                validate_windows_tunnel_name(bad).is_err(),
                "validator must reject {bad:?}"
            );
        }
        // 33-char name (the max is 32).
        let too_long = "a".repeat(33);
        assert!(validate_windows_tunnel_name(&too_long).is_err());
        // Reserved device name (case-insensitive).
        assert!(validate_windows_tunnel_name("CON").is_err());
        assert!(validate_windows_tunnel_name("com1").is_err());
    }

    #[test]
    fn windows_tunnel_name_validator_accepts_reviewed_identifiers() {
        // The validator must keep accepting reviewed real-world values so
        // production deployments don't regress.
        for ok in [
            "rustynet0",
            "rustynet-mesh",
            "rustynet_mesh.1",
            "RN+demo",
            "abcdefghijklmnopqrstuvwxyzABCDEF", // 32 chars, the maximum.
        ] {
            assert!(
                validate_windows_tunnel_name(ok).is_ok(),
                "validator must accept {ok:?}"
            );
        }
    }

    #[test]
    fn windows_route_helpers_render_reviewed_netsh_argv() {
        // Pin the exact netsh argv shape for `add` and `delete` route paths
        // — the same render-reviewed-args contract that `phase10.rs`'s
        // `windows_dns_helpers_render_reviewed_netsh_args` enforces for the
        // killswitch helpers.  A regression that drops `metric=1`, the
        // `store=active` qualifier, or that flips ipv4↔ipv6 family selection
        // must fail CI here rather than at first contact with a Windows lab.
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");
        let peer = sample_peer("peer-a");

        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "2001:db8::/64".to_owned(),
                via_node: peer.node_id.clone(),
                kind: RouteKind::Mesh,
            }])
            .expect("ipv6 route should apply");

        let recorded = runner.recorded();
        // ipv6 add must select the ipv6 family and the unspecified next hop.
        assert!(
            recorded.iter().any(|(program, args)| {
                program == &netsh_path.to_string_lossy()
                    && args
                        == &vec![
                            "interface".to_owned(),
                            "ipv6".to_owned(),
                            "add".to_owned(),
                            "route".to_owned(),
                            "prefix=2001:db8::/64".to_owned(),
                            "interface=rustynet0".to_owned(),
                            "nexthop=::".to_owned(),
                            "store=active".to_owned(),
                            "metric=1".to_owned(),
                        ]
            }),
            "ipv6 mesh route must use the reviewed netsh argv with metric=1 and store=active"
        );

        backend
            .apply_routes(Vec::new())
            .expect("route removal should succeed");
        let recorded = runner.recorded();
        // ipv6 delete must use the ipv6 family and store=active, but does not
        // need the nexthop or metric arguments.
        assert!(
            recorded.iter().any(|(program, args)| {
                program == &netsh_path.to_string_lossy()
                    && args
                        == &vec![
                            "interface".to_owned(),
                            "ipv6".to_owned(),
                            "delete".to_owned(),
                            "route".to_owned(),
                            "prefix=2001:db8::/64".to_owned(),
                            "interface=rustynet0".to_owned(),
                            "store=active".to_owned(),
                        ]
            }),
            "ipv6 mesh route delete must use the reviewed netsh argv shape"
        );
    }

    #[test]
    fn windows_route_helpers_select_ipv4_or_ipv6_family_per_destination() {
        // Direct-call contract on the routing helpers: the family selector
        // and next-hop sentinel must be derived from the destination CIDR
        // shape, not from caller-supplied data.  Pinning this makes a future
        // refactor that mistakenly threads the family from a peer field
        // (instead of the destination) fail CI immediately.
        let (family, next_hop) =
            route_family_and_next_hop("100.64.0.0/10").expect("ipv4 routing tuple");
        assert_eq!(family, "ipv4");
        assert_eq!(next_hop, "nexthop=0.0.0.0");
        let (family, next_hop) =
            route_family_and_next_hop("2001:db8::/64").expect("ipv6 routing tuple");
        assert_eq!(family, "ipv6");
        assert_eq!(next_hop, "nexthop=::");
    }

    #[test]
    fn windows_command_paths_are_argv_only_with_no_shell_construction() {
        // This test pins the architectural property that distinguishes the
        // hardened Windows backend from a shelled-out implementation: every
        // recorded command program must be one of the validated absolute
        // binary paths, and every recorded argument must be a plain argv
        // value — never a shell metacharacter sequence (`|`, `&`, `;`, `>`,
        // backticks) and never an interpolated PowerShell command line.
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");
        let peer = sample_peer("peer-a");

        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "100.64.20.0/24".to_owned(),
                via_node: peer.node_id.clone(),
                kind: RouteKind::Mesh,
            }])
            .expect("route should apply");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("full-tunnel mode should apply");

        let allowed_programs: BTreeSet<String> = [
            wireguard_path.to_string_lossy().to_string(),
            wg_path.to_string_lossy().to_string(),
            netsh_path.to_string_lossy().to_string(),
        ]
        .into_iter()
        .collect();

        for (program, args) in runner.recorded() {
            assert!(
                allowed_programs.contains(&program),
                "command program {program:?} must be one of the validated binary paths"
            );
            // The Windows backend must never invoke PowerShell — that family
            // of helpers lives in rustynetd's phase10 system, not here.  A
            // regression that smuggles a PowerShell command into the
            // backend argv path would also need to satisfy the per-arg
            // metacharacter guard below, but pinning the program list
            // gives a clearer failure signal first.
            let lower = program.to_lowercase();
            assert!(
                !lower.contains("powershell")
                    && !lower.contains("pwsh")
                    && !lower.contains("cmd.exe"),
                "windows wireguard backend must not shell out to PowerShell or cmd.exe (saw {program:?})"
            );
            for arg in &args {
                for forbidden in ['|', '&', ';', '>', '<', '`', '\n', '\r'] {
                    assert!(
                        !arg.contains(forbidden),
                        "argv value {arg:?} must not contain shell metacharacter {forbidden:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn windows_install_tunnel_service_uses_argv_only_path_arguments() {
        // Pin the argv shape for the privileged `wireguard.exe
        // /installtunnelservice` invocation.  The tunnel-service install is
        // the single point where rustynetd hands a config-file path to the
        // WireGuard tunnel manager service; it must remain a pure argv
        // pair (`/installtunnelservice <path>`), with no shell or PS
        // wrapping, so the privileged process boundary stays sealed.
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        backend
            .start(runtime_context())
            .expect("backend should start");

        let recorded = runner.recorded();
        let install = recorded
            .iter()
            .find(|(_, args)| {
                args.first().map(std::string::String::as_str) == Some("/installtunnelservice")
            })
            .expect("install command should be recorded");
        assert_eq!(install.0, wireguard_path.to_string_lossy());
        assert_eq!(install.1.len(), 2);
        assert_eq!(install.1[0], "/installtunnelservice");
        assert_eq!(install.1[1], config_path.display().to_string());
    }

    #[test]
    fn windows_remove_peer_issues_argv_only_wg_set_remove() {
        // Pin the argv shape for `wg set <tunnel> peer <pubkey> remove` —
        // the same pure-argv contract phase10 enforces on its NetNat
        // helpers, but for the WireGuard control plane.
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");
        let peer = sample_peer("peer-a");
        let public_key = encode_wg_public_key_base64(&peer.public_key);

        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .configure_peer(peer.clone())
            .expect("peer should configure");
        backend
            .remove_peer(&peer.node_id)
            .expect("peer should remove");

        let recorded = runner.recorded();
        let remove = recorded
            .iter()
            .find(|(program, args)| {
                program == &wg_path.to_string_lossy() && args.iter().any(|a| a == "remove")
            })
            .expect("remove command should be recorded");
        assert_eq!(
            remove.1,
            vec![
                "set".to_owned(),
                "rustynet0".to_owned(),
                "peer".to_owned(),
                public_key,
                "remove".to_owned(),
            ]
        );
    }

    #[test]
    fn windows_ensure_running_fails_closed_on_missing_start() {
        // The `ensure_running` gate is the backend's flag-only fail-closed
        // assertion — any operation that goes through it must refuse to
        // touch the OS until `start` has succeeded.  This pins the contract
        // so a future refactor that drops the gate (or replaces it with a
        // fall-through) fails CI.  This is the WireGuard-backend analogue
        // of `assert_killswitch`'s pre-fix flag check; the OS-state-aware
        // fail-closed for tunnel posture is already covered by phase10's
        // `assert_killswitch` and is intentionally not duplicated here.
        let temp_dir = TempDir::new().expect("temp dir");
        let (config_path, private_key_path, wireguard_path, wg_path, netsh_path) =
            backend_paths(&temp_dir);
        let runner = RecordingRunner::default();
        let mut backend = WindowsWireguardBackend::new(
            runner.clone(),
            "rustynet0",
            config_path.to_string_lossy(),
            private_key_path.to_string_lossy(),
            wireguard_path.to_string_lossy(),
            wg_path.to_string_lossy(),
            netsh_path.to_string_lossy(),
            51820,
        )
        .expect("backend should construct");

        let peer = sample_peer("peer-a");
        assert!(backend.configure_peer(peer.clone()).is_err());
        assert!(
            backend
                .apply_routes(vec![Route {
                    destination_cidr: "100.64.20.0/24".to_owned(),
                    via_node: peer.node_id.clone(),
                    kind: RouteKind::Mesh,
                }])
                .is_err()
        );
        assert!(backend.set_exit_mode(ExitMode::FullTunnel).is_err());
        assert!(backend.remove_peer(&peer.node_id).is_err());
        assert!(backend.shutdown().is_err());
        assert!(backend.stats().is_err());

        // No commands should have been recorded because every
        // `ensure_running` gate must short-circuit before reaching the
        // runner.
        assert!(
            runner.recorded().is_empty(),
            "no command should reach the runner before start() succeeds"
        );
    }

    #[test]
    fn windows_validate_cidr_rejects_shell_and_argv_metachars() {
        // The CIDR validator is the single guard between caller-supplied
        // route/allowed-IP strings and netsh argv values like
        // `prefix=<cidr>`.  Pin that it rejects characters that would
        // either corrupt the netsh argv shape or open a shell-construction
        // path.  Mirrors the spirit of phase10's argv-only metacharacter
        // tests but applied to the WireGuard backend's CIDR ingress point.
        for bad in [
            "100.64.0.0/24=foo",
            "100.64.0.0/24 extra",
            "100.64.0.0/24;rm -rf /",
            "100.64.0.0/24|cmd",
            "100.64.0.0/24`",
            "100.64.0.0/24\n",
            "",
            "no-slash",
        ] {
            assert!(
                validate_cidr(bad).is_err(),
                "validate_cidr must reject {bad:?}"
            );
        }
        for ok in ["100.64.0.0/10", "0.0.0.0/0", "::/0", "2001:db8::/64"] {
            assert!(
                validate_cidr(ok).is_ok(),
                "validate_cidr must accept {ok:?}"
            );
        }
    }

    #[test]
    fn windows_private_key_validator_rejects_unsafe_content() {
        // The private-key file content is rendered into the WireGuard
        // config body; a stray newline or shell metacharacter in the value
        // would corrupt the rendered `[Interface]` section.  This is a
        // structural fail-closed check parallel to phase10's argv guards
        // — a regression that loosened the validator would let a malformed
        // key file produce a structurally-broken config file.
        let temp_dir = TempDir::new().expect("temp dir");
        let path = temp_dir.path().join("bad.key");

        for bad in [
            "",
            "   \n  \n",
            "abc def",
            "abc\tdef",
            "abc;rm",
            "abc\u{0007}d",
        ] {
            fs::write(&path, bad).expect("write key");
            assert!(
                read_private_key_value(&path).is_err(),
                "read_private_key_value must reject {bad:?}"
            );
        }
    }
}
