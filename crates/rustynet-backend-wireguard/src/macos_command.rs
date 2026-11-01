use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr};

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};

use crate::linux_command::{
    SAFE_BRINGUP_TUNNEL_MTU, WireguardCommandRunner, encode_wg_public_key_base64,
    parse_peer_latest_handshake_unix, validate_interface_name, validate_listen_port,
    validate_private_key_path,
};

/// Function-pointer type for the wireguard-go prerequisite check.
/// Production code uses [`ensure_wireguard_go_on_path`]; tests inject
/// [`no_prerequisite_check`] to avoid depending on the host PATH.
type PrerequisiteCheckFn = fn() -> Result<(), BackendError>;

/// No-op prerequisite checker for unit tests.
fn no_prerequisite_check() -> Result<(), BackendError> {
    Ok(())
}

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
    default_gateway: Option<Ipv4Addr>,
    endpoint_bypass_hosts: BTreeSet<String>,
    /// Called at the start of `configure_interface` to verify that the
    /// `wireguard-go` binary is available before any system state is mutated.
    /// Swapped to [`no_prerequisite_check`] in unit tests.
    prerequisite_check: PrerequisiteCheckFn,
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
            prerequisite_check: ensure_wireguard_go_on_path,
        })
    }

    /// Constructs a backend with the prerequisite check disabled.
    ///
    /// For use in tests only. Tests that specifically exercise the
    /// wireguard-go prerequisite check should call
    /// [`wireguard_go_is_on_path`] or [`ensure_wireguard_go_on_path_with`]
    /// directly rather than going through the backend.
    #[doc(hidden)]
    pub fn new_for_test(
        runner: R,
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        egress_interface: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        let mut backend = Self::new(
            runner,
            interface_name,
            private_key_path,
            egress_interface,
            listen_port,
        )?;
        backend.prerequisite_check = no_prerequisite_check;
        Ok(backend)
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
        ParsedCidr::parse(value).map(|_| ())
    }

    fn validate_peer_endpoint(endpoint: SocketEndpoint) -> Result<(), BackendError> {
        if endpoint.port == 0 {
            return Err(BackendError::invalid_input(
                "peer endpoint port must be non-zero",
            ));
        }
        if endpoint.addr.is_unspecified() {
            return Err(BackendError::invalid_input(
                "peer endpoint address must not be unspecified",
            ));
        }
        if endpoint.addr.is_multicast() {
            return Err(BackendError::invalid_input(
                "peer endpoint address must not be multicast",
            ));
        }
        if matches!(endpoint.addr, IpAddr::V4(addr) if addr.is_broadcast()) {
            return Err(BackendError::invalid_input(
                "peer endpoint address must not be broadcast",
            ));
        }
        Ok(())
    }

    fn configure_interface(&mut self, context: &RuntimeContext) -> Result<(), BackendError> {
        // Validate all inputs before touching the system.
        self.validate_runtime_context(context)?;
        // Then verify external prerequisites (wireguard-go on PATH).
        (self.prerequisite_check)()?;
        let local_cidr = ParsedCidr::parse(&context.local_cidr)?;

        if let Err(err) = self
            .runner
            .run("wireguard-go", std::slice::from_ref(&self.interface_name))
        {
            if let Err(cleanup_err) = self.remove_interface() {
                return Err(combine_interface_cleanup_error(err, cleanup_err));
            }
            self.runner
                .run("wireguard-go", std::slice::from_ref(&self.interface_name))?;
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
            return Err(match self.remove_interface() {
                Ok(()) => err,
                Err(cleanup_err) => combine_interface_cleanup_error(err, cleanup_err),
            });
        }

        let ifconfig_addr_args = ifconfig_address_args(&self.interface_name, &local_cidr);
        if let Err(err) = self.runner.run("ifconfig", &ifconfig_addr_args) {
            return Err(match self.remove_interface() {
                Ok(()) => err,
                Err(cleanup_err) => combine_interface_cleanup_error(err, cleanup_err),
            });
        }

        // FIS-0027 Phase 2: pin the tunnel MTU explicitly (before interface-up,
        // wg-quick order) instead of trusting the wireguard-go/platform
        // default, closing the never-set-MTU gap.
        if let Err(err) = self.runner.run(
            "ifconfig",
            &[
                self.interface_name.clone(),
                "mtu".to_owned(),
                SAFE_BRINGUP_TUNNEL_MTU.to_string(),
            ],
        ) {
            return Err(match self.remove_interface() {
                Ok(()) => err,
                Err(cleanup_err) => combine_interface_cleanup_error(err, cleanup_err),
            });
        }

        if let Err(err) = self
            .runner
            .run("ifconfig", &[self.interface_name.clone(), "up".to_owned()])
        {
            return Err(match self.remove_interface() {
                Ok(()) => err,
                Err(cleanup_err) => combine_interface_cleanup_error(err, cleanup_err),
            });
        }

        Ok(())
    }

    fn validate_runtime_context(&self, context: &RuntimeContext) -> Result<(), BackendError> {
        if context.interface_name != self.interface_name {
            return Err(BackendError::invalid_input(format!(
                "macos wireguard runtime context interface mismatch: backend interface is {}, context interface is {}",
                self.interface_name, context.interface_name
            )));
        }
        Self::ensure_cidr(&context.mesh_cidr)?;
        Self::ensure_cidr(&context.local_cidr)?;
        Ok(())
    }

    fn remove_interface(&mut self) -> Result<(), BackendError> {
        let down_result = match self.runner.run(
            "ifconfig",
            &[self.interface_name.clone(), "down".to_owned()],
        ) {
            Ok(()) => Ok(()),
            Err(err) if is_missing_interface_error(&err) => Ok(()),
            Err(err) => Err(err),
        };
        let restore_result = self.restore_default_route();
        let terminate_result = self.terminate_wireguard_go_processes();
        combine_cleanup_step_results([
            ("interface down", down_result),
            ("default route restore", restore_result),
            ("wireguard-go termination", terminate_result),
        ])
    }

    fn apply_route_reconciliation(&mut self, next_routes: &[Route]) -> Result<(), BackendError> {
        validate_route_set(&self.routes)?;
        validate_route_set(next_routes)?;

        let forward_result = apply_route_plan(
            &mut self.runner,
            &self.interface_name,
            &self.routes,
            next_routes,
        );
        if let Err(err) = forward_result {
            let rollback_result = apply_route_plan(
                &mut self.runner,
                &self.interface_name,
                next_routes,
                &self.routes,
            );
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_route_reconciliation_error(err, rollback_err)),
            };
        }

        self.routes = next_routes.to_vec();
        Ok(())
    }

    fn capture_default_gateway(&mut self) -> Result<Ipv4Addr, BackendError> {
        let output = self.runner.run_capture(
            "route",
            &["-n".to_owned(), "get".to_owned(), "default".to_owned()],
        )?;
        parse_default_gateway_output(&output.stdout)
    }

    fn install_endpoint_bypass_routes(&mut self) -> Result<(), BackendError> {
        let gateway = self
            .default_gateway
            .as_ref()
            .ok_or_else(|| BackendError::internal("default gateway not captured"))?
            .to_owned();
        let previous_hosts = self.endpoint_bypass_hosts.clone();
        let next_hosts = self
            .peers
            .values()
            .map(|peer| peer.endpoint.addr.to_string())
            .collect::<BTreeSet<_>>();

        let forward_result = apply_endpoint_bypass_plan(
            &mut self.runner,
            gateway,
            &self.egress_interface,
            &previous_hosts,
            &next_hosts,
        );
        if let Err(err) = forward_result {
            let rollback_result = apply_endpoint_bypass_plan(
                &mut self.runner,
                gateway,
                &self.egress_interface,
                &next_hosts,
                &previous_hosts,
            );
            self.endpoint_bypass_hosts = previous_hosts;
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_endpoint_bypass_error(err, rollback_err)),
            };
        }
        self.endpoint_bypass_hosts = next_hosts;
        Ok(())
    }

    fn remove_endpoint_bypass_routes(&mut self) -> Result<(), BackendError> {
        let mut first_error = None;
        for endpoint in self.endpoint_bypass_hosts.clone() {
            match remove_endpoint_bypass_route(&mut self.runner, &endpoint) {
                Ok(()) => {
                    self.endpoint_bypass_hosts.remove(&endpoint);
                }
                Err(err) if first_error.is_none() => {
                    first_error = Some(err);
                }
                Err(_) => {}
            }
        }
        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn apply_default_route_to_tunnel(&mut self) -> Result<(), BackendError> {
        if self.exit_mode == ExitMode::FullTunnel && self.default_gateway.is_some() {
            return self.install_endpoint_bypass_routes();
        }
        let previous_gateway = self.default_gateway;
        let previous_hosts = self.endpoint_bypass_hosts.clone();
        let gateway = match self.default_gateway {
            Some(gateway) => gateway,
            None => self.capture_default_gateway()?,
        };
        self.default_gateway = Some(gateway);
        if let Err(err) = self.install_endpoint_bypass_routes() {
            self.default_gateway = previous_gateway;
            self.endpoint_bypass_hosts = previous_hosts;
            return Err(err);
        }

        if let Err(err) = self.change_default_route_to_tunnel() {
            let cleanup_result = self.remove_endpoint_bypass_routes();
            if cleanup_result.is_ok() {
                self.default_gateway = previous_gateway;
                self.endpoint_bypass_hosts = previous_hosts;
            }
            return match cleanup_result {
                Ok(()) => Err(err),
                Err(cleanup_err) => Err(combine_endpoint_bypass_error(err, cleanup_err)),
            };
        }
        Ok(())
    }

    fn change_default_route_to_tunnel(&mut self) -> Result<(), BackendError> {
        // wg-quick split-default: route ALL of 0.0.0.0/0 through the tunnel via
        // the two halves 0.0.0.0/1 + 128.0.0.0/1 instead of repointing the
        // system `default` route. Repointing `default` at the utun makes the
        // utun the PRIMARY interface, so macOS source-address selection picks
        // the utun address as the source for LAN-destined packets and the
        // strong-host / scoped-routing check then drops them — breaking the
        // WireGuard underlay's path to a same-subnet peer endpoint. The /1
        // halves stay strictly more specific than `default` while still
        // covering all of 0.0.0.0/0, so the physical interface stays primary
        // and egresses the underlay with the correct source, while every
        // internet address is still fully tunneled. Fail-closed: if the utun
        // drops, the /1 routes blackhole the traffic rather than leaking it
        // onto the physical link.
        for half in MACOS_SPLIT_DEFAULT_HALVES {
            let add_args = [
                "-n".to_owned(),
                "add".to_owned(),
                "-inet".to_owned(),
                "-net".to_owned(),
                half.to_owned(),
                "-interface".to_owned(),
                self.interface_name.clone(),
            ];
            if self.runner.run("route", &add_args).is_err() {
                // Already present from a prior partial apply — converge it.
                self.runner.run(
                    "route",
                    &[
                        "-n".to_owned(),
                        "change".to_owned(),
                        "-inet".to_owned(),
                        "-net".to_owned(),
                        half.to_owned(),
                        "-interface".to_owned(),
                        self.interface_name.clone(),
                    ],
                )?;
            }
        }
        Ok(())
    }

    fn restore_default_route(&mut self) -> Result<(), BackendError> {
        // wg-quick split-default teardown: delete the 0.0.0.0/1 + 128.0.0.0/1
        // tunnel halves. The system `default` route was never repointed (see
        // change_default_route_to_tunnel), so there is nothing to restore there
        // — just drop the halves and the per-peer bypass routes.
        if self.default_gateway.is_none() {
            return self.remove_endpoint_bypass_routes();
        }
        for half in MACOS_SPLIT_DEFAULT_HALVES {
            match self.runner.run(
                "route",
                &[
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    half.to_owned(),
                ],
            ) {
                Ok(()) => {}
                Err(err) if is_missing_route_error(&err) => {}
                Err(err) => return Err(err),
            }
        }
        self.remove_endpoint_bypass_routes()?;
        self.default_gateway = None;
        Ok(())
    }

    fn terminate_wireguard_go_processes(&mut self) -> Result<(), BackendError> {
        // RSA-0033: the backend no longer names pids. It asks the privileged
        // helper's purpose-built builtin to enumerate the wireguard-go
        // processes itself, select only the allowlisted wireguard-go binary
        // serving exactly this interface, and signal those alone. The client
        // cannot choose (or even see) a target pid. Zero matches is success —
        // there is simply nothing to stop.
        self.runner
            .run("terminate-wireguard-go", &[self.interface_name.clone()])
    }

    fn set_exit_tables(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        match mode {
            ExitMode::Off => self.restore_default_route(),
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
                "show".to_owned(),
                self.interface_name.clone(),
                "latest-handshakes".to_owned(),
            ],
        )?;
        let public_key = encode_wg_public_key_base64(&peer.public_key);
        parse_peer_latest_handshake_unix(&output.stdout, &public_key, self.peers.len().max(1))
    }

    fn apply_peer_config_to_wg(&mut self, peer: &PeerConfig) -> Result<(), BackendError> {
        let allowed_ips = peer.allowed_ips.join(",");
        let endpoint = render_peer_endpoint(peer.endpoint);
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
        // FIS-0015: only when configured — None preserves today's behavior.
        if let Some(interval_secs) = peer.persistent_keepalive_secs {
            args.push("persistent-keepalive".to_owned());
            args.push(interval_secs.to_string());
        }
        // Default-deny (plan §4.8): `peer.preshared_key` is deliberately NOT
        // emitted here — kernel-attach PSK configuration is owner-gated (S8)
        // and must never be configured through wg(8) by this backend. The
        // field is stored with the peer but never read into args.
        self.runner.run("wg", &args)
    }

    fn remove_peer_from_wg(&mut self, peer: &PeerConfig) -> Result<(), BackendError> {
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

    fn update_peer_endpoint_in_wg(
        &mut self,
        peer: &PeerConfig,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        let endpoint_value = render_peer_endpoint(endpoint);
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
        )
    }

    fn refresh_endpoint_bypass_routes_if_needed(&mut self) -> Result<(), BackendError> {
        if self.exit_mode != ExitMode::FullTunnel {
            return Ok(());
        }
        self.install_endpoint_bypass_routes()
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
            supports_exit_client: true,
            supports_exit_serving: true,
            supports_lan_routes: true,
            supports_ipv6: true,
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
        Self::validate_peer_endpoint(peer.endpoint)?;

        for cidr in &peer.allowed_ips {
            Self::ensure_cidr(cidr)?;
        }

        self.apply_peer_config_to_wg(&peer)?;
        let previous_peer = self.peers.insert(peer.node_id.clone(), peer.clone());
        if let Err(err) = self.refresh_endpoint_bypass_routes_if_needed() {
            let rollback_result = match previous_peer {
                Some(previous_peer) => {
                    self.peers
                        .insert(previous_peer.node_id.clone(), previous_peer.clone());
                    self.apply_peer_config_to_wg(&previous_peer)
                }
                None => {
                    self.peers.remove(&peer.node_id);
                    self.remove_peer_from_wg(&peer)
                }
            };
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
            };
        }
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        self.ensure_running()?;
        let Some(peer) = self.peers.get(node_id).cloned() else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        Self::validate_peer_endpoint(endpoint)?;
        let previous_endpoint = peer.endpoint;
        self.update_peer_endpoint_in_wg(&peer, endpoint)?;
        if let Some(peer) = self.peers.get_mut(node_id) {
            peer.endpoint = endpoint;
        }
        if let Err(err) = self.refresh_endpoint_bypass_routes_if_needed() {
            if let Some(peer) = self.peers.get_mut(node_id) {
                peer.endpoint = previous_endpoint;
            }
            let rollback_result = self.update_peer_endpoint_in_wg(&peer, previous_endpoint);
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
            };
        }
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
        let Some(peer) = self.peers.get(node_id).cloned() else {
            return Ok(());
        };
        self.remove_peer_from_wg(&peer)?;
        self.peers.remove(node_id);
        if let Err(err) = self.refresh_endpoint_bypass_routes_if_needed() {
            self.peers.insert(node_id.clone(), peer.clone());
            let rollback_result = self.apply_peer_config_to_wg(&peer);
            return match rollback_result {
                Ok(()) => Err(err),
                Err(rollback_err) => Err(combine_peer_mutation_error(err, rollback_err)),
            };
        }
        Ok(())
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
            "macos wireguard backend is a command-only adapter over wireguard-go and its OS-managed UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned(),
        )
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
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
    validate_macos_wireguard_interface_name(name).map_err(BackendError::invalid_input)
}

/// The macOS wireguard-go interface-name rule, shared with the privileged
/// helper's `terminate-wireguard-go` builtin (RSA-0033) so the helper and the
/// backend can never disagree about which interface a wireguard-go process
/// serves: the base interface-name rule ([`validate_interface_name`]: 1..=15
/// ASCII alphanumeric/`-`/`_` characters) plus a required `utun` prefix and a
/// non-empty run of ASCII digits.
pub fn validate_macos_wireguard_interface_name(name: &str) -> Result<(), String> {
    validate_interface_name(name).map_err(|err| err.message)?;
    if !name.starts_with("utun") {
        return Err("macos wireguard interface name must start with utun".to_owned());
    }
    let suffix = &name[4..];
    if suffix.is_empty() || !suffix.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("macos wireguard interface name must be utun followed by digits".to_owned());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCidr {
    address: IpAddr,
    prefix_len: u8,
}

impl ParsedCidr {
    fn parse(value: &str) -> Result<Self, BackendError> {
        let (address, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| BackendError::invalid_input("invalid cidr value"))?;
        if address.is_empty() || prefix_len.is_empty() || prefix_len.contains('/') {
            return Err(BackendError::invalid_input("invalid cidr value"));
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| BackendError::invalid_input("invalid cidr address"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|_| BackendError::invalid_input("invalid cidr prefix"))?;
        match address {
            IpAddr::V4(_) if prefix_len <= 32 => {}
            IpAddr::V4(_) => return Err(BackendError::invalid_input("invalid ipv4 prefix")),
            IpAddr::V6(_) if prefix_len <= 128 => {}
            IpAddr::V6(_) => return Err(BackendError::invalid_input("invalid ipv6 prefix")),
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    fn family_arg(&self) -> String {
        if self.address.is_ipv6() {
            "-inet6".to_owned()
        } else {
            "-inet".to_owned()
        }
    }

    fn route_arg(&self) -> String {
        format!("{}/{}", self.address, self.prefix_len)
    }
}

/// Builds the `ifconfig` arguments to assign a local mesh address on the
/// WireGuard interface. The argument form differs by IP family:
///
/// - IPv4: `<iface> inet <addr> <addr> netmask 255.255.255.255`
///   (point-to-point notation; destination equals source for WireGuard)
/// - IPv6: `<iface> inet6 <addr> prefixlen <prefix_len>`
fn ifconfig_address_args(interface_name: &str, cidr: &ParsedCidr) -> Vec<String> {
    let addr = cidr.address.to_string();
    match cidr.address {
        IpAddr::V4(_) => vec![
            interface_name.to_owned(),
            "inet".to_owned(),
            addr.clone(),
            addr,
            "netmask".to_owned(),
            "255.255.255.255".to_owned(),
        ],
        IpAddr::V6(_) => vec![
            interface_name.to_owned(),
            "inet6".to_owned(),
            addr,
            "prefixlen".to_owned(),
            cidr.prefix_len.to_string(),
        ],
    }
}

fn route_add_args(cidr: &str, interface_name: &str) -> Result<Vec<String>, BackendError> {
    let cidr = ParsedCidr::parse(cidr)?;
    Ok(vec![
        "-n".to_owned(),
        "add".to_owned(),
        cidr.family_arg(),
        "-net".to_owned(),
        cidr.route_arg(),
        "-interface".to_owned(),
        interface_name.to_owned(),
    ])
}

fn route_delete_args(cidr: &str) -> Result<Vec<String>, BackendError> {
    let cidr = ParsedCidr::parse(cidr)?;
    Ok(vec![
        "-n".to_owned(),
        "delete".to_owned(),
        cidr.family_arg(),
        "-net".to_owned(),
        cidr.route_arg(),
    ])
}

fn validate_route_set(routes: &[Route]) -> Result<(), BackendError> {
    for route in routes {
        if is_default_route_cidr(&route.destination_cidr) {
            continue;
        }
        ParsedCidr::parse(&route.destination_cidr)?;
    }
    Ok(())
}

fn apply_route_plan(
    runner: &mut dyn WireguardCommandRunner,
    interface_name: &str,
    previous_routes: &[Route],
    next_routes: &[Route],
) -> Result<(), BackendError> {
    for route in next_routes {
        if is_default_route_cidr(&route.destination_cidr)
            || previous_routes.iter().any(|previous| previous == route)
        {
            continue;
        }
        let args = route_add_args(&route.destination_cidr, interface_name)?;
        runner.run("route", &args)?;
    }

    for route in previous_routes {
        if is_default_route_cidr(&route.destination_cidr)
            || next_routes.iter().any(|next| next == route)
        {
            continue;
        }
        let args = route_delete_args(&route.destination_cidr)?;
        match runner.run("route", &args) {
            Ok(()) => {}
            Err(err) if is_missing_route_error(&err) => {}
            Err(err) => return Err(err),
        }
    }

    Ok(())
}

fn is_default_route_cidr(cidr: &str) -> bool {
    matches!(cidr, "0.0.0.0/0" | "::/0")
}

fn combine_route_reconciliation_error(
    primary: BackendError,
    rollback: BackendError,
) -> BackendError {
    BackendError::internal(format!(
        "{}; route rollback failed: {}",
        primary.message, rollback.message
    ))
}

/// The two halves that together cover all of `0.0.0.0/0` while remaining MORE
/// specific than the system `default` route (the standard wg-quick trick).
const MACOS_SPLIT_DEFAULT_HALVES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];

fn apply_endpoint_bypass_plan(
    runner: &mut dyn WireguardCommandRunner,
    gateway: Ipv4Addr,
    egress_interface: &str,
    previous_hosts: &BTreeSet<String>,
    next_hosts: &BTreeSet<String>,
) -> Result<(), BackendError> {
    for endpoint in next_hosts {
        if previous_hosts.contains(endpoint) {
            continue;
        }
        if !endpoint_needs_gateway_bypass(runner, endpoint) {
            // On-link (same-subnet) peer endpoint: the intact connected route
            // already reaches it directly on the physical interface. A
            // /32-via-gateway bypass would be MORE specific than the connected
            // route and shadow it, sending the underlay to the LAN gateway —
            // which cannot hairpin a same-subnet destination, so the WireGuard
            // underlay would never arrive. Under the wg-quick split-default the
            // connected LAN /24 stays intact, so same-subnet peers need no
            // bypass at all. Skip it; the connected route handles this peer.
            continue;
        }
        add_endpoint_bypass_route(runner, gateway, egress_interface, endpoint)?;
    }
    for endpoint in previous_hosts {
        if next_hosts.contains(endpoint) {
            continue;
        }
        remove_endpoint_bypass_route(runner, endpoint)?;
    }
    Ok(())
}

fn add_endpoint_bypass_route(
    runner: &mut dyn WireguardCommandRunner,
    gateway: Ipv4Addr,
    _egress_interface: &str,
    endpoint: &str,
) -> Result<(), BackendError> {
    let endpoint_ip = endpoint
        .parse::<IpAddr>()
        .map_err(|_| BackendError::invalid_input("endpoint bypass host is not an IP address"))?;
    // No `-ifscope`: an ifscope'd route on macOS is only consulted for
    // sockets bound to the named interface, and the WireGuard
    // authoritative UDP socket is bound to 0.0.0.0. With `-ifscope` the
    // route lookup falls through to the default route, which after
    // full-tunnel exit mode points at utun — so encrypted handshake
    // frames to the peer endpoint loop back into the tunnel they are
    // supposed to bring up.
    runner.run(
        "route",
        &[
            "-n".to_owned(),
            "add".to_owned(),
            route_family_arg(endpoint_ip),
            "-host".to_owned(),
            endpoint.to_owned(),
            gateway.to_string(),
        ],
    )
}

/// Whether a peer underlay endpoint needs a `/32`-via-gateway bypass under the
/// wg-quick split-default. Only OFF-subnet endpoints (reached via the default
/// gateway, hence captured by the `0.0.0.0/1`+`128.0.0.0/1` tunnel halves) need
/// one; an on-link (same-subnet) endpoint is delivered directly by the intact
/// connected route, and a via-gateway bypass would shadow that connected route
/// and break the underlay. Decided from the pre-enforce routing table: a
/// `gateway:` line in `route -n get` output means the endpoint is reached via a
/// gateway (off-subnet). On any query failure (including an unparseable
/// endpoint) default to NOT needing a bypass — the safe choice for the common
/// same-subnet topology, since a wrongly-added gateway bypass breaks the
/// underlay whereas a missing one merely leaves a genuinely off-subnet peer to
/// the tunnel halves.
fn endpoint_needs_gateway_bypass(runner: &mut dyn WireguardCommandRunner, endpoint: &str) -> bool {
    let Ok(endpoint_ip) = endpoint.parse::<IpAddr>() else {
        return false;
    };
    match runner.run_capture(
        "route",
        &[
            "-n".to_owned(),
            "get".to_owned(),
            route_family_arg(endpoint_ip),
            endpoint.to_owned(),
        ],
    ) {
        Ok(output) => output
            .stdout
            .lines()
            .any(|line| line.trim().starts_with("gateway:")),
        Err(_) => false,
    }
}

fn remove_endpoint_bypass_route(
    runner: &mut dyn WireguardCommandRunner,
    endpoint: &str,
) -> Result<(), BackendError> {
    let endpoint_ip = endpoint
        .parse::<IpAddr>()
        .map_err(|_| BackendError::invalid_input("endpoint bypass host is not an IP address"))?;
    match runner.run(
        "route",
        &[
            "-n".to_owned(),
            "delete".to_owned(),
            route_family_arg(endpoint_ip),
            "-host".to_owned(),
            endpoint.to_owned(),
        ],
    ) {
        Ok(()) => Ok(()),
        Err(err) if is_missing_route_error(&err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn route_family_arg(endpoint: IpAddr) -> String {
    if endpoint.is_ipv6() {
        "-inet6".to_owned()
    } else {
        "-inet".to_owned()
    }
}

fn render_peer_endpoint(endpoint: SocketEndpoint) -> String {
    if endpoint.addr.is_ipv6() {
        format!("[{}]:{}", endpoint.addr, endpoint.port)
    } else {
        format!("{}:{}", endpoint.addr, endpoint.port)
    }
}

fn combine_endpoint_bypass_error(primary: BackendError, rollback: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; endpoint bypass rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn combine_interface_cleanup_error(primary: BackendError, cleanup: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; interface cleanup failed: {}",
        primary.message, cleanup.message
    ))
}

fn combine_cleanup_step_results<const N: usize>(
    steps: [(&'static str, Result<(), BackendError>); N],
) -> Result<(), BackendError> {
    let failures = steps
        .into_iter()
        .filter_map(|(label, result)| match result {
            Ok(()) => None,
            Err(err) => Some(format!("{label} failed: {}", err.message)),
        })
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(BackendError::internal(failures.join("; ")))
    }
}

fn combine_peer_mutation_error(primary: BackendError, rollback: BackendError) -> BackendError {
    BackendError::internal(format!(
        "{}; peer state rollback failed: {}",
        primary.message, rollback.message
    ))
}

fn is_missing_interface_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("does not exist")
        || message.contains("no such interface")
        || message.contains("interface not found")
        || message.contains("no such device")
}

fn is_missing_route_error(err: &BackendError) -> bool {
    let message = err.message.to_ascii_lowercase();
    message.contains("not in table") || message.contains("no such process")
}

fn parse_default_gateway_output(stdout: &str) -> Result<Ipv4Addr, BackendError> {
    for line in stdout.lines() {
        let normalized = line.trim();
        if let Some(value) = normalized.strip_prefix("gateway:") {
            let gateway = value.trim();
            if gateway.is_empty() {
                continue;
            }
            return gateway.parse::<Ipv4Addr>().map_err(|_| {
                BackendError::internal("default gateway is not a valid IPv4 address")
            });
        }
    }
    Err(BackendError::internal(
        "default gateway not found in route output",
    ))
}

/// Returns `true` if a file named `wireguard-go` exists in any directory
/// listed in `path_env` (colon-separated PATH string).
#[doc(hidden)]
pub fn wireguard_go_is_on_path(path_env: &str) -> bool {
    path_env.split(':').any(|dir| {
        if dir.is_empty() {
            return false;
        }
        let candidate = std::path::Path::new(dir).join("wireguard-go");
        candidate.is_file()
    })
}

/// Inner form — accepts an explicit PATH string so tests can inject a known
/// value without touching the process environment.
#[doc(hidden)]
pub fn ensure_wireguard_go_on_path_with(path_env: &str) -> Result<(), BackendError> {
    if wireguard_go_is_on_path(path_env) {
        return Ok(());
    }
    Err(BackendError::invalid_input(
        "wireguard-go not found on PATH; \
         install via: brew install wireguard-go",
    ))
}

/// Checks that `wireguard-go` is available on `$PATH` and returns a clear,
/// actionable error if it is not.
fn ensure_wireguard_go_on_path() -> Result<(), BackendError> {
    let path_env = std::env::var("PATH").unwrap_or_default();
    ensure_wireguard_go_on_path_with(&path_env)
}

/// One `wireguard-go <interface>` process line from a `ps -axo pid=,command=`
/// listing, shared between the macOS backend and the privileged helper's
/// `terminate-wireguard-go` builtin (RSA-0033). This module IS the
/// WireGuard-specific boundary, so naming the process shape here leaks nothing
/// into backend-agnostic crates (see scripts/ci/check_backend_boundary_leakage.sh).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireguardGoProcessEntry {
    /// The pid field exactly as `ps` printed it. Callers parse it after their
    /// own selection filters so a malformed pid fails closed only where it
    /// matters; the helper does exactly that.
    pub pid_raw: String,
    /// argv[0] as ps reported it (the executable path the process was exec'd
    /// with).
    pub executable: String,
    /// argv[1]: the interface the process was started for.
    pub interface: String,
}

/// Parse a `ps -axo pid=,command=` listing into wireguard-go candidate
/// entries. A line qualifies only when its command is EXACTLY two whitespace
/// separated tokens (executable + interface); everything else is noise from
/// some other process and is skipped. A non-numeric pid field on any
/// considered line is an error — the helper treats an unparseable ps listing
/// as a failure rather than silently terminating nothing.
pub fn parse_wireguard_go_process_entries(
    stdout: &str,
) -> Result<Vec<WireguardGoProcessEntry>, String> {
    let mut entries = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let mut fields = trimmed.split_whitespace();
        let Some(pid_raw) = fields.next() else {
            continue;
        };
        let command = trimmed
            .strip_prefix(pid_raw)
            .map(str::trim_start)
            .unwrap_or_default();
        if command.is_empty() {
            continue;
        }
        let mut argv = command.split_whitespace();
        let Some(executable) = argv.next() else {
            continue;
        };
        let Some(interface) = argv.next() else {
            continue;
        };
        if argv.next().is_some() {
            continue;
        }
        pid_raw
            .parse::<u32>()
            .map_err(|err| format!("invalid ps pid value: {err}"))?;
        entries.push(WireguardGoProcessEntry {
            pid_raw: pid_raw.to_owned(),
            executable: executable.to_owned(),
            interface: interface.to_owned(),
        });
    }
    Ok(entries)
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

    #[derive(Debug, Default)]
    struct ScriptedRunner {
        calls: Vec<Vec<String>>,
        fail_on_arg: Option<String>,
        fail_on_arg_always: Option<String>,
        capture_stdout: String,
    }

    impl WireguardCommandRunner for ScriptedRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            if let Some(arg) = self.fail_on_arg.as_deref()
                && args.iter().any(|candidate| candidate == arg)
            {
                self.fail_on_arg = None;
                return Err(BackendError::internal("scripted macos command failure"));
            }
            if let Some(arg) = self.fail_on_arg_always.as_deref()
                && args.iter().any(|candidate| candidate == arg)
            {
                return Err(BackendError::internal("scripted macos command failure"));
            }
            Ok(())
        }

        fn run_capture(
            &mut self,
            program: &str,
            args: &[String],
        ) -> Result<WireguardCommandOutput, BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            Ok(WireguardCommandOutput {
                stdout: self.capture_stdout.clone(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct MissingMacosRouteDeleteRunner {
        calls: Vec<Vec<String>>,
    }

    impl WireguardCommandRunner for MissingMacosRouteDeleteRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            if program == "route"
                && args.first().map(String::as_str) == Some("-n")
                && args.get(1).map(String::as_str) == Some("delete")
            {
                return Err(BackendError::internal(
                    "route: writing to routing socket: not in table",
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
                stdout: "gateway: 192.0.2.1\n".to_owned(),
                stderr: String::new(),
            })
        }
    }

    #[derive(Debug, Default)]
    struct InterfaceCleanupFailureRunner {
        calls: Vec<Vec<String>>,
    }

    impl WireguardCommandRunner for InterfaceCleanupFailureRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);
            if program == "wg" && args.iter().any(|arg| arg == "private-key") {
                return Err(BackendError::internal("wg set failed"));
            }
            if program == "ifconfig" && args.iter().any(|arg| arg == "down") {
                return Err(BackendError::internal("ifconfig down failed"));
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

    #[derive(Debug, Default)]
    struct MultiCleanupFailureRunner {
        calls: Vec<Vec<String>>,
    }

    impl WireguardCommandRunner for MultiCleanupFailureRunner {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
            let mut call = Vec::with_capacity(args.len() + 1);
            call.push(program.to_owned());
            call.extend(args.iter().cloned());
            self.calls.push(call);

            if program == "ifconfig" && args.iter().any(|arg| arg == "down") {
                return Err(BackendError::internal("ifconfig down failed"));
            }
            if program == "route"
                && args.get(1).map(String::as_str) == Some("delete")
                && args.iter().any(|arg| arg == "0.0.0.0/1")
            {
                return Err(BackendError::internal("default route restore failed"));
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
            interface_name: "utun9".to_owned(),
            mesh_cidr: "100.64.0.1/32".to_owned(),
            local_cidr: "100.64.0.1/32".to_owned(),
        }
    }

    fn route(cidr: &str) -> Route {
        Route {
            destination_cidr: cidr.to_owned(),
            via_node: NodeId::new("peer-a").expect("id should parse"),
            kind: rustynet_backend_api::RouteKind::Mesh,
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
            preshared_key: None,
        }
    }

    #[test]
    fn macos_backend_reports_transport_socket_identity_blocker() {
        let backend = MacosWireguardBackend::new_for_test(
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
        let err = MacosWireguardBackend::new_for_test(
            RecordingRunner,
            "rustynet0",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect_err("non-utun interface names must be rejected");
        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
    }

    #[test]
    fn macos_backend_reports_ipv6_supported() {
        let backend = MacosWireguardBackend::new_for_test(
            RecordingRunner,
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        assert!(
            backend.capabilities().supports_ipv6,
            "macOS WireGuard backend must report IPv6 support"
        );
    }

    #[test]
    fn macos_backend_rejects_context_interface_mismatch_before_mutation() {
        let mut backend = MacosWireguardBackend::new_for_test(
            RecordingRunner,
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        let mut context = runtime_context();
        context.interface_name = "utun10".to_owned();

        let err = backend
            .start(context)
            .expect_err("mismatched runtime context interface should fail closed");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("runtime context interface mismatch"));
        assert!(!backend.running);
    }

    #[test]
    fn macos_backend_rejects_invalid_mesh_cidr_before_mutation() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        let mut context = runtime_context();
        context.mesh_cidr = "100.64.0.0/99".to_owned();

        let err = backend
            .start(context)
            .expect_err("invalid mesh cidr should fail closed before start");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("invalid ipv4 prefix"));
        assert!(!backend.running);
        assert!(backend.runner.calls.is_empty());
    }

    #[test]
    fn macos_backend_accepts_ipv6_local_cidr() {
        let mut backend = MacosWireguardBackend::new_for_test(
            RecordingRunner,
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        let mut context = runtime_context();
        context.local_cidr = "fd00::1/128".to_owned();

        backend
            .start(context)
            .expect("IPv6 local CIDR must be accepted");
        assert!(backend.running);
    }

    #[test]
    fn macos_backend_configure_interface_uses_inet6_for_ipv6_local_cidr() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        let mut context = runtime_context();
        context.local_cidr = "fd00::1/128".to_owned();

        backend
            .start(context)
            .expect("IPv6 local CIDR must be accepted");

        let ifconfig_call = backend
            .runner
            .calls
            .iter()
            .find(|call| {
                call.first().map(String::as_str) == Some("ifconfig")
                    && call.contains(&"inet6".to_owned())
            })
            .expect("ifconfig inet6 call must be present");
        assert!(
            ifconfig_call.contains(&"prefixlen".to_owned()),
            "IPv6 ifconfig call must use prefixlen form; call: {ifconfig_call:?}"
        );
        assert!(
            ifconfig_call.contains(&"128".to_owned()),
            "prefixlen value must match local_cidr /128; call: {ifconfig_call:?}"
        );
    }

    #[test]
    fn macos_backend_accepts_basic_lifecycle_with_recording_runner() {
        let mut backend = MacosWireguardBackend::new_for_test(
            RecordingRunner,
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
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
        backend.shutdown().expect("shutdown should work");
    }

    #[test]
    fn macos_backend_sets_safe_bringup_mtu_before_interface_up() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");

        backend
            .start(runtime_context())
            .expect("start should execute runner calls");

        let expected_mtu_call = vec![
            "ifconfig".to_owned(),
            "utun9".to_owned(),
            "mtu".to_owned(),
            SAFE_BRINGUP_TUNNEL_MTU.to_string(),
        ];
        let expected_up_call = vec!["ifconfig".to_owned(), "utun9".to_owned(), "up".to_owned()];
        let mtu_index = backend
            .runner
            .calls
            .iter()
            .position(|call| call == &expected_mtu_call)
            .expect("start must set the safe bring-up MTU explicitly");
        let up_index = backend
            .runner
            .calls
            .iter()
            .position(|call| call == &expected_up_call)
            .expect("start must bring the interface up");
        assert!(
            mtu_index < up_index,
            "MTU must be pinned before the interface comes up (wg-quick order)"
        );
    }

    #[test]
    fn macos_backend_start_cleans_up_interface_when_mtu_set_fails() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg_always: Some("mtu".to_owned()),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");

        backend
            .start(runtime_context())
            .expect_err("mtu set failure must fail the start");
        assert!(!backend.running, "backend must not report running");
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|call| call.first().map(String::as_str) == Some("ifconfig")
                    && call.iter().any(|arg| arg == "down")),
            "failed mtu set must run the interface cleanup path"
        );
    }

    #[test]
    fn macos_backend_wg_set_includes_persistent_keepalive_when_configured() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
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
                .any(|call| call.iter().any(|arg| arg == "persistent-keepalive")),
            "None must not emit persistent-keepalive"
        );

        // Some(n): the wg set call carries `persistent-keepalive n`.
        let mut peer = sample_peer("peer-b");
        peer.persistent_keepalive_secs = Some(21);
        backend
            .configure_peer(peer)
            .expect("peer configure should work");
        assert!(
            backend.runner.calls.iter().any(|call| {
                call.first().is_some_and(|program| program == "wg")
                    && call
                        .windows(2)
                        .any(|pair| pair[0] == "persistent-keepalive" && pair[1] == "21")
            }),
            "Some(21) must emit `persistent-keepalive 21`"
        );
    }

    #[test]
    fn macos_backend_ignores_preshared_key_and_never_emits_key_material() {
        // Plan §4.8: the command (kernel) backend stays default-deny — a
        // configured PSK must produce byte-identical wg(8) args to a peer
        // without one, and no encoding of the key bytes may leak into any
        // executed arg.
        let psk_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xA5);
        let psk = rustynet_backend_api::PresharedKey::new(zeroize::Zeroizing::new(psk_bytes));

        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");

        // The peer's `wg set` call is identified by its public-key argument
        // (start()'s interface `wg set` call carries only private-key path +
        // listen-port, so pubkey membership selects exactly the peer call).
        let peer_public_key = encode_wg_public_key_base64(&[7; 32]);
        let peer_set_args = |calls: &[Vec<String>], label: &'static str| {
            calls
                .iter()
                .find(|call| {
                    call.first().map(String::as_str) == Some("wg")
                        && call.iter().any(|arg| arg == &peer_public_key)
                })
                .cloned()
                .map(|mut call| {
                    call.drain(..2);
                    call
                })
                .unwrap_or_else(|| panic!("{label} wg set call should be recorded"))
        };

        let mut peer = sample_peer("peer-a");
        peer.preshared_key = Some(psk);
        backend
            .configure_peer(peer)
            .expect("peer configure should work");
        let args_with_psk = peer_set_args(&backend.runner.calls, "Some(psk)");
        backend.runner.calls.clear();

        let bare = sample_peer("peer-a");
        backend
            .configure_peer(bare)
            .expect("peer configure should work");
        let args_without_psk = peer_set_args(&backend.runner.calls, "None");

        assert_eq!(
            args_with_psk, args_without_psk,
            "Some(psk) must produce byte-identical wg args to None (backend ignores the field)"
        );

        let hex_lower: String = psk_bytes.iter().map(|b| format!("{b:02x}")).collect();
        let hex_upper: String = psk_bytes.iter().map(|b| format!("{b:02X}")).collect();
        let base64 = encode_wg_public_key_base64(&psk_bytes);
        let decimal_commas = psk_bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let decimal_spaces = psk_bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        for arg in &args_with_psk {
            for (label, encoding) in [
                ("lowercase hex", hex_lower.as_str()),
                ("uppercase hex", hex_upper.as_str()),
                ("base64", base64.as_str()),
                ("decimal (comma-joined)", decimal_commas.as_str()),
                ("decimal (space-joined)", decimal_spaces.as_str()),
            ] {
                assert!(
                    !arg.contains(encoding),
                    "wg arg {arg:?} must not contain PSK {label} encoding"
                );
            }
        }
    }

    #[test]
    fn macos_command_backend_rejects_invalid_peer_endpoint_without_wg_mutation() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;

        for (endpoint, expected) in [
            (
                SocketEndpoint {
                    addr: "203.0.113.10".parse().expect("valid ip"),
                    port: 0,
                },
                "port must be non-zero",
            ),
            (
                SocketEndpoint {
                    addr: "0.0.0.0".parse().expect("valid ip"),
                    port: 51820,
                },
                "must not be unspecified",
            ),
            (
                SocketEndpoint {
                    addr: "224.0.0.1".parse().expect("valid ip"),
                    port: 51820,
                },
                "must not be multicast",
            ),
            (
                SocketEndpoint {
                    addr: "255.255.255.255".parse().expect("valid ip"),
                    port: 51820,
                },
                "must not be broadcast",
            ),
        ] {
            let mut peer = sample_peer("peer-a");
            peer.endpoint = endpoint;

            let err = backend
                .configure_peer(peer)
                .expect_err("invalid peer endpoint should fail closed");

            assert_eq!(
                err.kind,
                rustynet_backend_api::BackendErrorKind::InvalidInput
            );
            assert!(err.message.contains(expected));
            assert!(backend.peers.is_empty());
        }

        assert!(
            backend.runner.calls.is_empty(),
            "invalid endpoint must fail before wg mutation; calls: {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_command_backend_rejects_invalid_endpoint_update_without_state_mutation() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        let peer = sample_peer("peer-a");
        let node_id = peer.node_id.clone();
        let previous_endpoint = peer.endpoint;
        backend.peers.insert(node_id.clone(), peer);

        let err = backend
            .update_peer_endpoint(
                &node_id,
                SocketEndpoint {
                    addr: "203.0.113.10".parse().expect("valid ip"),
                    port: 0,
                },
            )
            .expect_err("invalid endpoint update should fail closed");

        assert_eq!(
            err.kind,
            rustynet_backend_api::BackendErrorKind::InvalidInput
        );
        assert!(err.message.contains("port must be non-zero"));
        assert_eq!(
            backend.peers.get(&node_id).map(|peer| peer.endpoint),
            Some(previous_endpoint)
        );
        assert!(
            backend.runner.calls.is_empty(),
            "invalid endpoint update must fail before wg mutation; calls: {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_command_backend_renders_ipv6_peer_endpoints_with_brackets() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        let mut peer = sample_peer("peer-a");
        peer.endpoint = SocketEndpoint {
            addr: "2001:db8::10".parse().expect("valid ipv6"),
            port: 51820,
        };
        let node_id = peer.node_id.clone();

        backend
            .configure_peer(peer)
            .expect("ipv6 peer endpoint should render for wg");
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|call| call.iter().any(|arg| arg == "[2001:db8::10]:51820")),
            "wg peer configure should bracket ipv6 endpoint; calls: {:?}",
            backend.runner.calls
        );

        backend.runner.calls.clear();
        backend
            .update_peer_endpoint(
                &node_id,
                SocketEndpoint {
                    addr: "2001:db8::11".parse().expect("valid ipv6"),
                    port: 51821,
                },
            )
            .expect("ipv6 endpoint update should render for wg");
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|call| call.iter().any(|arg| arg == "[2001:db8::11]:51821")),
            "wg endpoint update should bracket ipv6 endpoint; calls: {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_validate_cidr_rejects_malformed_addresses_prefixes_and_metachars() {
        for bad in [
            "999.64.0.0/24",
            "100.64.0.0/33",
            "fd00::/129",
            "100.64.0.0/24/extra",
            "100.64.0.0/24=foo",
            "100.64.0.0/24 extra",
            "100.64.0.0/24;rm -rf /",
            "100.64.0.0/24|cmd",
            "100.64.0.0/24\n",
            "",
            "no-slash",
        ] {
            assert!(
                MacosWireguardBackend::<RecordingRunner>::ensure_cidr(bad).is_err(),
                "macOS CIDR validator must reject {bad:?}"
            );
            assert!(
                route_add_args(bad, "utun9").is_err(),
                "macOS route add args must reject {bad:?}"
            );
            assert!(
                route_delete_args(bad).is_err(),
                "macOS route delete args must reject {bad:?}"
            );
        }

        for ok in ["100.64.0.0/10", "0.0.0.0/0", "::/0", "2001:db8::/64"] {
            assert!(
                MacosWireguardBackend::<RecordingRunner>::ensure_cidr(ok).is_ok(),
                "macOS CIDR validator must accept {ok:?}"
            );
        }
    }

    #[test]
    fn macos_route_args_are_argv_only_and_family_specific() {
        assert_eq!(
            route_add_args("100.64.0.0/10", "utun9").expect("ipv4 route args"),
            vec![
                "-n".to_owned(),
                "add".to_owned(),
                "-inet".to_owned(),
                "-net".to_owned(),
                "100.64.0.0/10".to_owned(),
                "-interface".to_owned(),
                "utun9".to_owned(),
            ]
        );
        assert_eq!(
            route_delete_args("2001:db8::/64").expect("ipv6 route args"),
            vec![
                "-n".to_owned(),
                "delete".to_owned(),
                "-inet6".to_owned(),
                "-net".to_owned(),
                "2001:db8::/64".to_owned(),
            ]
        );
    }

    #[test]
    fn macos_ifconfig_address_args_are_family_specific() {
        let ipv4_cidr = ParsedCidr::parse("10.0.0.1/32").expect("valid ipv4 cidr");
        assert_eq!(
            ifconfig_address_args("utun9", &ipv4_cidr),
            vec![
                "utun9".to_owned(),
                "inet".to_owned(),
                "10.0.0.1".to_owned(),
                "10.0.0.1".to_owned(),
                "netmask".to_owned(),
                "255.255.255.255".to_owned(),
            ],
            "IPv4 address args must use inet point-to-point form"
        );

        let ipv6_cidr = ParsedCidr::parse("fd00::1/128").expect("valid ipv6 cidr");
        assert_eq!(
            ifconfig_address_args("utun9", &ipv6_cidr),
            vec![
                "utun9".to_owned(),
                "inet6".to_owned(),
                "fd00::1".to_owned(),
                "prefixlen".to_owned(),
                "128".to_owned(),
            ],
            "IPv6 address args must use inet6 prefixlen form"
        );
    }

    #[test]
    fn macos_missing_route_detector_does_not_hide_route_tool_failures() {
        assert!(is_missing_route_error(&BackendError::internal(
            "route: writing to routing socket: not in table"
        )));
        assert!(is_missing_route_error(&BackendError::internal(
            "route exited with status 1: writing to routing socket: No such process"
        )));
        assert!(!is_missing_route_error(&BackendError::internal(
            "route spawn failed: No such file or directory"
        )));
    }

    #[test]
    fn macos_default_gateway_parser_rejects_untyped_or_injected_gateway() {
        for bad in [
            "gateway: 192.0.2.1; route delete default\ninterface: en0\n",
            "gateway: 192.0.2.1 -ifscope en0\ninterface: en0\n",
            "gateway: link#12\ninterface: en0\n",
            "interface: en0\n",
        ] {
            assert!(
                parse_default_gateway_output(bad).is_err(),
                "default gateway parser must reject {bad:?}"
            );
        }

        assert_eq!(
            parse_default_gateway_output("gateway: 192.0.2.1\ninterface: en0\n")
                .expect("valid gateway should parse"),
            Ipv4Addr::new(192, 0, 2, 1)
        );
    }

    #[test]
    fn macos_backend_wireguard_go_path_check_returns_false_for_empty_path() {
        assert!(
            !wireguard_go_is_on_path(""),
            "empty PATH must not report wireguard-go as available"
        );
    }

    #[test]
    fn macos_backend_wireguard_go_path_check_returns_false_when_not_present() {
        // Use a directory that definitely does not contain wireguard-go.
        assert!(
            !wireguard_go_is_on_path("/usr/bin:/bin"),
            "wireguard-go must not be reported as available in /usr/bin:/bin unless \
             it is actually installed there; if this test fails the binary is present, \
             which is fine — remove this assertion"
        );
    }

    #[test]
    fn macos_backend_wireguard_go_path_check_finds_binary_in_known_dir() {
        // Write a fake wireguard-go into a temp dir and verify detection.
        let dir = tempfile::tempdir().expect("temp dir should be created");
        let fake_bin = dir.path().join("wireguard-go");
        std::fs::write(&fake_bin, b"#!/bin/sh\n").expect("fake binary should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
                .expect("fake binary should be made executable");
        }
        let path_env = dir.path().to_string_lossy().to_string();
        assert!(
            wireguard_go_is_on_path(&path_env),
            "wireguard-go should be detected in {path_env}"
        );
    }

    #[test]
    fn macos_backend_reports_missing_wireguard_go_with_install_hint() {
        let err = ensure_wireguard_go_on_path_with("")
            .expect_err("ensure_wireguard_go_on_path must return an error when PATH is empty");
        let msg = err.to_string();
        assert!(
            msg.contains("wireguard-go"),
            "error must mention the missing binary; got: {msg}"
        );
        assert!(
            msg.contains("brew install wireguard-go"),
            "error must include install command; got: {msg}"
        );
    }

    #[test]
    fn macos_wireguard_go_ps_parser_keeps_only_exact_two_token_entries() {
        let stdout = "\
            101 wireguard-go utun9\n\
            102 /usr/local/bin/wireguard-go utun9\n\
            103 /tmp/not-wireguard-go utun9\n\
            104 wireguard-go utun9 --extra\n\
            105 sh -c wireguard-go utun9\n\
            106 wireguard-go utun10\n";

        let entries = parse_wireguard_go_process_entries(stdout).expect("pid parse should succeed");

        // Exact two-token entries only (executable + interface); the extra
        // token lines and the sh -c line are other processes' noise.
        assert_eq!(entries.len(), 4, "{entries:?}");
        assert!(
            entries
                .iter()
                .all(|entry| entry.interface == "utun9" || entry.interface == "utun10")
        );
        // The allowlisted-executable + interface selection is the helper's
        // (wireguard_go_terminate); the basename form is what the backend used
        // before RSA-0033 and is kept covered here via the shared parser:
        let matching: Vec<_> = entries
            .iter()
            .filter(|entry| {
                entry.interface == "utun9"
                    && std::path::Path::new(&entry.executable)
                        .file_name()
                        .and_then(|n| n.to_str())
                        == Some("wireguard-go")
            })
            .collect();
        assert_eq!(matching.len(), 2, "{entries:?}");
    }

    #[test]
    fn macos_wireguard_go_ps_parser_rejects_invalid_pid() {
        let err = parse_wireguard_go_process_entries("not-a-pid wireguard-go utun9\n")
            .expect_err("a non-numeric pid field must fail closed");

        assert!(err.contains("invalid ps pid value"), "{err}");
    }

    #[test]
    fn macos_wireguard_go_teardown_interface_rule_is_the_shared_utun_rule() {
        // RSA-0033: the helper validates the builtin's interface with THIS
        // rule, so it must keep the backend's exact utun semantics.
        assert!(validate_macos_wireguard_interface_name("utun7").is_ok());
        assert!(validate_macos_wireguard_interface_name("utun123").is_ok());
        assert!(validate_macos_wireguard_interface_name("en0").is_err());
        assert!(validate_macos_wireguard_interface_name("utun").is_err());
        assert!(validate_macos_wireguard_interface_name("utun7x").is_err());
        assert!(validate_macos_wireguard_interface_name("utun7; id").is_err());
        assert!(validate_macos_wireguard_interface_name("").is_err());
        assert!(validate_macos_wireguard_interface_name(&"u".repeat(16)).is_err());
    }

    #[test]
    fn macos_command_backend_route_reconciliation_rolls_back_on_add_failure() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("100.64.2.0/24".to_owned()),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.routes = vec![route("100.64.1.0/24")];

        let err = backend
            .apply_route_reconciliation(&[route("100.64.2.0/24")])
            .expect_err("route add failure should fail closed");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(backend.routes, vec![route("100.64.1.0/24")]);
        assert!(
            backend.runner.calls.iter().any(|call| call
                == &vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "add".to_owned(),
                    "-inet".to_owned(),
                    "-net".to_owned(),
                    "100.64.1.0/24".to_owned(),
                    "-interface".to_owned(),
                    "utun9".to_owned(),
                ]),
            "rollback should re-add previous route; calls: {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_command_backend_route_reconciliation_validates_before_mutation() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.routes = vec![route("100.64.1.0/24")];

        let err = backend
            .apply_route_reconciliation(&[route("999.64.2.0/24")])
            .expect_err("invalid route must fail before command execution");

        assert!(err.message.contains("invalid cidr address"));
        assert!(backend.runner.calls.is_empty());
        assert_eq!(backend.routes, vec![route("100.64.1.0/24")]);
    }

    #[test]
    fn macos_command_backend_route_reconciliation_treats_missing_delete_as_idempotent() {
        let mut backend = MacosWireguardBackend::new_for_test(
            MissingMacosRouteDeleteRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.routes = vec![route("100.64.1.0/24")];

        backend
            .apply_route_reconciliation(&[])
            .expect("missing route delete should be idempotent");

        assert!(backend.routes.is_empty());
        assert!(backend.runner.calls.iter().any(|call| call
            == &vec![
                "route".to_owned(),
                "-n".to_owned(),
                "delete".to_owned(),
                "-inet".to_owned(),
                "-net".to_owned(),
                "100.64.1.0/24".to_owned(),
            ]));
    }

    #[test]
    fn macos_command_backend_endpoint_bypass_missing_delete_clears_retry_state() {
        let mut backend = MacosWireguardBackend::new_for_test(
            MissingMacosRouteDeleteRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend
            .endpoint_bypass_hosts
            .insert("203.0.113.10".to_owned());

        backend
            .remove_endpoint_bypass_routes()
            .expect("missing bypass route delete should be idempotent");

        assert!(backend.endpoint_bypass_hosts.is_empty());
    }

    #[test]
    fn macos_command_backend_start_reports_cleanup_failure() {
        let mut backend = MacosWireguardBackend::new_for_test(
            InterfaceCleanupFailureRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");

        let err = backend
            .start(runtime_context())
            .expect_err("start should fail when config and cleanup fail");

        assert!(err.message.contains("wg set failed"));
        assert!(err.message.contains("interface cleanup failed"));
        assert!(err.message.contains("ifconfig down failed"));
        assert!(!backend.running);
    }

    #[test]
    fn macos_command_backend_remove_interface_reports_multiple_cleanup_failures() {
        let mut backend = MacosWireguardBackend::new_for_test(
            MultiCleanupFailureRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));

        let err = backend
            .remove_interface()
            .expect_err("cleanup should report both failures");

        assert!(err.message.contains("interface down failed"));
        assert!(err.message.contains("ifconfig down failed"));
        assert!(err.message.contains("default route restore failed"));
        assert!(backend.runner.calls.iter().any(|call| {
            call == &vec!["ifconfig".to_owned(), "utun9".to_owned(), "down".to_owned()]
        }));
        assert!(backend.runner.calls.iter().any(|call| {
            call == &vec![
                "route".to_owned(),
                "-n".to_owned(),
                "delete".to_owned(),
                "-inet".to_owned(),
                "-net".to_owned(),
                "0.0.0.0/1".to_owned(),
            ]
        }));
    }

    #[test]
    fn macos_command_backend_teardown_sends_terminate_wireguard_go_builtin() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner::default(),
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");

        backend
            .terminate_wireguard_go_processes()
            .expect("teardown termination should succeed");

        assert!(
            backend.runner.calls.iter().any(|call| {
                call == &vec!["terminate-wireguard-go".to_owned(), "utun9".to_owned()]
            }),
            "teardown must delegate to the terminate-wireguard-go helper builtin, got {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_command_backend_configure_peer_rolls_back_when_bypass_refresh_fails() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("203.0.113.10".to_owned()),
                capture_stdout: "gateway: 192.0.2.1\n".to_owned(),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        backend.exit_mode = ExitMode::FullTunnel;
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let peer = sample_peer("peer-a");

        let err = backend
            .configure_peer(peer.clone())
            .expect_err("bypass refresh failure should fail peer configure");

        assert!(err.message.contains("scripted macos command failure"));
        assert!(backend.peers.is_empty());
        assert!(backend.endpoint_bypass_hosts.is_empty());
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|call| call.iter().any(|arg| arg == "remove")),
            "rollback should remove newly configured wg peer; calls: {:?}",
            backend.runner.calls
        );
    }

    #[test]
    fn macos_command_backend_update_peer_endpoint_rolls_back_when_bypass_refresh_fails() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("203.0.113.11".to_owned()),
                capture_stdout: "gateway: 192.0.2.1\n".to_owned(),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        backend.exit_mode = ExitMode::FullTunnel;
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let peer = sample_peer("peer-a");
        let node_id = peer.node_id.clone();
        let previous_endpoint = peer.endpoint;
        backend
            .endpoint_bypass_hosts
            .insert(previous_endpoint.addr.to_string());
        backend.peers.insert(node_id.clone(), peer);
        let next_endpoint = SocketEndpoint {
            addr: "203.0.113.11".parse().expect("valid ip"),
            port: 51820,
        };

        let err = backend
            .update_peer_endpoint(&node_id, next_endpoint)
            .expect_err("bypass refresh failure should fail endpoint update");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(
            backend.peers.get(&node_id).map(|peer| peer.endpoint),
            Some(previous_endpoint)
        );
        assert_eq!(
            backend.endpoint_bypass_hosts,
            BTreeSet::from([previous_endpoint.addr.to_string()])
        );
    }

    #[test]
    fn macos_command_backend_remove_peer_rolls_back_when_bypass_refresh_fails() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("203.0.113.10".to_owned()),
                capture_stdout: "gateway: 192.0.2.1\n".to_owned(),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        backend.exit_mode = ExitMode::FullTunnel;
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        let peer = sample_peer("peer-a");
        let node_id = peer.node_id.clone();
        backend
            .endpoint_bypass_hosts
            .insert(peer.endpoint.addr.to_string());
        backend.peers.insert(node_id.clone(), peer.clone());

        let err = backend
            .remove_peer(&node_id)
            .expect_err("bypass refresh failure should fail peer removal");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(
            backend.peers.get(&node_id).map(|peer| peer.endpoint),
            Some(peer.endpoint)
        );
        assert_eq!(
            backend.endpoint_bypass_hosts,
            BTreeSet::from([peer.endpoint.addr.to_string()])
        );
    }

    #[test]
    fn macos_command_backend_exit_off_failure_preserves_default_route_state_for_retry() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("0.0.0.0/1".to_owned()),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        backend.exit_mode = ExitMode::FullTunnel;
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        backend
            .endpoint_bypass_hosts
            .insert("203.0.113.10".to_owned());

        let err = backend
            .set_exit_mode(ExitMode::Off)
            .expect_err("default route restore failure must be reported");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(backend.default_gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            backend.endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".to_owned()])
        );
        assert_eq!(backend.exit_mode, ExitMode::FullTunnel);
    }

    #[test]
    fn macos_command_backend_exit_off_bypass_failure_preserves_failed_host_for_retry() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("203.0.113.10".to_owned()),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        backend.exit_mode = ExitMode::FullTunnel;
        backend.default_gateway = Some(Ipv4Addr::new(192, 0, 2, 1));
        backend
            .endpoint_bypass_hosts
            .extend(["203.0.113.10".to_owned(), "203.0.113.11".to_owned()]);

        let err = backend
            .set_exit_mode(ExitMode::Off)
            .expect_err("bypass removal failure must be reported");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(backend.default_gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            backend.endpoint_bypass_hosts,
            BTreeSet::from(["203.0.113.10".to_owned()])
        );
        assert_eq!(backend.exit_mode, ExitMode::FullTunnel);

        backend.runner.fail_on_arg = None;
        backend
            .set_exit_mode(ExitMode::Off)
            .expect("retry should clear retained bypass state");
        assert_eq!(backend.default_gateway, None);
        assert!(backend.endpoint_bypass_hosts.is_empty());
        assert_eq!(backend.exit_mode, ExitMode::Off);
    }

    #[test]
    fn macos_command_backend_full_tunnel_bypass_failure_leaves_no_exit_state() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg: Some("203.0.113.10".to_owned()),
                capture_stdout: "gateway: 192.0.2.1\n".to_owned(),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        let peer = sample_peer("peer-a");
        backend.peers.insert(peer.node_id.clone(), peer);

        let err = backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect_err("bypass install failure must fail full tunnel enable");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(backend.default_gateway, None);
        assert!(backend.endpoint_bypass_hosts.is_empty());
        assert_eq!(backend.exit_mode, ExitMode::Off);
    }

    #[test]
    fn macos_command_backend_full_tunnel_default_route_failure_cleans_bypass_state() {
        let mut backend = MacosWireguardBackend::new_for_test(
            ScriptedRunner {
                fail_on_arg_always: Some("utun9".to_owned()),
                capture_stdout: "gateway: 192.0.2.1\n".to_owned(),
                ..ScriptedRunner::default()
            },
            "utun9",
            "/tmp/wg.key",
            "en0",
            51820,
        )
        .expect("backend should construct");
        backend.running = true;
        let peer = sample_peer("peer-a");
        backend.peers.insert(peer.node_id.clone(), peer);

        let err = backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect_err("default route change failure must fail full tunnel enable");

        assert!(err.message.contains("scripted macos command failure"));
        assert_eq!(backend.default_gateway, None);
        assert!(backend.endpoint_bypass_hosts.is_empty());
        assert_eq!(backend.exit_mode, ExitMode::Off);
        assert!(
            backend.runner.calls.iter().any(|call| call
                == &vec![
                    "route".to_owned(),
                    "-n".to_owned(),
                    "delete".to_owned(),
                    "-inet".to_owned(),
                    "-host".to_owned(),
                    "203.0.113.10".to_owned(),
                ]),
            "failed default route change should remove installed bypass route; calls: {:?}",
            backend.runner.calls
        );
    }
}
