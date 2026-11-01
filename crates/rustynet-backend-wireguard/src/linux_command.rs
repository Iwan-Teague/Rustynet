#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::BTreeMap;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

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

/// WG-06: the hard upper bound on how long ONE helper command may block.
///
/// Every helper call these runners issue (`ip tuntap add`, `ip address add`,
/// `ip link set`, `ip route replace`, `ip rule`, `wg set`, `wg show
/// latest-handshakes`) executes INLINE on the backend's single worker thread:
/// `DirectTunLifecycle::prepare_and_open` / `reconcile_routes` /
/// `reconcile_exit_mode` and the `LinuxWireguardBackend` bring-up sequence are
/// driven from `handle_request` on that one thread. A child that never exits —
/// a netlink socket wedged under RTNETLINK pressure, a helper waiting on an
/// entropy or cgroup stall — therefore does not fail one route; it wedges the
/// whole dataplane AND makes `Runtime::shutdown`'s `join_handle.join()` block
/// forever, because shutdown cannot complete until the worker returns.
///
/// Bounding the wait converts that unbounded hang into an ordinary
/// `BackendErrorKind::Internal` failure of the specific operation, which is
/// what the caller's fail-closed path already handles. 10 s is far longer than
/// any healthy `ip`/`wg` call (milliseconds) and far shorter than the operator
/// noticing a dead tunnel.
pub const HELPER_COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

// Test-only override of the bound, so a test can drive the REAL
// `LinuxCommandRunner::run_capture` path — the one production uses — at
// millisecond scale instead of waiting out a 10 s timeout. Thread-local, so
// concurrent tests cannot see each other's override.
#[cfg(test)]
thread_local! {
    static TEST_TIMEOUT_OVERRIDE: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

// Run `body` with `helper_command_timeout` temporarily set to `timeout`.
#[cfg(test)]
fn with_test_timeout<R>(timeout: Duration, body: impl FnOnce() -> R) -> R {
    TEST_TIMEOUT_OVERRIDE.with(|slot| slot.set(Some(timeout)));
    let outcome = body();
    TEST_TIMEOUT_OVERRIDE.with(|slot| slot.set(None));
    outcome
}

/// The bound one helper invocation gets. Production always yields the constant;
/// the override arm exists only so the behavioural tests below exercise the
/// production call path rather than a parallel one.
fn helper_command_timeout() -> Duration {
    #[cfg(test)]
    if let Some(override_timeout) = TEST_TIMEOUT_OVERRIDE.with(std::cell::Cell::take) {
        return override_timeout;
    }
    HELPER_COMMAND_TIMEOUT
}

/// Poll granularity for the bounded child wait. Matches the house pattern in
/// `rustynetd::wireguard_go_terminate`.
const HELPER_COMMAND_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Drain one child pipe to EOF on its own thread.
///
/// The bounded wait polls `Child::try_wait`, so the pipes must be drained
/// concurrently: a helper that writes more than a pipe buffer's worth of stdout
/// (the `wg show latest-handshakes` output alone is capped at 64 KiB) would
/// otherwise block in `write(2)` forever and never be observed as exited.
fn drain_child_pipe<R>(pipe: Option<R>) -> thread::JoinHandle<Vec<u8>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = pipe {
            let _ = pipe.read_to_end(&mut buf);
        }
        buf
    })
}

/// Join a drain thread, degrading to an empty buffer if the reader itself
/// panicked. A reader thread cannot fail closed in any meaningful way here —
/// the child's own exit status is the authoritative verdict — so this never
/// turns a helper result into a panic.
fn join_child_pipe(handle: thread::JoinHandle<Vec<u8>>) -> Vec<u8> {
    handle.join().unwrap_or_default()
}

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
        run_capture_within(program, args, helper_command_timeout())
    }
}

/// Run one helper command under a hard wall-clock bound, killing the child when
/// it overruns. Split out from [`LinuxCommandRunner::run_capture`] so the bound
/// is a parameter the tests can drive without a 10 s wait.
fn run_capture_within(
    program: &str,
    args: &[String],
    timeout: Duration,
) -> Result<WireguardCommandOutput, BackendError> {
    // `stdin` is closed off: a helper that reads stdin must see EOF, not
    // inherit and steal the daemon's own stdin.
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| BackendError::internal(format!("{program} spawn failed: {err}")))?;

    let stdout_pipe = drain_child_pipe(child.stdout.take());
    let stderr_pipe = drain_child_pipe(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(HELPER_COMMAND_POLL_INTERVAL),
            Ok(None) => break None,
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = join_child_pipe(stdout_pipe);
                let _ = join_child_pipe(stderr_pipe);
                return Err(BackendError::internal(format!(
                    "{program} wait failed: {err}"
                )));
            }
        }
    };

    let Some(status) = exit else {
        let _ = child.kill();
        let _ = child.wait();
        let _ = join_child_pipe(stdout_pipe);
        let _ = join_child_pipe(stderr_pipe);
        return Err(BackendError::internal(format!(
            "{program} timed out after {}ms and was killed",
            timeout.as_millis()
        )));
    };

    let stdout_bytes = join_child_pipe(stdout_pipe);
    let stderr_bytes = join_child_pipe(stderr_pipe);

    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr_bytes).trim().to_owned();
        if stderr.is_empty() {
            return Err(BackendError::internal(format!(
                "{program} exited with status {status}"
            )));
        }
        return Err(BackendError::internal(format!(
            "{program} exited with status {status}: {stderr}"
        )));
    }
    let stdout = String::from_utf8(stdout_bytes)
        .map_err(|_| BackendError::internal(format!("{program} produced non-utf8 stdout")))?;
    let stderr = String::from_utf8(stderr_bytes)
        .map_err(|_| BackendError::internal(format!("{program} produced non-utf8 stderr")))?;
    Ok(WireguardCommandOutput { stdout, stderr })
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

    /// RSA-0044: the Linux `configure_peer`/`update_peer_endpoint` paths
    /// format the peer endpoint straight into `wg` argv. Mirror the macOS
    /// backend's `validate_peer_endpoint` (macos_command.rs:115) so both
    /// platforms reject zero-port / unspecified / multicast / broadcast
    /// endpoints instead of handing them to `wg`.
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

    /// RSA-0044 defense-in-depth for the argv surface: the rendered
    /// `addr:port` token must stay a bare IPv4/IPv6 socket-address form —
    /// non-empty, no leading dash, no whitespace, no shell metacharacters.
    /// Unreachable for the typed `SocketEndpoint` (`IpAddr` + `u16`) today;
    /// this pins the invariant the `wg` argv depends on against future
    /// format changes.
    fn validate_endpoint_arg_token(value: &str) -> Result<(), BackendError> {
        fn is_clean_token_char(ch: char) -> bool {
            !(ch.is_whitespace()
                || matches!(
                    ch,
                    ';' | '&' | '|' | '$' | '`' | '(' | ')' | '<' | '>' | '\\' | '\'' | '"'
                ))
        }
        if value.is_empty() || value.starts_with('-') || !value.chars().all(is_clean_token_char) {
            return Err(BackendError::invalid_input(
                "peer endpoint must render as a bare IPv4/IPv6 addr:port argv token",
            ));
        }
        Ok(())
    }

    fn endpoint_arg(endpoint: SocketEndpoint) -> Result<String, BackendError> {
        Self::validate_peer_endpoint(endpoint)?;
        // IPv6 needs the bracketed `[addr]:port` form for wg(8) — same
        // rendering as macOS `render_peer_endpoint` (macos_command.rs:1010).
        let token = if endpoint.addr.is_ipv6() {
            format!("[{}]:{}", endpoint.addr, endpoint.port)
        } else {
            format!("{}:{}", endpoint.addr, endpoint.port)
        };
        Self::validate_endpoint_arg_token(&token)?;
        Ok(token)
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
        let endpoint = Self::endpoint_arg(peer.endpoint)?;
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
        // Default-deny (plan §4.8): `peer.preshared_key` is deliberately NOT
        // emitted here — kernel-attach PSK configuration is owner-gated (S8)
        // and must never be configured through wg(8) by this backend. The
        // field is stored with the peer but never read into args.
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
        let endpoint_value = Self::endpoint_arg(endpoint)?;
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

pub(crate) fn encode_wg_public_key_base64(value: &[u8; 32]) -> String {
    // AQ-08 step 4: the hand-rolled table/index encoder (12 indexing
    // sites) is replaced by the crate's STANDARD encoder, which emits
    // the identical RFC 4648 alphabet + `=` padding — byte-for-byte the
    // same 44-character output for every 32-byte input (the only input
    // length this signature accepts). Verified by the differential
    // harness (see REVIEW-aq08-step4 report).
    use base64::Engine as _;
    base64::prelude::BASE64_STANDARD.encode(value)
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
            preshared_key: None,
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
    fn linux_backend_ignores_preshared_key_and_never_emits_key_material() {
        // Plan §4.8: the command (kernel) backend stays default-deny — a
        // configured PSK must produce byte-identical wg(8) args to a peer
        // without one, and no encoding of the key bytes may leak into any
        // executed arg.
        let psk_bytes: [u8; 32] = core::array::from_fn(|i| (i as u8) ^ 0xA5);
        let psk = rustynet_backend_api::PresharedKey::new(zeroize::Zeroizing::new(psk_bytes));

        let runner = RecordingRunner::default();
        let mut backend = LinuxWireguardBackend::new(runner, "rustynet0", "/tmp/wg.key", 51820)
            .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");

        let mut peer = sample_peer("peer-a");
        peer.preshared_key = Some(psk);
        backend
            .configure_peer(peer)
            .expect("peer configure should work");
        // The peer's `wg set` call is identified by its public-key argument
        // (start()'s interface `wg set` call carries only private-key path +
        // listen-port, so pubkey membership selects exactly the peer call).
        let peer_public_key = encode_wg_public_key_base64(&[7; 32]);
        let peer_set_args = |calls: &[(String, Vec<String>)], label: &'static str| {
            calls
                .iter()
                .find(|(program, args)| {
                    program == "wg" && args.iter().any(|arg| arg == &peer_public_key)
                })
                .map(|(_, args)| args.clone())
                .unwrap_or_else(|| panic!("{label} wg set call should be recorded"))
        };
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

    // ---- WG-06: the helper-command wall-clock bound -----------------------
    //
    // These two tests spawn REAL children on purpose. A `RecordingRunner`
    // fake cannot witness the defect: faking the runner makes the fake's
    // return value, not the child's overrun, the thing under test, which is
    // exactly the gap that let the unbounded `Command::output()` ship. The
    // bound itself is platform-free; only the POSIX helper binaries are not,
    // so the pair is cfg(unix) and the Windows CI leg skips them.

    #[cfg(unix)]
    #[test]
    fn helper_command_bound_kills_an_overrunning_child_instead_of_hanging() {
        let started = Instant::now();
        let err = with_test_timeout(Duration::from_millis(200), || {
            // Through `LinuxCommandRunner::run_capture` itself, not the helper
            // beneath it: the defect was the runner never bounding its wait.
            LinuxCommandRunner.run_capture("sleep", &["30".to_owned()])
        })
        .expect_err("a helper that overruns its bound must fail the call, not hang the worker");

        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(
            err.message.contains("timed out") && err.message.contains("killed"),
            "error must name the timeout and the kill, got: {}",
            err.message
        );
        // The bound, not the child's own 30 s lifetime, decides when we return.
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "call returned only after {:?}; the 30 s child outlived the bound",
            started.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn helper_command_bound_preserves_fast_child_output_and_exit_status() {
        // The bound must not change the happy path: a helper that exits inside
        // the window still yields its stdout and its normal error shape.
        let ok = LinuxCommandRunner
            .run_capture("echo", &["ready".to_owned()])
            .expect("a fast helper must succeed");
        assert_eq!(ok.stdout.trim(), "ready");

        let err = LinuxCommandRunner
            .run_capture("false", &[])
            .expect_err("a non-zero exit must surface");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(
            err.message.contains("exited with status"),
            "error must keep the exit-status shape, got: {}",
            err.message
        );
    }

    #[test]
    fn helper_command_default_bound_stays_far_below_an_unbounded_wait() {
        // Pins the production default against a future "just make it big"
        // edit: the bound exists so a wedged helper cannot hold the single
        // backend worker thread (and Runtime::shutdown's join) forever.
        assert!(HELPER_COMMAND_TIMEOUT >= Duration::from_secs(1));
        assert!(
            HELPER_COMMAND_TIMEOUT <= Duration::from_secs(30),
            "default helper bound {}s is too long to bound a wedged `ip`",
            HELPER_COMMAND_TIMEOUT.as_secs()
        );
        // Every helper call the runners issue goes through the bounded path.
        // Scanned over the production half only: this file's own test module
        // names the API in prose, which is not an invocation.
        let source = include_str!("linux_command.rs");
        let production = source
            .split("#[cfg(test)]\nmod tests {")
            .next()
            .unwrap_or_default();
        assert!(
            !production.contains(".output()"),
            "no helper invocation may bypass the bounded wait"
        );
        assert!(
            production.contains("run_capture_within(program, args, helper_command_timeout())"),
            "run_capture must delegate to the bounded path, got a body that calls: {}",
            production
                .lines()
                .find(|line| line.contains("run_capture_within("))
                .unwrap_or("<none>")
                .trim()
        );
    }

    // RSA-0044 witnesses: the macOS backend rejects zero-port / unspecified /
    // multicast / broadcast peer endpoints before they reach `wg` argv; the
    // Linux configure/update paths must refuse them the same way.
    fn started_backend() -> LinuxWireguardBackend<RecordingRunner> {
        let mut backend = LinuxWireguardBackend::new(
            RecordingRunner::default(),
            "rustynet0",
            "/tmp/wg.key",
            51820,
        )
        .expect("backend should be constructed");
        backend
            .start(runtime_context())
            .expect("start should execute runner calls");
        backend
    }

    #[test]
    fn linux_backend_configure_peer_rejects_zero_port_endpoint() {
        let mut backend = started_backend();
        let mut peer = sample_peer("peer-bad-port");
        peer.endpoint.port = 0;

        let err = backend
            .configure_peer(peer)
            .expect_err("zero-port endpoint must be rejected before wg argv");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert!(
            !backend
                .runner
                .calls
                .iter()
                .any(|(program, args)| program == "wg" && args.contains(&"endpoint".to_owned())),
            "rejected endpoint must never reach wg argv: {:?}",
            backend
                .runner
                .calls
                .iter()
                .filter(|(program, args)| program == "wg" && args.contains(&"endpoint".to_owned()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn linux_backend_configure_peer_rejects_unspecified_endpoint() {
        for addr in ["0.0.0.0", "::"] {
            let mut backend = started_backend();
            let mut peer = sample_peer("peer-unspecified");
            peer.endpoint.addr = addr.parse().expect("valid ip");

            let err = backend
                .configure_peer(peer)
                .expect_err("unspecified endpoint must be rejected before wg argv");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
            assert!(
                !backend.runner.calls.iter().any(|(program, args)| program
                    == "wg"
                    && args.contains(&"endpoint".to_owned())),
                "rejected endpoint must never reach wg argv: {:?}",
            backend
                .runner
                .calls
                .iter()
                .filter(|(program, args)| program == "wg" && args.contains(&"endpoint".to_owned()))
                .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn linux_backend_configure_peer_rejects_multicast_and_broadcast_endpoint() {
        for addr in ["224.0.0.1", "255.255.255.255", "ff02::1"] {
            let mut backend = started_backend();
            let mut peer = sample_peer("peer-bad-addr");
            peer.endpoint.addr = addr.parse().expect("valid ip");

            let err = backend
                .configure_peer(peer)
                .expect_err("multicast/broadcast endpoint must be rejected before wg argv");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
            assert!(
                !backend.runner.calls.iter().any(|(program, args)| program
                    == "wg"
                    && args.contains(&"endpoint".to_owned())),
                "rejected endpoint must never reach wg argv: {:?}",
            backend
                .runner
                .calls
                .iter()
                .filter(|(program, args)| program == "wg" && args.contains(&"endpoint".to_owned()))
                .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn linux_backend_update_peer_endpoint_rejects_invalid_endpoint() {
        let mut backend = started_backend();
        let node_id = NodeId::new("peer-a").expect("valid node id");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer configure should work");
        let calls_before = backend.runner.calls.len();

        for bad_endpoint in [
            SocketEndpoint {
                addr: "203.0.113.10".parse().expect("valid ip"),
                port: 0,
            },
            SocketEndpoint {
                addr: "0.0.0.0".parse().expect("valid ip"),
                port: 51820,
            },
        ] {
            let err = backend
                .update_peer_endpoint(&node_id, bad_endpoint)
                .expect_err("invalid endpoint must be rejected before wg argv");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        }

        assert_eq!(
            backend.runner.calls.len(),
            calls_before,
            "rejected endpoint updates must not run wg"
        );
        let stored = backend
            .current_peer_endpoint(&node_id)
            .expect("current endpoint should read")
            .expect("peer should remain configured");
        assert_eq!(stored.port, 51820, "stored endpoint must stay unchanged");
    }

    #[test]
    fn linux_backend_endpoint_arg_rejects_injection_shaped_tokens() {
        for bad in [
            "--help",
            "1.2.3.4:51820 extra",
            "[::1]:1;x",
            "",
            "1.2.3.4:51820\n51821",
            "1.2.3.4:51820 & id",
            "1.2.3.4:51820$(id)",
        ] {
            let err = LinuxWireguardBackend::<RecordingRunner>::validate_endpoint_arg_token(bad)
                .expect_err("injection-shaped endpoint token must be rejected");
            assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        }
        for good in ["203.0.113.10:51820", "2001:db8::1:51820"] {
            LinuxWireguardBackend::<RecordingRunner>::validate_endpoint_arg_token(good)
                .expect("bare addr:port token must be accepted");
        }
    }

    #[test]
    fn linux_backend_endpoint_arg_mirrors_macos_accepted_forms() {
        // macOS parity: the forms macOS accepts reach argv, rendered the way
        // macOS renders them (bracketed IPv6); the forms it rejects never do.
        let rendered_v4 = LinuxWireguardBackend::<RecordingRunner>::endpoint_arg(SocketEndpoint {
            addr: "203.0.113.10".parse().expect("valid ip"),
            port: 51820,
        })
        .expect("accepted form must render");
        assert_eq!(rendered_v4, "203.0.113.10:51820");

        let rendered_v6 = LinuxWireguardBackend::<RecordingRunner>::endpoint_arg(SocketEndpoint {
            addr: "2001:db8::1".parse().expect("valid ip"),
            port: 51820,
        })
        .expect("accepted IPv6 form must render");
        assert_eq!(rendered_v6, "[2001:db8::1]:51820");

        LinuxWireguardBackend::<RecordingRunner>::endpoint_arg(SocketEndpoint {
            addr: "127.0.0.1".parse().expect("valid ip"),
            port: 1,
        })
        .expect("loopback is accepted");

        let rejected_port_zero = SocketEndpoint {
            addr: "203.0.113.10".parse().expect("valid ip"),
            port: 0,
        };
        let err = LinuxWireguardBackend::<RecordingRunner>::endpoint_arg(rejected_port_zero)
            .expect_err("zero port must be rejected");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    }

    #[test]
    fn linux_backend_ipv6_endpoint_renders_bracketed_in_wg_args() {
        let mut backend = started_backend();
        let mut peer = sample_peer("peer-v6");
        peer.endpoint = SocketEndpoint {
            addr: "2001:db8::10".parse().expect("valid ip"),
            port: 51820,
        };
        backend
            .configure_peer(peer)
            .expect("peer configure should work");
        assert!(
            backend
                .runner
                .calls
                .iter()
                .any(|(program, args)| program == "wg"
                    && args.iter().any(|arg| arg == "[2001:db8::10]:51820")),
            "IPv6 endpoint must render bracketed for wg(8)"
        );
        assert!(
            !backend
                .runner
                .calls
                .iter()
                .any(|(_, args)| args.iter().any(|arg| arg == "2001:db8::10:51820")),
            "unbracketed IPv6 rendering must not reach wg argv"
        );
    }
}
