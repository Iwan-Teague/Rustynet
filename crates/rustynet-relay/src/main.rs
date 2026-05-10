#![forbid(unsafe_code)]

//! Rustynet Relay Daemon
//!
//! A production relay server that enables NAT traversal for Rustynet nodes
//! when direct UDP connectivity is unavailable.
//!
//! # Architecture
//!
//! The relay uses **allocated-port demultiplexing**:
//! - A control port receives RelayHello messages and allocates sessions
//! - Each session gets a unique allocated port for ciphertext forwarding
//! - Inbound packets on allocated ports are forwarded to the paired session
//!
//! # Security Model
//!
//! - Ciphertext-only: relay never sees plaintext
//! - Signed tokens: ed25519 signatures from control plane
//! - Constant-time auth: no timing side channels
//! - Replay protection: nonce tracking
//! - Session binding: tokens bound to (node_id, peer_node_id, relay_id)
//! - Rate limiting: per-node packet and hello rate limits
//!
//! # Usage
//!
//! ```bash
//! rustynet-relay --bind 0.0.0.0:4500 \
//!                --relay-id "relay-us-east-1" \
//!                --verifier-key /path/to/control-verifier.pub \
//!                --replay-store /var/lib/rustynet-relay/replay.store \
//!                --port-range 50000-59999
//! ```

#[cfg(feature = "daemon")]
mod daemon {
    use std::collections::HashMap;
    use std::fs;
    use std::net::{IpAddr, SocketAddr};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Serialize};
    use subtle::ConstantTimeEq;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::net::UdpSocket;
    use tokio::sync::RwLock;
    use tokio::time::interval;

    use rustynet_control::canonical_relay_id_from_label;
    use rustynet_relay::session::SessionId;
    use rustynet_relay::transport::{RelayHelloResponse, RelayTransport};

    const DEFAULT_MAX_TOTAL_SESSIONS: usize = 4096;
    const DEFAULT_WINDOWS_RELAY_SERVICE_NAME: &str = "RustyNetRelay";
    const DEFAULT_WINDOWS_RELAY_BINARY_FILE_NAME: &str = "rustynet-relay.exe";
    const DEFAULT_WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
    #[cfg_attr(not(windows), allow(dead_code))]
    const DEFAULT_WINDOWS_RELAY_ROOT: &str = r"C:\ProgramData\RustyNet\relay";
    const FORBIDDEN_WINDOWS_RELAY_SDDL_PRINCIPALS: [&str; 3] = ["WD", "AU", "BU"];
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    const WINDOWS_RELAY_ARGS_ENV: &str = "RUSTYNET_RELAY_ARGS_JSON";
    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    const MAX_WINDOWS_RELAY_ENV_FILE_BYTES: u64 = 32 * 1024;
    static RELAY_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

    pub fn reset_relay_stop_requested() {
        RELAY_STOP_REQUESTED.store(false, Ordering::SeqCst);
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn request_relay_stop() {
        RELAY_STOP_REQUESTED.store(true, Ordering::SeqCst);
    }

    pub fn relay_stop_requested() -> bool {
        RELAY_STOP_REQUESTED.load(Ordering::SeqCst)
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct WindowsRelayServiceOptions {
        pub service_name: String,
        pub env_file: PathBuf,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum RelayHostEntrySelection {
        RelayArgs(Vec<String>),
        WindowsService(WindowsRelayServiceOptions),
        WindowsServiceHardeningCheck { fail_on_drift: bool },
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct WindowsRelayServiceHardeningSnapshot {
        pub schema_version: u32,
        pub service_name: String,
        pub binary_image_path: String,
        pub binary_image_argv: Vec<String>,
        pub start_name: String,
        pub service_sid_type: String,
        pub start_type: String,
        pub interactive_process: bool,
        pub failure_action_count: u32,
        pub binary_path_acl_sddl: String,
        pub env_file_acl_sddl: String,
        pub env_file_parent_acl_sddl: String,
        pub env_file_runtime_args_valid: bool,
        pub env_file_runtime_args_reason: String,
        pub binary_authenticode_trusted: bool,
        pub binary_authenticode_reason: String,
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct WindowsRelayServiceHardeningReport {
        pub schema_version: u32,
        pub overall_ok: bool,
        pub snapshot: WindowsRelayServiceHardeningSnapshot,
        pub drift_reasons: Vec<String>,
    }

    /// Relay daemon configuration.
    #[derive(Debug, Clone)]
    pub struct RelayConfig {
        /// UDP address to bind the control port.
        pub bind_addr: SocketAddr,
        /// 16-byte relay identifier.
        pub relay_id: [u8; 16],
        /// Path to control-plane verifier public key.
        pub verifier_key_path: String,
        /// Durable replay store path for accepted relay token nonces.
        pub replay_store_path: String,
        /// Port range for session allocations.
        pub port_range_start: u16,
        pub port_range_end: u16,
        /// Maximum sessions per node.
        pub max_sessions_per_node: usize,
        /// Maximum active sessions across all nodes.
        pub max_total_sessions: usize,
        /// Clock skew tolerance in seconds.
        pub clock_skew_tolerance_secs: u64,
        /// Cleanup interval in seconds.
        pub cleanup_interval_secs: u64,
        /// Optional loopback-only HTTP health/metrics bind address.
        pub health_bind_addr: Option<SocketAddr>,
    }

    impl Default for RelayConfig {
        fn default() -> Self {
            Self {
                bind_addr: "0.0.0.0:4500".parse().unwrap(),
                relay_id: [0; 16],
                verifier_key_path: String::new(),
                replay_store_path: String::new(),
                port_range_start: 50_000,
                port_range_end: 59_999,
                max_sessions_per_node: 8,
                max_total_sessions: DEFAULT_MAX_TOTAL_SESSIONS,
                clock_skew_tolerance_secs: 90,
                cleanup_interval_secs: 10,
                health_bind_addr: None,
            }
        }
    }

    impl RelayConfig {
        fn validate(&self) -> Result<(), String> {
            if self.relay_id == [0; 16] {
                return Err("--relay-id is required".to_string());
            }
            if self.verifier_key_path.trim().is_empty() {
                return Err("--verifier-key is required".to_string());
            }
            if self.replay_store_path.trim().is_empty() {
                return Err("--replay-store is required".to_string());
            }
            if !Path::new(&self.verifier_key_path).is_absolute() {
                return Err("--verifier-key must be an absolute path".to_string());
            }
            if !Path::new(&self.replay_store_path).is_absolute() {
                return Err("--replay-store must be an absolute path".to_string());
            }
            if self.bind_addr.port() == 0 {
                return Err("--bind port must not be 0".to_string());
            }
            if self.port_range_start == 0 || self.port_range_end == 0 {
                return Err("--port-range must not include port 0".to_string());
            }
            if self.port_range_start > self.port_range_end {
                return Err("--port-range start must be <= end".to_string());
            }
            if (self.port_range_start..=self.port_range_end).contains(&self.bind_addr.port()) {
                return Err("--port-range must not include the control bind port".to_string());
            }
            if self.max_sessions_per_node == 0 {
                return Err("--max-sessions-per-node must be greater than 0".to_string());
            }
            if self.max_total_sessions == 0 {
                return Err("--max-total-sessions must be greater than 0".to_string());
            }
            let available_dataplane_ports =
                usize::from(self.port_range_end) - usize::from(self.port_range_start) + 1;
            if self.max_total_sessions > available_dataplane_ports {
                return Err(format!(
                    "--max-total-sessions ({}) exceeds available dataplane ports ({available_dataplane_ports})",
                    self.max_total_sessions
                ));
            }
            if self.cleanup_interval_secs == 0 {
                return Err("cleanup interval must be greater than 0".to_string());
            }
            if let Some(health_bind_addr) = self.health_bind_addr {
                if health_bind_addr.port() == 0 {
                    return Err("--health-bind port must not be 0".to_string());
                }
                if !health_bind_addr.ip().is_loopback() {
                    return Err("--health-bind must use a loopback address".to_string());
                }
            }
            Ok(())
        }
    }

    /// Wire format constants matching relay_client.rs
    const RELAY_HELLO_MSG_TYPE: u8 = 0x01;
    const RELAY_HELLO_ACK_MSG_TYPE: u8 = 0x02;
    const RELAY_REJECT_MSG_TYPE: u8 = 0x03;
    const RELAY_REJECT_GENERIC_REASON: &str = "Rejected";
    const RELAY_KEEPALIVE_MSG_TYPE: u8 = 0x04;
    const MAX_PRE_AUTH_HELLOS_PER_IP_PER_SEC: u32 = 50;
    const MAX_PRE_AUTH_HELLO_SOURCE_IPS: usize = 4096;

    /// Maps allocated ports to session IDs for ciphertext forwarding.
    struct PortAllocation {
        session_id: SessionId,
    }

    /// Relay daemon state.
    pub struct RelayDaemon {
        config: RelayConfig,
        transport: Arc<RwLock<RelayTransport>>,
        control_socket: UdpSocket,
        pre_auth_hello_limiter: Arc<RwLock<PreAuthHelloLimiter>>,
        /// Allocated port sockets indexed by port number.
        allocated_sockets: Arc<RwLock<HashMap<u16, (UdpSocket, PortAllocation)>>>,
        /// Next port to try allocating.
        next_port: Arc<RwLock<u16>>,
    }

    impl RelayDaemon {
        /// Creates a new relay daemon.
        pub async fn new(config: RelayConfig) -> Result<Self, String> {
            config.validate()?;

            let verifier_key = load_control_verifier_key(&config.verifier_key_path)?;

            // Bind control socket
            let control_socket = UdpSocket::bind(config.bind_addr)
                .await
                .map_err(|e| format!("failed to bind control socket: {e}"))?;

            let mut transport = RelayTransport::new_with_replay_store_path(
                config.relay_id,
                verifier_key,
                config.max_sessions_per_node,
                config.clock_skew_tolerance_secs,
                config.replay_store_path.clone(),
            )
            .map_err(|e| format!("failed to initialize relay replay store: {e}"))?;
            transport.set_max_total_sessions(config.max_total_sessions)?;

            Ok(Self {
                config: config.clone(),
                transport: Arc::new(RwLock::new(transport)),
                control_socket,
                pre_auth_hello_limiter: Arc::new(RwLock::new(PreAuthHelloLimiter::new(
                    MAX_PRE_AUTH_HELLOS_PER_IP_PER_SEC,
                ))),
                allocated_sockets: Arc::new(RwLock::new(HashMap::new())),
                next_port: Arc::new(RwLock::new(config.port_range_start)),
            })
        }

        /// Allocates a new port for a session.
        async fn allocate_port(&self) -> Result<(u16, UdpSocket), String> {
            let mut next = self.next_port.write().await;
            let sockets = self.allocated_sockets.read().await;

            let range_size =
                (self.config.port_range_end - self.config.port_range_start + 1) as usize;
            let mut attempts = 0;

            loop {
                if attempts >= range_size {
                    return Err("no available ports in range".to_string());
                }

                let port = *next;
                *next = if *next >= self.config.port_range_end {
                    self.config.port_range_start
                } else {
                    *next + 1
                };

                if sockets.contains_key(&port) {
                    attempts += 1;
                    continue;
                }

                // Try to bind
                let addr = SocketAddr::new(self.config.bind_addr.ip(), port);
                match UdpSocket::bind(addr).await {
                    Ok(socket) => return Ok((port, socket)),
                    Err(_) => {
                        attempts += 1;
                        continue;
                    }
                }
            }
        }

        /// Runs the relay daemon main loop.
        pub async fn run(&self) -> Result<(), String> {
            eprintln!(
                "rustynet-relay starting on {} relay_id={:02x?}",
                self.config.bind_addr,
                &self.config.relay_id[..4]
            );

            let health_listener = if let Some(health_bind_addr) = self.config.health_bind_addr {
                Some(bind_health_listener(health_bind_addr).await?)
            } else {
                None
            };

            // Spawn cleanup task
            let transport_cleanup = Arc::clone(&self.transport);
            let allocated_cleanup = Arc::clone(&self.allocated_sockets);
            let cleanup_interval = self.config.cleanup_interval_secs;

            tokio::spawn(async move {
                let mut ticker = interval(Duration::from_secs(cleanup_interval));
                loop {
                    ticker.tick().await;
                    {
                        let mut transport = transport_cleanup.write().await;
                        let _ = transport.cleanup_idle_sessions();
                    }
                    Self::prune_inactive_allocated_sockets(&allocated_cleanup, &transport_cleanup)
                        .await;
                }
            });

            if let Some(health_listener) = health_listener {
                let transport_health = Arc::clone(&self.transport);
                let allocated_health = Arc::clone(&self.allocated_sockets);
                let max_sessions_per_node = self.config.max_sessions_per_node;
                let max_total_sessions = self.config.max_total_sessions;
                tokio::spawn(async move {
                    if let Err(err) = serve_health_endpoint(
                        health_listener,
                        transport_health,
                        allocated_health,
                        max_sessions_per_node,
                        max_total_sessions,
                    )
                    .await
                    {
                        eprintln!("health endpoint stopped: {err}");
                    }
                });
            }

            // Main receive loop on control socket
            let mut buf = [0u8; 65536];
            let mut stop_ticker = interval(Duration::from_millis(250));

            loop {
                tokio::select! {
                    recv_result = self.control_socket.recv_from(&mut buf) => {
                        match recv_result {
                            Ok((len, from_addr)) => {
                                if let Err(e) = self.handle_control_packet(&buf[..len], from_addr).await {
                                    eprintln!("control packet error from {from_addr}: {e}");
                                }
                            }
                            Err(e) => {
                                eprintln!("control socket recv error: {e}");
                            }
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        eprintln!("rustynet-relay shutting down");
                        break;
                    }
                    _ = stop_ticker.tick() => {
                        if relay_stop_requested() {
                            eprintln!("rustynet-relay service stop requested");
                            break;
                        }
                    }
                }
            }

            Ok(())
        }

        /// Handles a packet on the control port.
        async fn handle_control_packet(
            &self,
            data: &[u8],
            from_addr: SocketAddr,
        ) -> Result<(), String> {
            if data.is_empty() {
                return Err("empty packet".to_string());
            }

            match data[0] {
                RELAY_HELLO_MSG_TYPE => {
                    if !self
                        .pre_auth_hello_limiter
                        .write()
                        .await
                        .check(from_addr.ip())
                    {
                        let reject_bytes = serialize_relay_reject();
                        self.control_socket
                            .send_to(&reject_bytes, from_addr)
                            .await
                            .map_err(|e| format!("failed to send rate-limit reject: {e}"))?;
                        eprintln!("pre-auth relay hello rate limited from {}", from_addr.ip());
                        return Ok(());
                    }
                    self.handle_hello(data, from_addr).await
                }
                _ => Err(format!("unknown message type: {:#02x}", data[0])),
            }
        }

        /// Handles a RelayHello message.
        async fn handle_hello(&self, data: &[u8], from_addr: SocketAddr) -> Result<(), String> {
            let hello = parse_relay_hello(data)?;

            if let Err(reason) = {
                let mut transport = self.transport.write().await;
                transport.validate_hello_from_tuple(&hello, from_addr)
            } {
                let reject_bytes = serialize_relay_reject();
                self.control_socket
                    .send_to(&reject_bytes, from_addr)
                    .await
                    .map_err(|e| format!("failed to send reject: {e}"))?;

                eprintln!("session rejected from {from_addr}: {reason:?}");
                return Ok(());
            }

            Self::prune_inactive_allocated_sockets(&self.allocated_sockets, &self.transport).await;

            // Allocate the real UDP dataplane port before committing the session.
            // The committed transport state and the ack must carry this same port.
            let (allocated_port, socket) = self.allocate_port().await?;

            let response = {
                let mut transport = self.transport.write().await;
                transport.handle_hello_from_tuple_with_allocated_port(
                    hello,
                    from_addr,
                    allocated_port,
                )
            };

            match response {
                RelayHelloResponse::Accepted(ack) => {
                    Self::prune_inactive_allocated_sockets(
                        &self.allocated_sockets,
                        &self.transport,
                    )
                    .await;

                    // Store the allocation
                    {
                        let mut sockets = self.allocated_sockets.write().await;
                        sockets.insert(
                            allocated_port,
                            (
                                socket,
                                PortAllocation {
                                    session_id: ack.session_id,
                                },
                            ),
                        );
                    }

                    // Send ack with allocated port
                    let ack_bytes = serialize_relay_hello_ack(ack.session_id, allocated_port);
                    self.control_socket
                        .send_to(&ack_bytes, from_addr)
                        .await
                        .map_err(|e| format!("failed to send ack: {e}"))?;

                    // Spawn task to forward packets on the allocated port
                    self.spawn_forward_task(allocated_port).await;

                    eprintln!(
                        "session established: {:02x?} -> port {} from {}",
                        &ack.session_id.as_bytes()[..4],
                        allocated_port,
                        from_addr
                    );
                }
                RelayHelloResponse::Rejected(reason) => {
                    drop(socket);
                    let reject_bytes = serialize_relay_reject();
                    self.control_socket
                        .send_to(&reject_bytes, from_addr)
                        .await
                        .map_err(|e| format!("failed to send reject: {e}"))?;

                    eprintln!("session rejected from {from_addr}: {reason:?}");
                }
            }

            Ok(())
        }

        /// Spawns a task to forward packets on an allocated port.
        async fn spawn_forward_task(&self, port: u16) {
            let allocated_sockets = Arc::clone(&self.allocated_sockets);
            let transport = Arc::clone(&self.transport);

            tokio::spawn(async move {
                let mut buf = [0u8; 65536];

                loop {
                    // Get socket reference
                    let socket_result = {
                        let sockets = allocated_sockets.read().await;
                        sockets.get(&port).map(|(s, _)| s.local_addr())
                    };

                    let Some(Some(_)) = socket_result.map(|result| result.ok()) else {
                        // Socket no longer exists
                        break;
                    };

                    // We need to recv on the socket
                    let recv_result = {
                        let sockets = allocated_sockets.read().await;
                        if let Some((socket, alloc)) = sockets.get(&port) {
                            let session_id = alloc.session_id;
                            match socket.try_recv_from(&mut buf) {
                                Ok((len, from_addr)) => Some((len, from_addr, session_id)),
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
                                Err(_) => None,
                            }
                        } else {
                            break;
                        }
                    };

                    if let Some((len, from_addr, session_id)) = recv_result {
                        // Check for keepalive packet (5 bytes: msg_type + 4 bytes session prefix)
                        // Keepalives refresh session activity but don't forward to peer
                        if len == 5 && buf[0] == RELAY_KEEPALIVE_MSG_TYPE {
                            let mut t = transport.write().await;
                            let _ = t.touch_session_from_tuple(session_id, from_addr);
                            continue;
                        }

                        // Forward packet through transport
                        let forward_result = {
                            let mut t = transport.write().await;
                            t.forward_packet(session_id, &buf[..len], from_addr)
                        };

                        match forward_result {
                            Ok(Some(target)) => {
                                let sockets = allocated_sockets.read().await;
                                if let Some((peer_socket, _)) =
                                    sockets.get(&target.peer_allocated_port)
                                {
                                    let _ = peer_socket
                                        .send_to(&target.payload, target.peer_addr)
                                        .await;
                                }
                            }
                            Ok(None) => {}
                            Err(_) => {
                                Self::prune_inactive_allocated_sockets(
                                    &allocated_sockets,
                                    &transport,
                                )
                                .await;
                            }
                        }
                    }

                    // Small delay to avoid busy-spinning
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
            });
        }

        async fn prune_inactive_allocated_sockets(
            allocated_sockets: &Arc<RwLock<HashMap<u16, (UdpSocket, PortAllocation)>>>,
            transport: &Arc<RwLock<RelayTransport>>,
        ) {
            let active_sessions = {
                let transport = transport.read().await;
                let sockets = allocated_sockets.read().await;
                sockets
                    .iter()
                    .filter_map(|(port, (_socket, alloc))| {
                        transport
                            .has_session(alloc.session_id)
                            .then_some((*port, alloc.session_id))
                    })
                    .collect::<HashMap<_, _>>()
            };

            let mut sockets = allocated_sockets.write().await;
            sockets.retain(|port, (_socket, alloc)| {
                active_sessions
                    .get(port)
                    .map(|session_id| {
                        bool::from(session_id.as_bytes().ct_eq(alloc.session_id.as_bytes()))
                    })
                    .unwrap_or(false)
            });
        }
    }

    struct PreAuthHelloLimiter {
        max_per_sec: u32,
        counts: HashMap<IpAddr, (u32, Instant)>,
    }

    impl PreAuthHelloLimiter {
        fn new(max_per_sec: u32) -> Self {
            Self {
                max_per_sec,
                counts: HashMap::new(),
            }
        }

        fn check(&mut self, ip: IpAddr) -> bool {
            let now = Instant::now();
            self.prune(now);
            if !self.counts.contains_key(&ip) && self.counts.len() >= MAX_PRE_AUTH_HELLO_SOURCE_IPS
            {
                return false;
            }
            let entry = self.counts.entry(ip).or_insert((0, now));
            if now.duration_since(entry.1) >= Duration::from_secs(1) {
                *entry = (0, now);
            }
            if entry.0 >= self.max_per_sec {
                return false;
            }
            entry.0 += 1;
            true
        }

        fn prune(&mut self, now: Instant) {
            self.counts.retain(|_, (_, window_start)| {
                now.duration_since(*window_start) < Duration::from_secs(1)
            });
        }
    }

    /// Parses a RelayHello from wire format.
    fn parse_relay_hello(data: &[u8]) -> Result<rustynet_relay::transport::RelayHello, String> {
        if data.is_empty() || data[0] != RELAY_HELLO_MSG_TYPE {
            return Err("not a hello message".to_string());
        }

        let mut pos = 1;

        // Node ID
        if pos + 2 > data.len() {
            return Err("truncated node_id length".to_string());
        }
        let node_id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + node_id_len > data.len() {
            return Err("truncated node_id".to_string());
        }
        let node_id =
            String::from_utf8(data[pos..pos + node_id_len].to_vec()).map_err(|e| e.to_string())?;
        pos += node_id_len;

        // Peer node ID
        if pos + 2 > data.len() {
            return Err("truncated peer_node_id length".to_string());
        }
        let peer_node_id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + peer_node_id_len > data.len() {
            return Err("truncated peer_node_id".to_string());
        }
        let peer_node_id = String::from_utf8(data[pos..pos + peer_node_id_len].to_vec())
            .map_err(|e| e.to_string())?;
        pos += peer_node_id_len;

        // Token
        if pos + 2 > data.len() {
            return Err("truncated token length".to_string());
        }
        let token_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + token_len > data.len() {
            return Err("truncated token".to_string());
        }
        let token_data = &data[pos..pos + token_len];
        let session_token = parse_relay_token(token_data)?;

        Ok(rustynet_relay::transport::RelayHello {
            node_id,
            peer_node_id,
            session_token,
        })
    }

    /// Parses a RelaySessionToken from wire format.
    fn parse_relay_token(data: &[u8]) -> Result<rustynet_control::RelaySessionToken, String> {
        use rustynet_control::RelaySessionToken;

        let mut pos = 0;

        // Version
        if pos >= data.len() {
            return Err("missing version".to_string());
        }
        let version = data[pos];
        if version != 1 {
            return Err(format!("unsupported token version: {version}"));
        }
        pos += 1;

        // Node ID
        if pos + 2 > data.len() {
            return Err("truncated token node_id length".to_string());
        }
        let node_id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + node_id_len > data.len() {
            return Err("truncated token node_id".to_string());
        }
        let node_id = String::from_utf8(data[pos..pos + node_id_len].to_vec())
            .map_err(|e| format!("invalid token node_id: {e}"))?;
        pos += node_id_len;

        // Peer node ID
        if pos + 2 > data.len() {
            return Err("truncated token peer_node_id length".to_string());
        }
        let peer_node_id_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + peer_node_id_len > data.len() {
            return Err("truncated token peer_node_id".to_string());
        }
        let peer_node_id = String::from_utf8(data[pos..pos + peer_node_id_len].to_vec())
            .map_err(|e| format!("invalid token peer_node_id: {e}"))?;
        pos += peer_node_id_len;

        // Relay ID (16 bytes)
        if pos + 16 > data.len() {
            return Err("truncated relay_id".to_string());
        }
        let relay_id: [u8; 16] = data[pos..pos + 16]
            .try_into()
            .map_err(|_| "invalid relay_id")?;
        pos += 16;

        // Scope
        if pos + 2 > data.len() {
            return Err("truncated scope length".to_string());
        }
        let scope_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if pos + scope_len > data.len() {
            return Err("truncated scope".to_string());
        }
        let scope = String::from_utf8(data[pos..pos + scope_len].to_vec())
            .map_err(|e| format!("invalid scope: {e}"))?;
        pos += scope_len;

        // Timestamps
        if pos + 16 > data.len() {
            return Err("truncated timestamps".to_string());
        }
        let issued_at_unix = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;
        let expires_at_unix = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
        pos += 8;

        // Nonce (16 bytes)
        if pos + 16 > data.len() {
            return Err("truncated nonce".to_string());
        }
        let nonce: [u8; 16] = data[pos..pos + 16]
            .try_into()
            .map_err(|_| "invalid nonce")?;
        pos += 16;

        // Signature (64 bytes)
        if pos + 64 > data.len() {
            return Err("truncated signature".to_string());
        }
        let signature: [u8; 64] = data[pos..pos + 64]
            .try_into()
            .map_err(|_| "invalid signature")?;

        Ok(RelaySessionToken {
            node_id,
            peer_node_id,
            relay_id,
            scope,
            issued_at_unix,
            expires_at_unix,
            nonce,
            signature,
        })
    }

    /// Serializes a RelayHelloAck for wire transmission.
    fn serialize_relay_hello_ack(session_id: SessionId, allocated_port: u16) -> Vec<u8> {
        let mut buf = Vec::with_capacity(19);
        buf.push(RELAY_HELLO_ACK_MSG_TYPE);
        buf.extend_from_slice(session_id.as_bytes());
        buf.extend_from_slice(&allocated_port.to_be_bytes());
        buf
    }

    /// Serializes a rejection message.
    fn serialize_relay_reject() -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + RELAY_REJECT_GENERIC_REASON.len());
        buf.push(RELAY_REJECT_MSG_TYPE);
        buf.extend_from_slice(RELAY_REJECT_GENERIC_REASON.as_bytes());
        buf
    }

    fn load_control_verifier_key(path: &str) -> Result<VerifyingKey, String> {
        let path = Path::new(path);
        validate_verifier_key_path(path)?;
        let key_bytes = fs::read(path).map_err(|e| format!("failed to read verifier key: {e}"))?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "verifier key must be 32 bytes, got {}",
                key_bytes.len()
            ));
        }
        VerifyingKey::from_bytes(
            key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "invalid key length")?,
        )
        .map_err(|e| format!("invalid verifier key: {e}"))
    }

    fn validate_verifier_key_path(path: &Path) -> Result<(), String> {
        if !path.is_absolute() {
            return Err("verifier key path must be absolute".to_string());
        }
        let metadata =
            fs::symlink_metadata(path).map_err(|err| format!("stat verifier key: {err}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err("verifier key path must be a regular file".to_string());
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o022 != 0 {
                return Err(format!("verifier key permissions too broad: {mode:o}"));
            }
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            let metadata = fs::symlink_metadata(parent)
                .map_err(|err| format!("stat verifier key dir: {err}"))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err("verifier key parent must be a directory".to_string());
            }
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o022 != 0 {
                    return Err(format!(
                        "verifier key parent permissions too broad: {mode:o}"
                    ));
                }
            }
        }
        Ok(())
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct HealthSnapshot {
        active_sessions: usize,
        allocated_ports: usize,
        max_sessions_per_node: usize,
        max_total_sessions: usize,
    }

    async fn bind_health_listener(bind_addr: SocketAddr) -> Result<TcpListener, String> {
        if !bind_addr.ip().is_loopback() {
            return Err("health endpoint bind address must be loopback".to_string());
        }
        TcpListener::bind(bind_addr)
            .await
            .map_err(|err| format!("bind health endpoint: {err}"))
    }

    async fn serve_health_endpoint(
        listener: TcpListener,
        transport: Arc<RwLock<RelayTransport>>,
        allocated_sockets: Arc<RwLock<HashMap<u16, (UdpSocket, PortAllocation)>>>,
        max_sessions_per_node: usize,
        max_total_sessions: usize,
    ) -> Result<(), String> {
        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .map_err(|err| format!("accept health connection: {err}"))?;
            let transport = Arc::clone(&transport);
            let allocated_sockets = Arc::clone(&allocated_sockets);
            tokio::spawn(async move {
                let mut request = [0u8; 1024];
                let read = match stream.read(&mut request).await {
                    Ok(read) => read,
                    Err(err) => {
                        eprintln!("health request read failed: {err}");
                        return;
                    }
                };
                let path = http_request_path(&request[..read]).unwrap_or("/");
                let snapshot = HealthSnapshot {
                    active_sessions: transport.read().await.session_count(),
                    allocated_ports: allocated_sockets.read().await.len(),
                    max_sessions_per_node,
                    max_total_sessions,
                };
                let (status, content_type, body) = match path {
                    "/healthz" => ("200 OK", "application/json", render_health_json(snapshot)),
                    "/metrics" => (
                        "200 OK",
                        "text/plain; version=0.0.4",
                        render_metrics(snapshot),
                    ),
                    _ => ("404 Not Found", "text/plain", "not found\n".to_string()),
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                if let Err(err) = stream.write_all(response.as_bytes()).await {
                    eprintln!("health response write failed: {err}");
                }
            });
        }
    }

    fn http_request_path(request: &[u8]) -> Option<&str> {
        let request = std::str::from_utf8(request).ok()?;
        let line = request.lines().next()?;
        let mut parts = line.split_whitespace();
        if parts.next()? != "GET" {
            return None;
        }
        parts.next()
    }

    fn render_health_json(snapshot: HealthSnapshot) -> String {
        format!(
            "{{\"status\":\"ok\",\"active_sessions\":{},\"allocated_ports\":{},\"max_sessions_per_node\":{},\"max_total_sessions\":{}}}\n",
            snapshot.active_sessions,
            snapshot.allocated_ports,
            snapshot.max_sessions_per_node,
            snapshot.max_total_sessions
        )
    }

    fn render_metrics(snapshot: HealthSnapshot) -> String {
        format!(
            "# TYPE rustynet_relay_active_sessions gauge\nrustynet_relay_active_sessions {}\n# TYPE rustynet_relay_allocated_ports gauge\nrustynet_relay_allocated_ports {}\n# TYPE rustynet_relay_max_sessions_per_node gauge\nrustynet_relay_max_sessions_per_node {}\n# TYPE rustynet_relay_max_total_sessions gauge\nrustynet_relay_max_total_sessions {}\n",
            snapshot.active_sessions,
            snapshot.allocated_ports,
            snapshot.max_sessions_per_node,
            snapshot.max_total_sessions
        )
    }

    fn parse_relay_id_arg(value: &str) -> Result<[u8; 16], String> {
        canonical_relay_id_from_label(value).map_err(|err| format!("invalid --relay-id: {err}"))
    }

    fn parse_windows_relay_service_hardening_check_args(
        args: &[String],
    ) -> Result<Option<bool>, String> {
        let Some(command) = args.get(1) else {
            return Ok(None);
        };
        if command != "windows-service-hardening-check" {
            return Ok(None);
        }
        let mut fail_on_drift = true;
        for flag in &args[2..] {
            match flag.as_str() {
                "--no-fail-on-drift" => fail_on_drift = false,
                _ => {
                    return Err(format!(
                        "unknown windows-service-hardening-check argument: {flag}"
                    ));
                }
            }
        }
        Ok(Some(fail_on_drift))
    }

    pub fn select_relay_host_entry(args: &[String]) -> Result<RelayHostEntrySelection, String> {
        if let Some(fail_on_drift) = parse_windows_relay_service_hardening_check_args(args)? {
            return Ok(RelayHostEntrySelection::WindowsServiceHardeningCheck { fail_on_drift });
        }
        let (relay_args, service) = strip_windows_service_args(args)?;
        if let Some(service) = service {
            if relay_args.len() > 1 {
                return Err(
                    "--windows-service does not accept inline relay flags; use --env-file with RUSTYNET_RELAY_ARGS_JSON"
                        .to_string(),
                );
            }
            return Ok(RelayHostEntrySelection::WindowsService(service));
        }
        Ok(RelayHostEntrySelection::RelayArgs(relay_args))
    }

    pub fn strip_windows_service_args(
        args: &[String],
    ) -> Result<(Vec<String>, Option<WindowsRelayServiceOptions>), String> {
        let mut relay_args = Vec::new();
        let mut windows_service = false;
        let mut service_name: Option<String> = None;
        let mut env_file: Option<PathBuf> = None;
        let mut index = 0usize;

        while index < args.len() {
            match args[index].as_str() {
                "--windows-service" => {
                    windows_service = true;
                    index += 1;
                }
                "--service-name" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--service-name requires a value".to_string())?;
                    service_name = Some(value.clone());
                    index += 2;
                }
                "--env-file" => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--env-file requires a value".to_string())?;
                    env_file = Some(PathBuf::from(value));
                    index += 2;
                }
                _ => {
                    relay_args.push(args[index].clone());
                    index += 1;
                }
            }
        }

        if !windows_service {
            if service_name.is_some() {
                return Err("--service-name requires --windows-service".to_string());
            }
            if env_file.is_some() {
                return Err("--env-file requires --windows-service".to_string());
            }
            return Ok((relay_args, None));
        }

        let env_file = env_file.ok_or_else(|| {
            "--windows-service requires --env-file so the Windows SCM host loads reviewed config input"
                .to_string()
        })?;
        validate_windows_relay_service_env_file_path(&env_file)?;

        Ok((
            relay_args,
            Some(WindowsRelayServiceOptions {
                service_name: service_name
                    .unwrap_or_else(|| DEFAULT_WINDOWS_RELAY_SERVICE_NAME.to_string()),
                env_file,
            }),
        ))
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    pub fn load_windows_relay_service_args(env_file: &Path) -> Result<Vec<String>, String> {
        validate_windows_relay_service_env_file_path(env_file)?;
        validate_windows_relay_service_env_file_acl(env_file)?;
        let metadata = fs::metadata(env_file).map_err(|err| {
            format!(
                "failed to read Windows relay service env-file metadata {}: {err}",
                env_file.display()
            )
        })?;
        if metadata.len() > MAX_WINDOWS_RELAY_ENV_FILE_BYTES {
            return Err(format!(
                "Windows relay service env-file is too large ({} bytes > {MAX_WINDOWS_RELAY_ENV_FILE_BYTES})",
                metadata.len()
            ));
        }
        let text = fs::read_to_string(env_file).map_err(|err| {
            format!(
                "failed to read Windows relay service env-file {}: {err}",
                env_file.display()
            )
        })?;
        let variables = parse_windows_relay_env_file(&text)?;
        let relay_args_json = variables.get(WINDOWS_RELAY_ARGS_ENV).ok_or_else(|| {
            format!(
                "Windows relay service env-file must define {WINDOWS_RELAY_ARGS_ENV} as a JSON array of relay flags"
            )
        })?;
        let relay_args: Vec<String> = serde_json::from_str(relay_args_json).map_err(|err| {
            format!("{WINDOWS_RELAY_ARGS_ENV} must be a JSON string array: {err}")
        })?;
        if relay_args.is_empty() {
            return Err(format!("{WINDOWS_RELAY_ARGS_ENV} must not be empty"));
        }
        Ok(relay_args)
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn validate_windows_relay_service_runtime_args(args: &[String]) -> Result<(), String> {
        validate_windows_relay_service_runtime_arg_shape(args)?;
        let verifier_key =
            extract_unique_relay_arg_value(args, "--verifier-key")?.ok_or_else(|| {
                "Windows relay service runtime args must include --verifier-key".to_string()
            })?;
        let replay_store =
            extract_unique_relay_arg_value(args, "--replay-store")?.ok_or_else(|| {
                "Windows relay service runtime args must include --replay-store".to_string()
            })?;

        validate_windows_relay_service_runtime_path(
            Path::new(verifier_key),
            "Windows relay verifier key",
        )?;
        validate_windows_relay_service_runtime_path(
            Path::new(replay_store),
            "Windows relay replay store",
        )
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn validate_windows_relay_service_runtime_arg_shape(args: &[String]) -> Result<(), String> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut index = 0usize;
        while index < args.len() {
            let flag = args[index].as_str();
            if flag == "--help" || flag == "-h" {
                return Err(
                    "Windows relay service runtime args must not include --help/-h".to_string(),
                );
            }
            if !windows_relay_service_runtime_flag_takes_value(flag) {
                return Err(format!(
                    "Windows relay service runtime args contain unsupported argument: {flag}"
                ));
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a non-flag value"));
            }
            *counts.entry(flag).or_insert(0) += 1;
            index += 2;
        }

        for flag in ["--relay-id", "--verifier-key", "--replay-store"] {
            if counts.get(flag).copied().unwrap_or(0) != 1 {
                return Err(format!(
                    "Windows relay service runtime args must include {flag} exactly once"
                ));
            }
        }
        for (flag, count) in counts {
            if count > 1 {
                return Err(format!(
                    "Windows relay service runtime args must include {flag} at most once"
                ));
            }
        }

        let relay_id = extract_unique_relay_arg_value(args, "--relay-id")?
            .expect("required relay id count checked above");
        parse_relay_id_arg(relay_id)?;

        let bind_addr = extract_unique_relay_arg_value(args, "--bind")?
            .map(parse_socket_addr_for_windows_relay_service)
            .transpose()?
            .unwrap_or_else(|| "0.0.0.0:4500".parse().expect("default bind must parse"));
        if bind_addr.port() == 0 {
            return Err("Windows relay service --bind port must not be 0".to_string());
        }

        if let Some(health_bind) = extract_unique_relay_arg_value(args, "--health-bind")? {
            let health_bind = parse_socket_addr_for_windows_relay_service(health_bind)?;
            if health_bind.port() == 0 || !health_bind.ip().is_loopback() {
                return Err(
                    "Windows relay service --health-bind must use a non-zero loopback address"
                        .to_string(),
                );
            }
        }

        if let Some(port_range) = extract_unique_relay_arg_value(args, "--port-range")? {
            let (start, end) = parse_windows_relay_service_port_range(port_range)?;
            if (start..=end).contains(&bind_addr.port()) {
                return Err(
                    "Windows relay service --port-range must not include the control bind port"
                        .to_string(),
                );
            }
        }

        for flag in ["--max-sessions-per-node", "--max-total-sessions"] {
            if let Some(raw) = extract_unique_relay_arg_value(args, flag)? {
                let value = raw.parse::<usize>().map_err(|err| {
                    format!("Windows relay service {flag} must be numeric: {err}")
                })?;
                if value == 0 {
                    return Err(format!(
                        "Windows relay service {flag} must be greater than 0"
                    ));
                }
            }
        }

        Ok(())
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn windows_relay_service_runtime_flag_takes_value(flag: &str) -> bool {
        matches!(
            flag,
            "--bind"
                | "--relay-id"
                | "--verifier-key"
                | "--replay-store"
                | "--port-range"
                | "--max-sessions-per-node"
                | "--max-total-sessions"
                | "--health-bind"
        )
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn parse_socket_addr_for_windows_relay_service(value: &str) -> Result<SocketAddr, String> {
        value
            .parse()
            .map_err(|err| format!("invalid Windows relay service socket address {value:?}: {err}"))
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn parse_windows_relay_service_port_range(value: &str) -> Result<(u16, u16), String> {
        let (start_raw, end_raw) = value
            .split_once('-')
            .ok_or_else(|| "Windows relay service --port-range must be START-END".to_string())?;
        let start = start_raw
            .parse::<u16>()
            .map_err(|err| format!("invalid Windows relay service port range start: {err}"))?;
        let end = end_raw
            .parse::<u16>()
            .map_err(|err| format!("invalid Windows relay service port range end: {err}"))?;
        if start == 0 || end == 0 || start > end {
            return Err(
                "Windows relay service --port-range must be non-zero and ordered".to_string(),
            );
        }
        Ok((start, end))
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn extract_unique_relay_arg_value<'a>(
        args: &'a [String],
        flag: &str,
    ) -> Result<Option<&'a str>, String> {
        let mut found = None;
        let mut index = 0usize;
        while index < args.len() {
            if args[index] == flag {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("{flag} requires a value"))?;
                if found.replace(value.as_str()).is_some() {
                    return Err(format!(
                        "Windows relay service runtime args must include {flag} exactly once"
                    ));
                }
                index += 2;
                continue;
            }
            index += 1;
        }
        Ok(found)
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn validate_windows_relay_service_runtime_path(path: &Path, label: &str) -> Result<(), String> {
        let normalized = normalize_windows_relay_service_path(path)?;
        if !windows_relay_service_path_under_reviewed_root(normalized.as_str()) {
            return Err(format!(
                "{label} must stay under reviewed relay runtime root {DEFAULT_WINDOWS_RELAY_ROOT}: {}",
                path.display()
            ));
        }
        validate_windows_relay_service_runtime_file_acl(path, label)
    }

    #[cfg(windows)]
    fn validate_windows_relay_service_runtime_file_acl(
        path: &Path,
        label: &str,
    ) -> Result<(), String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|err| format!("failed to read {label} metadata {}: {err}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(format!(
                "{label} must be a regular file, not a symlink or directory: {}",
                path.display()
            ));
        }
        let sddl = rustynet_windows_native::inspect_file_sddl(path)
            .map_err(|err| format!("{label} ACL inspection failed ({}): {err}", path.display()))?;
        let parent = path
            .parent()
            .ok_or_else(|| format!("{label} must have a parent directory: {}", path.display()))?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|err| {
            format!(
                "failed to read {label} parent metadata {}: {err}",
                parent.display()
            )
        })?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
            return Err(format!(
                "{label} parent must be a real directory: {}",
                parent.display()
            ));
        }
        let parent_sddl = rustynet_windows_native::inspect_file_sddl(parent).map_err(|err| {
            format!(
                "{label} parent ACL inspection failed ({}): {err}",
                parent.display()
            )
        })?;
        validate_windows_relay_service_runtime_acl_sddl(label, sddl.as_str(), parent_sddl.as_str())
    }

    #[cfg(not(windows))]
    fn validate_windows_relay_service_runtime_file_acl(
        _path: &Path,
        _label: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn validate_windows_relay_service_runtime_acl_sddl(
        label: &str,
        file_sddl: &str,
        parent_sddl: &str,
    ) -> Result<(), String> {
        evaluate_windows_relay_service_acl_sddl(label, file_sddl, true)?;
        evaluate_windows_relay_service_acl_sddl(&format!("{label} parent"), parent_sddl, true)
    }

    #[cfg_attr(not(any(windows, test)), allow(dead_code))]
    fn parse_windows_relay_env_file(text: &str) -> Result<HashMap<String, String>, String> {
        let mut variables = HashMap::new();
        for (line_index, raw_line) in text.lines().enumerate() {
            let line_no = line_index + 1;
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                format!("invalid Windows relay service env-file line {line_no}: expected KEY=VALUE")
            })?;
            if key.is_empty()
                || !key
                    .chars()
                    .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
            {
                return Err(format!(
                    "invalid Windows relay service env-file key '{key}' on line {line_no}"
                ));
            }
            if variables
                .insert(key.to_string(), value.to_string())
                .is_some()
            {
                return Err(format!(
                    "duplicate Windows relay service env-file key '{key}' on line {line_no}"
                ));
            }
        }
        Ok(variables)
    }

    fn validate_windows_relay_service_env_file_path(path: &Path) -> Result<(), String> {
        #[cfg(windows)]
        {
            validate_windows_relay_service_env_file_path_windows(path)
        }
        #[cfg(not(windows))]
        {
            if !path.is_absolute() {
                return Err("--env-file must be an absolute path".to_string());
            }
            Ok(())
        }
    }

    #[cfg(windows)]
    fn validate_windows_relay_service_env_file_acl(path: &Path) -> Result<(), String> {
        let file_metadata = fs::symlink_metadata(path).map_err(|err| {
            format!(
                "failed to read Windows relay service env-file metadata {}: {err}",
                path.display()
            )
        })?;
        if file_metadata.file_type().is_symlink() || !file_metadata.file_type().is_file() {
            return Err(format!(
                "Windows relay service env-file must be a regular file, not a symlink or directory: {}",
                path.display()
            ));
        }
        let file_sddl = rustynet_windows_native::inspect_file_sddl(path).map_err(|err| {
            format!(
                "Windows relay service env-file ACL inspection failed ({}): {err}",
                path.display()
            )
        })?;
        evaluate_windows_relay_service_acl_sddl(
            "Windows relay service env-file",
            file_sddl.as_str(),
            true,
        )?;

        let parent = path.parent().ok_or_else(|| {
            format!(
                "Windows relay service env-file must have a parent directory: {}",
                path.display()
            )
        })?;
        let parent_metadata = fs::symlink_metadata(parent).map_err(|err| {
            format!(
                "failed to read Windows relay service env-file parent metadata {}: {err}",
                parent.display()
            )
        })?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.file_type().is_dir() {
            return Err(format!(
                "Windows relay service env-file parent must be a real directory: {}",
                parent.display()
            ));
        }
        let parent_sddl = rustynet_windows_native::inspect_file_sddl(parent).map_err(|err| {
            format!(
                "Windows relay service env-file parent ACL inspection failed ({}): {err}",
                parent.display()
            )
        })?;
        evaluate_windows_relay_service_acl_sddl(
            "Windows relay service env-file parent",
            parent_sddl.as_str(),
            true,
        )
    }

    #[cfg(not(windows))]
    fn validate_windows_relay_service_env_file_acl(_path: &Path) -> Result<(), String> {
        Ok(())
    }

    #[cfg(windows)]
    fn validate_windows_relay_service_env_file_path_windows(path: &Path) -> Result<(), String> {
        let normalized = normalize_windows_relay_service_path(path)?;
        if !windows_relay_service_path_under_reviewed_root(normalized.as_str()) {
            return Err(format!(
                "Windows relay service env-file must stay under reviewed relay runtime root {DEFAULT_WINDOWS_RELAY_ROOT}: {}",
                path.display()
            ));
        }
        Ok(())
    }

    fn normalize_windows_relay_service_path(path: &Path) -> Result<String, String> {
        let text = path.to_string_lossy();
        let normalized = text.replace('/', "\\");
        if normalized.is_empty() {
            return Err("Windows relay service env-file path must not be empty".to_string());
        }
        if is_linux_runtime_root_text(text.as_ref()) {
            return Err(format!(
                "Windows relay service env-file must not use Linux runtime roots on Windows: {}",
                path.display()
            ));
        }
        if normalized.starts_with(r"\\.\pipe\") {
            return Err(format!(
                "Windows relay service env-file must use a filesystem path, not a Windows named pipe: {}",
                path.display()
            ));
        }
        if normalized.starts_with(r"\\") {
            return Err(format!(
                "Windows relay service env-file must not use remote or UNC paths: {}",
                path.display()
            ));
        }
        if !looks_like_windows_absolute_path(normalized.as_str()) {
            return Err(format!(
                "Windows relay service env-file must use an absolute Windows path: {}",
                path.display()
            ));
        }
        if normalized
            .split('\\')
            .skip(1)
            .any(|segment| segment == ".." || segment == ".")
        {
            return Err(format!(
                "Windows relay service env-file must not contain path traversal: {}",
                path.display()
            ));
        }
        Ok(normalized)
    }

    fn windows_relay_service_path_under_reviewed_root(normalized: &str) -> bool {
        let candidate = normalized
            .strip_prefix(r"\\?\")
            .unwrap_or(normalized)
            .to_ascii_lowercase();
        let root = DEFAULT_WINDOWS_RELAY_ROOT.to_ascii_lowercase();
        candidate == root || candidate.starts_with(&format!("{root}\\"))
    }

    fn evaluate_windows_relay_service_acl_sddl(
        label: &str,
        sddl: &str,
        require_protected_dacl: bool,
    ) -> Result<(), String> {
        if !sddl.contains("D:") {
            return Err(format!("{label} must expose a Windows DACL in SDDL form"));
        }
        if require_protected_dacl && !sddl.contains("D:P") {
            return Err(format!(
                "{label} must use a protected DACL with inheritance disabled"
            ));
        }
        for principal in FORBIDDEN_WINDOWS_RELAY_SDDL_PRINCIPALS {
            if sddl_contains_principal(sddl, principal) {
                return Err(format!(
                    "{label} ACL grants a broader-than-reviewed Windows principal ({principal})"
                ));
            }
        }
        if !sddl_contains_principal(sddl, "SY") {
            return Err(format!("{label} ACL must grant LocalSystem access"));
        }
        if !sddl_contains_principal(sddl, "BA") {
            return Err(format!(
                "{label} ACL must grant Builtin Administrators access"
            ));
        }
        let owner = extract_sddl_owner(sddl)
            .ok_or_else(|| format!("{label} ACL must expose an owner entry in SDDL form"))?;
        if !matches!(owner, "SY" | "BA") && !owner.starts_with("S-1-5-80-") {
            return Err(format!(
                "{label} ACL owner must be LocalSystem, Builtin Administrators, or a service SID; found {owner}"
            ));
        }
        Ok(())
    }

    fn extract_sddl_owner(sddl: &str) -> Option<&str> {
        let owner_start = sddl.strip_prefix("O:")?;
        let mut owner_len = owner_start.len();
        for marker in ["G:", "D:", "S:"] {
            if let Some(index) = owner_start.find(marker) {
                owner_len = owner_len.min(index);
            }
        }
        Some(&owner_start[..owner_len])
    }

    fn sddl_contains_principal(sddl: &str, principal: &str) -> bool {
        sddl.contains(&format!(";;;{principal})"))
    }

    pub fn evaluate_windows_relay_service_hardening(
        snapshot: &WindowsRelayServiceHardeningSnapshot,
    ) -> Result<(), Vec<String>> {
        let mut reasons = Vec::new();

        if snapshot.schema_version != 1 {
            reasons.push(format!(
                "Windows relay service hardening snapshot has unsupported schema_version={}",
                snapshot.schema_version
            ));
        }

        if snapshot.service_name != DEFAULT_WINDOWS_RELAY_SERVICE_NAME {
            reasons.push(format!(
                "Windows relay service name must be {DEFAULT_WINDOWS_RELAY_SERVICE_NAME}; found {:?}",
                snapshot.service_name
            ));
        }

        if snapshot.binary_image_argv.is_empty() {
            reasons.push(format!(
                "Windows relay service binary image path failed to parse into argv: {:?}",
                snapshot.binary_image_path
            ));
        } else {
            let exe_path = &snapshot.binary_image_argv[0];
            let lowered = exe_path.to_ascii_lowercase().replace('/', "\\");
            let install_root_lower = DEFAULT_WINDOWS_INSTALL_ROOT.to_ascii_lowercase();
            if !lowered.starts_with(&format!("{install_root_lower}\\")) {
                reasons.push(format!(
                    "Windows relay service binary path must live under {DEFAULT_WINDOWS_INSTALL_ROOT}; found {exe_path}"
                ));
            }
            if !lowered.ends_with(&format!(
                "\\{}",
                DEFAULT_WINDOWS_RELAY_BINARY_FILE_NAME.to_ascii_lowercase()
            )) {
                reasons.push(format!(
                    "Windows relay service binary path must end with {DEFAULT_WINDOWS_RELAY_BINARY_FILE_NAME}; found {exe_path}"
                ));
            }

            let argv_tail = &snapshot.binary_image_argv[1..];
            if !argv_tail.iter().any(|arg| arg == "--windows-service") {
                reasons.push(
                    "Windows relay service argv must include --windows-service so the SCM host path is taken"
                        .to_string(),
                );
            }
            let env_files = windows_relay_service_flag_values(argv_tail, "--env-file");
            if env_files.len() != 1 {
                reasons.push(format!(
                    "Windows relay service argv must include exactly one --env-file <path>; found {}",
                    env_files.len()
                ));
            }
            let service_names = windows_relay_service_flag_values(argv_tail, "--service-name");
            if service_names.len() > 1 {
                reasons.push(format!(
                    "Windows relay service argv must include at most one --service-name <name>; found {}",
                    service_names.len()
                ));
            }
            if let Some(service_name) = service_names.first()
                && *service_name != DEFAULT_WINDOWS_RELAY_SERVICE_NAME
            {
                reasons.push(format!(
                    "Windows relay service argv --service-name must be {DEFAULT_WINDOWS_RELAY_SERVICE_NAME}; found {service_name}"
                ));
            }
            let env_file = env_files.first().copied();
            if env_file.is_none() {
                reasons.push(
                    "Windows relay service argv must include --env-file <path> so relay args are read from reviewed config input"
                        .to_string(),
                );
            }
            if let Some(env_file) = env_file {
                match normalize_windows_relay_service_path(Path::new(env_file)) {
                    Ok(normalized) => {
                        if !windows_relay_service_path_under_reviewed_root(normalized.as_str()) {
                            reasons.push(format!(
                                "Windows relay service env-file must stay under reviewed relay runtime root {DEFAULT_WINDOWS_RELAY_ROOT}; found {env_file}"
                            ));
                        }
                    }
                    Err(err) => reasons.push(err),
                }
            }
            for arg in argv_tail {
                if arg.starts_with("--")
                    && arg != "--windows-service"
                    && arg != "--env-file"
                    && arg != "--service-name"
                {
                    reasons.push(format!(
                        "Windows relay service argv must not include inline relay flags; found {arg}"
                    ));
                }
            }

            if env_files.len() == 1 {
                if snapshot.env_file_acl_sddl.trim().is_empty() {
                    reasons.push(
                        "Windows relay service env-file ACL SDDL is empty; cannot verify lockdown"
                            .to_string(),
                    );
                } else if let Err(err) = evaluate_windows_relay_service_acl_sddl(
                    "Windows relay service env-file",
                    snapshot.env_file_acl_sddl.as_str(),
                    true,
                ) {
                    reasons.push(format!("Windows relay service env-file ACL drift: {err}"));
                }
                if snapshot.env_file_parent_acl_sddl.trim().is_empty() {
                    reasons.push(
                        "Windows relay service env-file parent ACL SDDL is empty; cannot verify lockdown"
                            .to_string(),
                    );
                } else if let Err(err) = evaluate_windows_relay_service_acl_sddl(
                    "Windows relay service env-file parent",
                    snapshot.env_file_parent_acl_sddl.as_str(),
                    true,
                ) {
                    reasons.push(format!(
                        "Windows relay service env-file parent ACL drift: {err}"
                    ));
                }
                if !snapshot.env_file_runtime_args_valid {
                    reasons.push(format!(
                        "Windows relay service env-file runtime args are invalid: {}",
                        snapshot.env_file_runtime_args_reason
                    ));
                }
            }
        }

        let start_name_lower = snapshot.start_name.to_ascii_lowercase();
        let start_name_ok =
            start_name_lower == "localsystem" || start_name_lower.starts_with("nt service\\");
        if !start_name_ok {
            reasons.push(format!(
                "Windows relay service must run as LocalSystem or an NT SERVICE\\* virtual account; found {:?}",
                snapshot.start_name
            ));
        }

        let service_sid_type = snapshot.service_sid_type.to_ascii_lowercase();
        if service_sid_type != "unrestricted" && service_sid_type != "restricted" {
            reasons.push(format!(
                "Windows relay service SID type must be unrestricted or restricted; found {:?}",
                snapshot.service_sid_type
            ));
        }

        if snapshot.interactive_process {
            reasons.push(
                "Windows relay service must not carry SERVICE_INTERACTIVE_PROCESS; relay service is non-interactive"
                    .to_string(),
            );
        }

        if snapshot.failure_action_count == 0 {
            reasons.push(
                "Windows relay service must have at least one configured failure action"
                    .to_string(),
            );
        }

        if snapshot.binary_path_acl_sddl.trim().is_empty() {
            reasons.push(
                "Windows relay service binary ACL SDDL is empty; cannot verify lockdown"
                    .to_string(),
            );
        } else if let Err(err) = evaluate_windows_relay_service_acl_sddl(
            "Windows relay service binary",
            snapshot.binary_path_acl_sddl.as_str(),
            false,
        ) {
            reasons.push(format!("Windows relay service binary ACL drift: {err}"));
        }

        if !snapshot.binary_authenticode_trusted {
            reasons.push(format!(
                "Windows relay service binary Authenticode trust failed: {}",
                snapshot.binary_authenticode_reason
            ));
        }

        if reasons.is_empty() {
            Ok(())
        } else {
            Err(reasons)
        }
    }

    fn windows_relay_service_flag_values<'a>(argv_tail: &'a [String], flag: &str) -> Vec<&'a str> {
        argv_tail
            .windows(2)
            .filter_map(|pair| {
                if pair[0] == flag {
                    Some(pair[1].as_str())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn build_windows_relay_service_hardening_report(
        snapshot: WindowsRelayServiceHardeningSnapshot,
    ) -> WindowsRelayServiceHardeningReport {
        let drift_reasons = match evaluate_windows_relay_service_hardening(&snapshot) {
            Ok(()) => Vec::new(),
            Err(reasons) => reasons,
        };
        WindowsRelayServiceHardeningReport {
            schema_version: 1,
            overall_ok: drift_reasons.is_empty(),
            snapshot,
            drift_reasons,
        }
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn parse_windows_image_path_argv(image_path: &str) -> Vec<String> {
        let trimmed = image_path.trim();
        if trimmed.is_empty() {
            return Vec::new();
        }
        let mut argv = Vec::new();
        let mut chars = trimmed.chars().peekable();
        let mut current = String::new();
        let mut in_quotes = false;
        while let Some(ch) = chars.next() {
            match ch {
                '"' => in_quotes = !in_quotes,
                ch if ch.is_whitespace() && !in_quotes => {
                    if !current.is_empty() {
                        argv.push(std::mem::take(&mut current));
                    }
                    while matches!(chars.peek(), Some(next) if next.is_whitespace()) {
                        chars.next();
                    }
                }
                _ => current.push(ch),
            }
        }
        if !current.is_empty() {
            argv.push(current);
        }
        argv
    }

    pub fn collect_windows_relay_service_hardening_snapshot()
    -> Result<WindowsRelayServiceHardeningSnapshot, String> {
        #[cfg(not(windows))]
        {
            Err(
                "windows-service-hardening-check is only available on Windows hosts; relay service snapshot collection requires Win32 SCM access"
                    .to_string(),
            )
        }
        #[cfg(windows)]
        {
            windows_service_hardening_collector::collect()
        }
    }

    fn looks_like_windows_absolute_path(text: &str) -> bool {
        let candidate = text.strip_prefix(r"\\?\").unwrap_or(text);
        let bytes = candidate.as_bytes();
        bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
    }

    fn is_linux_runtime_root_text(text: &str) -> bool {
        let lowered = text.to_ascii_lowercase();
        [
            "/run/rustynet",
            "/var/lib/rustynet",
            "/etc/rustynet",
            "/var/log/rustynet",
        ]
        .iter()
        .any(|root| lowered == *root || lowered.starts_with(&format!("{root}/")))
    }

    fn parse_args_from(args: impl IntoIterator<Item = String>) -> Result<RelayConfig, String> {
        let args: Vec<String> = args.into_iter().collect();
        let mut config = RelayConfig::default();

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--bind" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--bind requires an argument".to_string());
                    }
                    config.bind_addr = args[i]
                        .parse()
                        .map_err(|e| format!("invalid bind address: {e}"))?;
                }
                "--relay-id" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--relay-id requires an argument".to_string());
                    }
                    config.relay_id = parse_relay_id_arg(&args[i])?;
                }
                "--verifier-key" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--verifier-key requires an argument".to_string());
                    }
                    config.verifier_key_path = args[i].clone();
                }
                "--replay-store" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--replay-store requires an argument".to_string());
                    }
                    config.replay_store_path = args[i].clone();
                }
                "--port-range" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--port-range requires an argument".to_string());
                    }
                    let parts: Vec<&str> = args[i].split('-').collect();
                    if parts.len() != 2 {
                        return Err("--port-range must be START-END".to_string());
                    }
                    config.port_range_start = parts[0]
                        .parse()
                        .map_err(|e| format!("invalid port range start: {e}"))?;
                    config.port_range_end = parts[1]
                        .parse()
                        .map_err(|e| format!("invalid port range end: {e}"))?;
                }
                "--max-sessions-per-node" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--max-sessions-per-node requires an argument".to_string());
                    }
                    config.max_sessions_per_node = args[i]
                        .parse()
                        .map_err(|e| format!("invalid max sessions: {e}"))?;
                }
                "--max-total-sessions" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--max-total-sessions requires an argument".to_string());
                    }
                    config.max_total_sessions = args[i]
                        .parse()
                        .map_err(|e| format!("invalid max total sessions: {e}"))?;
                }
                "--health-bind" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--health-bind requires an argument".to_string());
                    }
                    config.health_bind_addr = Some(
                        args[i]
                            .parse()
                            .map_err(|e| format!("invalid health bind address: {e}"))?,
                    );
                }
                "--help" | "-h" => {
                    eprintln!(
                        "Usage: rustynet-relay [OPTIONS]\n\n\
                        Options:\n  \
                          --bind <ADDR>              UDP bind address (default: 0.0.0.0:4500)\n  \
                          --relay-id <ID>            Relay identifier string\n  \
                          --verifier-key <PATH>      Path to control verifier public key\n  \
                          --replay-store <PATH>      Durable replay nonce store path\n  \
                          --port-range <START-END>   Port range for allocations (default: 50000-59999)\n  \
                          --max-sessions-per-node <N> Max sessions per node (default: 8)\n  \
                          --max-total-sessions <N>   Max active sessions across all nodes (default: 4096)\n  \
                          --health-bind <ADDR>       Loopback-only HTTP health/metrics bind address\n  \
                          --help                     Show this help"
                    );
                    std::process::exit(0);
                }
                arg => {
                    return Err(format!("unknown argument: {arg}"));
                }
            }
            i += 1;
        }

        config.validate()?;
        Ok(config)
    }

    pub async fn run_relay_from_args(mut args: Vec<String>) -> Result<(), String> {
        if args
            .first()
            .map(|value| value.starts_with('-'))
            .unwrap_or(true)
        {
            args.insert(0, "rustynet-relay".to_string());
        }
        reset_relay_stop_requested();
        let config = parse_args_from(args)?;
        let daemon = RelayDaemon::new(config).await?;
        daemon.run().await
    }

    pub fn run_windows_relay_service_host(
        options: WindowsRelayServiceOptions,
    ) -> Result<(), String> {
        #[cfg(not(windows))]
        {
            let _ = options;
            Err("--windows-service is only supported on Windows SCM hosts".to_string())
        }
        #[cfg(windows)]
        {
            windows_service_host::run(options)
        }
    }

    pub fn run_windows_relay_service_hardening_check(fail_on_drift: bool) -> Result<(), String> {
        let snapshot = collect_windows_relay_service_hardening_snapshot()?;
        let report = build_windows_relay_service_hardening_report(snapshot);
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|err| format!("serialize relay service-hardening report failed: {err}"))?
        );
        if fail_on_drift && !report.overall_ok {
            return Err(
                "windows-service-hardening-check reported drift in the live RustyNet relay service registration"
                    .to_string(),
            );
        }
        Ok(())
    }

    #[cfg(windows)]
    mod windows_service_hardening_collector {
        use super::{
            DEFAULT_WINDOWS_RELAY_SERVICE_NAME, WindowsRelayServiceHardeningSnapshot,
            load_windows_relay_service_args, parse_windows_image_path_argv,
            validate_windows_relay_service_runtime_args, windows_relay_service_flag_values,
        };
        use rustynet_windows_native::{
            AuthenticodeChainOutcome, inspect_file_sddl, verify_authenticode_chain,
        };
        use std::path::Path;
        use windows_service::service::{ServiceAccess, ServiceSidType, ServiceStartType};
        use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

        pub(super) fn collect() -> Result<WindowsRelayServiceHardeningSnapshot, String> {
            let manager =
                ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                    .map_err(|err| format!("open SCM failed: {err}"))?;
            let service = manager
                .open_service(
                    DEFAULT_WINDOWS_RELAY_SERVICE_NAME,
                    ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
                )
                .map_err(|err| {
                    format!("open service {DEFAULT_WINDOWS_RELAY_SERVICE_NAME} failed: {err}")
                })?;
            let config = service
                .query_config()
                .map_err(|err| format!("query relay service config failed: {err}"))?;
            let sid_type = service
                .get_config_service_sid_info()
                .map_err(|err| format!("query relay service SID info failed: {err}"))?;
            let failure_actions = service
                .get_failure_actions()
                .map_err(|err| format!("query relay service failure actions failed: {err}"))?;
            let interactive_process = config
                .service_type
                .contains(windows_service::service::ServiceType::INTERACTIVE_PROCESS);
            let image_path = config.executable_path.to_string_lossy().to_string();
            let argv = parse_windows_image_path_argv(image_path.as_str());
            let start_name = config
                .account_name
                .as_ref()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "LocalSystem".to_string());
            let binary_path_acl_sddl = if let Some(exe) = argv.first() {
                inspect_file_sddl(Path::new(exe.as_str())).map_err(|err| {
                    format!("inspect relay service binary ACL failed for {exe}: {err}")
                })?
            } else {
                String::new()
            };
            let (binary_authenticode_trusted, binary_authenticode_reason) =
                if let Some(exe) = argv.first() {
                    match verify_authenticode_chain(Path::new(exe.as_str())) {
                        Ok(AuthenticodeChainOutcome::Verified) => (true, "verified".to_string()),
                        Ok(AuthenticodeChainOutcome::Untrusted { reason, hresult }) => {
                            (false, format!("{reason} ({hresult})"))
                        }
                        Err(err) => (false, err),
                    }
                } else {
                    (false, "binary argv missing".to_string())
                };
            let (
                env_file_acl_sddl,
                env_file_parent_acl_sddl,
                env_file_runtime_args_valid,
                env_file_runtime_args_reason,
            ) = collect_env_file_hardening(&argv);
            Ok(WindowsRelayServiceHardeningSnapshot {
                schema_version: 1,
                service_name: DEFAULT_WINDOWS_RELAY_SERVICE_NAME.to_string(),
                binary_image_path: image_path,
                binary_image_argv: argv,
                start_name,
                service_sid_type: service_sid_type_label(sid_type).to_string(),
                start_type: service_start_type_label(config.start_type).to_string(),
                interactive_process,
                failure_action_count: failure_actions
                    .actions
                    .as_ref()
                    .map(|actions| actions.len() as u32)
                    .unwrap_or(0),
                binary_path_acl_sddl,
                env_file_acl_sddl,
                env_file_parent_acl_sddl,
                env_file_runtime_args_valid,
                env_file_runtime_args_reason,
                binary_authenticode_trusted,
                binary_authenticode_reason,
            })
        }

        fn collect_env_file_hardening(argv: &[String]) -> (String, String, bool, String) {
            let argv_tail = argv.get(1..).unwrap_or(&[]);
            let env_files = windows_relay_service_flag_values(argv_tail, "--env-file");
            let Some(env_file) = env_files.first().copied() else {
                return (
                    String::new(),
                    String::new(),
                    false,
                    "missing --env-file".to_string(),
                );
            };
            if env_files.len() != 1 {
                return (
                    String::new(),
                    String::new(),
                    false,
                    format!("ambiguous --env-file count: {}", env_files.len()),
                );
            }
            let env_path = Path::new(env_file);
            let file_sddl = inspect_file_sddl(env_path).unwrap_or_default();
            let parent_sddl = env_path
                .parent()
                .and_then(|parent| inspect_file_sddl(parent).ok())
                .unwrap_or_default();
            match load_windows_relay_service_args(env_path)
                .and_then(|args| validate_windows_relay_service_runtime_args(&args))
            {
                Ok(()) => (file_sddl, parent_sddl, true, "valid".to_string()),
                Err(err) => (file_sddl, parent_sddl, false, err),
            }
        }

        fn service_sid_type_label(value: ServiceSidType) -> &'static str {
            match value {
                ServiceSidType::None => "none",
                ServiceSidType::Unrestricted => "unrestricted",
                ServiceSidType::Restricted => "restricted",
            }
        }

        fn service_start_type_label(value: ServiceStartType) -> &'static str {
            match value {
                ServiceStartType::AutoStart => "auto_start",
                ServiceStartType::OnDemand => "demand_start",
                ServiceStartType::Disabled => "disabled",
                ServiceStartType::SystemStart => "system_start",
                ServiceStartType::BootStart => "boot_start",
            }
        }
    }

    #[cfg(windows)]
    mod windows_service_host {
        use std::ffi::OsString;
        use std::sync::OnceLock;
        use std::time::Duration;

        use windows_service::define_windows_service;
        use windows_service::service::{
            ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
        };
        use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
        use windows_service::service_dispatcher;

        use super::{
            WindowsRelayServiceOptions, load_windows_relay_service_args, request_relay_stop,
            reset_relay_stop_requested, run_relay_from_args,
            validate_windows_relay_service_runtime_args,
        };

        static SERVICE_OPTIONS: OnceLock<WindowsRelayServiceOptions> = OnceLock::new();

        define_windows_service!(ffi_relay_service_main, relay_service_main);

        pub fn run(options: WindowsRelayServiceOptions) -> Result<(), String> {
            let service_name = options.service_name.clone();
            SERVICE_OPTIONS
                .set(options)
                .map_err(|_| "rustynet-relay Windows service already initialized".to_string())?;
            service_dispatcher::start(service_name.as_str(), ffi_relay_service_main)
                .map_err(|err| format!("failed to dispatch rustynet-relay Windows service: {err}"))
        }

        fn relay_service_main(_arguments: Vec<OsString>) {
            if let Err(err) = run_service_main() {
                eprintln!("rustynet-relay Windows service failed: {err}");
            }
        }

        fn run_service_main() -> Result<(), String> {
            let options = SERVICE_OPTIONS
                .get()
                .ok_or_else(|| "missing rustynet-relay Windows service options".to_string())?;
            reset_relay_stop_requested();
            let status_handle = service_control_handler::register(
                options.service_name.as_str(),
                move |control_event| match control_event {
                    windows_service::service::ServiceControl::Interrogate => {
                        ServiceControlHandlerResult::NoError
                    }
                    windows_service::service::ServiceControl::Stop
                    | windows_service::service::ServiceControl::Shutdown => {
                        request_relay_stop();
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                },
            )
            .map_err(|err| format!("register Windows relay service handler: {err}"))?;

            status_handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::StartPending,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 1,
                    wait_hint: Duration::from_secs(10),
                    process_id: None,
                })
                .map_err(|err| format!("report relay service start-pending: {err}"))?;

            let relay_args = load_windows_relay_service_args(&options.env_file)?;
            validate_windows_relay_service_runtime_args(&relay_args)?;
            status_handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Running,
                    controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                    exit_code: ServiceExitCode::Win32(0),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                })
                .map_err(|err| format!("report relay service running: {err}"))?;

            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|err| format!("build relay service runtime: {err}"))?;
            let result = runtime.block_on(run_relay_from_args(relay_args));

            status_handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(if result.is_ok() { 0 } else { 1 }),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                })
                .map_err(|err| format!("report relay service stopped: {err}"))?;
            result
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{
            HealthSnapshot, MAX_PRE_AUTH_HELLO_SOURCE_IPS, PreAuthHelloLimiter,
            RELAY_REJECT_GENERIC_REASON, RELAY_REJECT_MSG_TYPE, RelayConfig,
            RelayHostEntrySelection, RelayTransport, WindowsRelayServiceHardeningSnapshot,
            WindowsRelayServiceOptions, bind_health_listener,
            build_windows_relay_service_hardening_report,
            collect_windows_relay_service_hardening_snapshot,
            evaluate_windows_relay_service_hardening, http_request_path, load_control_verifier_key,
            load_windows_relay_service_args, parse_relay_id_arg, parse_windows_image_path_argv,
            render_health_json, render_metrics, select_relay_host_entry, serialize_relay_reject,
            serve_health_endpoint,
        };
        use ed25519_dalek::SigningKey;
        use std::collections::HashMap;
        use std::fs;
        use std::net::{IpAddr, Ipv4Addr};
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        use std::path::{Path, PathBuf};
        use std::sync::Arc;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpStream, UdpSocket};
        use tokio::sync::RwLock;

        #[test]
        fn relay_id_arg_uses_shared_ascii_canonicalization() {
            let relay_id = parse_relay_id_arg(" relay-eu-1 ").expect("relay id should parse");
            let mut expected = [0u8; 16];
            expected[..10].copy_from_slice(b"relay-eu-1");
            assert_eq!(relay_id, expected);
        }

        #[test]
        fn relay_id_arg_rejects_ambiguous_labels() {
            assert!(parse_relay_id_arg("relay-label-too-long").is_err());
            assert!(parse_relay_id_arg("relay-éu-1").is_err());
        }

        fn valid_config() -> RelayConfig {
            RelayConfig {
                relay_id: parse_relay_id_arg("relay-eu-1").expect("relay id should parse"),
                verifier_key_path: "/tmp/rustynet-relay-verifier.pub".to_string(),
                replay_store_path: "/tmp/rustynet-relay-replay.store".to_string(),
                ..RelayConfig::default()
            }
        }

        fn reviewed_relay_service_snapshot() -> WindowsRelayServiceHardeningSnapshot {
            WindowsRelayServiceHardeningSnapshot {
                schema_version: 1,
                service_name: super::DEFAULT_WINDOWS_RELAY_SERVICE_NAME.to_string(),
                binary_image_path: format!(
                    "\"{}\\{}\" --windows-service --env-file {}\\relay.env",
                    super::DEFAULT_WINDOWS_INSTALL_ROOT,
                    super::DEFAULT_WINDOWS_RELAY_BINARY_FILE_NAME,
                    super::DEFAULT_WINDOWS_RELAY_ROOT
                ),
                binary_image_argv: vec![
                    format!(
                        "{}\\{}",
                        super::DEFAULT_WINDOWS_INSTALL_ROOT,
                        super::DEFAULT_WINDOWS_RELAY_BINARY_FILE_NAME
                    ),
                    "--windows-service".to_string(),
                    "--env-file".to_string(),
                    format!("{}\\relay.env", super::DEFAULT_WINDOWS_RELAY_ROOT),
                ],
                start_name: "LocalSystem".to_string(),
                service_sid_type: "unrestricted".to_string(),
                start_type: "auto_start".to_string(),
                interactive_process: false,
                failure_action_count: 3,
                binary_path_acl_sddl: "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)".to_string(),
                env_file_acl_sddl: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_string(),
                env_file_parent_acl_sddl: "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".to_string(),
                env_file_runtime_args_valid: true,
                env_file_runtime_args_reason: "valid".to_string(),
                binary_authenticode_trusted: true,
                binary_authenticode_reason: "verified".to_string(),
            }
        }

        #[test]
        fn relay_config_validation_accepts_safe_defaults_with_required_paths() {
            valid_config()
                .validate()
                .expect("valid relay config should pass");
        }

        #[test]
        fn relay_config_validation_rejects_bad_port_ranges() {
            let mut config = valid_config();
            config.port_range_start = 60_000;
            config.port_range_end = 50_000;
            assert!(config.validate().unwrap_err().contains("start"));

            let mut config = valid_config();
            config.port_range_start = 0;
            assert!(config.validate().unwrap_err().contains("port 0"));

            let mut config = valid_config();
            config.port_range_start = 4_500;
            config.port_range_end = 4_500;
            assert!(config.validate().unwrap_err().contains("control bind port"));
        }

        #[test]
        fn relay_config_validation_rejects_zero_capacity_or_cleanup() {
            let mut config = valid_config();
            config.max_sessions_per_node = 0;
            assert!(config.validate().unwrap_err().contains("max-sessions"));

            let mut config = valid_config();
            config.max_total_sessions = 0;
            assert!(
                config
                    .validate()
                    .unwrap_err()
                    .contains("max-total-sessions")
            );

            let mut config = valid_config();
            config.cleanup_interval_secs = 0;
            assert!(config.validate().unwrap_err().contains("cleanup interval"));
        }

        #[test]
        fn relay_config_validation_rejects_total_sessions_above_port_capacity() {
            let mut config = valid_config();
            config.port_range_start = 50_000;
            config.port_range_end = 50_001;
            config.max_total_sessions = 3;

            let err = config
                .validate()
                .expect_err("session cap above port capacity must fail closed");
            assert!(err.contains("available dataplane ports"));
        }

        #[test]
        fn relay_config_validation_rejects_public_or_zero_health_bind() {
            let mut config = valid_config();
            config.health_bind_addr = Some("0.0.0.0:9100".parse().unwrap());
            assert!(config.validate().unwrap_err().contains("loopback"));

            let mut config = valid_config();
            config.health_bind_addr = Some("127.0.0.1:0".parse().unwrap());
            assert!(config.validate().unwrap_err().contains("port"));
        }

        #[test]
        fn relay_config_validation_accepts_loopback_health_bind() {
            let mut config = valid_config();
            config.health_bind_addr = Some("127.0.0.1:9100".parse().unwrap());
            config
                .validate()
                .expect("loopback health bind should be accepted");
        }

        #[test]
        fn parse_args_from_parses_loopback_health_bind() {
            let config = super::parse_args_from(
                [
                    "rustynet-relay",
                    "--relay-id",
                    "relay-eu-1",
                    "--verifier-key",
                    "/tmp/rustynet-relay-verifier.pub",
                    "--replay-store",
                    "/tmp/rustynet-relay-replay.store",
                    "--max-total-sessions",
                    "32",
                    "--health-bind",
                    "127.0.0.1:9100",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .expect("health bind args should parse");
            assert_eq!(
                config.health_bind_addr,
                Some("127.0.0.1:9100".parse().unwrap())
            );
            assert_eq!(config.max_total_sessions, 32);
        }

        #[test]
        fn parse_args_from_rejects_public_health_bind() {
            let err = super::parse_args_from(
                [
                    "rustynet-relay",
                    "--relay-id",
                    "relay-eu-1",
                    "--verifier-key",
                    "/tmp/rustynet-relay-verifier.pub",
                    "--replay-store",
                    "/tmp/rustynet-relay-replay.store",
                    "--health-bind",
                    "0.0.0.0:9100",
                ]
                .into_iter()
                .map(str::to_string),
            )
            .expect_err("public health bind args should fail closed");
            assert!(err.contains("loopback"));
        }

        #[test]
        fn relay_windows_service_entry_requires_env_file_and_rejects_inline_flags() {
            let err = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "--windows-service".to_string(),
            ])
            .expect_err("service mode without env file must fail closed");
            assert!(err.contains("--env-file"));

            let selection = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "--windows-service".to_string(),
                "--env-file".to_string(),
                "/tmp/rustynet-relay.env".to_string(),
                "--service-name".to_string(),
                "RustyNetRelayTest".to_string(),
            ])
            .expect("service mode should parse");
            assert_eq!(
                selection,
                RelayHostEntrySelection::WindowsService(WindowsRelayServiceOptions {
                    service_name: "RustyNetRelayTest".to_string(),
                    env_file: PathBuf::from("/tmp/rustynet-relay.env"),
                })
            );

            let err = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "--windows-service".to_string(),
                "--env-file".to_string(),
                "/tmp/rustynet-relay.env".to_string(),
                "--bind".to_string(),
                "0.0.0.0:4500".to_string(),
            ])
            .expect_err("service mode must reject inline relay flags");
            assert!(err.contains("does not accept inline relay flags"));
        }

        #[test]
        fn relay_windows_service_env_file_parses_json_args_and_rejects_duplicates() {
            let dir = restricted_temp_dir("relay-service-env");
            let env_path = dir.join("relay.env");
            fs::write(
                &env_path,
                "RUSTYNET_RELAY_ARGS_JSON=[\"--relay-id\",\"relay-eu-1\",\"--verifier-key\",\"/tmp/control.pub\",\"--replay-store\",\"/tmp/replay.store\"]\n",
            )
            .expect("env file should be written");
            let args = load_windows_relay_service_args(&env_path)
                .expect("relay service env args should parse");
            assert_eq!(args[0], "--relay-id");
            assert_eq!(args[1], "relay-eu-1");

            fs::write(
                &env_path,
                "RUSTYNET_RELAY_ARGS_JSON=[]\nRUSTYNET_RELAY_ARGS_JSON=[]\n",
            )
            .expect("env file should be rewritten");
            let err = load_windows_relay_service_args(&env_path)
                .expect_err("duplicate env keys must fail closed");
            assert!(err.contains("duplicate Windows relay service env-file key"));

            fs::remove_dir_all(dir).expect("test dir should be removed");
        }

        #[test]
        fn relay_windows_service_runtime_args_require_reviewed_runtime_paths() {
            let args = vec![
                "--relay-id".to_string(),
                "relay-eu-1".to_string(),
                "--verifier-key".to_string(),
                r"C:\ProgramData\RustyNet\relay\relay-verifier.key".to_string(),
                "--replay-store".to_string(),
                r"C:\ProgramData\RustyNet\relay\relay-replay.nonces".to_string(),
            ];
            super::validate_windows_relay_service_runtime_args(&args)
                .expect("reviewed relay runtime paths should pass");

            let mut outside_root = args.clone();
            outside_root[3] = r"C:\Temp\relay-verifier.key".to_string();
            let err = super::validate_windows_relay_service_runtime_args(&outside_root)
                .expect_err("verifier key outside reviewed root must fail closed");
            assert!(err.contains("Windows relay verifier key"));
            assert!(err.contains("reviewed relay runtime root"));

            let mut linux_path = args.clone();
            linux_path[5] = "/var/lib/rustynet/relay-replay.nonces".to_string();
            let err = super::validate_windows_relay_service_runtime_args(&linux_path)
                .expect_err("Linux runtime path must fail closed in Windows service mode");
            assert!(err.contains("Linux runtime roots"));

            let mut duplicate = args.clone();
            duplicate.extend([
                "--replay-store".to_string(),
                r"C:\ProgramData\RustyNet\relay\other.nonces".to_string(),
            ]);
            let err = super::validate_windows_relay_service_runtime_args(&duplicate)
                .expect_err("duplicate runtime path flag must fail closed");
            assert!(err.contains("--replay-store exactly once"));
        }

        #[test]
        fn relay_windows_service_runtime_args_reject_ambiguous_or_side_effect_flags() {
            let args = vec![
                "--relay-id".to_string(),
                "relay-eu-1".to_string(),
                "--verifier-key".to_string(),
                r"C:\ProgramData\RustyNet\relay\relay-verifier.key".to_string(),
                "--replay-store".to_string(),
                r"C:\ProgramData\RustyNet\relay\relay-replay.nonces".to_string(),
                "--health-bind".to_string(),
                "127.0.0.1:9100".to_string(),
                "--port-range".to_string(),
                "50000-59999".to_string(),
                "--max-total-sessions".to_string(),
                "4096".to_string(),
            ];
            super::validate_windows_relay_service_runtime_args(&args)
                .expect("reviewed optional runtime args should validate");

            let mut help = args.clone();
            help.push("--help".to_string());
            let err = super::validate_windows_relay_service_runtime_args(&help)
                .expect_err("help flag must fail closed in service runtime args");
            assert!(err.contains("--help"));

            let mut unknown = args.clone();
            unknown.extend(["--unknown".to_string(), "value".to_string()]);
            let err = super::validate_windows_relay_service_runtime_args(&unknown)
                .expect_err("unknown runtime flags must fail closed");
            assert!(err.contains("unsupported argument"));

            let mut public_health = args.clone();
            let health_value = public_health
                .iter_mut()
                .find(|arg| arg.as_str() == "127.0.0.1:9100")
                .expect("health bind value should exist");
            *health_value = "0.0.0.0:9100".to_string();
            let err = super::validate_windows_relay_service_runtime_args(&public_health)
                .expect_err("public health bind must fail closed");
            assert!(err.contains("--health-bind"));

            let mut duplicate_optional = args.clone();
            duplicate_optional.extend(["--bind".to_string(), "0.0.0.0:4500".to_string()]);
            duplicate_optional.extend(["--bind".to_string(), "0.0.0.0:4501".to_string()]);
            let err = super::validate_windows_relay_service_runtime_args(&duplicate_optional)
                .expect_err("duplicate optional flags must fail closed");
            assert!(err.contains("--bind at most once"));
        }

        #[test]
        fn relay_windows_service_runtime_acl_requires_hardened_file_and_parent() {
            super::validate_windows_relay_service_runtime_acl_sddl(
                "Windows relay replay store",
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
            )
            .expect("reviewed runtime file and parent ACLs should validate");

            let err = super::validate_windows_relay_service_runtime_acl_sddl(
                "Windows relay replay store",
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)",
            )
            .expect_err("broad runtime parent ACL must fail closed");
            assert!(err.contains("Windows relay replay store parent"));
            assert!(err.contains("broader-than-reviewed Windows principal"));
        }

        #[test]
        fn relay_windows_service_path_normalization_rejects_unsafe_windows_shapes() {
            let normalized = super::normalize_windows_relay_service_path(Path::new(
                r"C:/ProgramData/RustyNet/relay/relay.env",
            ))
            .expect("reviewed absolute path should normalize");
            assert_eq!(normalized, r"C:\ProgramData\RustyNet\relay\relay.env");
            assert!(super::windows_relay_service_path_under_reviewed_root(
                normalized.as_str()
            ));
            assert!(super::windows_relay_service_path_under_reviewed_root(
                r"\\?\C:\ProgramData\RustyNet\relay\relay.env"
            ));
            assert!(!super::windows_relay_service_path_under_reviewed_root(
                r"C:\ProgramData\RustyNet\relay2\relay.env"
            ));

            for path in [
                r"\\.\pipe\rustynet-relay",
                r"\\server\share\rustynet-relay.env",
                r"C:\ProgramData\RustyNet\relay\..\secrets\relay.env",
                r"/var/lib/rustynet/relay.env",
                r"relay.env",
            ] {
                assert!(
                    super::normalize_windows_relay_service_path(Path::new(path)).is_err(),
                    "unsafe Windows relay service path should reject: {path}"
                );
            }
        }

        #[test]
        fn relay_windows_service_acl_evaluator_requires_hardened_sddl() {
            super::evaluate_windows_relay_service_acl_sddl(
                "Windows relay service env-file",
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                true,
            )
            .expect("reviewed relay service env-file ACL should validate");

            let service_sid_owner = "O:S-1-5-80-1234G:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
            super::evaluate_windows_relay_service_acl_sddl(
                "Windows relay service env-file",
                service_sid_owner,
                true,
            )
            .expect("service SID owner should validate");

            for (sddl, expected) in [
                ("O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)", "protected DACL"),
                (
                    "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)",
                    "broader-than-reviewed Windows principal",
                ),
                ("O:BAG:BAD:P(A;;FA;;;BA)", "LocalSystem"),
                ("O:BAG:BAD:P(A;;FA;;;SY)", "Builtin Administrators"),
                (
                    "O:WDG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
                    "ACL owner must be LocalSystem",
                ),
                ("G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)", "owner entry"),
                ("O:BAG:BA", "Windows DACL"),
            ] {
                let err = super::evaluate_windows_relay_service_acl_sddl(
                    "Windows relay service env-file",
                    sddl,
                    true,
                )
                .expect_err("unsafe relay service env-file ACL must fail closed");
                assert!(err.contains(expected), "unexpected error for {sddl}: {err}");
            }
        }

        #[test]
        fn relay_windows_service_hardening_check_entry_parses_flags() {
            let selection = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "windows-service-hardening-check".to_string(),
            ])
            .expect("service hardening check should parse");
            assert_eq!(
                selection,
                RelayHostEntrySelection::WindowsServiceHardeningCheck {
                    fail_on_drift: true,
                }
            );

            let selection = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "windows-service-hardening-check".to_string(),
                "--no-fail-on-drift".to_string(),
            ])
            .expect("service hardening check no-fail flag should parse");
            assert_eq!(
                selection,
                RelayHostEntrySelection::WindowsServiceHardeningCheck {
                    fail_on_drift: false,
                }
            );

            let err = select_relay_host_entry(&[
                "rustynet-relay".to_string(),
                "windows-service-hardening-check".to_string(),
                "--bogus".to_string(),
            ])
            .expect_err("unknown service hardening flag must fail closed");
            assert!(err.contains("unknown windows-service-hardening-check argument"));
        }

        #[test]
        fn relay_windows_service_hardening_evaluator_accepts_reviewed_snapshot() {
            evaluate_windows_relay_service_hardening(&reviewed_relay_service_snapshot())
                .expect("reviewed relay service snapshot should validate");
        }

        #[test]
        fn relay_windows_service_hardening_evaluator_accepts_service_account() {
            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot.start_name = r"NT SERVICE\RustyNetRelay".to_string();
            snapshot.service_sid_type = "restricted".to_string();
            evaluate_windows_relay_service_hardening(&snapshot)
                .expect("reviewed NT SERVICE account should validate");
        }

        #[test]
        fn relay_windows_service_hardening_evaluator_rejects_drift() {
            for mutate in [
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| snapshot.schema_version = 99,
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.service_name = "RustyNet".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_image_argv[0] = r"C:\Tools\rustynet-relay.exe".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_image_argv[0] =
                        format!("{}\\rustynetd.exe", super::DEFAULT_WINDOWS_INSTALL_ROOT)
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot
                        .binary_image_argv
                        .retain(|arg| arg != "--windows-service")
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_image_argv.retain(|arg| arg != "--env-file")
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot
                        .binary_image_argv
                        .push("--verifier-key".to_string())
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.start_name = r".\Administrator".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.service_sid_type = "none".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.interactive_process = true
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.failure_action_count = 0
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_path_acl_sddl = String::new()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_path_acl_sddl = "O:BAG:BAD:(A;;FA;;;WD)".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.env_file_acl_sddl = String::new()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.env_file_acl_sddl =
                        "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.env_file_parent_acl_sddl = String::new()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.env_file_parent_acl_sddl =
                        "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)".to_string()
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.env_file_runtime_args_valid = false;
                    snapshot.env_file_runtime_args_reason =
                        "Windows relay service runtime args must include --replay-store"
                            .to_string();
                },
                |snapshot: &mut WindowsRelayServiceHardeningSnapshot| {
                    snapshot.binary_authenticode_trusted = false;
                    snapshot.binary_authenticode_reason = "TRUST_E_NOSIGNATURE".to_string();
                },
            ] {
                let mut snapshot = reviewed_relay_service_snapshot();
                mutate(&mut snapshot);
                let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                    .expect_err("relay service hardening drift must fail closed");
                assert!(!reasons.is_empty());
            }
        }

        #[test]
        fn relay_windows_service_hardening_rejects_env_file_outside_reviewed_root() {
            let mut snapshot = reviewed_relay_service_snapshot();
            let env_arg = snapshot
                .binary_image_argv
                .iter_mut()
                .find(|arg| arg.ends_with("relay.env"))
                .expect("env-file arg should exist");
            *env_arg = r"C:\ProgramData\RustyNet\config\relay.env".to_string();
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("env-file outside reviewed relay root must fail");
            assert!(
                reasons.iter().any(|reason| reason.contains("env-file")),
                "unexpected reasons: {reasons:?}"
            );
        }

        #[test]
        fn relay_windows_service_hardening_rejects_env_file_acl_and_runtime_arg_drift() {
            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot.env_file_acl_sddl =
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;WD)".to_string();
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("broad env-file ACL must fail closed");
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason.contains("env-file ACL drift")),
                "unexpected reasons: {reasons:?}"
            );

            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot.env_file_parent_acl_sddl =
                "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)".to_string();
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("broad env-file parent ACL must fail closed");
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason.contains("env-file parent ACL drift")),
                "unexpected reasons: {reasons:?}"
            );

            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot.env_file_runtime_args_valid = false;
            snapshot.env_file_runtime_args_reason =
                "Windows relay verifier key must stay under reviewed relay runtime root"
                    .to_string();
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("runtime args drift must fail closed");
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason.contains("env-file runtime args are invalid")),
                "unexpected reasons: {reasons:?}"
            );
        }

        #[test]
        fn relay_windows_service_hardening_rejects_ambiguous_service_argv() {
            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot.binary_image_argv.extend([
                "--env-file".to_string(),
                format!("{}\\second.env", super::DEFAULT_WINDOWS_RELAY_ROOT),
            ]);
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("duplicate env-file flags must fail closed");
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason.contains("exactly one --env-file")),
                "unexpected reasons: {reasons:?}"
            );

            let mut snapshot = reviewed_relay_service_snapshot();
            snapshot
                .binary_image_argv
                .extend(["--service-name".to_string(), "OtherRelay".to_string()]);
            let reasons = evaluate_windows_relay_service_hardening(&snapshot)
                .expect_err("wrong service-name flag must fail closed");
            assert!(
                reasons
                    .iter()
                    .any(|reason| reason.contains("--service-name must be RustyNetRelay")),
                "unexpected reasons: {reasons:?}"
            );
        }

        #[test]
        fn relay_windows_service_hardening_report_serializes() {
            let report =
                build_windows_relay_service_hardening_report(reviewed_relay_service_snapshot());
            assert!(report.overall_ok);
            let json = serde_json::to_value(&report).expect("report should serialize");
            assert_eq!(json["schema_version"], 1);
            assert_eq!(json["overall_ok"], true);
            assert!(json["snapshot"].is_object());
        }

        #[test]
        fn relay_windows_image_path_parser_handles_quoted_executable() {
            let argv = parse_windows_image_path_argv(
                r#""C:\Program Files\RustyNet\rustynet-relay.exe" --windows-service --env-file C:\ProgramData\RustyNet\relay\relay.env"#,
            );
            assert_eq!(
                argv,
                vec![
                    r"C:\Program Files\RustyNet\rustynet-relay.exe".to_string(),
                    "--windows-service".to_string(),
                    "--env-file".to_string(),
                    r"C:\ProgramData\RustyNet\relay\relay.env".to_string(),
                ]
            );
            assert!(parse_windows_image_path_argv("   ").is_empty());
        }

        #[test]
        fn relay_windows_image_path_parser_returns_empty_for_empty_or_whitespace_input() {
            // Both empty string and pure whitespace must produce an empty argv
            // so the hardening checker rejects rather than treating any flag
            // present as the trusted runtime args.
            assert!(parse_windows_image_path_argv("").is_empty());
            assert!(parse_windows_image_path_argv("\t \r\n").is_empty());
        }

        #[test]
        fn relay_windows_image_path_parser_handles_unquoted_path_without_spaces() {
            // Unquoted path with arguments — the SCM stores the binary unquoted
            // when there are no spaces in the path.  Each whitespace-separated
            // token must come back as its own argv element.
            let argv = parse_windows_image_path_argv(
                r"C:\RustyNet\rustynet-relay.exe --windows-service --env-file C:\ProgramData\RustyNet\relay\relay.env",
            );
            assert_eq!(
                argv,
                vec![
                    r"C:\RustyNet\rustynet-relay.exe".to_string(),
                    "--windows-service".to_string(),
                    "--env-file".to_string(),
                    r"C:\ProgramData\RustyNet\relay\relay.env".to_string(),
                ]
            );
        }

        #[test]
        fn relay_windows_image_path_parser_collapses_runs_of_whitespace() {
            // Multiple spaces between tokens (or tabs / mixed whitespace) must
            // collapse into a single delimiter, matching Windows
            // CommandLineToArgvW behaviour.  This prevents an attacker from
            // crafting a service ImagePath with extra whitespace that confuses
            // a naive parser into producing a different argv than the
            // hardening checker expects.
            let argv = parse_windows_image_path_argv(
                "C:\\rustynet-relay.exe   --windows-service \t --env-file\t\tC:\\relay.env",
            );
            assert_eq!(
                argv,
                vec![
                    r"C:\rustynet-relay.exe".to_string(),
                    "--windows-service".to_string(),
                    "--env-file".to_string(),
                    r"C:\relay.env".to_string(),
                ]
            );
        }

        #[test]
        fn relay_windows_image_path_parser_preserves_whitespace_inside_quotes() {
            // Whitespace inside quoted segments must stay part of the argv
            // token so the hardening checker compares against the correct
            // path.  Mismatch with the canonical reviewed runtime path must
            // still fail closed downstream — but that is a different layer.
            let argv = parse_windows_image_path_argv(
                r#""C:\My\Strange  Path\rustynet-relay.exe" --env-file "C:\With Spaces\relay.env""#,
            );
            assert_eq!(
                argv,
                vec![
                    r"C:\My\Strange  Path\rustynet-relay.exe".to_string(),
                    "--env-file".to_string(),
                    r"C:\With Spaces\relay.env".to_string(),
                ]
            );
        }

        #[test]
        fn relay_windows_image_path_parser_joins_concatenated_quoted_and_unquoted_segments() {
            // Per Windows CommandLineToArgvW behaviour, a quoted segment
            // adjacent to an unquoted segment is part of the same argv token.
            // For example "abc"def becomes the single token "abcdef".
            // We do not need to support this in practice, but we must produce
            // a single token (never silently split or drop characters) so the
            // hardening comparison fails closed if the SCM ImagePath ever
            // contains such a value.
            let argv = parse_windows_image_path_argv(r#"abc"def"ghi --flag"#);
            assert_eq!(argv, vec!["abcdefghi".to_string(), "--flag".to_string()]);
        }

        #[cfg(not(windows))]
        #[test]
        fn relay_windows_service_hardening_collector_fails_closed_off_windows() {
            let err = collect_windows_relay_service_hardening_snapshot()
                .expect_err("off-Windows collector must fail closed");
            assert!(err.contains("only available on Windows"));
        }

        #[test]
        fn relay_config_validation_requires_security_paths() {
            let mut config = valid_config();
            config.verifier_key_path.clear();
            assert!(config.validate().unwrap_err().contains("verifier-key"));

            let mut config = valid_config();
            config.replay_store_path.clear();
            assert!(config.validate().unwrap_err().contains("replay-store"));
        }

        #[test]
        fn relay_config_validation_requires_absolute_security_paths() {
            let mut config = valid_config();
            config.verifier_key_path = "control.pub".to_string();
            assert!(config.validate().unwrap_err().contains("absolute"));

            let mut config = valid_config();
            config.replay_store_path = "relay.replay".to_string();
            assert!(config.validate().unwrap_err().contains("absolute"));
        }

        fn restricted_temp_dir(test_name: &str) -> PathBuf {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!(
                "rustynet-relay-{test_name}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("test dir should be created");
            #[cfg(unix)]
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("test dir permissions should be restricted");
            dir
        }

        fn write_verifier_key(path: &std::path::Path) {
            let signing_key = SigningKey::from_bytes(&[7u8; 32]);
            fs::write(path, signing_key.verifying_key().to_bytes())
                .expect("verifier key should be written");
            #[cfg(unix)]
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("verifier key permissions should be restricted");
        }

        #[test]
        fn verifier_key_loader_accepts_restricted_regular_file() {
            let dir = restricted_temp_dir("verifier-ok");
            let key_path = dir.join("control.pub");
            write_verifier_key(&key_path);

            load_control_verifier_key(key_path.to_str().expect("test path should be utf8"))
                .expect("restricted verifier key should load");

            fs::remove_dir_all(dir).expect("test dir should be removed");
        }

        #[test]
        #[cfg(unix)]
        fn verifier_key_loader_rejects_broad_file_permissions() {
            let dir = restricted_temp_dir("verifier-broad-file");
            let key_path = dir.join("control.pub");
            write_verifier_key(&key_path);
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o622))
                .expect("verifier key permissions should be widened");

            let err =
                load_control_verifier_key(key_path.to_str().expect("test path should be utf8"))
                    .expect_err("broad verifier key permissions must fail closed");
            assert!(err.contains("permissions too broad"));

            fs::remove_dir_all(dir).expect("test dir should be removed");
        }

        #[test]
        #[cfg(unix)]
        fn verifier_key_loader_rejects_broad_parent_permissions() {
            let dir = restricted_temp_dir("verifier-broad-parent");
            let key_path = dir.join("control.pub");
            write_verifier_key(&key_path);
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o722))
                .expect("verifier key parent permissions should be widened");

            let err =
                load_control_verifier_key(key_path.to_str().expect("test path should be utf8"))
                    .expect_err("broad verifier key parent permissions must fail closed");
            assert!(err.contains("parent permissions too broad"));

            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
                .expect("test dir permissions should be restored");
            fs::remove_dir_all(dir).expect("test dir should be removed");
        }

        #[test]
        fn relay_reject_wire_reason_is_generic() {
            let reject = serialize_relay_reject();
            assert_eq!(reject[0], RELAY_REJECT_MSG_TYPE);
            assert_eq!(reject.len(), 1 + RELAY_REJECT_GENERIC_REASON.len());
            assert_eq!(&reject[1..], RELAY_REJECT_GENERIC_REASON.as_bytes());
            assert!(!String::from_utf8_lossy(&reject).contains("InvalidToken"));
            assert!(!String::from_utf8_lossy(&reject).contains("ReplayedNonce"));
            assert!(!String::from_utf8_lossy(&reject).contains("RateLimitExceeded"));
        }

        #[test]
        fn health_renderers_expose_counts_without_secrets() {
            let snapshot = HealthSnapshot {
                active_sessions: 2,
                allocated_ports: 2,
                max_sessions_per_node: 8,
                max_total_sessions: 32,
            };

            let health = render_health_json(snapshot);
            assert!(health.contains("\"status\":\"ok\""));
            assert!(health.contains("\"active_sessions\":2"));
            assert!(health.contains("\"max_total_sessions\":32"));
            assert!(!health.contains("verifier"));
            assert!(!health.contains("replay"));
            assert!(!health.contains("token"));
            assert!(!health.contains("relay_id"));

            let metrics = render_metrics(snapshot);
            assert!(metrics.contains("rustynet_relay_active_sessions 2"));
            assert!(metrics.contains("rustynet_relay_allocated_ports 2"));
            assert!(metrics.contains("rustynet_relay_max_total_sessions 32"));
            assert!(!metrics.contains("verifier"));
            assert!(!metrics.contains("replay"));
            assert!(!metrics.contains("token"));
            assert!(!metrics.contains("relay_id"));
        }

        #[test]
        fn health_request_path_accepts_get_only() {
            assert_eq!(
                http_request_path(b"GET /healthz HTTP/1.1\r\nhost: localhost\r\n\r\n"),
                Some("/healthz")
            );
            assert_eq!(
                http_request_path(b"POST /healthz HTTP/1.1\r\nhost: localhost\r\n\r\n"),
                None
            );
        }

        #[tokio::test]
        async fn health_listener_rejects_public_bind_before_listen() {
            let err = bind_health_listener("0.0.0.0:9100".parse().unwrap())
                .await
                .expect_err("public health bind must fail closed");
            assert!(err.contains("loopback"));
        }

        #[tokio::test]
        async fn health_endpoint_serves_loopback_only_aggregate_state() {
            let listener = match bind_health_listener("127.0.0.1:0".parse().unwrap()).await {
                Ok(listener) => listener,
                Err(err)
                    if err.contains("Operation not permitted")
                        || err.contains("Permission denied") =>
                {
                    eprintln!("skipping loopback health endpoint socket test: {err}");
                    return;
                }
                Err(err) => panic!("loopback health listener should bind: {err}"),
            };
            let health_addr = listener.local_addr().expect("health addr should exist");
            let signing_key = SigningKey::from_bytes(&[9u8; 32]);
            let transport = Arc::new(RwLock::new(RelayTransport::new(
                [1u8; 16],
                signing_key.verifying_key(),
                8,
                90,
            )));
            let allocated_sockets = Arc::new(RwLock::new(HashMap::<u16, (UdpSocket, _)>::new()));

            let health_task = tokio::spawn(serve_health_endpoint(
                listener,
                Arc::clone(&transport),
                Arc::clone(&allocated_sockets),
                8,
                4096,
            ));

            let health_response = request_health_path(health_addr, "/healthz").await;
            assert!(health_response.starts_with("HTTP/1.1 200 OK"));
            assert!(health_response.contains("\"status\":\"ok\""));
            assert!(health_response.contains("\"active_sessions\":0"));
            assert!(!health_response.contains("token"));
            assert!(!health_response.contains("relay_id"));
            assert!(!health_response.contains("verifier"));
            assert!(!health_response.contains("replay"));

            let metrics_response = request_health_path(health_addr, "/metrics").await;
            assert!(metrics_response.starts_with("HTTP/1.1 200 OK"));
            assert!(metrics_response.contains("rustynet_relay_active_sessions 0"));
            assert!(metrics_response.contains("rustynet_relay_max_sessions_per_node 8"));
            assert!(metrics_response.contains("rustynet_relay_max_total_sessions 4096"));
            assert!(!metrics_response.contains("token"));
            assert!(!metrics_response.contains("relay_id"));
            assert!(!metrics_response.contains("verifier"));
            assert!(!metrics_response.contains("replay"));

            health_task.abort();
        }

        async fn request_health_path(addr: std::net::SocketAddr, path: &str) -> String {
            let mut stream = TcpStream::connect(addr)
                .await
                .expect("health endpoint should accept connection");
            let request = format!("GET {path} HTTP/1.1\r\nhost: localhost\r\n\r\n");
            stream
                .write_all(request.as_bytes())
                .await
                .expect("health request should write");
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("health response should read");
            response
        }

        #[test]
        fn pre_auth_hello_limiter_blocks_source_ip_flood() {
            let mut limiter = PreAuthHelloLimiter::new(2);
            let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

            assert!(limiter.check(ip));
            assert!(limiter.check(ip));
            assert!(!limiter.check(ip));
        }

        #[test]
        fn pre_auth_hello_limiter_isolates_source_ips_and_resets() {
            let mut limiter = PreAuthHelloLimiter::new(1);
            let ip_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
            let ip_b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));

            assert!(limiter.check(ip_a));
            assert!(!limiter.check(ip_a));
            assert!(limiter.check(ip_b));

            limiter
                .counts
                .insert(ip_a, (1, Instant::now() - Duration::from_secs(2)));
            assert!(limiter.check(ip_a));
        }

        #[test]
        fn pre_auth_hello_limiter_bounds_source_ip_table() {
            let mut limiter = PreAuthHelloLimiter::new(1);
            for index in 0..MAX_PRE_AUTH_HELLO_SOURCE_IPS {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    10,
                    ((index >> 16) & 0xff) as u8,
                    ((index >> 8) & 0xff) as u8,
                    (index & 0xff) as u8,
                ));
                assert!(limiter.check(ip));
            }

            assert!(!limiter.check(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30))));
            limiter.counts.values_mut().for_each(|(_, window_start)| {
                *window_start = Instant::now() - Duration::from_secs(2);
            });
            assert!(limiter.check(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 30))));
        }
    }
}

#[cfg(feature = "daemon")]
#[tokio::main]
async fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match daemon::select_relay_host_entry(&args) {
        Ok(daemon::RelayHostEntrySelection::RelayArgs(args)) => {
            daemon::run_relay_from_args(args).await
        }
        Ok(daemon::RelayHostEntrySelection::WindowsService(options)) => {
            daemon::run_windows_relay_service_host(options)
        }
        Ok(daemon::RelayHostEntrySelection::WindowsServiceHardeningCheck { fail_on_drift }) => {
            daemon::run_windows_relay_service_hardening_check(fail_on_drift)
        }
        Err(err) => Err(err),
    };

    if let Err(e) = result {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "daemon"))]
fn main() {
    eprintln!("rustynet-relay binary requires the `daemon` feature");
    std::process::exit(1);
}
