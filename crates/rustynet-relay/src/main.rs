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
//!                --port-range 50000-59999
//! ```

#[cfg(feature = "daemon")]
mod daemon {
    use std::collections::HashMap;
    use std::fs;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use ed25519_dalek::VerifyingKey;
    use subtle::ConstantTimeEq;
    use tokio::net::UdpSocket;
    use tokio::sync::RwLock;
    use tokio::time::interval;

    use rustynet_relay::session::SessionId;
    use rustynet_relay::transport::{RelayHelloResponse, RelayTransport};

    /// Relay daemon configuration.
    #[derive(Debug, Clone)]
    pub struct RelayConfig {
        /// UDP address to bind the control port.
        pub bind_addr: SocketAddr,
        /// 16-byte relay identifier.
        pub relay_id: [u8; 16],
        /// Path to control-plane verifier public key.
        pub verifier_key_path: String,
        /// Port range for session allocations.
        pub port_range_start: u16,
        pub port_range_end: u16,
        /// Maximum sessions per node.
        pub max_sessions_per_node: usize,
        /// Clock skew tolerance in seconds.
        pub clock_skew_tolerance_secs: u64,
        /// Cleanup interval in seconds.
        pub cleanup_interval_secs: u64,
    }

    impl Default for RelayConfig {
        fn default() -> Self {
            Self {
                bind_addr: "0.0.0.0:4500".parse().unwrap(),
                relay_id: [0; 16],
                verifier_key_path: String::new(),
                port_range_start: 50_000,
                port_range_end: 59_999,
                max_sessions_per_node: 8,
                clock_skew_tolerance_secs: 90,
                cleanup_interval_secs: 10,
            }
        }
    }

    /// Wire format constants matching relay_client.rs
    const RELAY_HELLO_MSG_TYPE: u8 = 0x01;
    const RELAY_HELLO_ACK_MSG_TYPE: u8 = 0x02;
    const RELAY_REJECT_MSG_TYPE: u8 = 0x03;
    const RELAY_KEEPALIVE_MSG_TYPE: u8 = 0x04;

    /// Maps allocated ports to session IDs for ciphertext forwarding.
    struct PortAllocation {
        session_id: SessionId,
    }

    /// Relay daemon state.
    pub struct RelayDaemon {
        config: RelayConfig,
        transport: Arc<RwLock<RelayTransport>>,
        control_socket: UdpSocket,
        /// Allocated port sockets indexed by port number.
        allocated_sockets: Arc<RwLock<HashMap<u16, (UdpSocket, PortAllocation)>>>,
        /// Next port to try allocating.
        next_port: Arc<RwLock<u16>>,
    }

    impl RelayDaemon {
        /// Creates a new relay daemon.
        pub async fn new(config: RelayConfig) -> Result<Self, String> {
            // Load verifier key
            let key_bytes = fs::read(&config.verifier_key_path)
                .map_err(|e| format!("failed to read verifier key: {e}"))?;

            let verifier_key = if key_bytes.len() == 32 {
                VerifyingKey::from_bytes(
                    key_bytes
                        .as_slice()
                        .try_into()
                        .map_err(|_| "invalid key length")?,
                )
                .map_err(|e| format!("invalid verifier key: {e}"))?
            } else {
                return Err(format!(
                    "verifier key must be 32 bytes, got {}",
                    key_bytes.len()
                ));
            };

            // Bind control socket
            let control_socket = UdpSocket::bind(config.bind_addr)
                .await
                .map_err(|e| format!("failed to bind control socket: {e}"))?;

            let transport = RelayTransport::new(
                config.relay_id,
                verifier_key,
                config.max_sessions_per_node,
                config.clock_skew_tolerance_secs,
            );

            Ok(Self {
                config: config.clone(),
                transport: Arc::new(RwLock::new(transport)),
                control_socket,
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

            // Main receive loop on control socket
            let mut buf = [0u8; 65536];

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
                RELAY_HELLO_MSG_TYPE => self.handle_hello(data, from_addr).await,
                _ => Err(format!("unknown message type: {:#02x}", data[0])),
            }
        }

        /// Handles a RelayHello message.
        async fn handle_hello(&self, data: &[u8], from_addr: SocketAddr) -> Result<(), String> {
            let hello = parse_relay_hello(data)?;

            let response = {
                let mut transport = self.transport.write().await;
                transport.handle_hello_from_tuple(hello, from_addr)
            };

            match response {
                RelayHelloResponse::Accepted(ack) => {
                    Self::prune_inactive_allocated_sockets(
                        &self.allocated_sockets,
                        &self.transport,
                    )
                    .await;

                    // Allocate a port for this session
                    let (allocated_port, socket) = self.allocate_port().await?;

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
                    let reject_bytes = serialize_relay_reject(&format!("{reason:?}"));
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
    fn serialize_relay_reject(reason: &str) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + reason.len());
        buf.push(RELAY_REJECT_MSG_TYPE);
        buf.extend_from_slice(reason.as_bytes());
        buf
    }

    /// Parses command-line arguments into RelayConfig.
    pub fn parse_args() -> Result<RelayConfig, String> {
        let args: Vec<String> = std::env::args().collect();
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
                    let id_str = &args[i];
                    // Hash the string to get a 16-byte relay ID
                    use sha2::{Digest, Sha256};
                    let hash = Sha256::digest(id_str.as_bytes());
                    config.relay_id.copy_from_slice(&hash[..16]);
                }
                "--verifier-key" => {
                    i += 1;
                    if i >= args.len() {
                        return Err("--verifier-key requires an argument".to_string());
                    }
                    config.verifier_key_path = args[i].clone();
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
                "--help" | "-h" => {
                    eprintln!(
                        "Usage: rustynet-relay [OPTIONS]\n\n\
                        Options:\n  \
                          --bind <ADDR>              UDP bind address (default: 0.0.0.0:4500)\n  \
                          --relay-id <ID>            Relay identifier string\n  \
                          --verifier-key <PATH>      Path to control verifier public key\n  \
                          --port-range <START-END>   Port range for allocations (default: 50000-59999)\n  \
                          --max-sessions-per-node <N> Max sessions per node (default: 8)\n  \
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

        if config.verifier_key_path.is_empty() {
            return Err("--verifier-key is required".to_string());
        }

        if config.relay_id == [0; 16] {
            return Err("--relay-id is required".to_string());
        }

        Ok(config)
    }
}

#[cfg(feature = "daemon")]
#[tokio::main]
async fn main() {
    use daemon::{RelayDaemon, parse_args};

    let config = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    let daemon = match RelayDaemon::new(config).await {
        Ok(d) => d,
        Err(e) => {
            eprintln!("failed to start relay: {e}");
            std::process::exit(1);
        }
    };

    if let Err(e) = daemon.run().await {
        eprintln!("relay error: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "daemon"))]
fn main() {
    // Fallback for when daemon feature is not enabled - basic selection demo
    use rustynet_relay::{RelayFleet, RelayNode};

    let fleet = RelayFleet {
        nodes: vec![
            RelayNode {
                id: "relay-us-east".to_string(),
                region: "us-east".to_string(),
                healthy: true,
                latency_ms: 20,
            },
            RelayNode {
                id: "relay-us-west".to_string(),
                region: "us-west".to_string(),
                healthy: true,
                latency_ms: 28,
            },
        ],
    };

    match fleet.select_best(Some("us-east")) {
        Some(relay) => println!(
            "rustynet-relay ready: selected={} region={} latency_ms={}",
            relay.id, relay.region, relay.latency_ms
        ),
        None => {
            eprintln!("rustynet-relay startup failed: no healthy relays available");
            std::process::exit(1);
        }
    }
}
