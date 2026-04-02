#![forbid(unsafe_code)]

//! Relay client for daemon-side relay path transport.
//!
//! This module provides the client-side relay session management that enables
//! the daemon to establish authenticated sessions with relay servers and
//! forward encrypted WireGuard packets when direct connectivity is unavailable.
//!
//! # Security model
//!
//! - **Ciphertext-only**: packets are WireGuard-encrypted before relay handoff;
//!   the relay cannot see plaintext.
//! - **Signed tokens**: each session requires a control-plane-issued
//!   [`RelaySessionToken`] with a valid ed25519 signature.
//! - **Fail-closed**: if token issuance, relay connection, or session
//!   establishment fails, the relay path remains unavailable.
//! - **Replay protection**: token nonces prevent replay attacks.
//! - **Session binding**: tokens are bound to specific (node_id, peer_node_id,
//!   relay_id) tuples.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rustynet_backend_api::{NodeId, SocketEndpoint};
use rustynet_control::RelaySessionToken;
use rustynet_relay::{RelayHello, RelayHelloAck, SessionId};

/// Configuration for relay client behavior.
#[derive(Debug, Clone)]
pub struct RelayClientConfig {
    /// Maximum time to wait for relay session establishment.
    pub session_timeout: Duration,
    /// How often to send keepalive packets to maintain relay NAT bindings.
    pub keepalive_interval: Duration,
    /// Maximum number of concurrent relay sessions per peer.
    pub max_sessions_per_peer: usize,
    /// Socket receive timeout for relay operations.
    pub recv_timeout: Duration,
    /// Optional local port hint for an authoritative relay transport socket.
    ///
    /// This value is configuration only; it does not establish authority by
    /// itself. A separate daemon-owned socket bound to the same local port is
    /// not equivalent to the backend's authoritative peer-traffic transport
    /// socket and must not be treated as such.
    pub local_port: Option<u16>,
}

impl Default for RelayClientConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(25),
            max_sessions_per_peer: 2,
            recv_timeout: Duration::from_secs(5),
            local_port: None,
        }
    }
}

/// Represents an established relay session from the client perspective.
#[derive(Debug)]
pub struct RelayClientSession {
    /// The session ID assigned by the relay.
    pub session_id: SessionId,
    /// The relay server address.
    pub relay_addr: SocketAddr,
    /// The allocated port on the relay for this session.
    pub allocated_port: u16,
    /// The peer this session connects to.
    pub peer_node_id: NodeId,
    /// When the session was established.
    pub established_at: Instant,
    /// When we last sent or received a packet.
    pub last_activity: Instant,
    /// The relay ID this session is bound to.
    pub relay_id: [u8; 16],
    /// When the session token expires according to the control-plane signer.
    pub token_expires_at_unix: u64,
}

impl RelayClientSession {
    /// Returns the effective endpoint to use for this relay path.
    pub fn effective_endpoint(&self) -> SocketEndpoint {
        SocketEndpoint {
            addr: self.relay_addr.ip(),
            port: self.allocated_port,
        }
    }

    /// Returns true if the session has been idle too long.
    pub fn is_idle(&self, idle_timeout: Duration) -> bool {
        self.last_activity.elapsed() > idle_timeout
    }

    /// Returns true if the signed relay session has expired.
    pub fn is_expired(&self, now_unix: u64) -> bool {
        self.token_expires_at_unix <= now_unix
    }

    /// Returns true when the session token must be refreshed to avoid expiry.
    pub fn token_refresh_due(&self, now_unix: u64, refresh_margin_secs: u64) -> bool {
        self.token_expires_at_unix <= now_unix.saturating_add(refresh_margin_secs)
    }

    /// Returns true when the selected backend endpoint is the live relay
    /// endpoint allocated for this session.
    pub fn matches_selected_endpoint(&self, endpoint: SocketEndpoint) -> bool {
        self.effective_endpoint() == endpoint
    }
}

/// Errors that can occur during relay client operations.
#[derive(Debug)]
pub enum RelayClientError {
    /// Socket I/O error.
    Io(io::Error),
    /// Backend authoritative transport operation failed.
    AuthoritativeTransport(String),
    /// Token signing failed.
    TokenSigning(String),
    /// Session establishment was rejected by the relay.
    SessionRejected(String),
    /// Session establishment timed out.
    Timeout,
    /// No suitable relay available.
    NoRelayAvailable,
    /// Session capacity exceeded.
    CapacityExceeded,
    /// Relay returned an invalid response.
    InvalidResponse(String),
}

impl std::fmt::Display for RelayClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "relay I/O error: {err}"),
            Self::AuthoritativeTransport(msg) => {
                write!(f, "relay authoritative transport error: {msg}")
            }
            Self::TokenSigning(msg) => write!(f, "token signing failed: {msg}"),
            Self::SessionRejected(reason) => write!(f, "relay session rejected: {reason}"),
            Self::Timeout => f.write_str("relay session establishment timed out"),
            Self::NoRelayAvailable => f.write_str("no relay available for path"),
            Self::CapacityExceeded => f.write_str("relay session capacity exceeded"),
            Self::InvalidResponse(msg) => write!(f, "invalid relay response: {msg}"),
        }
    }
}

impl std::error::Error for RelayClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for RelayClientError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Manages relay client sessions for the daemon.
///
/// The `RelayClient` handles session establishment, keepalive, and cleanup
/// for all active relay paths. It integrates with the Phase10Controller to
/// provide relay endpoints when direct connectivity fails.
pub struct RelayClient {
    /// Our node ID.
    node_id: NodeId,
    /// The signing key used to create relay session tokens.
    signing_key: Arc<SigningKey>,
    /// Active sessions indexed by peer node ID.
    sessions: HashMap<NodeId, RelayClientSession>,
    /// Configuration for relay behavior.
    config: RelayClientConfig,
    /// The UDP socket used for relay communication.
    socket: Option<UdpSocket>,
    #[cfg(test)]
    scripted_establishments: VecDeque<Result<u16, RelayClientError>>,
    #[cfg(test)]
    bound_override: bool,
}

impl RelayClient {
    /// Creates a new relay client.
    pub fn new(node_id: NodeId, signing_key: Arc<SigningKey>, config: RelayClientConfig) -> Self {
        Self {
            node_id,
            signing_key,
            sessions: HashMap::new(),
            config,
            socket: None,
            #[cfg(test)]
            scripted_establishments: VecDeque::new(),
            #[cfg(test)]
            bound_override: false,
        }
    }

    /// Returns the configured local port for the relay client socket, if any.
    pub fn local_port(&self) -> Option<u16> {
        self.config.local_port
    }

    /// Binds the relay client to a local socket.
    ///
    /// This must be called only with an authoritative transport socket owned by
    /// the selected backend transport path, or by a test harness explicitly
    /// modeling that authority. A second socket bound to the same local port is
    /// not sufficient.
    pub fn bind(&mut self, socket: UdpSocket) -> Result<(), RelayClientError> {
        socket.set_read_timeout(Some(self.config.recv_timeout))?;
        socket.set_write_timeout(Some(self.config.recv_timeout))?;
        self.socket = Some(socket);
        Ok(())
    }

    /// Returns true when the relay client has an authoritative transport socket
    /// bound for live relay control traffic.
    pub fn is_bound(&self) -> bool {
        self.socket.is_some() || {
            #[cfg(test)]
            {
                self.bound_override
            }
            #[cfg(not(test))]
            {
                false
            }
        }
    }

    /// Establishes a relay session for the given peer.
    ///
    /// This creates a signed session token, sends it to the relay server,
    /// and waits for acknowledgment. On success, the relay path becomes
    /// available for packet forwarding.
    ///
    /// # Arguments
    ///
    /// * `peer_node_id` - The peer to establish a relay path with.
    /// * `relay_addr` - The relay server address.
    /// * `relay_id` - The 16-byte relay identifier.
    /// * `ttl_secs` - Token time-to-live in seconds.
    ///
    /// # Returns
    ///
    /// The effective endpoint to configure in the backend for this peer.
    pub fn establish_session(
        &mut self,
        peer_node_id: &NodeId,
        relay_addr: SocketAddr,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Result<SocketEndpoint, RelayClientError> {
        #[cfg(test)]
        if !self.scripted_establishments.is_empty() {
            return self.establish_session_with_round_trip(
                peer_node_id,
                relay_addr,
                relay_id,
                ttl_secs,
                |_target, _hello_bytes, _timeout| {
                    unreachable!(
                        "scripted relay-client establishment should short-circuit before transport"
                    )
                },
            );
        }

        let socket = self
            .socket
            .as_ref()
            .ok_or(RelayClientError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "relay socket not bound",
            )))?
            .try_clone()?;
        self.establish_session_with_round_trip(
            peer_node_id,
            relay_addr,
            relay_id,
            ttl_secs,
            |target, hello_bytes, timeout| {
                socket.set_read_timeout(Some(timeout))?;
                socket.send_to(hello_bytes, target)?;
                let mut buf = [0u8; 1500];
                loop {
                    match socket.recv_from(&mut buf) {
                        Ok((len, from_addr)) if from_addr == relay_addr => {
                            return Ok((buf[..len].to_vec(), from_addr));
                        }
                        Ok(_) => continue,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                        Err(e) => return Err(RelayClientError::Io(e)),
                    }
                }
            },
        )
    }

    pub fn establish_session_with_round_trip<F>(
        &mut self,
        peer_node_id: &NodeId,
        relay_addr: SocketAddr,
        relay_id: [u8; 16],
        ttl_secs: u64,
        mut round_trip: F,
    ) -> Result<SocketEndpoint, RelayClientError>
    where
        F: FnMut(SocketAddr, &[u8], Duration) -> Result<(Vec<u8>, SocketAddr), RelayClientError>,
    {
        if self.sessions.len() >= self.config.max_sessions_per_peer * 16 {
            return Err(RelayClientError::CapacityExceeded);
        }

        let token = RelaySessionToken::sign(
            &self.signing_key,
            self.node_id.as_str(),
            peer_node_id.as_str(),
            relay_id,
            ttl_secs,
        );
        let token_expires_at_unix = token.expires_at_unix;

        #[cfg(test)]
        if let Some(scripted) = self.scripted_establishments.pop_front() {
            return match scripted {
                Ok(allocated_port) => {
                    let now = Instant::now();
                    let session = RelayClientSession {
                        session_id: SessionId::from([0xAA; 16]),
                        relay_addr,
                        allocated_port,
                        peer_node_id: peer_node_id.clone(),
                        established_at: now,
                        last_activity: now,
                        relay_id,
                        token_expires_at_unix,
                    };
                    let endpoint = session.effective_endpoint();
                    self.sessions.insert(peer_node_id.clone(), session);
                    Ok(endpoint)
                }
                Err(err) => Err(err),
            };
        }

        // Build hello message
        let hello = RelayHello {
            node_id: self.node_id.as_str().to_string(),
            peer_node_id: peer_node_id.as_str().to_string(),
            session_token: token,
        };

        let hello_bytes = serialize_relay_hello(&hello);
        let (response, from_addr) =
            round_trip(relay_addr, &hello_bytes, self.config.session_timeout)?;
        if from_addr != relay_addr {
            return Err(RelayClientError::InvalidResponse(format!(
                "unexpected relay response source {from_addr}"
            )));
        }
        match parse_relay_hello_ack(&response) {
            Ok(ack) => {
                let now = Instant::now();
                let session = RelayClientSession {
                    session_id: ack.session_id,
                    relay_addr,
                    allocated_port: ack.allocated_port,
                    peer_node_id: peer_node_id.clone(),
                    established_at: now,
                    last_activity: now,
                    relay_id,
                    token_expires_at_unix,
                };
                let endpoint = session.effective_endpoint();
                self.sessions.insert(peer_node_id.clone(), session);
                Ok(endpoint)
            }
            Err(e) => Err(RelayClientError::SessionRejected(e)),
        }
    }

    /// Returns the active session for a peer, if any.
    pub fn session_for_peer(&self, peer_node_id: &NodeId) -> Option<&RelayClientSession> {
        self.sessions.get(peer_node_id)
    }

    /// Returns the relay endpoint for a peer, if a session exists.
    pub fn relay_endpoint_for_peer(&self, peer_node_id: &NodeId) -> Option<SocketEndpoint> {
        self.sessions
            .get(peer_node_id)
            .map(|s| s.effective_endpoint())
    }

    /// Returns true if the peer's selected backend endpoint matches the active
    /// relay session endpoint.
    pub fn session_matches_selected_endpoint(
        &self,
        peer_node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> bool {
        self.sessions
            .get(peer_node_id)
            .map(|session| session.matches_selected_endpoint(endpoint))
            .unwrap_or(false)
    }

    /// Closes the session for a peer.
    pub fn close_session(&mut self, peer_node_id: &NodeId) -> Option<RelayClientSession> {
        self.sessions.remove(peer_node_id)
    }

    /// Cleans up idle sessions.
    pub fn cleanup_idle_sessions(&mut self, idle_timeout: Duration) {
        self.sessions
            .retain(|_, session| !session.is_idle(idle_timeout));
    }

    /// Removes a specific session for a peer.
    ///
    /// Used during clean failover to release a relay session before
    /// transitioning to a different path.
    pub fn remove_session(&mut self, peer_node_id: &NodeId) -> Option<RelayClientSession> {
        self.sessions.remove(peer_node_id)
    }

    /// Returns the number of active sessions.
    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns true if a session exists for the given peer.
    pub fn has_session(&self, peer_node_id: &NodeId) -> bool {
        self.sessions.contains_key(peer_node_id)
    }

    /// Updates the last activity time for a peer session (e.g., on packet
    /// received).
    pub fn touch_session(&mut self, peer_node_id: &NodeId) {
        if let Some(session) = self.sessions.get_mut(peer_node_id) {
            session.last_activity = Instant::now();
        }
    }

    /// Returns the keepalive interval from config.
    pub fn keepalive_interval(&self) -> Duration {
        self.config.keepalive_interval
    }

    /// Returns peer IDs that need keepalive packets sent.
    ///
    /// A session needs keepalive when `last_activity` is older than
    /// `keepalive_interval` but not yet idle (cleanup would handle idle).
    pub fn sessions_needing_keepalive(&self) -> Vec<NodeId> {
        let keepalive_threshold = self.config.keepalive_interval;
        self.sessions
            .iter()
            .filter(|(_, session)| session.last_activity.elapsed() >= keepalive_threshold)
            .map(|(peer_id, _)| peer_id.clone())
            .collect()
    }

    /// Sends a keepalive packet to maintain NAT binding for a relay session.
    ///
    /// Keepalives are small UDP packets sent to the relay's allocated port
    /// to refresh NAT mappings. The relay should echo or acknowledge.
    ///
    /// # Returns
    /// `Ok(())` if the keepalive was sent successfully.
    pub fn send_keepalive(&mut self, peer_node_id: &NodeId) -> Result<(), RelayClientError> {
        let session = self
            .sessions
            .get(peer_node_id)
            .ok_or(RelayClientError::NoRelayAvailable)?;

        let socket = self
            .socket
            .as_ref()
            .ok_or(RelayClientError::Io(io::Error::new(
                io::ErrorKind::NotConnected,
                "relay socket not bound",
            )))?
            .try_clone()?;

        // Keepalive is a minimal packet to the allocated port.
        // Use a simple format: [KEEPALIVE_MSG_TYPE, session_id[0..4]]
        // This is enough to keep NAT mappings alive without being a full hello.
        let mut keepalive = [0u8; 5];
        keepalive[0] = RELAY_KEEPALIVE_MSG_TYPE;
        keepalive[1..5].copy_from_slice(&session.session_id.as_bytes()[0..4]);

        self.send_keepalive_with_sender(peer_node_id, |target, keepalive| {
            socket.send_to(keepalive, target)?;
            Ok(())
        })
    }

    pub fn send_keepalive_with_sender<F>(
        &mut self,
        peer_node_id: &NodeId,
        mut sender: F,
    ) -> Result<(), RelayClientError>
    where
        F: FnMut(SocketAddr, &[u8]) -> Result<(), RelayClientError>,
    {
        let session = self
            .sessions
            .get(peer_node_id)
            .ok_or(RelayClientError::NoRelayAvailable)?;

        let mut keepalive = [0u8; 5];
        keepalive[0] = RELAY_KEEPALIVE_MSG_TYPE;
        keepalive[1..5].copy_from_slice(&session.session_id.as_bytes()[0..4]);

        let target = SocketAddr::new(session.relay_addr.ip(), session.allocated_port);
        sender(target, &keepalive)?;

        if let Some(session) = self.sessions.get_mut(peer_node_id) {
            session.last_activity = Instant::now();
        }

        Ok(())
    }

    /// Sends keepalives to all sessions that need them.
    ///
    /// Returns the number of keepalives sent and any errors encountered.
    pub fn send_all_keepalives(&mut self) -> (usize, Vec<(NodeId, RelayClientError)>) {
        let peers_needing_keepalive = self.sessions_needing_keepalive();
        let mut sent = 0;
        let mut errors = Vec::new();

        for peer_id in peers_needing_keepalive {
            match self.send_keepalive(&peer_id) {
                Ok(()) => sent += 1,
                Err(e) => errors.push((peer_id, e)),
            }
        }

        (sent, errors)
    }

    /// Returns sessions with tokens expiring soon.
    ///
    /// This allows the daemon to proactively refresh tokens before they expire.
    pub fn sessions_needing_token_refresh(&self, now_unix: u64) -> Vec<(NodeId, u64)> {
        let refresh_margin = 60; // 60 seconds before expiry
        self.sessions
            .iter()
            .filter(|(_, session)| session.token_refresh_due(now_unix, refresh_margin))
            .map(|(peer_id, session)| (peer_id.clone(), session.token_expires_at_unix))
            .collect()
    }

    #[cfg(test)]
    pub fn set_session_token_expiry_for_test(
        &mut self,
        peer_node_id: &NodeId,
        token_expires_at_unix: u64,
    ) {
        if let Some(session) = self.sessions.get_mut(peer_node_id) {
            session.token_expires_at_unix = token_expires_at_unix;
        }
    }

    #[cfg(test)]
    pub fn set_session_last_activity_for_test(
        &mut self,
        peer_node_id: &NodeId,
        last_activity: Instant,
    ) {
        if let Some(session) = self.sessions.get_mut(peer_node_id) {
            session.last_activity = last_activity;
        }
    }

    #[cfg(test)]
    pub fn script_establish_session_result(&mut self, result: Result<u16, RelayClientError>) {
        self.scripted_establishments.push_back(result);
    }

    #[cfg(test)]
    pub fn set_bound_for_test(&mut self, value: bool) {
        self.bound_override = value;
    }
}

// Wire format constants for relay protocol
const RELAY_HELLO_MSG_TYPE: u8 = 0x01;
const RELAY_HELLO_ACK_MSG_TYPE: u8 = 0x02;
const RELAY_REJECT_MSG_TYPE: u8 = 0x03;
const RELAY_KEEPALIVE_MSG_TYPE: u8 = 0x04;

/// Serializes a RelayHello message for wire transmission.
fn serialize_relay_hello(hello: &RelayHello) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.push(RELAY_HELLO_MSG_TYPE);

    // Node ID (length-prefixed)
    let node_id_bytes = hello.node_id.as_bytes();
    buf.extend_from_slice(&(node_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(node_id_bytes);

    // Peer node ID (length-prefixed)
    let peer_node_id_bytes = hello.peer_node_id.as_bytes();
    buf.extend_from_slice(&(peer_node_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_node_id_bytes);

    // Session token (serialized via canonical payload + signature)
    let token_bytes = serialize_relay_token(&hello.session_token);
    buf.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(&token_bytes);

    buf
}

/// Serializes a RelaySessionToken for wire transmission.
fn serialize_relay_token(token: &RelaySessionToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // Version
    buf.push(1);

    // Node ID
    let node_id_bytes = token.node_id.as_bytes();
    buf.extend_from_slice(&(node_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(node_id_bytes);

    // Peer node ID
    let peer_node_id_bytes = token.peer_node_id.as_bytes();
    buf.extend_from_slice(&(peer_node_id_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_node_id_bytes);

    // Relay ID (fixed 16 bytes)
    buf.extend_from_slice(&token.relay_id);

    // Scope
    let scope_bytes = token.scope.as_bytes();
    buf.extend_from_slice(&(scope_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(scope_bytes);

    // Timestamps
    buf.extend_from_slice(&token.issued_at_unix.to_be_bytes());
    buf.extend_from_slice(&token.expires_at_unix.to_be_bytes());

    // Nonce (fixed 16 bytes)
    buf.extend_from_slice(&token.nonce);

    // Signature (fixed 64 bytes)
    buf.extend_from_slice(&token.signature);

    buf
}

/// Parses a RelayHelloAck from wire format.
fn parse_relay_hello_ack(data: &[u8]) -> Result<RelayHelloAck, String> {
    if data.is_empty() {
        return Err("empty response".to_string());
    }

    match data[0] {
        RELAY_HELLO_ACK_MSG_TYPE => {
            if data.len() < 19 {
                return Err("ack message too short".to_string());
            }
            // Session ID (16 bytes)
            let session_id_bytes: [u8; 16] =
                data[1..17].try_into().map_err(|_| "invalid session id")?;
            let session_id = SessionId::from(session_id_bytes);

            // Allocated port (2 bytes)
            let port_bytes: [u8; 2] = data[17..19].try_into().map_err(|_| "invalid port")?;
            let allocated_port = u16::from_be_bytes(port_bytes);

            Ok(RelayHelloAck {
                session_id,
                allocated_port,
            })
        }
        RELAY_REJECT_MSG_TYPE => {
            let reason = if data.len() > 1 {
                String::from_utf8_lossy(&data[1..]).to_string()
            } else {
                "unknown".to_string()
            };
            Err(reason)
        }
        other => Err(format!("unexpected message type: {other:#02x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_node_id(value: &str) -> NodeId {
        NodeId::new(value.to_string()).expect("test node id should parse")
    }

    #[test]
    fn relay_client_config_has_reasonable_defaults() {
        let config = RelayClientConfig::default();
        assert!(config.session_timeout >= Duration::from_secs(5));
        assert!(config.keepalive_interval >= Duration::from_secs(10));
        assert!(config.max_sessions_per_peer >= 1);
    }

    #[test]
    fn relay_client_session_effective_endpoint() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = RelayClientSession {
            session_id: SessionId::from([0x11; 16]),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5000,
            peer_node_id: test_node_id("peer-a"),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            relay_id: [0xAA; 16],
            token_expires_at_unix: now_unix + 60,
        };

        let endpoint = session.effective_endpoint();
        assert_eq!(
            endpoint.addr,
            "192.168.1.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(endpoint.port, 5000);
    }

    #[test]
    fn relay_client_session_idle_detection() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut session = RelayClientSession {
            session_id: SessionId::from([0x22; 16]),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5000,
            peer_node_id: test_node_id("peer-a"),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            relay_id: [0xAA; 16],
            token_expires_at_unix: now_unix + 60,
        };

        // Fresh session should not be idle
        assert!(!session.is_idle(Duration::from_secs(30)));

        // Manually set last_activity to the past
        session.last_activity = Instant::now() - Duration::from_secs(60);
        assert!(session.is_idle(Duration::from_secs(30)));
    }

    #[test]
    fn serialize_relay_hello_produces_valid_format() {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&signing_key, "node-a", "node-b", [0xAA; 16], 60);

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let bytes = serialize_relay_hello(&hello);
        assert!(!bytes.is_empty());
        assert_eq!(bytes[0], RELAY_HELLO_MSG_TYPE);
    }

    #[test]
    fn parse_relay_hello_ack_valid() {
        let session_id = [0x55; 16];
        let mut data = vec![RELAY_HELLO_ACK_MSG_TYPE];
        data.extend_from_slice(&session_id);
        data.extend_from_slice(&5000u16.to_be_bytes()); // allocated_port

        let ack = parse_relay_hello_ack(&data).expect("should parse valid ack");
        assert_eq!(*ack.session_id.as_bytes(), session_id);
        assert_eq!(ack.allocated_port, 5000);
    }

    #[test]
    fn parse_relay_hello_ack_reject() {
        let mut data = vec![RELAY_REJECT_MSG_TYPE];
        data.extend_from_slice(b"capacity exceeded");

        let err = parse_relay_hello_ack(&data).expect_err("should return error for reject");
        assert!(err.contains("capacity"));
    }

    #[test]
    fn relay_client_new_creates_empty_session_map() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[1u8; 32]));
        let client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        assert_eq!(client.active_session_count(), 0);
        assert!(!client.has_session(&test_node_id("peer-b")));
        assert!(!client.is_bound());
    }

    #[test]
    fn relay_client_cleanup_removes_idle_sessions() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[1u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Manually insert a session
        let peer_id = test_node_id("peer-b");
        client.sessions.insert(
            peer_id.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x33; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5000,
                peer_node_id: peer_id.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now() - Duration::from_secs(120),
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix + 60,
            },
        );

        assert_eq!(client.active_session_count(), 1);
        client.cleanup_idle_sessions(Duration::from_secs(60));
        assert_eq!(client.active_session_count(), 0);
    }

    #[test]
    fn relay_client_session_token_refresh_due_tracks_expiry_margin() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = RelayClientSession {
            session_id: SessionId::from([0x44; 16]),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5001,
            peer_node_id: test_node_id("peer-b"),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            relay_id: [0xBB; 16],
            token_expires_at_unix: now_unix + 30,
        };

        assert!(!session.token_refresh_due(now_unix, 10));
        assert!(session.token_refresh_due(now_unix, 31));
    }

    #[test]
    fn relay_client_scripted_establish_session_success() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[2u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Script a successful establishment
        client.script_establish_session_result(Ok(5001));

        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let relay_id = [0xAA; 16];

        let endpoint = client
            .establish_session(&peer_id, relay_addr, relay_id, 60)
            .expect("should succeed with scripted result");

        assert_eq!(endpoint.port, 5001);
        assert!(client.has_session(&peer_id));
        assert_eq!(client.active_session_count(), 1);
    }

    #[test]
    fn relay_client_scripted_establish_session_failure_then_success() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[3u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Script a failure followed by success (simulating retry scenario)
        client.script_establish_session_result(Err(RelayClientError::Timeout));
        client.script_establish_session_result(Ok(5002));

        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let relay_id = [0xAA; 16];

        // First attempt fails
        let err = client
            .establish_session(&peer_id, relay_addr, relay_id, 60)
            .expect_err("first attempt should fail");
        assert!(matches!(err, RelayClientError::Timeout));
        assert!(!client.has_session(&peer_id));

        // Second attempt succeeds
        let endpoint = client
            .establish_session(&peer_id, relay_addr, relay_id, 60)
            .expect("second attempt should succeed");
        assert_eq!(endpoint.port, 5002);
        assert!(client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_close_session_removes_from_map() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[4u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        client.script_establish_session_result(Ok(5003));

        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let relay_id = [0xAA; 16];

        client
            .establish_session(&peer_id, relay_addr, relay_id, 60)
            .expect("should succeed");
        assert!(client.has_session(&peer_id));

        let closed = client.close_session(&peer_id);
        assert!(closed.is_some());
        assert!(!client.has_session(&peer_id));
        assert_eq!(client.active_session_count(), 0);
    }

    #[test]
    fn relay_client_touch_session_updates_last_activity() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[5u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        let peer_id = test_node_id("peer-b");

        // Manually insert an old session
        client.sessions.insert(
            peer_id.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x55; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5004,
                peer_node_id: peer_id.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now() - Duration::from_secs(100),
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        // Session should be idle
        let session = client.session_for_peer(&peer_id).unwrap();
        assert!(session.is_idle(Duration::from_secs(60)));

        // Touch session
        client.touch_session(&peer_id);

        // Session should no longer be idle
        let session = client.session_for_peer(&peer_id).unwrap();
        assert!(!session.is_idle(Duration::from_secs(60)));
    }

    #[test]
    fn relay_client_relay_endpoint_for_peer_returns_correct_endpoint() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[6u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        let peer_id = test_node_id("peer-b");

        // No session yet
        assert!(client.relay_endpoint_for_peer(&peer_id).is_none());

        // Add session
        client.sessions.insert(
            peer_id.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x66; 16]),
                relay_addr: "10.0.0.1:4500".parse().unwrap(),
                allocated_port: 6000,
                peer_node_id: peer_id.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xCC; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        let endpoint = client
            .relay_endpoint_for_peer(&peer_id)
            .expect("should have endpoint");
        assert_eq!(endpoint.addr.to_string(), "10.0.0.1");
        assert_eq!(endpoint.port, 6000);
    }

    #[test]
    fn relay_client_sessions_needing_keepalive_returns_stale_sessions() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[7u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig {
                keepalive_interval: Duration::from_secs(25),
                ..Default::default()
            },
        );

        let peer_a = test_node_id("peer-a");
        let peer_b = test_node_id("peer-b");

        // Add session with recent activity (should NOT need keepalive)
        client.sessions.insert(
            peer_a.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x77; 16]),
                relay_addr: "10.0.0.1:4500".parse().unwrap(),
                allocated_port: 7001,
                peer_node_id: peer_a.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xDD; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        // Add session with old activity (should need keepalive)
        client.sessions.insert(
            peer_b.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x88; 16]),
                relay_addr: "10.0.0.2:4500".parse().unwrap(),
                allocated_port: 7002,
                peer_node_id: peer_b.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now() - Duration::from_secs(30),
                relay_id: [0xEE; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        let needs_keepalive = client.sessions_needing_keepalive();
        assert_eq!(needs_keepalive.len(), 1);
        assert_eq!(needs_keepalive[0], peer_b);
    }

    #[test]
    fn relay_client_sessions_needing_token_refresh_returns_expiring_sessions() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[8u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        let peer_a = test_node_id("peer-a");
        let peer_b = test_node_id("peer-b");

        // Add session with long-lived token (should NOT need refresh)
        client.sessions.insert(
            peer_a.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x99; 16]),
                relay_addr: "10.0.0.1:4500".parse().unwrap(),
                allocated_port: 8001,
                peer_node_id: peer_a.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix + 300, // Expires in 5 minutes
            },
        );

        // Add session with soon-expiring token (should need refresh)
        client.sessions.insert(
            peer_b.clone(),
            RelayClientSession {
                session_id: SessionId::from([0xAA; 16]),
                relay_addr: "10.0.0.2:4500".parse().unwrap(),
                allocated_port: 8002,
                peer_node_id: peer_b.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xBB; 16],
                token_expires_at_unix: now_unix + 30, // Expires in 30 seconds
            },
        );

        let needs_refresh = client.sessions_needing_token_refresh(now_unix);
        assert_eq!(needs_refresh.len(), 1);
        assert_eq!(needs_refresh[0].0, peer_b);
        assert_eq!(needs_refresh[0].1, now_unix + 30);
    }

    #[test]
    fn relay_client_keepalive_interval_returns_config_value() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[9u8; 32]));
        let client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig {
                keepalive_interval: Duration::from_secs(42),
                ..Default::default()
            },
        );

        assert_eq!(client.keepalive_interval(), Duration::from_secs(42));
    }

    #[test]
    fn relay_client_establish_session_with_round_trip_uses_provided_transport() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[10u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let allocated_port: u16 = 5010;
        let session_id = [0x66; 16];

        let endpoint = client
            .establish_session_with_round_trip(
                &peer_id,
                relay_addr,
                [0xAA; 16],
                60,
                |target, _payload, _timeout| {
                    assert_eq!(target, relay_addr);
                    let mut ack = vec![RELAY_HELLO_ACK_MSG_TYPE];
                    ack.extend_from_slice(&session_id);
                    ack.extend_from_slice(&allocated_port.to_be_bytes());
                    Ok((ack, relay_addr))
                },
            )
            .expect("round-trip establish should succeed");

        assert_eq!(endpoint.addr, relay_addr.ip());
        assert_eq!(endpoint.port, allocated_port);
        assert!(client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_send_keepalive_with_sender_uses_allocated_port() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[11u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        client.script_establish_session_result(Ok(5008));
        client
            .establish_session_with_round_trip(
                &peer_id,
                relay_addr,
                [0xAA; 16],
                60,
                |_target, _payload, _timeout| Err(RelayClientError::Timeout),
            )
            .expect("scripted establish should succeed");

        let mut observed = None;
        client
            .send_keepalive_with_sender(&peer_id, |target, payload| {
                observed = Some((target, payload.to_vec()));
                Ok(())
            })
            .expect("keepalive send should succeed");

        let (target, payload) = observed.expect("keepalive should be observed");
        assert_eq!(target, "192.168.1.1:5008".parse().unwrap());
        assert_eq!(payload.len(), 5);
        assert_eq!(payload[0], RELAY_KEEPALIVE_MSG_TYPE);
    }

    #[test]
    fn relay_client_local_port_config_returns_configured_value() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[12u8; 32]));
        let client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig {
                local_port: Some(51820),
                ..Default::default()
            },
        );

        assert_eq!(client.local_port(), Some(51820));
    }

    #[test]
    fn relay_client_local_port_hint_does_not_imply_authoritative_binding() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[13u8; 32]));
        let client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig {
                local_port: Some(51820),
                ..Default::default()
            },
        );

        assert_eq!(client.local_port(), Some(51820));
        assert!(
            !client.is_bound(),
            "configured local port must not be treated as an authoritative transport socket"
        );
    }

    #[test]
    fn relay_client_local_port_default_is_none() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[14u8; 32]));
        let client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        assert_eq!(client.local_port(), None);
    }

    /// Verifies that session cleanup preserves live sessions while removing only
    /// expired/idle ones. This ensures fail-closed behavior during transitions.
    #[test]
    fn relay_client_cleanup_preserves_live_sessions_removes_only_idle() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[12u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Insert a live session (active recently)
        let live_peer = test_node_id("live-peer");
        client.sessions.insert(
            live_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x11; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5000,
                peer_node_id: live_peer.clone(),
                established_at: Instant::now() - Duration::from_secs(10),
                last_activity: Instant::now() - Duration::from_secs(5), // Recent activity
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        // Insert an idle session (inactive for too long)
        let idle_peer = test_node_id("idle-peer");
        client.sessions.insert(
            idle_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x22; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5001,
                peer_node_id: idle_peer.clone(),
                established_at: Instant::now() - Duration::from_secs(120),
                last_activity: Instant::now() - Duration::from_secs(120), // Idle
                relay_id: [0xBB; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        assert_eq!(client.active_session_count(), 2);

        // Cleanup with 60-second idle threshold
        client.cleanup_idle_sessions(Duration::from_secs(60));

        // Live session should remain, idle session should be removed
        assert_eq!(client.active_session_count(), 1);
        assert!(client.has_session(&live_peer));
        assert!(!client.has_session(&idle_peer));
    }

    /// Verifies that expired tokens are correctly identified for refresh,
    /// supporting Phase D token refresh across long uptime.
    #[test]
    fn relay_client_token_refresh_identifies_multiple_expiring_sessions() {
        let now_unix = 1000u64;
        let signing_key = Arc::new(SigningKey::from_bytes(&[13u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Session expiring soon (within margin)
        let expiring_peer_1 = test_node_id("expiring-1");
        client.sessions.insert(
            expiring_peer_1.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x01; 16]),
                relay_addr: "10.0.0.1:4500".parse().unwrap(),
                allocated_port: 6000,
                peer_node_id: expiring_peer_1.clone(),
                established_at: Instant::now() - Duration::from_secs(100),
                last_activity: Instant::now() - Duration::from_secs(5),
                relay_id: [0x11; 16],
                token_expires_at_unix: now_unix + 30, // Expires in 30s, within 60s margin
            },
        );

        // Another session expiring soon
        let expiring_peer_2 = test_node_id("expiring-2");
        client.sessions.insert(
            expiring_peer_2.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x02; 16]),
                relay_addr: "10.0.0.2:4500".parse().unwrap(),
                allocated_port: 6001,
                peer_node_id: expiring_peer_2.clone(),
                established_at: Instant::now() - Duration::from_secs(200),
                last_activity: Instant::now() - Duration::from_secs(10),
                relay_id: [0x22; 16],
                token_expires_at_unix: now_unix + 45, // Expires in 45s, within 60s margin
            },
        );

        // Session not expiring soon
        let healthy_peer = test_node_id("healthy-peer");
        client.sessions.insert(
            healthy_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x03; 16]),
                relay_addr: "10.0.0.3:4500".parse().unwrap(),
                allocated_port: 6002,
                peer_node_id: healthy_peer.clone(),
                established_at: Instant::now() - Duration::from_secs(50),
                last_activity: Instant::now() - Duration::from_secs(2),
                relay_id: [0x33; 16],
                token_expires_at_unix: now_unix + 3600, // Expires in 1 hour
            },
        );

        let needs_refresh = client.sessions_needing_token_refresh(now_unix);

        // Should find exactly 2 sessions needing refresh
        assert_eq!(needs_refresh.len(), 2);
        let refresh_peers: Vec<_> = needs_refresh.iter().map(|(n, _)| n.clone()).collect();
        assert!(refresh_peers.contains(&expiring_peer_1));
        assert!(refresh_peers.contains(&expiring_peer_2));
        assert!(!refresh_peers.contains(&healthy_peer));
    }

    /// Verifies that remove_session correctly removes a specific session,
    /// supporting clean failover transitions.
    #[test]
    fn relay_client_remove_session_supports_clean_failover() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[14u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        // Create two sessions
        let peer_1 = test_node_id("peer-1");
        let peer_2 = test_node_id("peer-2");

        client.sessions.insert(
            peer_1.clone(),
            RelayClientSession {
                session_id: SessionId::from([0xAA; 16]),
                relay_addr: "10.0.0.1:4500".parse().unwrap(),
                allocated_port: 7000,
                peer_node_id: peer_1.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0x11; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        client.sessions.insert(
            peer_2.clone(),
            RelayClientSession {
                session_id: SessionId::from([0xBB; 16]),
                relay_addr: "10.0.0.2:4500".parse().unwrap(),
                allocated_port: 7001,
                peer_node_id: peer_2.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0x22; 16],
                token_expires_at_unix: now_unix + 300,
            },
        );

        assert_eq!(client.active_session_count(), 2);

        // Remove one session (simulating failover cleanup)
        client.remove_session(&peer_1);

        // Only peer_2 should remain
        assert_eq!(client.active_session_count(), 1);
        assert!(!client.has_session(&peer_1));
        assert!(client.has_session(&peer_2));
    }
}
