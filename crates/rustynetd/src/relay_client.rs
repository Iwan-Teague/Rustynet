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
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

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
}

impl Default for RelayClientConfig {
    fn default() -> Self {
        Self {
            session_timeout: Duration::from_secs(10),
            keepalive_interval: Duration::from_secs(25),
            max_sessions_per_peer: 2,
            recv_timeout: Duration::from_secs(5),
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

    /// Returns true when the session token must be refreshed to avoid expiry.
    pub fn token_refresh_due(&self, now_unix: u64, refresh_margin_secs: u64) -> bool {
        self.token_expires_at_unix
            <= now_unix.saturating_add(refresh_margin_secs)
    }
}

/// Errors that can occur during relay client operations.
#[derive(Debug)]
pub enum RelayClientError {
    /// Socket I/O error.
    Io(io::Error),
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
        }
    }

    /// Binds the relay client to a local socket.
    ///
    /// This should be called with the same socket used for WireGuard traffic
    /// to ensure NAT mappings are shared for hole punching.
    pub fn bind(&mut self, socket: UdpSocket) -> Result<(), RelayClientError> {
        socket.set_read_timeout(Some(self.config.recv_timeout))?;
        socket.set_write_timeout(Some(self.config.recv_timeout))?;
        self.socket = Some(socket);
        Ok(())
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
        // Check capacity
        if self.sessions.len() >= self.config.max_sessions_per_peer * 16 {
            return Err(RelayClientError::CapacityExceeded);
        }

        // Create signed session token
        let token = RelaySessionToken::sign(
            &self.signing_key,
            &self.node_id,
            peer_node_id,
            relay_id,
            ttl_secs,
        );

        // Build hello message
        let hello = RelayHello {
            node_id: self.node_id.clone(),
            peer_node_id: peer_node_id.clone(),
            session_token: token,
        };

        // Send hello to relay
        let socket = self.socket.as_ref().ok_or(RelayClientError::Io(
            io::Error::new(io::ErrorKind::NotConnected, "relay socket not bound"),
        ))?;

        let hello_bytes = serialize_relay_hello(&hello);
        socket.send_to(&hello_bytes, relay_addr)?;

        // Wait for acknowledgment
        let deadline = Instant::now() + self.config.session_timeout;
        let mut buf = [0u8; 1500];

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(RelayClientError::Timeout);
            }

            socket.set_read_timeout(Some(remaining.min(Duration::from_secs(1))))?;

            match socket.recv_from(&mut buf) {
                Ok((len, from_addr)) => {
                    if from_addr != relay_addr {
                        continue; // Ignore packets from other sources
                    }

                    match parse_relay_hello_ack(&buf[..len]) {
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
                                token_expires_at_unix: token.expires_at_unix,
                            };
                            let endpoint = session.effective_endpoint();
                            self.sessions.insert(peer_node_id.clone(), session);
                            return Ok(endpoint);
                        }
                        Err(e) => {
                            return Err(RelayClientError::SessionRejected(e));
                        }
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) if e.kind() == io::ErrorKind::TimedOut => continue,
                Err(e) => return Err(RelayClientError::Io(e)),
            }
        }
    }

    /// Returns the active session for a peer, if any.
    pub fn session_for_peer(&self, peer_node_id: &NodeId) -> Option<&RelayClientSession> {
        self.sessions.get(peer_node_id)
    }

    /// Returns the relay endpoint for a peer, if a session exists.
    pub fn relay_endpoint_for_peer(&self, peer_node_id: &NodeId) -> Option<SocketEndpoint> {
        self.sessions.get(peer_node_id).map(|s| s.effective_endpoint())
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
}

// Wire format constants for relay protocol
const RELAY_HELLO_MSG_TYPE: u8 = 0x01;
const RELAY_HELLO_ACK_MSG_TYPE: u8 = 0x02;
const RELAY_REJECT_MSG_TYPE: u8 = 0x03;

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
            if data.len() < 11 {
                return Err("ack message too short".to_string());
            }
            // Session ID (8 bytes)
            let session_id_bytes: [u8; 8] = data[1..9]
                .try_into()
                .map_err(|_| "invalid session id")?;
            let session_id = SessionId(u64::from_be_bytes(session_id_bytes));

            // Allocated port (2 bytes)
            let port_bytes: [u8; 2] = data[9..11]
                .try_into()
                .map_err(|_| "invalid port")?;
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
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let session = RelayClientSession {
            session_id: SessionId(12345),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5000,
            peer_node_id: "peer-a".to_string(),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            relay_id: [0xAA; 16],
            token_expires_at_unix: now_unix + 60,
        };

        let endpoint = session.effective_endpoint();
        assert_eq!(endpoint.addr, "192.168.1.1".parse().unwrap());
        assert_eq!(endpoint.port, 5000);
    }

    #[test]
    fn relay_client_session_idle_detection() {
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut session = RelayClientSession {
            session_id: SessionId(12345),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5000,
            peer_node_id: "peer-a".to_string(),
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
        let mut data = vec![RELAY_HELLO_ACK_MSG_TYPE];
        data.extend_from_slice(&12345u64.to_be_bytes()); // session_id
        data.extend_from_slice(&5000u16.to_be_bytes()); // allocated_port

        let ack = parse_relay_hello_ack(&data).expect("should parse valid ack");
        assert_eq!(ack.session_id.0, 12345);
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
            "node-a".to_string(),
            signing_key,
            RelayClientConfig::default(),
        );

        assert_eq!(client.active_session_count(), 0);
        assert!(!client.has_session(&"peer-b".to_string()));
    }

    #[test]
    fn relay_client_cleanup_removes_idle_sessions() {
        let now_unix = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signing_key = Arc::new(SigningKey::from_bytes(&[1u8; 32]));
        let mut client = RelayClient::new(
            "node-a".to_string(),
            signing_key,
            RelayClientConfig::default(),
        );

        // Manually insert a session
        let peer_id = "peer-b".to_string();
        client.sessions.insert(
            peer_id.clone(),
            RelayClientSession {
                session_id: SessionId(1),
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
        let now_unix = unix_now();
        let session = RelayClientSession {
            session_id: SessionId(7),
            relay_addr: "192.168.1.1:4500".parse().unwrap(),
            allocated_port: 5001,
            peer_node_id: "peer-b".to_string(),
            established_at: Instant::now(),
            last_activity: Instant::now(),
            relay_id: [0xBB; 16],
            token_expires_at_unix: now_unix + 30,
        };

        assert!(!session.token_refresh_due(now_unix, 10));
        assert!(session.token_refresh_due(now_unix, 31));
    }
}
