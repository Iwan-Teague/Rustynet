#![forbid(unsafe_code)]

//! Relay client for daemon-side relay path transport.
//!
//! This module provides the client-side relay session management that enables
//! the daemon to establish authenticated sessions with relay servers and
//! forward encrypted `WireGuard` packets when direct connectivity is unavailable.
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
//! - **Session binding**: tokens are bound to specific (`node_id`, `peer_node_id`,
//!   `relay_id`) tuples.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustynet_backend_api::{NodeId, SocketEndpoint};
pub use rustynet_control::MAX_RELAY_SESSION_TOKEN_TTL_SECS;
use rustynet_control::{RELAY_TOKEN_SCOPE, RelaySessionToken, parse_relay_session_token_wire};
use rustynet_relay::{RelayHello, RelayHelloAck, SessionId};

const RELAY_SESSION_TOKEN_CLIENT_CLOCK_SKEW_SECS: u64 = 90;
const PREISSUED_RELAY_TOKEN_MAX_BYTES: u64 = 4096;
const PREISSUED_RELAY_TOKEN_MAX_FILES: usize = 128;
const PREISSUED_RELAY_TOKEN_EXTENSION: &str = "relay-token";

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

/// Issues signed relay session tokens for session establishment.
///
/// Production deployments should prefer a control-plane-backed issuer. The
/// local signing-key issuer exists for reviewed lab or control-plane-collocated
/// deployments only, and is gated by daemon configuration before construction.
pub trait RelaySessionTokenIssuer: Send + Sync {
    fn issue_token(
        &self,
        node_id: &NodeId,
        peer_node_id: &NodeId,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Result<RelaySessionToken, RelayClientError>;
}

/// Local relay session token issuer backed by an Ed25519 signing key.
pub struct LocalRelaySessionTokenIssuer {
    signing_key: Arc<SigningKey>,
}

impl LocalRelaySessionTokenIssuer {
    pub fn new(signing_key: Arc<SigningKey>) -> Self {
        Self { signing_key }
    }
}

impl RelaySessionTokenIssuer for LocalRelaySessionTokenIssuer {
    fn issue_token(
        &self,
        node_id: &NodeId,
        peer_node_id: &NodeId,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Result<RelaySessionToken, RelayClientError> {
        // Fail-closed on CSPRNG unavailability: the relay-session token nonce
        // is the anti-replay key for the relay's nonce store, so a predictable
        // or degraded-entropy nonce would let an attacker replay a captured
        // token or collide with another peer's session. We surface the
        // structured error as a `RelayClientError::TokenSigning` so the
        // daemon's session-establishment loop can retry on transient faults
        // instead of crashing.
        RelaySessionToken::try_sign(
            &self.signing_key,
            node_id.as_str(),
            peer_node_id.as_str(),
            relay_id,
            ttl_secs,
        )
        .map_err(|err| RelayClientError::TokenSigning(err.to_string()))
    }
}

/// Relay session token issuer backed by pre-issued control-plane token files.
///
/// This keeps daemon runtime out of the token-signing trust boundary while
/// still allowing a hardened local deployment model: an external control-plane
/// process writes signed one-use token artifacts into a restricted spool.
pub struct PreissuedRelaySessionTokenIssuer {
    spool_dir: PathBuf,
    verifier_key: VerifyingKey,
}

impl PreissuedRelaySessionTokenIssuer {
    pub fn new(spool_dir: PathBuf, verifier_key: VerifyingKey) -> Result<Self, RelayClientError> {
        validate_preissued_token_spool_dir(&spool_dir)?;
        Ok(Self {
            spool_dir,
            verifier_key,
        })
    }
}

impl RelaySessionTokenIssuer for PreissuedRelaySessionTokenIssuer {
    fn issue_token(
        &self,
        node_id: &NodeId,
        peer_node_id: &NodeId,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Result<RelaySessionToken, RelayClientError> {
        let now_unix = current_unix();
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.spool_dir).map_err(|err| {
            RelayClientError::TokenSigning(format!("read relay token spool failed: {err}"))
        })? {
            let entry = entry.map_err(|err| {
                RelayClientError::TokenSigning(format!(
                    "read relay token spool entry failed: {err}"
                ))
            })?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str())
                != Some(PREISSUED_RELAY_TOKEN_EXTENSION)
            {
                continue;
            }
            entries.push(path);
            if entries.len() > PREISSUED_RELAY_TOKEN_MAX_FILES {
                return Err(RelayClientError::TokenSigning(
                    "relay token spool contains too many token artifacts".to_owned(),
                ));
            }
        }
        entries.sort();

        for path in entries {
            let token = read_preissued_relay_token(&path)?;
            token.verify_signature(&self.verifier_key).map_err(|err| {
                RelayClientError::TokenSigning(format!(
                    "preissued relay token signature invalid: {err}"
                ))
            })?;
            if token.node_id != node_id.as_str()
                || token.peer_node_id != peer_node_id.as_str()
                || token.relay_id != relay_id
            {
                continue;
            }
            validate_issued_relay_session_token(
                &token,
                node_id,
                peer_node_id,
                relay_id,
                ttl_secs,
                now_unix,
            )?;
            fs::remove_file(&path).map_err(|err| {
                RelayClientError::TokenSigning(format!(
                    "consume preissued relay token failed: {err}"
                ))
            })?;
            return Ok(token);
        }

        Err(RelayClientError::TokenSigning(
            "no matching preissued relay session token available".to_owned(),
        ))
    }
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
/// for all active relay paths. It integrates with the `Phase10Controller` to
/// provide relay endpoints when direct connectivity fails.
pub struct RelayClient {
    /// Our node ID.
    node_id: NodeId,
    /// Relay session token issuer.
    token_issuer: Arc<dyn RelaySessionTokenIssuer>,
    /// Active sessions indexed by peer node ID.
    sessions: HashMap<NodeId, RelayClientSession>,
    /// Configuration for relay behavior.
    config: RelayClientConfig,
    /// True when the daemon has explicitly attached this client to the
    /// authoritative WireGuard transport socket. The relay client does
    /// NOT own a UDP socket of its own — D3 in the dataplane execution
    /// plan pins that relay and direct frames flow on the same UDP
    /// socket. This flag asserts that wiring has happened; production
    /// callers MUST set it via [`RelayClient::attach_authoritative_transport`]
    /// before issuing relay traffic, and they MUST use the closure-
    /// based `_with_round_trip` / `_with_sender` methods to drive the
    /// authoritative transport.
    attached_to_authoritative_transport: bool,
    #[cfg(test)]
    scripted_establishments: VecDeque<Result<u16, RelayClientError>>,
    #[cfg(test)]
    bound_override: bool,
}

impl RelayClient {
    /// Creates a new relay client.
    pub fn new(node_id: NodeId, signing_key: Arc<SigningKey>, config: RelayClientConfig) -> Self {
        Self::new_with_token_issuer(
            node_id,
            Arc::new(LocalRelaySessionTokenIssuer::new(signing_key)),
            config,
        )
    }

    /// Creates a relay client with an explicit token issuer.
    pub fn new_with_token_issuer(
        node_id: NodeId,
        token_issuer: Arc<dyn RelaySessionTokenIssuer>,
        config: RelayClientConfig,
    ) -> Self {
        Self {
            node_id,
            token_issuer,
            sessions: HashMap::new(),
            config,
            attached_to_authoritative_transport: false,
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

    /// Assert that this RelayClient is wired into the WireGuard backend's
    /// authoritative UDP transport socket — the same socket the direct
    /// path uses. The supplied `wg_listen_port` is the port that
    /// transport is bound to.
    ///
    /// D3 in the dataplane execution plan pins that relay and direct
    /// frames flow on the same UDP socket. This method is the typed
    /// hand-off: the caller (the daemon's reconcile loop) calls it after
    /// the WireGuard backend has bound its transport. The relay client
    /// will then drive traffic through the supplied closure path
    /// (`_with_round_trip`, `_with_sender`) — never through a private
    /// ephemeral socket.
    ///
    /// Validates that `wg_listen_port` matches the configured
    /// `local_port` if one was supplied. Returns an error otherwise so
    /// a misconfiguration fails closed rather than silently using a
    /// different port.
    pub fn attach_authoritative_transport(
        &mut self,
        wg_listen_port: u16,
    ) -> Result<(), RelayClientError> {
        if let Some(configured) = self.config.local_port
            && configured != wg_listen_port
        {
            return Err(RelayClientError::AuthoritativeTransport(format!(
                "configured relay local_port {configured} does not match WireGuard transport port {wg_listen_port}; \
                 the relay path must share the WG transport socket per D3"
            )));
        }
        self.attached_to_authoritative_transport = true;
        Ok(())
    }

    /// True when the relay client has been attached to an authoritative
    /// transport via [`attach_authoritative_transport`] (or marked bound
    /// in a test harness).
    pub fn is_bound(&self) -> bool {
        self.attached_to_authoritative_transport || {
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
        let _ = (peer_node_id, relay_addr, relay_id, ttl_secs);

        // D3: relay and direct frames flow on the same UDP socket. The
        // RelayClient does NOT own a socket — production callers must
        // use `establish_session_with_round_trip` and pass the
        // authoritative transport closure (the daemon's controller
        // wires this in reconcile.rs). Reaching this branch outside a
        // scripted test means the caller violated the D3 contract.
        Err(RelayClientError::AuthoritativeTransport(
            "RelayClient::establish_session called without an authoritative transport — \
             production callers must use establish_session_with_round_trip and supply the \
             WireGuard backend's authoritative transport closure (D3 contract)"
                .to_owned(),
        ))
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
        if ttl_secs == 0 || ttl_secs > MAX_RELAY_SESSION_TOKEN_TTL_SECS {
            return Err(RelayClientError::TokenSigning(format!(
                "relay token ttl must be 1..={MAX_RELAY_SESSION_TOKEN_TTL_SECS} seconds"
            )));
        }

        let token =
            self.token_issuer
                .issue_token(&self.node_id, peer_node_id, relay_id, ttl_secs)?;
        validate_issued_relay_session_token(
            &token,
            &self.node_id,
            peer_node_id,
            relay_id,
            ttl_secs,
            current_unix(),
        )?;
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
            node_id: self.node_id.as_str().to_owned(),
            peer_node_id: peer_node_id.as_str().to_owned(),
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
                if ack.allocated_port == relay_addr.port() {
                    return Err(RelayClientError::InvalidResponse(
                        "relay ack allocated control port".to_owned(),
                    ));
                }
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
            .map(RelayClientSession::effective_endpoint)
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
            .is_some_and(|session| session.matches_selected_endpoint(endpoint))
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

    /// Cleans up idle or expired sessions.
    pub fn cleanup_inactive_sessions(&mut self, idle_timeout: Duration, now_unix: u64) {
        self.sessions
            .retain(|_, session| !session.is_idle(idle_timeout) && !session.is_expired(now_unix));
    }

    /// Cleans up expired sessions while preserving idle-but-refreshable ones.
    pub fn cleanup_expired_sessions(&mut self, now_unix: u64) {
        self.sessions
            .retain(|_, session| !session.is_expired(now_unix));
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
    pub fn send_keepalive(&mut self, _peer_node_id: &NodeId) -> Result<(), RelayClientError> {
        // D3: relay frames flow on the WireGuard backend's authoritative
        // UDP socket. Use `send_keepalive_with_sender` and pass the
        // controller's authoritative_transport_send closure instead.
        Err(RelayClientError::AuthoritativeTransport(
            "RelayClient::send_keepalive called without an authoritative transport — \
             production callers must use send_keepalive_with_sender and supply the \
             WireGuard backend's authoritative transport sender (D3 contract)"
                .to_owned(),
        ))
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

#[cfg(test)]
fn recv_relay_response_with_deadline<F>(
    relay_addr: SocketAddr,
    timeout: Duration,
    mut recv_from: F,
) -> Result<(Vec<u8>, SocketAddr), RelayClientError>
where
    F: FnMut(Duration, &mut [u8]) -> io::Result<(usize, SocketAddr)>,
{
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(RelayClientError::Timeout)?;
    let mut buf = [0u8; 1500];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(RelayClientError::Timeout);
        }
        match recv_from(deadline.saturating_duration_since(now), &mut buf) {
            Ok((len, from_addr)) if from_addr == relay_addr => {
                return Ok((buf[..len].to_vec(), from_addr));
            }
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                return Err(RelayClientError::Timeout);
            }
            Err(e) => return Err(RelayClientError::Io(e)),
        }
    }
}

fn validate_issued_relay_session_token(
    token: &RelaySessionToken,
    node_id: &NodeId,
    peer_node_id: &NodeId,
    relay_id: [u8; 16],
    requested_ttl_secs: u64,
    now_unix: u64,
) -> Result<(), RelayClientError> {
    let invalid = |reason: String| {
        RelayClientError::TokenSigning(format!(
            "relay token issuer returned invalid token: {reason}"
        ))
    };
    if token.node_id != node_id.as_str() {
        return Err(invalid("node_id mismatch".to_owned()));
    }
    if token.peer_node_id != peer_node_id.as_str() {
        return Err(invalid("peer_node_id mismatch".to_owned()));
    }
    if token.relay_id != relay_id {
        return Err(invalid("relay_id mismatch".to_owned()));
    }
    if token.scope != RELAY_TOKEN_SCOPE {
        return Err(invalid("scope mismatch".to_owned()));
    }
    if token.nonce == [0u8; 16] {
        return Err(invalid("nonce must not be all zero".to_owned()));
    }
    let ttl_secs = token.ttl_secs();
    if ttl_secs == 0 || ttl_secs > MAX_RELAY_SESSION_TOKEN_TTL_SECS {
        return Err(invalid(format!(
            "ttl must be 1..={MAX_RELAY_SESSION_TOKEN_TTL_SECS} seconds"
        )));
    }
    if ttl_secs > requested_ttl_secs {
        return Err(invalid("ttl exceeds requested ttl".to_owned()));
    }
    if token.expires_at_unix <= now_unix {
        return Err(invalid("token already expired".to_owned()));
    }
    if token.issued_at_unix > now_unix.saturating_add(RELAY_SESSION_TOKEN_CLIENT_CLOCK_SKEW_SECS) {
        return Err(invalid("issued_at_unix too far in the future".to_owned()));
    }
    Ok(())
}

fn validate_preissued_token_spool_dir(path: &Path) -> Result<(), RelayClientError> {
    if !path.is_absolute() {
        return Err(RelayClientError::TokenSigning(
            "relay token spool dir must be absolute".to_owned(),
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        RelayClientError::TokenSigning(format!("stat relay token spool dir failed: {err}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(RelayClientError::TokenSigning(
            "relay token spool dir must be a real directory".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(RelayClientError::TokenSigning(format!(
                "relay token spool dir permissions too broad: {mode:o}"
            )));
        }
    }
    Ok(())
}

fn read_preissued_relay_token(path: &Path) -> Result<RelaySessionToken, RelayClientError> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        RelayClientError::TokenSigning(format!("stat relay token artifact failed: {err}"))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(RelayClientError::TokenSigning(
            "relay token artifact must be a regular file".to_owned(),
        ));
    }
    if metadata.len() == 0 || metadata.len() > PREISSUED_RELAY_TOKEN_MAX_BYTES {
        return Err(RelayClientError::TokenSigning(
            "relay token artifact size is invalid".to_owned(),
        ));
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(RelayClientError::TokenSigning(format!(
                "relay token artifact permissions too broad: {mode:o}"
            )));
        }
    }
    let wire = fs::read_to_string(path).map_err(|err| {
        RelayClientError::TokenSigning(format!("read relay token artifact failed: {err}"))
    })?;
    parse_relay_session_token_wire(&wire).map_err(|err| {
        RelayClientError::TokenSigning(format!("parse relay token artifact failed: {err}"))
    })
}

/// Wall-clock seconds since UNIX_EPOCH.
///
/// **Security**: previously used `.expect(...)` which would panic
/// the daemon process if the system clock had been rolled back
/// before UNIX_EPOCH (boards with no RTC during very early boot,
/// misconfigured NTP, operator-run `date --set=...`). Now returns
/// 0 on failure, which makes any relay session token's
/// `expires_at_unix > 0` look already-expired — fail-closed. The
/// daemon stays up; the keepalive/relay paths just refuse to mint
/// new tokens until the clock recovers.
fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Serializes a `RelayHello` message for wire transmission.
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

/// Serializes a `RelaySessionToken` for wire transmission.
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

/// Parses a `RelayHelloAck` from wire format.
fn parse_relay_hello_ack(data: &[u8]) -> Result<RelayHelloAck, String> {
    if data.is_empty() {
        return Err("empty response".to_owned());
    }

    match data[0] {
        RELAY_HELLO_ACK_MSG_TYPE => {
            if data.len() < 19 {
                return Err("ack message too short".to_owned());
            }
            if data.len() != 19 {
                return Err("ack message has trailing bytes".to_owned());
            }
            // Session ID (16 bytes)
            let session_id_bytes: [u8; 16] =
                data[1..17].try_into().map_err(|_| "invalid session id")?;
            if session_id_bytes == [0u8; 16] {
                return Err("ack session id must not be all zero".to_owned());
            }
            let session_id = SessionId::from(session_id_bytes);

            // Allocated port (2 bytes)
            let port_bytes: [u8; 2] = data[17..19].try_into().map_err(|_| "invalid port")?;
            let allocated_port = u16::from_be_bytes(port_bytes);
            if allocated_port == 0 {
                return Err("ack allocated port must not be 0".to_owned());
            }

            Ok(RelayHelloAck {
                session_id,
                allocated_port,
            })
        }
        RELAY_REJECT_MSG_TYPE => {
            let reason = if data.len() > 1 {
                String::from_utf8_lossy(&data[1..]).to_string()
            } else {
                "unknown".to_owned()
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
        NodeId::new(value.to_owned()).expect("test node id should parse")
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
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
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
    fn parse_relay_hello_ack_rejects_malformed_ack_fields() {
        let valid_session_id = [0x55; 16];

        let mut zero_port = vec![RELAY_HELLO_ACK_MSG_TYPE];
        zero_port.extend_from_slice(&valid_session_id);
        zero_port.extend_from_slice(&0u16.to_be_bytes());
        assert!(
            parse_relay_hello_ack(&zero_port)
                .expect_err("zero allocated port must fail")
                .contains("port")
        );

        let mut zero_session = vec![RELAY_HELLO_ACK_MSG_TYPE];
        zero_session.extend_from_slice(&[0u8; 16]);
        zero_session.extend_from_slice(&5000u16.to_be_bytes());
        assert!(
            parse_relay_hello_ack(&zero_session)
                .expect_err("zero session id must fail")
                .contains("session id")
        );

        let mut trailing = vec![RELAY_HELLO_ACK_MSG_TYPE];
        trailing.extend_from_slice(&valid_session_id);
        trailing.extend_from_slice(&5000u16.to_be_bytes());
        trailing.push(0);
        assert!(
            parse_relay_hello_ack(&trailing)
                .expect_err("trailing bytes must fail")
                .contains("trailing")
        );
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
    fn local_relay_session_token_issuer_signs_bound_token() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[8u8; 32]));
        let issuer = LocalRelaySessionTokenIssuer::new(Arc::clone(&signing_key));
        let relay_id = [0xCC; 16];
        let token = issuer
            .issue_token(
                &test_node_id("node-a"),
                &test_node_id("peer-b"),
                relay_id,
                60,
            )
            .expect("local issuer should sign token");

        assert_eq!(token.node_id, "node-a");
        assert_eq!(token.peer_node_id, "peer-b");
        assert_eq!(token.relay_id, relay_id);
        token
            .verify_signature(&signing_key.verifying_key())
            .expect("token should verify");
    }

    #[test]
    fn preissued_relay_session_token_issuer_consumes_matching_signed_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let relay_id = [0xCC; 16];
        let token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            relay_id,
            current_unix(),
            60,
        );
        let token_path = dir.path().join("0001.relay-token");
        fs::write(
            &token_path,
            rustynet_control::relay_session_token_to_wire(&token),
        )
        .expect("write token");
        #[cfg(unix)]
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();

        let issuer = PreissuedRelaySessionTokenIssuer::new(
            dir.path().to_path_buf(),
            signing_key.verifying_key(),
        )
        .expect("restricted spool should be accepted");
        let issued = issuer
            .issue_token(
                &test_node_id("node-a"),
                &test_node_id("peer-b"),
                relay_id,
                60,
            )
            .expect("matching preissued token should issue");

        assert!(token.ct_eq(&issued));
        assert!(!token_path.exists(), "token artifact must be one-use");
    }

    #[test]
    fn preissued_relay_session_token_issuer_rejects_tampered_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let relay_id = [0xCC; 16];
        let token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            relay_id,
            current_unix(),
            60,
        );
        let token_path = dir.path().join("0001.relay-token");
        let wire = rustynet_control::relay_session_token_to_wire(&token)
            .replace("peer_node_id=peer-b", "peer_node_id=peer-c");
        fs::write(&token_path, wire).expect("write token");
        #[cfg(unix)]
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();

        let issuer = PreissuedRelaySessionTokenIssuer::new(
            dir.path().to_path_buf(),
            signing_key.verifying_key(),
        )
        .expect("restricted spool should be accepted");
        let err = issuer
            .issue_token(
                &test_node_id("node-a"),
                &test_node_id("peer-b"),
                relay_id,
                60,
            )
            .expect_err("tampered token must fail closed");

        assert!(err.to_string().contains("signature invalid"));
        assert!(
            token_path.exists(),
            "rejected token artifact must remain for audit"
        );
    }

    struct FailingRelaySessionTokenIssuer;

    impl RelaySessionTokenIssuer for FailingRelaySessionTokenIssuer {
        fn issue_token(
            &self,
            _node_id: &NodeId,
            _peer_node_id: &NodeId,
            _relay_id: [u8; 16],
            _ttl_secs: u64,
        ) -> Result<RelaySessionToken, RelayClientError> {
            Err(RelayClientError::TokenSigning(
                "issuer unavailable".to_owned(),
            ))
        }
    }

    struct StaticRelaySessionTokenIssuer {
        token: RelaySessionToken,
    }

    impl RelaySessionTokenIssuer for StaticRelaySessionTokenIssuer {
        fn issue_token(
            &self,
            _node_id: &NodeId,
            _peer_node_id: &NodeId,
            _relay_id: [u8; 16],
            _ttl_secs: u64,
        ) -> Result<RelaySessionToken, RelayClientError> {
            Ok(self.token.clone())
        }
    }

    #[test]
    fn relay_client_fails_closed_when_token_issuer_fails() {
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(FailingRelaySessionTokenIssuer),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60,
                |_target, _hello, _timeout| unreachable!("token failure must happen before I/O"),
            )
            .expect_err("token issuer failure must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_unbound_issuer_token_before_io() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "wrong-peer",
            [0xCC; 16],
            current_unix(),
            60,
        );
        token.scope = RELAY_TOKEN_SCOPE.to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60,
                |_target, _hello, _timeout| {
                    unreachable!("issuer token validation must happen before I/O")
                },
            )
            .expect_err("unbound issuer token must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("peer_node_id mismatch"));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_stale_or_oversized_issuer_token_before_io() {
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let peer_id = test_node_id("peer-b");
        let now = current_unix();

        for (token, expected) in [
            (
                RelaySessionToken::sign_at(
                    &signing_key,
                    "node-a",
                    "peer-b",
                    [0xCC; 16],
                    now.saturating_sub(120),
                    60,
                ),
                "already expired",
            ),
            (
                RelaySessionToken::sign_at(
                    &signing_key,
                    "node-a",
                    "peer-b",
                    [0xCC; 16],
                    now,
                    MAX_RELAY_SESSION_TOKEN_TTL_SECS + 1,
                ),
                "ttl must",
            ),
            (
                RelaySessionToken::sign_at(
                    &signing_key,
                    "node-a",
                    "peer-b",
                    [0xCC; 16],
                    now.saturating_add(RELAY_SESSION_TOKEN_CLIENT_CLOCK_SKEW_SECS + 1),
                    60,
                ),
                "future",
            ),
        ] {
            let mut client = RelayClient::new_with_token_issuer(
                test_node_id("node-a"),
                Arc::new(StaticRelaySessionTokenIssuer { token }),
                RelayClientConfig::default(),
            );
            let err = client
                .establish_session_with_round_trip(
                    &peer_id,
                    "192.168.1.1:4500".parse().unwrap(),
                    [0xCC; 16],
                    60,
                    |_target, _hello, _timeout| {
                        unreachable!("issuer token validation must happen before I/O")
                    },
                )
                .expect_err("invalid issuer token must fail closed");

            assert!(matches!(err, RelayClientError::TokenSigning(_)));
            assert!(
                err.to_string().contains(expected),
                "expected '{expected}' in '{err}'"
            );
            assert!(!client.has_session(&peer_id));
        }
    }

    #[test]
    fn relay_client_rejects_token_ttl_outside_relay_bounds_before_io() {
        let peer_id = test_node_id("peer-b");
        let signing_key = Arc::new(SigningKey::from_bytes(&[9u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );

        for ttl_secs in [0, MAX_RELAY_SESSION_TOKEN_TTL_SECS + 1] {
            let err = client
                .establish_session_with_round_trip(
                    &peer_id,
                    "192.168.1.1:4500".parse().unwrap(),
                    [0xCC; 16],
                    ttl_secs,
                    |_target, _hello, _timeout| {
                        unreachable!("ttl validation must happen before I/O")
                    },
                )
                .expect_err("out-of-bounds relay token ttl must fail closed");
            assert!(matches!(err, RelayClientError::TokenSigning(_)));
            assert!(!client.has_session(&peer_id));
        }
    }

    #[test]
    fn relay_client_rejects_token_with_node_id_mismatch_before_io() {
        // The token's own `node_id` field must match the client's node_id.
        // A token issued for a different node would let an attacker who
        // captured it impersonate that node against the relay.
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "wrong-node",
            "peer-b",
            [0xCC; 16],
            current_unix(),
            60,
        );
        token.scope = RELAY_TOKEN_SCOPE.to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60,
                |_target, _hello, _timeout| {
                    unreachable!("node_id validation must happen before I/O")
                },
            )
            .expect_err("token with node_id mismatch must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("node_id mismatch"));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_token_with_relay_id_mismatch_before_io() {
        // The token must be bound to the same relay_id the client is connecting
        // to.  A token issued for relay-A must not be redeemable at relay-B,
        // even if both are in the same signed fleet.
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            [0xAA; 16], // token bound to relay-AA
            current_unix(),
            60,
        );
        token.scope = RELAY_TOKEN_SCOPE.to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xBB; 16], // client requesting relay-BB
                60,
                |_target, _hello, _timeout| {
                    unreachable!("relay_id validation must happen before I/O")
                },
            )
            .expect_err("token with relay_id mismatch must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("relay_id mismatch"));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_token_with_wrong_scope_before_io() {
        // The token must carry the canonical relay-session scope label so a
        // token forged with a different scope (e.g. one issued for a separate
        // ceremony) cannot be replayed against the relay session protocol.
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            [0xCC; 16],
            current_unix(),
            60,
        );
        token.scope = "rustynet.relay.OTHER_SCOPE".to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60,
                |_target, _hello, _timeout| unreachable!("scope validation must happen before I/O"),
            )
            .expect_err("token with wrong scope must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("scope mismatch"));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_token_with_all_zero_nonce_before_io() {
        // An all-zero nonce is the signature of a forged or uninitialised
        // token — any genuine token signed with a CSPRNG will have a non-zero
        // nonce.  Accepting an all-zero nonce would let an attacker who
        // controlled the issuer trivially construct tokens with predictable
        // bytes (and risk replay if the relay caches by nonce).
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            [0xCC; 16],
            current_unix(),
            60,
        );
        // Force the nonce to all zeros after signing.
        token.nonce = [0u8; 16];
        token.scope = RELAY_TOKEN_SCOPE.to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60,
                |_target, _hello, _timeout| unreachable!("nonce validation must happen before I/O"),
            )
            .expect_err("token with all-zero nonce must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("nonce"));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_client_rejects_token_with_ttl_exceeding_requested_ttl_before_io() {
        // The token's encoded TTL must not exceed the TTL the client asked
        // the issuer for — otherwise an issuer-side bug or compromise could
        // grant a longer-lived session than the client is willing to hold.
        let signing_key = SigningKey::from_bytes(&[9u8; 32]);
        let mut token = RelaySessionToken::sign_at(
            &signing_key,
            "node-a",
            "peer-b",
            [0xCC; 16],
            current_unix(),
            120, // token TTL = 120s
        );
        token.scope = RELAY_TOKEN_SCOPE.to_owned();
        let peer_id = test_node_id("peer-b");
        let mut client = RelayClient::new_with_token_issuer(
            test_node_id("node-a"),
            Arc::new(StaticRelaySessionTokenIssuer { token }),
            RelayClientConfig::default(),
        );

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                "192.168.1.1:4500".parse().unwrap(),
                [0xCC; 16],
                60, // client only asked for 60s
                |_target, _hello, _timeout| {
                    unreachable!("ttl-exceeds validation must happen before I/O")
                },
            )
            .expect_err("token TTL exceeding requested TTL must fail closed");

        assert!(matches!(err, RelayClientError::TokenSigning(_)));
        assert!(err.to_string().contains("ttl exceeds requested"));
        assert!(!client.has_session(&peer_id));
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
    fn relay_client_cleanup_inactive_removes_expired_sessions() {
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

        let expired_peer = test_node_id("peer-expired");
        client.sessions.insert(
            expired_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x34; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5001,
                peer_node_id: expired_peer.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix,
            },
        );

        let live_peer = test_node_id("peer-live");
        client.sessions.insert(
            live_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x35; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5002,
                peer_node_id: live_peer.clone(),
                established_at: Instant::now(),
                last_activity: Instant::now(),
                relay_id: [0xAA; 16],
                token_expires_at_unix: now_unix + 60,
            },
        );

        client.cleanup_inactive_sessions(Duration::from_secs(60), now_unix);

        assert!(!client.has_session(&expired_peer));
        assert!(client.has_session(&live_peer));
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
    fn relay_client_establish_round_trip_timeout_leaves_no_session() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[10u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                relay_addr,
                [0xAA; 16],
                60,
                |_target, _payload, _timeout| Err(RelayClientError::Timeout),
            )
            .expect_err("relay timeout must fail closed");

        assert!(matches!(err, RelayClientError::Timeout));
        assert!(!client.has_session(&peer_id));
    }

    #[test]
    fn relay_response_deadline_returns_timeout_on_socket_timeout() {
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let err = recv_relay_response_with_deadline(
            relay_addr,
            Duration::from_secs(1),
            |_remaining, _buf| Err(io::Error::new(io::ErrorKind::TimedOut, "synthetic timeout")),
        )
        .expect_err("socket timeout must terminate relay response wait");

        assert!(matches!(err, RelayClientError::Timeout));
    }

    #[test]
    fn relay_response_deadline_ignores_unrelated_source_then_times_out() {
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let unrelated_addr: SocketAddr = "192.168.1.2:4500".parse().unwrap();
        let mut calls = 0usize;

        let err = recv_relay_response_with_deadline(
            relay_addr,
            Duration::from_secs(1),
            |_remaining, buf| {
                calls += 1;
                if calls == 1 {
                    buf[..3].copy_from_slice(b"ack");
                    Ok((3, unrelated_addr))
                } else {
                    Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "synthetic timeout",
                    ))
                }
            },
        )
        .expect_err("unrelated relay response source must not satisfy establishment");

        assert!(matches!(err, RelayClientError::Timeout));
        assert_eq!(calls, 2);
    }

    #[test]
    fn relay_client_rejects_ack_allocating_control_port() {
        let signing_key = Arc::new(SigningKey::from_bytes(&[10u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let session_id = [0x66; 16];

        let err = client
            .establish_session_with_round_trip(
                &peer_id,
                relay_addr,
                [0xAA; 16],
                60,
                |_target, _payload, _timeout| {
                    let mut ack = vec![RELAY_HELLO_ACK_MSG_TYPE];
                    ack.extend_from_slice(&session_id);
                    ack.extend_from_slice(&relay_addr.port().to_be_bytes());
                    Ok((ack, relay_addr))
                },
            )
            .expect_err("control-port allocation must fail closed");

        assert!(matches!(err, RelayClientError::InvalidResponse(_)));
        assert!(!client.has_session(&peer_id));
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
    fn relay_client_attach_authoritative_transport_marks_bound() {
        // D3 pin: the relay client is bound when (and only when) the
        // daemon explicitly attaches it to the WireGuard backend's
        // authoritative transport socket. No separate ephemeral
        // socket is involved.
        let signing_key = Arc::new(SigningKey::from_bytes(&[123u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        assert!(
            !client.is_bound(),
            "fresh client must not be bound until authoritative transport is attached"
        );
        client
            .attach_authoritative_transport(51820)
            .expect("attach succeeds when no port mismatch");
        assert!(
            client.is_bound(),
            "after attach_authoritative_transport, is_bound() must return true"
        );
    }

    #[test]
    fn relay_client_attach_authoritative_transport_rejects_port_mismatch() {
        // D3 pin: if the relay client config carries a `local_port`,
        // attach must verify it matches the WG transport port the
        // daemon supplies. A mismatch indicates a misconfiguration
        // (the relay client was wired to a different socket than the
        // direct path) — fail closed.
        let signing_key = Arc::new(SigningKey::from_bytes(&[124u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig {
                local_port: Some(51820),
                ..Default::default()
            },
        );
        let err = client
            .attach_authoritative_transport(40000)
            .expect_err("port mismatch must be rejected");
        match err {
            RelayClientError::AuthoritativeTransport(msg) => {
                assert!(
                    msg.contains("51820") && msg.contains("40000"),
                    "error must surface both ports for diagnostics, got: {msg}"
                );
            }
            other => panic!("expected AuthoritativeTransport, got {other:?}"),
        }
        assert!(
            !client.is_bound(),
            "after a rejected attach, the client must remain unbound"
        );
    }

    #[test]
    fn relay_client_establish_session_without_authoritative_transport_fails_closed() {
        // D3 pin: production callers must use
        // `establish_session_with_round_trip`. The convenience
        // `establish_session` method MUST refuse to fall back to a
        // private socket — it returns AuthoritativeTransport instead.
        let signing_key = Arc::new(SigningKey::from_bytes(&[125u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let relay_addr: SocketAddr = "192.168.1.1:4500".parse().unwrap();
        let err = client
            .establish_session(&peer_id, relay_addr, [0xAA; 16], 60)
            .expect_err("must refuse without authoritative transport");
        assert!(
            matches!(err, RelayClientError::AuthoritativeTransport(_)),
            "expected AuthoritativeTransport, got: {err:?}"
        );
    }

    #[test]
    fn relay_client_send_keepalive_without_authoritative_transport_fails_closed() {
        // D3 pin counterpart for the keepalive path.
        let signing_key = Arc::new(SigningKey::from_bytes(&[126u8; 32]));
        let mut client = RelayClient::new(
            test_node_id("node-a"),
            signing_key,
            RelayClientConfig::default(),
        );
        let peer_id = test_node_id("peer-b");
        let err = client
            .send_keepalive(&peer_id)
            .expect_err("must refuse without authoritative transport");
        assert!(
            matches!(err, RelayClientError::AuthoritativeTransport(_)),
            "expected AuthoritativeTransport, got: {err:?}"
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
    fn relay_client_cleanup_preserves_live_sessions_removes_inactive() {
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

        let expired_peer = test_node_id("expired-peer");
        client.sessions.insert(
            expired_peer.clone(),
            RelayClientSession {
                session_id: SessionId::from([0x33; 16]),
                relay_addr: "192.168.1.1:4500".parse().unwrap(),
                allocated_port: 5002,
                peer_node_id: expired_peer.clone(),
                established_at: Instant::now() - Duration::from_secs(10),
                last_activity: Instant::now() - Duration::from_secs(5),
                relay_id: [0xCC; 16],
                token_expires_at_unix: now_unix,
            },
        );

        assert_eq!(client.active_session_count(), 3);

        // Cleanup with 60-second idle threshold
        client.cleanup_inactive_sessions(Duration::from_secs(60), now_unix);

        // Live session should remain, idle and expired sessions should be removed
        assert_eq!(client.active_session_count(), 1);
        assert!(client.has_session(&live_peer));
        assert!(!client.has_session(&idle_peer));
        assert!(!client.has_session(&expired_peer));
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

    /// Verifies that `remove_session` correctly removes a specific session,
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
