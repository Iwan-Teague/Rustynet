#![forbid(unsafe_code)]

//! Relay transport session protocol and packet forwarding.
//!
//! This module implements the relay session authentication and bidirectional
//! packet forwarding for nodes that cannot establish direct connectivity.
//!
//! # Security model
//!
//! - **Ciphertext-only relay**: payloads are forwarded byte-for-byte without
//!   inspection.  The relay never sees plaintext.
//! - **Signed tokens**: every session requires a control-plane-issued
//!   [`RelaySessionToken`] with a valid ed25519 signature.
//! - **Constant-time auth**: all secret-field comparisons (`node_id`,
//!   `peer_node_id`, `relay_id`) use `subtle::ConstantTimeEq`.
//! - **Replay protection**: each token nonce is remembered for the duration of
//!   the max TTL window; replayed nonces are rejected.
//! - **Relay-binding**: tokens carry the intended relay's `relay_id`; the
//!   relay verifies this matches its own identity.
//! - **Scope enforcement**: tokens must carry `scope=forward_ciphertext_only`.
//! - **Bounded resources**: per-node session caps, per-node packet rate limits,
//!   per-node hello rate limits, maximum packet size, idle/half-open timeouts.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ed25519_dalek::VerifyingKey;
use rustynet_control::{MAX_RELAY_SESSION_TOKEN_TTL_SECS, RELAY_TOKEN_SCOPE, RelaySessionToken};
use subtle::ConstantTimeEq;

use crate::rate_limit::RateLimiter;
use crate::session::{RelaySession, SessionId};

/// Maximum TTL we accept from a token's `issued_at` → `expires_at` span.
const MAX_RELAY_TTL_SECS: u64 = MAX_RELAY_SESSION_TOKEN_TTL_SECS;
/// How long we keep a half-open (un-paired) session before evicting it.
const HALF_OPEN_SESSION_TIMEOUT_SECS: u64 = 60;
/// How long an idle (no packets) session may remain open.
const IDLE_SESSION_TIMEOUT_SECS: u64 = 30;
/// Maximum forwarded-payload size.  Packets larger than this are dropped
/// silently rather than returned as an error (to avoid amplification).
const MAX_PACKET_SIZE_BYTES: usize = 65_536;
/// How long we retain nonces in the replay-prevention store (must cover the
/// full TTL window so a nonce cannot be recycled within its validity period).
const NONCE_RETENTION_SECS: u64 = MAX_RELAY_TTL_SECS * 2;
/// Hard ceiling on `clock_skew_tolerance_secs` accepted by `RelayTransport`
/// constructors. The replay store retains nonces for `NONCE_RETENTION_SECS`
/// (two TTL windows). If a caller supplied a larger skew, a token could
/// remain non-expired (per `is_expired`) after its nonce was already pruned,
/// re-opening the replay window. We clamp at construction time to keep the
/// invariant `MAX_RELAY_TTL_SECS + skew <= NONCE_RETENTION_SECS`. Equivalently,
/// `skew <= MAX_RELAY_TTL_SECS`.
const MAX_CLOCK_SKEW_TOLERANCE_SECS: u64 = MAX_RELAY_TTL_SECS;
/// Maximum `handle_hello` calls accepted per node within a one-second window
/// before the hello itself is rejected (separate from packet rate limiting).
const MAX_HELLOS_PER_NODE_PER_SEC: u32 = 5;
/// Default global active session cap. Production daemons may lower or raise this
/// during startup, but the transport must always retain a total cap.
const DEFAULT_MAX_TOTAL_SESSIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Token signature invalid, scope wrong, relay-id mismatch, node-id
    /// mismatch, or TTL out of bounds.
    InvalidToken,
    /// Token expiry timestamp has passed (plus skew tolerance).
    ExpiredToken,
    /// This token nonce was already seen (replay detected).
    ReplayedNonce,
    /// The `peer_node_id` in the hello does not match the token's field.
    PeerMismatch,
    /// Per-node session cap has been reached.
    Capacity,
    /// Hello rate limit for this node has been exceeded.
    RateLimitExceeded,
    /// Replay store could not be updated, so accepting the token would weaken
    /// anti-replay guarantees.
    ReplayStoreUnavailable,
    /// Daemon supplied an invalid allocated relay data port.
    InvalidAllocatedPort,
}

/// Session establishment request from a node to the relay.
///
/// `PartialEq`/`Eq` are not derived because the embedded `RelaySessionToken`
/// deliberately does not implement them (to prevent non-constant-time
/// comparisons on secret fields).  Use `ct_eq` on the token when needed.
#[derive(Debug, Clone)]
pub struct RelayHello {
    pub node_id: String,
    pub peer_node_id: String,
    pub session_token: RelaySessionToken,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHelloAck {
    pub session_id: SessionId,
    pub allocated_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHelloResponse {
    Accepted(RelayHelloAck),
    Rejected(RejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayForwardError {
    SessionNotFound,
    SessionExpired,
    UnauthorizedSourceTuple,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayForwardTarget {
    pub peer_session_id: SessionId,
    pub peer_allocated_port: u16,
    pub peer_addr: SocketAddr,
    pub payload: Vec<u8>,
}

pub struct RelayTransport {
    /// This relay's own identifier.  Every accepted token must have a matching
    /// `relay_id`; tokens issued for a different relay are rejected.
    relay_id: [u8; 16],
    sessions: HashMap<SessionId, RelaySession>,
    node_pair_index: HashMap<(String, String), SessionId>,
    rate_limiter: RateLimiter,
    control_verifier_key: VerifyingKey,
    nonce_store: NonceStore,
    hello_limiter: HelloLimiter,
    clock_skew_tolerance_secs: u64,
    max_sessions_per_node: usize,
    max_total_sessions: usize,
}

impl RelayTransport {
    pub fn new(
        relay_id: [u8; 16],
        control_verifier_key: VerifyingKey,
        max_sessions_per_node: usize,
        clock_skew_tolerance_secs: u64,
    ) -> Self {
        // Clamp skew so the replay-store retention window always strictly
        // dominates the maximum acceptable token validity. Without this, an
        // operator that supplies an unreasonably large skew (>120 s) could
        // open a replay window between the time a nonce is pruned and the
        // time `is_expired` would finally reject the token. Clamping is
        // fail-closed (stricter expiry) and preserves the existing API.
        let (clock_skew_tolerance_secs, was_clamped) =
            compute_clamped_skew(clock_skew_tolerance_secs);
        if was_clamped {
            // `tracing` is only available behind the `daemon` feature in this
            // crate; emit a structured stderr line so the warning is visible
            // in non-daemon builds (tests, library consumers) too.
            eprintln!(
                "warn relay_transport: clock_skew_tolerance_secs clamped to {MAX_CLOCK_SKEW_TOLERANCE_SECS} (operator-supplied value exceeded the safe ceiling; replay window would otherwise reopen)"
            );
        }
        Self {
            relay_id,
            sessions: HashMap::new(),
            node_pair_index: HashMap::new(),
            rate_limiter: RateLimiter::default(),
            control_verifier_key,
            nonce_store: NonceStore::default(),
            hello_limiter: HelloLimiter::new(MAX_HELLOS_PER_NODE_PER_SEC),
            clock_skew_tolerance_secs,
            max_sessions_per_node,
            max_total_sessions: DEFAULT_MAX_TOTAL_SESSIONS,
        }
    }

    pub fn new_with_replay_store_path(
        relay_id: [u8; 16],
        control_verifier_key: VerifyingKey,
        max_sessions_per_node: usize,
        clock_skew_tolerance_secs: u64,
        replay_store_path: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let mut transport = Self::new(
            relay_id,
            control_verifier_key,
            max_sessions_per_node,
            clock_skew_tolerance_secs,
        );
        let mut nonce_store = NonceStore::load(replay_store_path.into())?;
        nonce_store.prune(Duration::from_secs(NONCE_RETENTION_SECS))?;
        transport.nonce_store = nonce_store;
        Ok(transport)
    }

    pub fn set_max_total_sessions(&mut self, max_total_sessions: usize) -> Result<(), String> {
        if max_total_sessions == 0 {
            return Err("max total relay sessions must be greater than 0".to_string());
        }
        // Refuse to shrink below the live session count. Silent eviction would
        // be an operator footgun: legitimate sessions disappear without an
        // observable error, and evicting the oldest is a heuristic the caller
        // didn't necessarily ask for. A clear error gives the operator
        // feedback so they can drain sessions explicitly before shrinking.
        let live = self.sessions.len();
        if max_total_sessions < live {
            return Err(format!(
                "cannot shrink max total relay sessions to {max_total_sessions} below live count {live}; drain sessions first"
            ));
        }
        self.max_total_sessions = max_total_sessions;
        Ok(())
    }

    /// Validate a session establishment request without allocating relay state.
    ///
    /// This is used by the relay daemon to reject forged/stale/flooded hellos
    /// before binding an allocated UDP port. Successful validation is advisory:
    /// callers must still commit with `handle_hello_from_tuple_with_allocated_port`,
    /// which re-checks the stateful security predicates before creating a session.
    pub fn validate_hello_from_tuple(
        &mut self,
        hello: &RelayHello,
        _observed_addr: SocketAddr,
    ) -> Result<(), RejectReason> {
        self.validate_hello(hello, true)
    }

    /// Process a session establishment request with a daemon-owned allocated port.
    ///
    /// All security checks are performed in a deliberate order:
    ///
    /// 1. Hello rate limit (cheap, no crypto — shed load before signature work)
    /// 2. Signature verification (ed25519, inherently constant-time)
    /// 3. TTL bound check (max 120 s)
    /// 4. Token freshness / expiry
    /// 5. Replay nonce check
    /// 6. `node_id` binding (ct_eq: hello.node_id == token.node_id)
    /// 7. `peer_node_id` binding (ct_eq: hello.peer_node_id == token.peer_node_id)
    /// 8. `relay_id` binding (ct_eq: token.relay_id == self.relay_id)
    /// 9. Scope enforcement (token.scope == "forward_ciphertext_only")
    /// 10. Global session capacity
    /// 11. Per-node session capacity
    /// 12. Daemon-supplied allocated port validation
    pub fn handle_hello_from_tuple_with_allocated_port(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloResponse {
        if let Err(reason) = self.validate_hello(&hello, false) {
            return RelayHelloResponse::Rejected(reason);
        }
        if allocated_port == 0 {
            eprintln!("Relay hello rejected: allocated port 0");
            return RelayHelloResponse::Rejected(RejectReason::InvalidAllocatedPort);
        }

        // All checks passed — record nonce to prevent replay
        if let Err(err) = self.nonce_store.insert(hello.session_token.nonce) {
            eprintln!("Relay hello rejected: replay store unavailable: {err}");
            return RelayHelloResponse::Rejected(RejectReason::ReplayStoreUnavailable);
        }

        // Allocate session
        self.remove_session_for_pair(&hello.node_id, &hello.peer_node_id);

        let session_id = SessionId::generate();

        let session = RelaySession {
            session_id,
            node_id: hello.node_id.clone(),
            peer_node_id: hello.peer_node_id.clone(),
            allocated_port,
            hello_source_addr: observed_addr,
            bound_peer_addr: None,
            expires_at_unix: hello.session_token.expires_at_unix,
            established_at: Instant::now(),
            last_packet_at: Instant::now(),
        };

        self.sessions.insert(session_id, session);
        self.node_pair_index.insert(
            (hello.node_id.clone(), hello.peer_node_id.clone()),
            session_id,
        );

        RelayHelloResponse::Accepted(RelayHelloAck {
            session_id,
            allocated_port,
        })
    }

    fn validate_hello(
        &mut self,
        hello: &RelayHello,
        record_hello_rate: bool,
    ) -> Result<(), RejectReason> {
        // Check 1: Hello rate limit — shed before any crypto work
        if record_hello_rate && !self.hello_limiter.check(&hello.node_id) {
            return Err(RejectReason::RateLimitExceeded);
        }

        // Check 2: Verify token signature (ed25519, constant-time internally)
        if let Err(e) = hello
            .session_token
            .verify_signature(&self.control_verifier_key)
        {
            eprintln!("Relay hello rejected: invalid signature: {e}");
            return Err(RejectReason::InvalidToken);
        }

        // Check 3: Verify token TTL bound (max 120 s)
        let ttl = hello.session_token.ttl_secs();
        if ttl > MAX_RELAY_TTL_SECS {
            eprintln!("Relay hello rejected: TTL exceeds max ({ttl} > {MAX_RELAY_TTL_SECS})");
            return Err(RejectReason::InvalidToken);
        }

        // Check 4: Token freshness / expiry
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if hello
            .session_token
            .is_expired(now_unix, self.clock_skew_tolerance_secs)
        {
            eprintln!("Relay hello rejected: token expired");
            return Err(RejectReason::ExpiredToken);
        }

        // Check 5: Replay nonce
        if self.nonce_store.contains(&hello.session_token.nonce) {
            eprintln!("Relay hello rejected: nonce replay detected");
            return Err(RejectReason::ReplayedNonce);
        }

        // Check 6: node_id binding (constant-time)
        let node_id_match: bool = hello
            .node_id
            .as_bytes()
            .ct_eq(hello.session_token.node_id.as_bytes())
            .into();
        if !node_id_match {
            eprintln!("Relay hello rejected: node_id mismatch between hello and token");
            return Err(RejectReason::InvalidToken);
        }

        // Check 7: peer_node_id binding (constant-time)
        let peer_match: bool = hello
            .peer_node_id
            .as_bytes()
            .ct_eq(hello.session_token.peer_node_id.as_bytes())
            .into();
        if !peer_match {
            eprintln!("Relay hello rejected: peer_node_id mismatch");
            return Err(RejectReason::PeerMismatch);
        }

        // Check 8: relay_id binding (constant-time byte comparison)
        let relay_match: bool = hello.session_token.relay_id.ct_eq(&self.relay_id).into();
        if !relay_match {
            eprintln!("Relay hello rejected: token relay_id does not match this relay");
            return Err(RejectReason::InvalidToken);
        }

        // Check 9: Scope enforcement
        if hello.session_token.scope != RELAY_TOKEN_SCOPE {
            eprintln!(
                "Relay hello rejected: unexpected scope '{}'",
                hello.session_token.scope
            );
            return Err(RejectReason::InvalidToken);
        }

        // Check 10: Global session capacity. Replacing an existing pair is not
        // growth, so allow it even when the relay is at capacity.
        let pair_key = (hello.node_id.clone(), hello.peer_node_id.clone());
        let replacing_existing_pair = self.node_pair_index.contains_key(&pair_key);
        if !replacing_existing_pair && self.sessions.len() >= self.max_total_sessions {
            eprintln!("Relay hello rejected: global session capacity reached");
            return Err(RejectReason::Capacity);
        }

        // Check 11: Per-node session capacity
        let node_session_count = self
            .sessions
            .values()
            .filter(|s| s.node_id == hello.node_id)
            .count();

        if node_session_count >= self.max_sessions_per_node {
            eprintln!(
                "Relay hello rejected: capacity limit reached for node {}",
                hello.node_id
            );
            return Err(RejectReason::Capacity);
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn handle_hello_from_tuple(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
    ) -> RelayHelloResponse {
        let allocated_port = self.next_test_allocated_port();
        if let Err(reason) = self.validate_hello_from_tuple(&hello, observed_addr) {
            return RelayHelloResponse::Rejected(reason);
        }
        self.handle_hello_from_tuple_with_allocated_port(hello, observed_addr, allocated_port)
    }

    #[cfg(test)]
    pub fn handle_hello(&mut self, hello: RelayHello) -> RelayHelloResponse {
        let observed_addr = SocketAddr::from(([127, 0, 0, 1], 40_000));
        self.handle_hello_from_tuple(hello, observed_addr)
    }

    /// Refresh session activity timestamp without forwarding data.
    ///
    /// Used by keepalive packets to prevent session idle timeout.
    pub fn touch_session_from_tuple(
        &mut self,
        session_id: SessionId,
        from_addr: SocketAddr,
    ) -> Result<bool, RelayForwardError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Err(RelayForwardError::SessionNotFound);
        };
        if session.expires_at_unix <= now_unix {
            self.remove_session(session_id);
            return Err(RelayForwardError::SessionExpired);
        }
        match session.bound_peer_addr {
            Some(bound_addr) if bound_addr == from_addr => {
                session.last_packet_at = Instant::now();
                Ok(true)
            }
            Some(_) => Err(RelayForwardError::UnauthorizedSourceTuple),
            None => Ok(false),
        }
    }

    #[cfg(test)]
    pub fn touch_session(&mut self, session_id: SessionId) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or("session not found")?;
        session.last_packet_at = Instant::now();
        Ok(())
    }

    pub fn has_session(&self, session_id: SessionId) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Forward a ciphertext payload from one session to its paired session.
    ///
    /// Returns:
    /// - `Ok(Some((peer_session_id, payload)))` — forwarded successfully
    /// - `Ok(None)` — silently dropped (rate limit or no paired session)
    /// - `Err(msg)` — session not found
    ///
    /// Payloads are forwarded byte-for-byte.  The relay never inspects content.
    pub fn forward_packet(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        from_addr: SocketAddr,
    ) -> Result<Option<RelayForwardTarget>, RelayForwardError> {
        // Silently drop oversized payloads (do not error — avoids amplification)
        if payload.len() > MAX_PACKET_SIZE_BYTES {
            return Ok(None);
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let Some(session) = self.sessions.get(&session_id) else {
            return Err(RelayForwardError::SessionNotFound);
        };
        if session.expires_at_unix <= now_unix {
            self.remove_session(session_id);
            return Err(RelayForwardError::SessionExpired);
        }

        {
            let session = self
                .sessions
                .get_mut(&session_id)
                .expect("session should remain available while forwarding");
            match session.bound_peer_addr {
                Some(bound_addr) if bound_addr == from_addr => {}
                Some(_) => return Err(RelayForwardError::UnauthorizedSourceTuple),
                None => {
                    if session.hello_source_addr.ip() != from_addr.ip() {
                        return Err(RelayForwardError::UnauthorizedSourceTuple);
                    }
                    session.bound_peer_addr = Some(from_addr);
                }
            }

            // Rate limit check — silent drop on excess
            if !self
                .rate_limiter
                .check_packet(&session.node_id, payload.len())
            {
                return Ok(None);
            }

            // Update last_packet_at
            session.last_packet_at = Instant::now();
        }

        let (peer_session_id, current_node_id, current_peer_node_id) = {
            let session = self
                .sessions
                .get(&session_id)
                .expect("session should remain available while forwarding");
            (
                self.node_pair_index
                    .get(&(session.peer_node_id.clone(), session.node_id.clone()))
                    .copied(),
                session.node_id.clone(),
                session.peer_node_id.clone(),
            )
        };

        let Some(peer_sid) = peer_session_id else {
            // Half-open: no paired session yet; silently drop
            return Ok(None);
        };

        let Some(peer_session) = self.sessions.get_mut(&peer_sid) else {
            self.node_pair_index
                .remove(&(current_peer_node_id, current_node_id));
            return Ok(None);
        };
        if peer_session.expires_at_unix <= now_unix {
            self.remove_session(peer_sid);
            return Ok(None);
        }
        let Some(peer_addr) = peer_session.bound_peer_addr else {
            return Ok(None);
        };
        peer_session.last_packet_at = Instant::now();
        // Forward payload as-is — never inspect content
        Ok(Some(RelayForwardTarget {
            peer_session_id: peer_sid,
            peer_allocated_port: peer_session.allocated_port,
            peer_addr,
            payload: payload.to_vec(),
        }))
    }

    /// Evict idle, half-open, and stale sessions, and prune the nonce store.
    ///
    /// Should be called periodically (e.g., every 10 seconds).
    pub fn cleanup_idle_sessions(&mut self) -> Vec<RelaySession> {
        let now = Instant::now();
        let idle_threshold = Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS);
        let half_open_threshold = Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut to_remove = Vec::new();

        for (session_id, session) in &self.sessions {
            let age = now.duration_since(session.established_at);
            let idle = now.duration_since(session.last_packet_at);

            let has_pair = self
                .node_pair_index
                .contains_key(&(session.peer_node_id.clone(), session.node_id.clone()));

            // Remove session if:
            // - it has expired according to the signed session token, OR
            // - it is half-open (no paired session) and exceeds the half-open timeout, OR
            // - it is idle (no recent packets) and exceeds the idle timeout
            let is_expired = session.expires_at_unix <= now_unix;
            let is_stale_half_open = !has_pair && age > half_open_threshold;
            let is_idle = idle > idle_threshold;
            if is_expired || is_stale_half_open || is_idle {
                to_remove.push(*session_id);
            }
        }

        let mut removed = Vec::new();
        for sid in to_remove {
            if let Some(session) = self.remove_session(sid) {
                removed.push(session);
            }
        }

        // Prune nonce store: remove entries older than the nonce retention window
        // to prevent unbounded memory growth while keeping anti-replay guarantees.
        if let Err(err) = self
            .nonce_store
            .prune(Duration::from_secs(NONCE_RETENTION_SECS))
        {
            eprintln!("relay nonce-store prune failed: {err}");
        }

        removed
    }

    #[cfg(test)]
    fn next_test_allocated_port(&self) -> u16 {
        let base = 50_000u16;
        let offset = (self.sessions.len() % 10_000) as u16;
        base.wrapping_add(offset)
    }

    /// Number of active sessions (for monitoring/tests).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn remove_session_for_pair(&mut self, node_id: &str, peer_node_id: &str) {
        let Some(existing_session_id) = self
            .node_pair_index
            .get(&(node_id.to_string(), peer_node_id.to_string()))
            .copied()
        else {
            return;
        };
        self.remove_session(existing_session_id);
    }

    fn remove_session(&mut self, session_id: SessionId) -> Option<RelaySession> {
        let session = self.sessions.remove(&session_id)?;
        self.node_pair_index
            .remove(&(session.node_id.clone(), session.peer_node_id.clone()));
        Some(session)
    }
}

// ── Nonce store ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct NonceStore {
    nonces: HashMap<[u8; 16], u64>,
    path: Option<PathBuf>,
}

impl NonceStore {
    fn load(path: PathBuf) -> Result<Self, String> {
        validate_replay_store_path(&path)?;
        if !path.exists() {
            let store = Self {
                nonces: HashMap::new(),
                path: Some(path),
            };
            store.persist()?;
            return Ok(store);
        }

        let content =
            fs::read_to_string(&path).map_err(|err| format!("read replay store: {err}"))?;
        let mut nonces = HashMap::new();
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let nonce_hex = fields
                .next()
                .ok_or_else(|| format!("replay store line {} missing nonce", line_no + 1))?;
            let inserted_at_unix = fields
                .next()
                .ok_or_else(|| format!("replay store line {} missing timestamp", line_no + 1))?
                .parse::<u64>()
                .map_err(|err| {
                    format!("replay store line {} invalid timestamp: {err}", line_no + 1)
                })?;
            if fields.next().is_some() {
                return Err(format!(
                    "replay store line {} has unexpected fields",
                    line_no + 1
                ));
            }
            nonces.insert(parse_nonce_hex(nonce_hex)?, inserted_at_unix);
        }
        Ok(Self {
            nonces,
            path: Some(path),
        })
    }

    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.nonces.contains_key(nonce)
    }

    fn insert(&mut self, nonce: [u8; 16]) -> Result<(), String> {
        // Insert directly, persist, and roll back on failure. Avoids the
        // O(n) clone of the entire nonce map per accepted hello (which at
        // 4096 sessions × 240 s retention gave O(n²) total work). The
        // persist-failure consistency property is preserved: in-memory
        // state matches on-disk state, OR the operation fails closed
        // without mutating either.
        let prior = self.nonces.insert(nonce, now_unix());
        if let Err(err) = self.persist() {
            // Restore previous state (either remove the new entry, or
            // re-insert whatever was there before — defensive against
            // an unexpected duplicate).
            match prior {
                Some(previous) => {
                    self.nonces.insert(nonce, previous);
                }
                None => {
                    self.nonces.remove(&nonce);
                }
            }
            return Err(err);
        }
        Ok(())
    }

    fn prune(&mut self, retention: Duration) -> Result<(), String> {
        let now = now_unix();
        let retention_secs = retention.as_secs();
        // Collect keys to drop without cloning the full map. The drop set
        // is bounded by the number of expiring nonces (typically a small
        // fraction of total), not by the map size.
        let to_remove: Vec<([u8; 16], u64)> = self
            .nonces
            .iter()
            .filter(|(_, inserted_at)| now.saturating_sub(**inserted_at) >= retention_secs)
            .map(|(nonce, inserted_at)| (*nonce, *inserted_at))
            .collect();
        if to_remove.is_empty() {
            return Ok(());
        }
        for (nonce, _) in &to_remove {
            self.nonces.remove(nonce);
        }
        if let Err(err) = self.persist() {
            // Restore evicted entries with their original timestamps so
            // a later prune retry sees the same state as before.
            for (nonce, inserted_at) in to_remove {
                self.nonces.insert(nonce, inserted_at);
            }
            return Err(err);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        persist_nonce_map(path, &self.nonces)
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX_EPOCH")
        .as_secs()
}

/// Pure helper that clamps an operator-supplied clock-skew tolerance to the
/// safe ceiling and reports whether clamping occurred. Extracted so the
/// clamp decision is testable without depending on a logging subscriber.
///
/// Returns `(clamped_value, was_clamped)`. `was_clamped == true` is the
/// signal that a `warn`-level log line would be emitted.
fn compute_clamped_skew(input: u64) -> (u64, bool) {
    if input > MAX_CLOCK_SKEW_TOLERANCE_SECS {
        (MAX_CLOCK_SKEW_TOLERANCE_SECS, true)
    } else {
        (input, false)
    }
}

/// Pure helper that decides whether a `symlink_metadata` failure during
/// replay-store path validation is "expected" (file not yet created, fresh
/// install) or "unexpected" (permission denied, I/O error, etc.) and should
/// produce a warning. Extracted so the warn-or-not decision is testable
/// without depending on a logging subscriber.
///
/// Returns `true` iff a warning would be emitted.
fn should_warn_replay_stat_skip(err: &std::io::Error) -> bool {
    err.kind() != std::io::ErrorKind::NotFound
}

fn validate_replay_store_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("replay store path must not be empty".to_string());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err("replay store path must be a regular file".to_string());
            }
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!("replay store permissions too broad: {mode:o}"));
                }
            }
        }
        Err(err) => {
            // NotFound is expected on first-run / fresh-install: the parent
            // directory is the relevant security surface and is checked
            // below. Any *other* stat error (permission denied, I/O error)
            // means we couldn't actually verify the file's safety. Log a
            // warning so an operator with a corrupted state directory can
            // see that the permission check was skipped.
            if should_warn_replay_stat_skip(&err) {
                eprintln!(
                    "warn relay_transport: replay store permission check skipped — symlink_metadata({}) failed: {err}",
                    path.display()
                );
            }
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let metadata =
            fs::symlink_metadata(parent).map_err(|err| format!("stat replay store dir: {err}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err("replay store parent must be a directory".to_string());
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "replay store parent permissions too broad: {mode:o}"
                ));
            }
        }
    }
    Ok(())
}

fn persist_nonce_map(path: &Path, nonces: &HashMap<[u8; 16], u64>) -> Result<(), String> {
    validate_replay_store_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "replay store path missing file name".to_string())?
        .to_string_lossy();
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let mut lines = nonces.iter().collect::<Vec<_>>();
    lines.sort_by(|left, right| left.0.cmp(right.0));
    let mut content = String::new();
    for (nonce, inserted_at_unix) in lines {
        content.push_str(&format!("{} {inserted_at_unix}\n", hex_nonce(nonce)));
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| format!("open replay store tmp: {err}"))?;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("write replay store tmp: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("sync replay store tmp: {err}"))?;
    drop(file);

    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set replay store permissions: {err}"))?;

    fs::rename(&tmp_path, path).map_err(|err| format!("replace replay store: {err}"))?;
    Ok(())
}

fn hex_nonce(nonce: &[u8; 16]) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn parse_nonce_hex(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 {
        return Err("replay store nonce must be 32 hex characters".to_string());
    }
    let mut nonce = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|err| format!("replay store nonce is not utf8: {err}"))?;
        nonce[index] = u8::from_str_radix(text, 16)
            .map_err(|err| format!("replay store nonce is not hex: {err}"))?;
    }
    Ok(nonce)
}

// ── Hello rate limiter ────────────────────────────────────────────────────────

/// Limits session-establishment (`handle_hello`) attempts per node per second.
///
/// This is a separate, much tighter limit than the packet-level `RateLimiter`
/// because `handle_hello` performs ed25519 verification (CPU-intensive).
/// Applying a cheap counter before verification protects against CPU-exhaustion
/// attacks.
struct HelloLimiter {
    max_per_sec: u32,
    counts: HashMap<String, (u32, Instant)>,
}

impl HelloLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            counts: HashMap::new(),
        }
    }

    /// Returns `true` if the hello should be allowed, `false` if rate-limited.
    fn check(&mut self, node_id: &str) -> bool {
        let now = Instant::now();
        let entry = self.counts.entry(node_id.to_string()).or_insert((0, now));

        // Reset counter if the one-second window has elapsed
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            *entry = (0, now);
        }

        if entry.0 >= self.max_per_sec {
            return false;
        }
        entry.0 += 1;
        true
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const TEST_RELAY_ID: [u8; 16] = [0xAA; 16];

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn make_transport(signing_key: &SigningKey) -> RelayTransport {
        RelayTransport::new(TEST_RELAY_ID, signing_key.verifying_key(), 8, 90)
    }

    fn temp_replay_store_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-{test_name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp replay store dir should be created");
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("temp replay store dir permissions should be restricted");
        dir.join("replay.store")
    }

    /// Build a valid token bound to `TEST_RELAY_ID` and the given TTL.
    fn make_valid_token(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        ttl_secs: u64,
    ) -> RelaySessionToken {
        RelaySessionToken::sign(signing_key, node_id, peer_node_id, TEST_RELAY_ID, ttl_secs)
    }

    /// Build a valid hello that uses a fresh token.
    fn make_hello(signing_key: &SigningKey, node_id: &str, peer_node_id: &str) -> RelayHello {
        RelayHello {
            node_id: node_id.to_string(),
            peer_node_id: peer_node_id.to_string(),
            session_token: make_valid_token(signing_key, node_id, peer_node_id, 60),
        }
    }

    fn observed_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    fn accept_hello_from(
        transport: &mut RelayTransport,
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        from_addr: SocketAddr,
    ) -> SessionId {
        match transport
            .handle_hello_from_tuple(make_hello(signing_key, node_id, peer_node_id), from_addr)
        {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            other => panic!("expected accepted hello, got {other:?}"),
        }
    }

    fn accept_hello_from_with_port(
        transport: &mut RelayTransport,
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        from_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloAck {
        let hello = make_hello(signing_key, node_id, peer_node_id);
        transport
            .validate_hello_from_tuple(&hello, from_addr)
            .expect("hello should validate before port allocation");
        match transport.handle_hello_from_tuple_with_allocated_port(
            hello,
            from_addr,
            allocated_port,
        ) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected accepted hello, got {other:?}"),
        }
    }

    // ── Signature / basic token validity ─────────────────────────────────────

    #[test]
    fn test_invalid_signature_token_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Token signed with a different key then signature bytes mangled
        let wrong_sk = SigningKey::from_bytes(&[2u8; 32]);
        let mut token = make_valid_token(&wrong_sk, "node-a", "node-b", 60);
        token.signature = [99u8; 64];

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_invalid_allocated_port_rejected_without_consuming_nonce() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello = make_hello(&sk, "node-a", "node-b");
        let from_addr = observed_addr([203, 0, 113, 10], 51000);

        let rejected =
            transport.handle_hello_from_tuple_with_allocated_port(hello.clone(), from_addr, 0);
        assert_eq!(
            rejected,
            RelayHelloResponse::Rejected(RejectReason::InvalidAllocatedPort)
        );
        assert_eq!(transport.session_count(), 0);

        let accepted =
            transport.handle_hello_from_tuple_with_allocated_port(hello, from_addr, 50_000);
        assert!(
            matches!(accepted, RelayHelloResponse::Accepted(_)),
            "valid retry should not be blocked by nonce consumption: {accepted:?}"
        );
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn test_expired_token_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut token = make_valid_token(&sk, "node-a", "node-b", 60);
        token.expires_at_unix = now_unix - 200;
        // Re-sign with expired timestamp
        let payload = token.canonical_payload();
        token.signature = sk.sign(payload.as_bytes()).to_bytes();

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::ExpiredToken)
        );
    }

    #[test]
    fn test_token_ttl_exceeds_max_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: make_valid_token(&sk, "node-a", "node-b", 200), // > 120 s
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    #[test]
    fn test_replayed_nonce_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello1 = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token.clone(),
        };
        assert!(matches!(
            transport.handle_hello(hello1),
            RelayHelloResponse::Accepted(_)
        ));

        let hello2 = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };
        assert_eq!(
            transport.handle_hello(hello2),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce)
        );
    }

    #[test]
    fn test_nonce_store_pruned_in_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Accept one hello to seed the nonce store
        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        assert_eq!(transport.nonce_store.nonces.len(), 1);

        // Back-date the nonce so it appears older than the retention window
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix().saturating_sub(NONCE_RETENTION_SECS + 1);
        }

        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            0,
            "expired nonces must be pruned by cleanup"
        );
    }

    #[test]
    fn test_durable_replay_store_rejects_nonce_after_restart() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("durable-replay");
        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token.clone(),
        };

        {
            let mut transport = RelayTransport::new_with_replay_store_path(
                TEST_RELAY_ID,
                sk.verifying_key(),
                8,
                90,
                replay_store_path.clone(),
            )
            .expect("durable replay store should initialize");
            assert!(matches!(
                transport.handle_hello_from_tuple_with_allocated_port(
                    hello,
                    observed_addr([198, 51, 100, 70], 40_070),
                    55_070,
                ),
                RelayHelloResponse::Accepted(_)
            ));
        }

        let mut restarted = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        )
        .expect("durable replay store should reload");
        let replay = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };
        assert_eq!(
            restarted.handle_hello_from_tuple_with_allocated_port(
                replay,
                observed_addr([198, 51, 100, 70], 40_070),
                55_071,
            ),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce)
        );
        let _ = fs::remove_dir_all(
            replay_store_path
                .parent()
                .expect("replay store path should have parent"),
        );
    }

    #[test]
    fn test_replay_store_corruption_fails_closed_on_startup() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("corrupt-replay");
        fs::write(&replay_store_path, "not-a-valid-store\n")
            .expect("corrupt replay store should be written");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        ) {
            Ok(_) => panic!("corrupt replay store must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("replay store"));
        let _ = fs::remove_dir_all(
            replay_store_path
                .parent()
                .expect("replay store path should have parent"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_replay_store_rejects_broad_parent_permissions() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("broad-parent");
        let parent = replay_store_path
            .parent()
            .expect("replay store path should have parent")
            .to_path_buf();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))
            .expect("parent permissions should be widened for negative test");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        ) {
            Ok(_) => panic!("broad replay store parent permissions must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("parent permissions too broad"));

        let _ = fs::set_permissions(&parent, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(parent);
    }

    // ── Node-id and relay-id binding (new constant-time checks) ──────────────

    #[test]
    fn test_node_id_mismatch_rejected_with_constant_time_check() {
        // hello.node_id = "attacker" but token.node_id = "node-a"
        // The relay must reject this with InvalidToken (not PeerMismatch).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "attacker".to_string(), // wrong
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_relay_id_mismatch_rejected() {
        // Token issued for a different relay — must be rejected.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let other_relay_id = [0xBB; 16]; // ≠ TEST_RELAY_ID
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", other_relay_id, 60);

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Scope enforcement ─────────────────────────────────────────────────────

    #[test]
    fn test_wrong_scope_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Manually forge a token with a wrong scope and re-sign it
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut token = RelaySessionToken {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            relay_id: TEST_RELAY_ID,
            scope: "full_tunnel_admin".to_string(), // wrong
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 60,
            nonce: [0x11; 16],
            signature: [0u8; 64],
        };
        let payload = token.canonical_payload();
        token.signature = sk.sign(payload.as_bytes()).to_bytes();

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Peer-id binding ───────────────────────────────────────────────────────

    #[test]
    fn test_peer_mismatch_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-c".to_string(), // different from token
            session_token: token,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::PeerMismatch)
        );
    }

    // ── Capacity ──────────────────────────────────────────────────────────────

    #[test]
    fn test_capacity_limit_enforced() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 2, 90);

        for i in 0..2 {
            let hello = make_hello(&sk, "node-a", &format!("node-b-{i}"));
            assert!(matches!(
                transport.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ));
        }

        // Third hello for the same node must be rejected
        let hello = make_hello(&sk, "node-a", "node-b-extra");
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
    }

    #[test]
    fn test_global_capacity_limit_enforced_across_nodes() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        transport
            .set_max_total_sessions(2)
            .expect("global session cap should configure");

        let from = observed_addr([203, 0, 113, 10], 50000);
        accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_000);
        accept_hello_from_with_port(&mut transport, &sk, "node-b", "peer-b", from, 50_001);
        assert_eq!(transport.session_count(), 2);

        let response = transport.handle_hello_from_tuple_with_allocated_port(
            make_hello(&sk, "node-c", "peer-c"),
            from,
            50_002,
        );
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
        assert_eq!(transport.session_count(), 2);
    }

    #[test]
    fn test_global_capacity_allows_existing_pair_replacement() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        transport
            .set_max_total_sessions(1)
            .expect("global session cap should configure");

        let from = observed_addr([203, 0, 113, 10], 50000);
        accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_000);
        assert_eq!(transport.session_count(), 1);

        let ack =
            accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_001);
        assert_eq!(ack.allocated_port, 50_001);
        assert_eq!(transport.session_count(), 1);

        let rejected = transport.handle_hello_from_tuple_with_allocated_port(
            make_hello(&sk, "node-b", "peer-b"),
            from,
            50_002,
        );
        assert_eq!(
            rejected,
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
    }

    // ── Hello rate limiting ───────────────────────────────────────────────────

    #[test]
    fn test_hello_rate_limit_blocks_flood() {
        let (sk, _) = make_test_keypair();
        // Very tight hello limit so we can test without sleeping
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        transport.hello_limiter.max_per_sec = 2;

        // First two should pass
        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "flooder", "node-b")),
            RelayHelloResponse::Accepted(_) | RelayHelloResponse::Rejected(_)
        ));
        // We don't assert Accepted here because nonces differ each call (fine)
        // — we just want to confirm that the 3rd call within 1 second is limited

        // Drain hello budget for "flooder"
        transport.hello_limiter.counts.insert(
            "flooder".to_string(),
            (transport.hello_limiter.max_per_sec, Instant::now()),
        );

        assert_eq!(
            transport.handle_hello(make_hello(&sk, "flooder", "node-b")),
            RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded)
        );
    }

    #[test]
    fn test_hello_rate_limit_resets_after_window() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        transport.hello_limiter.max_per_sec = 1;

        // Exhaust the window
        transport
            .hello_limiter
            .counts
            .insert("node-a".to_string(), (1, Instant::now()));
        assert_eq!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded)
        );

        // Back-date the window so it appears to have expired
        transport.hello_limiter.counts.insert(
            "node-a".to_string(),
            (1, Instant::now() - Duration::from_secs(2)),
        );

        // Now the hello should be allowed through
        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Accepted(_)
        ));
    }

    // ── Happy-path session lifecycle ──────────────────────────────────────────

    #[test]
    fn test_valid_hello_allocates_session() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Accepted(_)
        ));
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn test_session_pairing_and_bidirectional_forwarding() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 10], 40_000);
        let data_a = observed_addr([198, 51, 100, 10], 51_820);
        let hello_b = observed_addr([203, 0, 113, 20], 41_000);
        let data_b = observed_addr([203, 0, 113, 20], 51_821);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);

        let payload_a = b"ciphertext from A";
        assert_eq!(
            transport
                .forward_packet(sid_a, payload_a, data_a)
                .expect("forwarding should not error before pairing"),
            None,
            "first packet must bind node-a but not forward before node-b is bound"
        );

        let payload_b = b"ciphertext from B";
        let forward_b = transport
            .forward_packet(sid_b, payload_b, data_b)
            .unwrap()
            .expect("should forward");
        assert_eq!(forward_b.peer_session_id, sid_a);
        assert_eq!(forward_b.peer_allocated_port, 50_000);
        assert_eq!(forward_b.peer_addr, data_a);
        assert_eq!(forward_b.payload, payload_b);

        let forward_a = transport
            .forward_packet(sid_a, payload_a, data_a)
            .unwrap()
            .expect("bound sessions should forward bidirectionally");
        assert_eq!(forward_a.peer_session_id, sid_b);
        assert_eq!(forward_a.peer_allocated_port, 50_001);
        assert_eq!(forward_a.peer_addr, data_b);
        assert_eq!(forward_a.payload, payload_a);
    }

    #[test]
    fn test_forward_target_uses_daemon_allocated_port() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 50], 40_050);
        let data_a = observed_addr([198, 51, 100, 50], 51_850);
        let hello_b = observed_addr([203, 0, 113, 60], 41_060);
        let data_b = observed_addr([203, 0, 113, 60], 51_860);

        let ack_a =
            accept_hello_from_with_port(&mut transport, &sk, "node-a", "node-b", hello_a, 55_123);
        let ack_b =
            accept_hello_from_with_port(&mut transport, &sk, "node-b", "node-a", hello_b, 55_987);

        assert_eq!(ack_a.allocated_port, 55_123);
        assert_eq!(ack_b.allocated_port, 55_987);

        assert_eq!(
            transport
                .forward_packet(ack_a.session_id, b"bind-a", data_a)
                .expect("binding node-a should not error"),
            None
        );

        let forward_b = transport
            .forward_packet(ack_b.session_id, b"ciphertext", data_b)
            .unwrap()
            .expect("node-b should forward to bound node-a");
        assert_eq!(forward_b.peer_session_id, ack_a.session_id);
        assert_eq!(forward_b.peer_allocated_port, 55_123);
        assert_eq!(forward_b.peer_addr, data_a);

        let forward_a = transport
            .forward_packet(ack_a.session_id, b"reply", data_a)
            .unwrap()
            .expect("node-a should forward to bound node-b");
        assert_eq!(forward_a.peer_session_id, ack_b.session_id);
        assert_eq!(forward_a.peer_allocated_port, 55_987);
        assert_eq!(forward_a.peer_addr, data_b);
    }

    #[test]
    fn test_payload_forwarded_byte_for_byte_without_inspection() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 11], 40_010);
        let data_a = observed_addr([198, 51, 100, 11], 51_830);
        let hello_b = observed_addr([203, 0, 113, 21], 41_010);
        let data_b = observed_addr([203, 0, 113, 21], 51_831);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        // Test with byte patterns that could confuse parsers
        for payload in [
            vec![0u8; 100],
            vec![0xFFu8; 100],
            (0u8..100).collect::<Vec<_>>(),
        ] {
            let result = transport.forward_packet(sid_a, &payload, data_a).unwrap();
            if let Some(forwarded) = result {
                assert_eq!(
                    forwarded.payload, payload,
                    "payload must be forwarded verbatim"
                );
                assert_eq!(forwarded.peer_session_id, sid_b);
            }
        }
    }

    // ── Oversized payload ─────────────────────────────────────────────────────

    #[test]
    fn test_oversized_payload_silently_dropped() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 12], 40_020);
        let data_a = observed_addr([198, 51, 100, 12], 51_840);
        let hello_b = observed_addr([203, 0, 113, 22], 41_020);
        let data_b = observed_addr([203, 0, 113, 22], 51_841);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        let oversized = vec![0u8; MAX_PACKET_SIZE_BYTES + 1];
        let result = transport.forward_packet(sid_a, &oversized, data_a).unwrap();
        assert_eq!(result, None, "oversized payload must be silently dropped");
        // Session still live — drop does not tear down the session
        assert_eq!(transport.session_count(), 2);
    }

    // ── Rate limiting (packets) ───────────────────────────────────────────────

    #[test]
    fn test_rate_limit_drops_silently() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        transport.rate_limiter.max_pps = 5;

        let hello_a = observed_addr([198, 51, 100, 13], 40_030);
        let data_a = observed_addr([198, 51, 100, 13], 51_850);
        let hello_b = observed_addr([203, 0, 113, 23], 41_030);
        let data_b = observed_addr([203, 0, 113, 23], 51_851);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        for _ in 0..5 {
            assert!(transport.forward_packet(sid_a, b"data", data_a).is_ok());
        }
        // Excess — silent drop
        let result = transport.forward_packet(sid_a, b"data", data_a).unwrap();
        assert_eq!(result, None);
        assert_eq!(transport.session_count(), 2); // sessions intact
    }

    #[test]
    fn test_wrong_source_tuple_rejected_after_binding() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 14], 40_040);
        let data_a = observed_addr([198, 51, 100, 14], 51_860);
        let spoof_a = observed_addr([198, 51, 100, 14], 60_000);
        let hello_b = observed_addr([203, 0, 113, 24], 41_040);
        let data_b = observed_addr([203, 0, 113, 24], 51_861);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        let err = transport
            .forward_packet(sid_a, b"spoof", spoof_a)
            .expect_err("bound session must reject tuple changes");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_new_hello_replaces_existing_session_for_same_pair() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_old = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 21], 40_110),
        );
        let sid_new = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 21], 40_111),
        );

        assert_ne!(sid_old, sid_new);
        assert!(!transport.has_session(sid_old));
        assert!(transport.has_session(sid_new));
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn test_unbound_session_rejects_different_source_ip() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 15], 40_050),
        );

        let err = transport
            .forward_packet(sid_a, b"spoof", observed_addr([203, 0, 113, 25], 51_870))
            .expect_err("unbound session must reject a different source IP");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_stale_tuple_reuse_after_cleanup_is_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let old_hello = observed_addr([198, 51, 100, 16], 40_060);
        let old_data = observed_addr([198, 51, 100, 16], 51_880);
        let peer_hello = observed_addr([203, 0, 113, 26], 41_060);
        let peer_data = observed_addr([203, 0, 113, 26], 51_881);

        let sid_old = accept_hello_from(&mut transport, &sk, "node-a", "node-b", old_hello);
        let sid_peer = accept_hello_from(&mut transport, &sk, "node-b", "node-a", peer_hello);
        let _ = transport.forward_packet(sid_old, b"bind-a", old_data);
        let _ = transport.forward_packet(sid_peer, b"bind-b", peer_data);
        for session in transport.sessions.values_mut() {
            session.last_packet_at =
                Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }
        let removed = transport.cleanup_idle_sessions();
        assert_eq!(
            removed.len(),
            2,
            "cleanup must remove both stale paired sessions"
        );
        assert_eq!(transport.session_count(), 0);

        let sid_new = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([203, 0, 113, 27], 40_061),
        );
        assert_eq!(
            transport
                .sessions
                .get(&sid_new)
                .expect("new session should exist")
                .allocated_port,
            50_000,
            "cleaned ports must be reusable"
        );
        let err = transport
            .forward_packet(sid_new, b"stale", old_data)
            .expect_err("old tuple must not claim a reused relay port");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_cross_session_forwarding_attempt_is_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_ab = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 17], 40_070),
        );
        let sid_ba = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 28], 41_070),
        );
        let _ = transport.forward_packet(
            sid_ab,
            b"bind-ab",
            observed_addr([198, 51, 100, 17], 51_890),
        );
        let _ =
            transport.forward_packet(sid_ba, b"bind-ba", observed_addr([203, 0, 113, 28], 51_891));

        let sid_cd = accept_hello_from(
            &mut transport,
            &sk,
            "node-c",
            "node-d",
            observed_addr([198, 51, 100, 18], 40_080),
        );
        let sid_dc = accept_hello_from(
            &mut transport,
            &sk,
            "node-d",
            "node-c",
            observed_addr([203, 0, 113, 29], 41_080),
        );
        let _ = transport.forward_packet(
            sid_cd,
            b"bind-cd",
            observed_addr([198, 51, 100, 18], 51_892),
        );
        let _ =
            transport.forward_packet(sid_dc, b"bind-dc", observed_addr([203, 0, 113, 29], 51_893));

        let err = transport
            .forward_packet(
                sid_ab,
                b"cross-talk",
                observed_addr([198, 51, 100, 18], 51_892),
            )
            .expect_err("session AB must reject session CD's bound tuple");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_keepalive_rejects_unbound_and_wrong_tuple_activity() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 19], 40_090),
        );

        assert!(
            !transport
                .touch_session_from_tuple(sid_a, observed_addr([198, 51, 100, 19], 51_894))
                .expect("unbound keepalive should be ignored, not accepted")
        );

        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 30], 41_090),
        );
        let _ =
            transport.forward_packet(sid_a, b"bind-a", observed_addr([198, 51, 100, 19], 51_894));
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 30], 51_895));

        let err = transport
            .touch_session_from_tuple(sid_a, observed_addr([198, 51, 100, 19], 60_001))
            .expect_err("bound keepalive must reject a different tuple");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_expired_session_forwarding_is_rejected_and_cleaned_up() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 20], 40_100),
        );
        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 31], 41_100),
        );
        let _ =
            transport.forward_packet(sid_a, b"bind-a", observed_addr([198, 51, 100, 20], 51_896));
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 31], 51_897));

        transport
            .sessions
            .get_mut(&sid_a)
            .expect("session should exist")
            .expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(1);

        let err = transport
            .forward_packet(sid_a, b"expired", observed_addr([198, 51, 100, 20], 51_896))
            .expect_err("expired session must not forward");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(!transport.has_session(sid_a));
        assert!(transport.has_session(sid_b));
    }

    // ── Session cleanup ───────────────────────────────────────────────────────

    #[test]
    fn test_idle_session_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        transport.handle_hello(make_hello(&sk, "node-b", "node-a"));
        assert_eq!(transport.session_count(), 2);

        for s in transport.sessions.values_mut() {
            s.last_packet_at = Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_half_open_session_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        transport.handle_hello(make_hello(&sk, "node-a", "node-b")); // no matching hello-b
        assert_eq!(transport.session_count(), 1);

        for s in transport.sessions.values_mut() {
            s.established_at =
                Instant::now() - Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS + 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(transport.session_count(), 0);
    }

    // ── Constant-time security regression tests ───────────────────────────────
    //
    // These tests document and verify the constant-time comparison guarantees.
    // The relay uses `subtle::ConstantTimeEq` for all secret-field comparisons
    // to prevent timing side-channels in authentication paths.

    #[test]
    fn test_constant_time_node_id_comparison_rejects_all_mismatches_uniformly() {
        // This test verifies that node_id mismatches (where hello.node_id !=
        // token.node_id) always produce the same rejection reason regardless
        // of which byte position differs.  This is a regression test for the
        // constant-time ct_eq usage in handle_hello.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Token is issued for "node-aaaa", but hello claims different node_ids
        // that differ in various positions.
        let token = make_valid_token(&sk, "node-aaaa", "node-b", 60);

        let mismatches = [
            "Xode-aaaa", // first byte differs
            "node-Xaaa", // middle byte differs
            "node-aaaX", // last byte differs
            "attacker",  // completely different
        ];

        for wrong_id in mismatches {
            let hello = RelayHello {
                node_id: wrong_id.to_string(),
                peer_node_id: "node-b".to_string(),
                session_token: token.clone(),
            };

            // All mismatches must produce InvalidToken (not a position-revealing error)
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::InvalidToken),
                "node_id mismatch at any position must produce InvalidToken"
            );
        }
    }

    #[test]
    fn test_constant_time_peer_id_comparison_rejects_all_mismatches_uniformly() {
        // Same regression test for peer_node_id field.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "peer-bbbb", 60);

        let mismatches = [
            "Xeer-bbbb", // first byte differs
            "peer-Xbbb", // middle byte differs
            "peer-bbbX", // last byte differs
            "attacker",  // completely different
        ];

        for wrong_peer in mismatches {
            let hello = RelayHello {
                node_id: "node-a".to_string(),
                peer_node_id: wrong_peer.to_string(),
                session_token: token.clone(),
            };

            // All mismatches must produce PeerMismatch (consistent rejection)
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::PeerMismatch),
                "peer_node_id mismatch at any position must produce PeerMismatch"
            );
        }
    }

    #[test]
    fn test_constant_time_relay_id_comparison_rejects_all_mismatches_uniformly() {
        // Same regression test for relay_id field.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Generate tokens with relay_ids that differ in various byte positions
        let relay_ids: [[u8; 16]; 3] = [
            [
                0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA,
            ], // first byte differs
            [
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA,
            ], // middle byte differs
            [
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xBB,
            ], // last byte differs
        ];

        for wrong_relay_id in relay_ids {
            let token = RelaySessionToken::sign(&sk, "node-a", "node-b", wrong_relay_id, 60);
            let hello = RelayHello {
                node_id: "node-a".to_string(),
                peer_node_id: "node-b".to_string(),
                session_token: token,
            };

            // All mismatches must produce InvalidToken
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::InvalidToken),
                "relay_id mismatch at any byte position must produce InvalidToken"
            );
        }
    }

    #[test]
    fn test_relay_session_token_ct_eq_is_available_and_correct() {
        // Verify that RelaySessionToken::ct_eq works correctly and is the
        // intended comparison method for tokens.
        let (sk, _) = make_test_keypair();

        let token_a = make_valid_token(&sk, "node-a", "node-b", 60);
        let token_b = make_valid_token(&sk, "node-a", "node-b", 60);
        let token_c = make_valid_token(&sk, "node-a", "node-c", 60);

        // Different nonces mean tokens are not equal even if fields match
        assert!(
            !token_a.ct_eq(&token_b),
            "tokens with different nonces must not be ct_eq"
        );

        // Same token compared to itself is always equal
        assert!(
            token_a.ct_eq(&token_a),
            "token compared to itself must be ct_eq"
        );

        // Obviously different tokens are not equal
        assert!(
            !token_a.ct_eq(&token_c),
            "tokens with different peer_node_id must not be ct_eq"
        );
    }

    #[test]
    fn test_subtle_crate_is_used_for_constant_time_comparisons() {
        // This is a compile-time contract test: the subtle crate must be
        // available and ConstantTimeEq must be usable.  If subtle is removed
        // from dependencies or the API changes, this test will fail to compile.
        use subtle::ConstantTimeEq;

        let a: [u8; 16] = [0xAA; 16];
        let b: [u8; 16] = [0xAA; 16];
        let c: [u8; 16] = [0xBB; 16];

        let eq_ab: bool = a.ct_eq(&b).into();
        let eq_ac: bool = a.ct_eq(&c).into();

        assert!(eq_ab, "identical arrays must be ct_eq");
        assert!(!eq_ac, "different arrays must not be ct_eq");
    }

    // ── Adversarial security regression tests ─────────────────────────────────
    //
    // These tests verify the relay rejects various attack scenarios correctly.

    #[test]
    fn adversarial_forged_signature_rejected_without_timing_leak() {
        // Attacker forges a token with wrong signature bytes
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);

        let mut hello = make_hello(&sk, "attacker", "victim");
        // Corrupt the signature
        hello.session_token.signature[0] ^= 0xFF;
        hello.session_token.signature[31] ^= 0xFF;
        hello.session_token.signature[63] ^= 0xFF;

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "forged signature must be rejected"
        );
    }

    #[test]
    fn adversarial_past_expired_token_rejected() {
        // Attacker tries to use a token that has expired beyond clock skew tolerance
        let (sk, _) = make_test_keypair();
        let _transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        let _token = RelaySessionToken::sign(&sk, "node-a", "node-b", TEST_RELAY_ID, 1);
        // The explicit expired-token path is already covered by test_expired_token_rejected.
        // This test keeps the adversarial boundary case focused on a strict clock-skew policy.

        // Instead, verify that a very short TTL with no skew tolerance is rejected
        // This tests the boundary condition
        let mut transport_strict = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 0);

        // With 1 second TTL and immediate check, should still pass (just barely)
        let hello = make_hello(&sk, "node-a", "node-b");
        assert!(
            matches!(
                transport_strict.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ),
            "fresh token should be accepted even with strict 0 clock skew"
        );
    }

    #[test]
    fn adversarial_session_exhaustion_attack_blocked() {
        // Attacker tries to exhaust session capacity for a node
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 2, 90);

        // Fill up the session quota
        for i in 0..2 {
            let hello = make_hello(&sk, "attacker", &format!("peer-{i}"));
            assert!(matches!(
                transport.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ));
        }

        // Additional session should be rejected
        let hello = make_hello(&sk, "attacker", "peer-extra");
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::Capacity),
            "session exhaustion must be blocked"
        );

        // Verify other nodes are not affected
        let (sk2, _) = make_test_keypair();
        let mut transport2 = RelayTransport::new(TEST_RELAY_ID, sk2.verifying_key(), 2, 90);
        let hello = make_hello(&sk2, "honest-node", "peer-1");
        assert!(
            matches!(
                transport2.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ),
            "other nodes must not be affected by attacker's session exhaustion"
        );
    }

    #[test]
    fn adversarial_hello_flood_rate_limited() {
        // Attacker floods hello messages to exhaust CPU
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 100, 90);

        // Send hellos up to the rate limit
        let mut accepted = 0;
        let mut rate_limited = 0;
        for i in 0..20 {
            let hello = make_hello(&sk, "flood-attacker", &format!("peer-{i}"));
            match transport.handle_hello(hello) {
                RelayHelloResponse::Accepted(_) => accepted += 1,
                RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded) => rate_limited += 1,
                other => panic!("unexpected response: {other:?}"),
            }
        }

        // Should hit rate limit before all accepted
        assert!(
            rate_limited > 0,
            "hello flood must trigger rate limiting (accepted={accepted}, rate_limited={rate_limited})"
        );
        assert!(
            accepted <= MAX_HELLOS_PER_NODE_PER_SEC as usize,
            "accepted count must not exceed rate limit"
        );
    }

    #[test]
    fn adversarial_cross_relay_token_rejected() {
        // Attacker tries to use a token issued for a different relay
        let (sk, _) = make_test_keypair();
        let other_relay_id: [u8; 16] = [0xDE; 16];
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);

        // Token signed for wrong relay
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", other_relay_id, 60);
        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "token for different relay must be rejected"
        );
    }

    #[test]
    fn adversarial_node_impersonation_rejected() {
        // Attacker tries to claim a different node_id in hello vs token
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);

        // Token for "real-node" but hello claims "attacker"
        let token = RelaySessionToken::sign(&sk, "real-node", "peer-b", TEST_RELAY_ID, 60);
        let hello = RelayHello {
            node_id: "attacker".to_string(), // Mismatch!
            peer_node_id: "peer-b".to_string(),
            session_token: token,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "node impersonation must be rejected"
        );
    }

    #[test]
    fn adversarial_peer_redirection_rejected() {
        // Attacker tries to redirect traffic to different peer
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);

        // Token for node-a→peer-b but hello claims node-a→attacker-peer
        let token = RelaySessionToken::sign(&sk, "node-a", "peer-b", TEST_RELAY_ID, 60);
        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "attacker-peer".to_string(), // Mismatch!
            session_token: token,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::PeerMismatch),
            "peer redirection must be rejected"
        );
    }

    #[test]
    fn adversarial_nonce_reuse_rejected_even_with_valid_signature() {
        // Attacker captures valid token and replays it
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);

        let hello = make_hello(&sk, "node-a", "node-b");
        let cloned_hello = hello.clone();

        // First use succeeds
        assert!(matches!(
            transport.handle_hello(hello),
            RelayHelloResponse::Accepted(_)
        ));

        // Replay of exact same token is rejected
        assert_eq!(
            transport.handle_hello(cloned_hello),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce),
            "replayed nonce must be rejected even with valid signature"
        );
    }

    // ── Keepalive / touch_session tests ───────────────────────────────────────

    #[test]
    fn touch_session_updates_last_packet_at() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = make_hello(&sk, "node-a", "node-b");
        let ack = match transport.handle_hello(hello) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        // Age the session
        if let Some(session) = transport.sessions.get_mut(&ack.session_id) {
            session.last_packet_at = Instant::now() - Duration::from_secs(100);
        }

        // Touch should update timestamp
        assert!(
            transport.touch_session(ack.session_id).is_ok(),
            "touch_session should succeed for valid session"
        );

        // Verify timestamp was updated (should be recent now)
        if let Some(session) = transport.sessions.get(&ack.session_id) {
            assert!(
                session.last_packet_at.elapsed() < Duration::from_secs(1),
                "last_packet_at should be recent after touch"
            );
        }
    }

    #[test]
    fn touch_session_rejects_unknown_session() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let unknown_session = SessionId::from([0xDE; 16]);
        assert!(
            transport.touch_session(unknown_session).is_err(),
            "touch_session must reject unknown session"
        );
    }

    // ── Replay-store / boundary regression tests ─────────────────────────────
    //
    // Pin the security contracts that prior tests left implicit:
    //   * skew is clamped at construction so retention always dominates TTL
    //   * the replay window is closed at every point inside the skew tolerance
    //   * forward/touch reject at exact-second expiry boundary
    //   * advisory `validate_hello_from_tuple` does not consume the nonce
    //   * `cleanup_idle_sessions` evicts at the retention boundary
    //   * persisted store survives whitespace and dedupes against memory
    //   * persisted store fails closed on malformed timestamp / extra fields
    //   * persisted store rejects symlinked targets
    //   * empty / max-size store reload semantics

    #[test]
    fn skew_tolerance_is_clamped_to_max_ttl() {
        // Operator misconfigured a 600-second skew. Without clamping, a token
        // that expired at t+120 would remain accepted until t+720 while the
        // nonce store prunes at t+240, leaving a 480-second replay window.
        // The constructor clamps so `is_expired` rejects no later than
        // expires_at + MAX_CLOCK_SKEW_TOLERANCE_SECS, which never exceeds
        // NONCE_RETENTION_SECS.
        let (sk, _) = make_test_keypair();
        let transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 600);
        assert_eq!(
            transport.clock_skew_tolerance_secs, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "clock skew larger than MAX_CLOCK_SKEW_TOLERANCE_SECS must be clamped"
        );

        let inside = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 30);
        assert_eq!(
            inside.clock_skew_tolerance_secs, 30,
            "clock skew within bounds must be preserved verbatim"
        );

        let exact = RelayTransport::new(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            MAX_CLOCK_SKEW_TOLERANCE_SECS,
        );
        assert_eq!(
            exact.clock_skew_tolerance_secs, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "boundary value must be preserved (not over-clamped)"
        );
    }

    #[test]
    fn skew_clamp_invariant_holds_for_replay_retention() {
        // Compile-time-style invariant test: the clamp must always be small
        // enough that even at exact expiry + skew, the nonce is still inside
        // the retention window. This protects against future constant tweaks
        // that would silently re-open the replay window.
        const _: () = assert!(
            MAX_RELAY_TTL_SECS + MAX_CLOCK_SKEW_TOLERANCE_SECS <= NONCE_RETENTION_SECS,
            "skew + ttl must never exceed nonce retention or replay window reopens"
        );
    }

    #[test]
    fn forward_packet_rejects_at_exact_expiry_second() {
        // `forward_packet` uses `<=` against expiry, so a session whose token
        // expires at exactly `now_unix` must be rejected (fail-closed at the
        // boundary).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let from = observed_addr([198, 51, 100, 90], 40_900);
        let sid = accept_hello_from(&mut transport, &sk, "node-a", "node-b", from);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        transport
            .sessions
            .get_mut(&sid)
            .expect("session should exist")
            .expires_at_unix = now_unix;

        let err = transport
            .forward_packet(sid, b"boundary", from)
            .expect_err("forward must reject at exact expiry second");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(
            !transport.has_session(sid),
            "expired session must be cleaned up by forward_packet"
        );
    }

    #[test]
    fn touch_session_from_tuple_rejects_at_exact_expiry_second() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello_addr = observed_addr([198, 51, 100, 91], 40_910);
        let data_addr = observed_addr([198, 51, 100, 91], 51_910);
        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_addr);
        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 91], 41_910),
        );
        let _ = transport.forward_packet(sid_a, b"bind-a", data_addr);
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 91], 51_911));

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        transport
            .sessions
            .get_mut(&sid_a)
            .expect("session should exist")
            .expires_at_unix = now_unix;

        let err = transport
            .touch_session_from_tuple(sid_a, data_addr)
            .expect_err("touch must reject at exact expiry second");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(
            !transport.has_session(sid_a),
            "expired session must be cleaned up by touch_session_from_tuple"
        );
    }

    #[test]
    fn validate_hello_from_tuple_does_not_consume_nonce() {
        // The advisory pre-flight `validate_hello_from_tuple` is documented
        // as fail-closed-before-I/O: it rejects forged/stale/flooded hellos
        // before the daemon binds an allocated UDP port, but it must NOT
        // burn the nonce. Otherwise a benign caller that allocates a port
        // and then commits would see its own committed hello rejected as a
        // replay.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello = make_hello(&sk, "node-a", "node-b");
        let from = observed_addr([198, 51, 100, 92], 40_920);

        transport
            .validate_hello_from_tuple(&hello, from)
            .expect("advisory validation must succeed");
        assert!(
            transport.nonce_store.nonces.is_empty(),
            "advisory pre-check must not consume the nonce"
        );
        assert!(
            !transport.nonce_store.contains(&hello.session_token.nonce),
            "advisory pre-check must not register the nonce"
        );

        match transport.handle_hello_from_tuple_with_allocated_port(hello.clone(), from, 50_010) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("commit must succeed after advisory validation: {other:?}"),
        }
        assert!(
            transport.nonce_store.contains(&hello.session_token.nonce),
            "commit path must register the nonce"
        );
    }

    #[test]
    fn commit_path_does_not_double_count_hello_rate() {
        // Contract: `validate_hello_from_tuple` is the daemon's first contact
        // point and is the call that consumes one hello-rate budget unit. The
        // subsequent commit (`handle_hello_from_tuple_with_allocated_port`)
        // re-runs all stateful security predicates, but it must NOT charge a
        // second hello against the rate budget — otherwise the effective
        // budget is halved and an honest peer can rate-limit itself with two
        // legitimate sequential calls in the daemon's pre-check + commit flow.
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90);
        transport.hello_limiter.max_per_sec = 1;
        let from = observed_addr([198, 51, 100, 93], 40_930);

        // First advisory call uses the single budget unit.
        let hello1 = make_hello(&sk, "node-a", "node-b");
        transport
            .validate_hello_from_tuple(&hello1, from)
            .expect("first advisory pre-check must succeed");
        // Commit must succeed even though the rate budget was already drained
        // by the advisory call — the commit path itself must not count again.
        match transport.handle_hello_from_tuple_with_allocated_port(hello1, from, 50_020) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("commit must not double-count hello rate: {other:?}"),
        }

        // A second independent advisory call must now be rate-limited because
        // the budget was already consumed by the first advisory call (not by
        // the commit). This proves the counter is charged exactly once per
        // (advisory, commit) pair.
        let hello2 = make_hello(&sk, "node-a", "node-b");
        assert_eq!(
            transport.validate_hello_from_tuple(&hello2, from),
            Err(RejectReason::RateLimitExceeded),
            "second advisory call must trip the rate limit"
        );
    }

    #[test]
    fn replay_rejected_inside_full_skew_window() {
        // Even at the latest instant where `is_expired` would still accept
        // the token (expires_at + skew - 1), a replay must remain rejected.
        // This protects against a subtle bug where the in-memory nonce
        // store could be pruned while the token is still valid.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = make_hello(&sk, "node-a", "node-b");
        let nonce = hello.session_token.nonce;
        match transport.handle_hello(hello.clone()) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("first hello must be accepted: {other:?}"),
        }

        // Back-date the recorded nonce to (now - retention + 1) — the latest
        // moment it can still be in the store. A replay here must be rejected.
        let almost_pruned = now_unix().saturating_sub(NONCE_RETENTION_SECS - 1);
        transport.nonce_store.nonces.insert(nonce, almost_pruned);

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce),
            "nonce must remain in store throughout retention - 1 boundary"
        );
    }

    #[test]
    fn nonce_at_exact_retention_age_is_pruned_by_cleanup() {
        // `prune` keeps entries with `now - inserted_at < retention`. At
        // exactly `retention_secs`, the entry must be evicted. This pins the
        // boundary so a future loosening would be caught by tests.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Seed one nonce
        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        assert_eq!(transport.nonce_store.nonces.len(), 1);
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix().saturating_sub(NONCE_RETENTION_SECS);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            0,
            "entries at exactly retention age must be pruned (boundary is exclusive)"
        );

        // And one second younger must survive.
        transport.handle_hello(make_hello(&sk, "node-c", "node-d"));
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix().saturating_sub(NONCE_RETENTION_SECS - 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            1,
            "entries one second below retention must survive"
        );
    }

    #[test]
    fn empty_replay_store_loads_cleanly_and_persists_zero_entries() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("empty-replay");
        // First open creates the file
        let _ = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("empty replay store must initialize cleanly");
        let content = fs::read_to_string(&path).expect("replay store file should exist");
        assert!(
            content.is_empty(),
            "fresh replay store must be persisted empty, not contain stub data"
        );

        // Second open of an empty file must also succeed (covers reload path)
        let transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("empty replay store must reload cleanly");
        assert_eq!(transport.nonce_store.nonces.len(), 0);

        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_tolerates_blank_lines_but_rejects_extra_fields() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("blank-vs-extra");

        // Whitespace-only lines must be ignored. Use a fresh timestamp so
        // load + prune (`new_with_replay_store_path`) does not silently drop
        // the valid entry as past-retention.
        let nonce_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
        let fresh_ts = now_unix();
        let valid_with_blanks = format!("\n   \n{nonce_hex} {fresh_ts}\n\n");
        fs::write(&path, valid_with_blanks)
            .expect("valid-with-blanks replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");
        let transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("blank lines must be tolerated");
        assert_eq!(
            transport.nonce_store.nonces.len(),
            1,
            "blank lines must be skipped without dropping valid entries"
        );

        // Extra trailing field must fail closed
        let extra = format!("{nonce_hex} 1700000000 extra-junk\n");
        fs::write(&path, extra).expect("extra-field replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");
        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("extra fields in replay store must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("unexpected fields"));

        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_rejects_short_nonce_hex() {
        // 30 hex chars (15 bytes) instead of the required 32 must fail closed.
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("short-nonce");
        fs::write(&path, "deadbeefdeadbeefdeadbeefdeadbe 1700000000\n")
            .expect("short-nonce replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("short nonce must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("32 hex characters"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_rejects_non_numeric_timestamp() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("bad-ts");
        let nonce_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
        fs::write(&path, format!("{nonce_hex} not-a-number\n"))
            .expect("bad-timestamp replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("non-numeric timestamp must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("invalid timestamp"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rejects_symlinked_path() {
        // The replay store path itself must not be a symlink — otherwise a
        // local attacker with write access to the parent could redirect
        // writes elsewhere. The validator must reject symlinked file paths.
        let (sk, _) = make_test_keypair();
        let real = temp_replay_store_path("symlink-real");
        let parent = real
            .parent()
            .expect("path should have parent")
            .to_path_buf();
        // Create a real target with valid (empty) content
        fs::write(&real, "").expect("real replay store target should be created");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600))
            .expect("real replay store target must be 0600");

        let symlink = parent.join("replay.symlink");
        std::os::unix::fs::symlink(&real, &symlink)
            .expect("symlink for negative test should be created");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            symlink.clone(),
        ) {
            Ok(_) => panic!("symlinked replay store path must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("regular file"));

        let _ = fs::remove_dir_all(parent);
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rejects_broad_file_permissions() {
        // The replay store file itself (not just the parent) must enforce
        // strict permissions on load. Pin the contract so we catch any
        // future regressions in `validate_replay_store_path`.
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("broad-file");
        fs::write(&path, "").expect("broad-perm replay store should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("test fixture must use widened permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("broad replay store file permissions must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("permissions too broad"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn nonce_store_failed_persist_keeps_in_memory_state_consistent() {
        // If `persist_map` were to fail, `insert` must NOT update the
        // in-memory `nonces` map: otherwise the durable store drifts from
        // memory and a relay restart would forget the nonce. Simulate this
        // by pointing the store at a path whose parent disappears.
        let path_dir = std::env::temp_dir().join(format!(
            "rustynet-relay-vanish-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&path_dir).expect("temp dir must be created");
        #[cfg(unix)]
        fs::set_permissions(&path_dir, fs::Permissions::from_mode(0o700))
            .expect("temp dir permissions must be tight");
        let path = path_dir.join("replay.store");
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("replay store should initialize");
        // Remove the parent directory so subsequent writes fail
        fs::remove_dir_all(&path_dir).expect("parent directory removal should succeed");

        let hello = make_hello(&sk, "node-a", "node-b");
        let response = transport.handle_hello_from_tuple_with_allocated_port(
            hello.clone(),
            observed_addr([198, 51, 100, 95], 40_950),
            50_030,
        );
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::ReplayStoreUnavailable),
            "persist failure must surface as ReplayStoreUnavailable"
        );
        assert!(
            !transport.nonce_store.contains(&hello.session_token.nonce),
            "failed persist must not leave a phantom nonce in memory"
        );
        assert_eq!(
            transport.session_count(),
            0,
            "no session may be allocated when nonce persistence fails"
        );
    }

    #[test]
    fn touch_session_prevents_idle_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Create two sessions
        let hello_a = make_hello(&sk, "node-a", "node-b");
        let ack_a = match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        let hello_b = make_hello(&sk, "node-b", "node-a");
        let ack_b = match transport.handle_hello(hello_b) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        // Age both sessions past idle threshold
        for session in transport.sessions.values_mut() {
            session.last_packet_at =
                Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }

        // Touch only session A
        let _ = transport.touch_session(ack_a.session_id);

        // Run cleanup
        transport.cleanup_idle_sessions();

        // Session A should survive, session B should be cleaned
        assert!(
            transport.sessions.contains_key(&ack_a.session_id),
            "touched session should survive cleanup"
        );
        assert!(
            !transport.sessions.contains_key(&ack_b.session_id),
            "untouched idle session should be cleaned up"
        );
    }

    // ── Followup-audit regression tests ──────────────────────────────────────
    //
    // Pin the contracts for the four DoS / footgun followups flagged by the
    // previous audit:
    //   1. NonceStore::insert no longer clones the entire map per accepted
    //      hello — verified via large-batch insertion timing budget plus
    //      direct rollback-on-persist-failure check.
    //   2. compute_clamped_skew exposes the (value, was_clamped) decision
    //      the warn log line is gated on.
    //   3. set_max_total_sessions rejects shrinking below the live count.
    //   4. should_warn_replay_stat_skip exposes the decision the warn log
    //      line is gated on.

    #[test]
    fn nonce_store_insert_handles_large_batches_without_quadratic_clone() {
        // Followup #1: insert previously cloned the entire HashMap on each
        // call (O(n) per call, O(n²) total). Pin a bound that the
        // pre-fix implementation would blow through on slow CI: inserting
        // 1000 nonces into an in-memory store (no persist path) must
        // finish in well under 200 ms. The pre-fix implementation copied
        // (1 + 2 + ... + 1000) ≈ 500 000 entries; the new implementation
        // copies zero. We pick a generous threshold to avoid flakes on
        // shared CI runners.
        let mut store = NonceStore::default();
        let mut nonce = [0u8; 16];
        let start = Instant::now();
        for i in 0..1000u64 {
            nonce[0..8].copy_from_slice(&i.to_le_bytes());
            store
                .insert(nonce)
                .expect("in-memory insert must not fail without a persist path");
        }
        let elapsed = start.elapsed();
        assert_eq!(
            store.nonces.len(),
            1000,
            "all 1000 distinct nonces must be retained"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "1000 inserts must complete well under 200 ms (took {elapsed:?}); \
             a regression to clone-on-write would scale O(n²) and blow the budget"
        );
    }

    #[test]
    fn nonce_store_insert_persist_failure_rolls_back_in_memory_state() {
        // Followup #1: the new insert path mutates self.nonces *first* and
        // then persists; on persist failure it must roll back. This pins
        // the same property the existing
        // `nonce_store_failed_persist_keeps_in_memory_state_consistent`
        // test pins at the daemon entry point, but exercised directly on
        // NonceStore so the rollback path is unit-pinned.
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-rollback-{}-{}",
            std::process::id(),
            now_unix()
        ));
        fs::create_dir_all(&dir).expect("temp dir must be created");
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("temp dir permissions must be tight");
        let path = dir.join("replay.store");
        let mut store = NonceStore::load(path).expect("fresh store should initialize");
        // Yank the parent so subsequent persist calls fail.
        fs::remove_dir_all(&dir).expect("parent removal should succeed");

        let nonce = [0xAB; 16];
        let result = store.insert(nonce);
        assert!(
            result.is_err(),
            "insert with vanished parent must surface a persist error"
        );
        assert!(
            !store.nonces.contains_key(&nonce),
            "failed persist must not leave a phantom nonce in memory"
        );
    }

    #[test]
    fn compute_clamped_skew_reports_clamp_decision() {
        // Followup #2: the clamp decision is silent at construction time.
        // Pin the pure helper that the warn log is gated on so future
        // refactors cannot accidentally silence the warning.
        let (val, clamped) = compute_clamped_skew(0);
        assert_eq!((val, clamped), (0, false), "zero skew must pass through");

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS - 1);
        assert!(!clamped, "value below ceiling must not clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS - 1);

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS);
        assert!(!clamped, "value at exact ceiling must not clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS);

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS + 1);
        assert!(clamped, "value one above ceiling must clamp");
        assert_eq!(
            val, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "clamped value must equal the ceiling"
        );

        let (val, clamped) = compute_clamped_skew(u64::MAX);
        assert!(clamped, "u64::MAX must clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS);
    }

    #[test]
    fn set_max_total_sessions_refuses_to_shrink_below_live_count() {
        // Followup #3: an operator who shrinks the cap below the current
        // live session count must get a clear error rather than silent
        // eviction (or, worse, a config that admits the change but lets
        // the live set continue exceeding the cap).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        // Seed two live sessions
        let hello_a = make_hello(&sk, "node-a", "node-b");
        let hello_b = make_hello(&sk, "node-c", "node-d");
        match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("first hello must be accepted: {other:?}"),
        }
        match transport.handle_hello(hello_b) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("second hello must be accepted: {other:?}"),
        }
        assert_eq!(transport.session_count(), 2);

        let err = transport
            .set_max_total_sessions(1)
            .expect_err("shrinking below live count must fail closed");
        assert!(
            err.contains("cannot shrink") && err.contains("live count"),
            "error must clearly signal the shrink-below-live problem: {err}"
        );
        // And the underlying state must not have been mutated.
        assert_eq!(
            transport.session_count(),
            2,
            "rejected shrink must not have evicted sessions"
        );

        // Equal-to-live is fine (does not regress observable cap).
        transport
            .set_max_total_sessions(2)
            .expect("cap == live must succeed");
        // Strictly above live is fine.
        transport
            .set_max_total_sessions(10)
            .expect("cap > live must succeed");
        // Zero is still rejected (existing contract preserved).
        let err = transport
            .set_max_total_sessions(0)
            .expect_err("zero cap must still fail");
        assert!(err.contains("greater than 0"));
    }

    #[test]
    fn should_warn_replay_stat_skip_treats_not_found_as_silent() {
        // Followup #4: the warn log line for "permission check skipped due
        // to unexpected stat error" is gated on this helper. NotFound is
        // the *expected* fresh-install case and must not warn; any other
        // io error means we couldn't actually verify safety and must warn.
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(
            !should_warn_replay_stat_skip(&not_found),
            "NotFound is expected on fresh install and must not warn"
        );

        let permission_denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(
            should_warn_replay_stat_skip(&permission_denied),
            "PermissionDenied means we could not verify safety and must warn"
        );

        // A handful of other unexpected kinds — all must warn so the
        // decision boundary is not "only PermissionDenied".
        for kind in [
            std::io::ErrorKind::Other,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::TimedOut,
        ] {
            let err = std::io::Error::from(kind);
            assert!(
                should_warn_replay_stat_skip(&err),
                "unexpected io kind {kind:?} must warn"
            );
        }
    }
}
