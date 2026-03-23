#![forbid(unsafe_code)]

//! Relay transport session protocol and packet forwarding.
//!
//! This module implements the relay session authentication and bidirectional
//! packet forwarding for nodes that cannot establish direct connectivity.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::VerifyingKey;
use rand::RngCore;
use rustynet_control::RelaySessionToken;
use subtle::ConstantTimeEq;

use crate::rate_limit::RateLimiter;
use crate::session::{RelaySession, SessionId};

const MAX_RELAY_TTL_SECS: u64 = 120;
const HALF_OPEN_SESSION_TIMEOUT_SECS: u64 = 60;
const IDLE_SESSION_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    InvalidToken,
    ExpiredToken,
    ReplayedNonce,
    PeerMismatch,
    Capacity,
    RateLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

pub struct RelayTransport {
    sessions: HashMap<SessionId, RelaySession>,
    node_pair_index: HashMap<(String, String), SessionId>,
    rate_limiter: RateLimiter,
    control_verifier_key: VerifyingKey,
    nonce_store: NonceStore,
    clock_skew_tolerance_secs: u64,
    max_sessions_per_node: usize,
}

impl RelayTransport {
    pub fn new(
        control_verifier_key: VerifyingKey,
        max_sessions_per_node: usize,
        clock_skew_tolerance_secs: u64,
    ) -> Self {
        Self {
            sessions: HashMap::new(),
            node_pair_index: HashMap::new(),
            rate_limiter: RateLimiter::default(),
            control_verifier_key,
            nonce_store: NonceStore::default(),
            max_sessions_per_node,
            clock_skew_tolerance_secs,
        }
    }

    pub fn handle_hello(&mut self, hello: RelayHello) -> RelayHelloResponse {
        // Security check 1: Verify token signature
        if let Err(e) = hello
            .session_token
            .verify_signature(&self.control_verifier_key)
        {
            eprintln!("Relay hello rejected: invalid signature: {e}");
            return RelayHelloResponse::Rejected(RejectReason::InvalidToken);
        }

        // Security check 2: Verify token TTL (max 120s)
        let ttl = hello.session_token.ttl_secs();
        if ttl > MAX_RELAY_TTL_SECS {
            eprintln!("Relay hello rejected: TTL exceeds max ({ttl} > {MAX_RELAY_TTL_SECS})");
            return RelayHelloResponse::Rejected(RejectReason::InvalidToken);
        }

        // Security check 3: Check token freshness
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        if hello
            .session_token
            .is_expired(now_unix, self.clock_skew_tolerance_secs)
        {
            eprintln!("Relay hello rejected: token expired");
            return RelayHelloResponse::Rejected(RejectReason::ExpiredToken);
        }

        // Security check 4: Check nonce not replayed
        if self.nonce_store.contains(&hello.session_token.nonce) {
            eprintln!("Relay hello rejected: nonce replay detected");
            return RelayHelloResponse::Rejected(RejectReason::ReplayedNonce);
        }

        // Security check 5: Verify peer_node_id matches token
        if !hello
            .peer_node_id
            .as_bytes()
            .ct_eq(hello.session_token.peer_node_id.as_bytes())
            .into()
        {
            eprintln!("Relay hello rejected: peer_node_id mismatch");
            return RelayHelloResponse::Rejected(RejectReason::PeerMismatch);
        }

        // Security check 6: Check capacity per node
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
            return RelayHelloResponse::Rejected(RejectReason::Capacity);
        }

        // All checks passed - record nonce
        self.nonce_store.insert(hello.session_token.nonce);

        // Allocate session
        let session_id = SessionId::generate();
        let allocated_port = self.allocate_port();

        let session = RelaySession {
            session_id,
            node_id: hello.node_id.clone(),
            peer_node_id: hello.peer_node_id.clone(),
            allocated_port,
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

    pub fn forward_packet(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        _from_addr: SocketAddr,
    ) -> Result<Option<(SessionId, Vec<u8>)>, String> {
        // Rate limit check
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Err("session not found".to_string());
        };

        if !self
            .rate_limiter
            .check_packet(&session.node_id, payload.len())
        {
            // Silently drop - do not return error (avoid amplification)
            return Ok(None);
        }

        // Update last_packet_at
        session.last_packet_at = Instant::now();

        // Find paired session
        let peer_session_id = self
            .node_pair_index
            .get(&(session.peer_node_id.clone(), session.node_id.clone()))
            .copied();

        if let Some(peer_sid) = peer_session_id {
            // Update peer's last_packet_at
            if let Some(peer_session) = self.sessions.get_mut(&peer_sid) {
                peer_session.last_packet_at = Instant::now();
            }
            // Forward payload as-is (never inspect)
            Ok(Some((peer_sid, payload.to_vec())))
        } else {
            // No paired session - buffer would be here, but for simplicity we drop
            Ok(None)
        }
    }

    pub fn cleanup_idle_sessions(&mut self) {
        let now = Instant::now();
        let idle_threshold = Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS);
        let half_open_threshold = Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS);

        let mut to_remove = Vec::new();

        for (session_id, session) in &self.sessions {
            let age = now.duration_since(session.established_at);
            let idle = now.duration_since(session.last_packet_at);

            // Check if paired
            let has_pair = self
                .node_pair_index
                .contains_key(&(session.peer_node_id.clone(), session.node_id.clone()));

            if !has_pair && age > half_open_threshold {
                // Half-open session timeout
                to_remove.push(*session_id);
            } else if idle > idle_threshold {
                // Idle session timeout
                to_remove.push(*session_id);
            }
        }

        for sid in to_remove {
            if let Some(session) = self.sessions.remove(&sid) {
                self.node_pair_index
                    .remove(&(session.node_id.clone(), session.peer_node_id.clone()));
            }
        }
    }

    fn allocate_port(&self) -> u16 {
        // Simple port allocation - in production would track actual UDP bindings
        let base = 50000u16;
        let offset = (self.sessions.len() % 10000) as u16;
        base.wrapping_add(offset)
    }
}

#[derive(Default)]
struct NonceStore {
    nonces: HashMap<[u8; 16], Instant>,
}

impl NonceStore {
    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.nonces.contains_key(nonce)
    }

    fn insert(&mut self, nonce: [u8; 16]) {
        self.nonces.insert(nonce, Instant::now());
    }

    #[allow(dead_code)]
    fn prune(&mut self, retention: Duration) {
        let now = Instant::now();
        self.nonces
            .retain(|_, inserted_at| now.duration_since(*inserted_at) < retention);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn make_valid_token(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        ttl_secs: u64,
    ) -> RelaySessionToken {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut relay_id = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut relay_id);
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut token = RelaySessionToken {
            node_id: node_id.to_string(),
            peer_node_id: peer_node_id.to_string(),
            relay_id,
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_secs,
            nonce,
            signature: [0u8; 64],
        };

        let payload = token.canonical_payload();
        let signature = signing_key.sign(payload.as_bytes());
        token.signature = signature.to_bytes();

        token
    }

    #[test]
    fn test_invalid_signature_token_rejected() {
        let (_, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        // Create token with wrong signature
        let mut token =
            make_valid_token(&SigningKey::from_bytes(&[2u8; 32]), "node-a", "node-b", 60);
        token.signature = [99u8; 64]; // Invalid signature

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
        assert_eq!(transport.sessions.len(), 0);
    }

    #[test]
    fn test_expired_token_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut token = make_valid_token(&signing_key, "node-a", "node-b", 60);
        // Set expiry in the past
        token.expires_at_unix = now_unix - 200;

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::ExpiredToken)
        );
    }

    #[test]
    fn test_token_ttl_exceeds_max_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token = make_valid_token(&signing_key, "node-a", "node-b", 200); // TTL > 120s

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    #[test]
    fn test_replayed_nonce_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token = make_valid_token(&signing_key, "node-a", "node-b", 60);

        let hello1 = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token.clone(),
        };

        let response1 = transport.handle_hello(hello1);
        assert!(matches!(response1, RelayHelloResponse::Accepted(_)));

        // Replay same token
        let hello2 = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let response2 = transport.handle_hello(hello2);
        assert_eq!(
            response2,
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce)
        );
    }

    #[test]
    fn test_peer_mismatch_rejected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token = make_valid_token(&signing_key, "node-a", "node-b", 60);

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-c".to_string(), // Different from token
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::PeerMismatch)
        );
    }

    #[test]
    fn test_valid_hello_allocates_session() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token = make_valid_token(&signing_key, "node-a", "node-b", 60);

        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert!(matches!(response, RelayHelloResponse::Accepted(_)));

        assert_eq!(transport.sessions.len(), 1);
    }

    #[test]
    fn test_session_pairing_and_bidirectional_forwarding() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token_a = make_valid_token(&signing_key, "node-a", "node-b", 60);
        let token_b = make_valid_token(&signing_key, "node-b", "node-a", 60);

        let hello_a = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token_a,
        };

        let hello_b = RelayHello {
            node_id: "node-b".to_string(),
            peer_node_id: "node-a".to_string(),
            session_token: token_b,
        };

        let response_a = transport.handle_hello(hello_a);
        let sid_a = match response_a {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            _ => panic!("expected accepted"),
        };

        let response_b = transport.handle_hello(hello_b);
        let sid_b = match response_b {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            _ => panic!("expected accepted"),
        };

        // Forward packet from A to B
        let payload_a = b"test payload from A";
        let result = transport
            .forward_packet(sid_a, payload_a, "0.0.0.0:0".parse().unwrap())
            .unwrap();

        assert!(result.is_some());
        let (forwarded_sid, forwarded_payload) = result.unwrap();
        assert_eq!(forwarded_sid, sid_b);
        assert_eq!(forwarded_payload, payload_a);

        // Forward packet from B to A
        let payload_b = b"test payload from B";
        let result = transport
            .forward_packet(sid_b, payload_b, "0.0.0.0:0".parse().unwrap())
            .unwrap();

        assert!(result.is_some());
        let (forwarded_sid, forwarded_payload) = result.unwrap();
        assert_eq!(forwarded_sid, sid_a);
        assert_eq!(forwarded_payload, payload_b);
    }

    #[test]
    fn test_payload_is_not_inspected() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token_a = make_valid_token(&signing_key, "node-a", "node-b", 60);
        let token_b = make_valid_token(&signing_key, "node-b", "node-a", 60);

        let hello_a = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token_a,
        };

        let hello_b = RelayHello {
            node_id: "node-b".to_string(),
            peer_node_id: "node-a".to_string(),
            session_token: token_b,
        };

        let sid_a = match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            _ => panic!("expected accepted"),
        };

        let _ = transport.handle_hello(hello_b);

        // Test with random bytes (including zeros and all-255)
        let test_payloads = vec![
            vec![0u8; 100],
            vec![255u8; 100],
            (0..100).map(|i| i as u8).collect::<Vec<_>>(),
        ];

        for payload in test_payloads {
            let result = transport
                .forward_packet(sid_a, &payload, "0.0.0.0:0".parse().unwrap())
                .unwrap();

            if let Some((_, forwarded)) = result {
                // Byte-for-byte identity check
                assert_eq!(forwarded, payload);
            }
        }
    }

    #[test]
    fn test_capacity_limit_enforced() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 2, 90); // Max 2 sessions per node

        // Create 2 sessions for node-a
        for i in 0..2 {
            let token = make_valid_token(&signing_key, "node-a", &format!("node-b-{i}"), 60);
            let hello = RelayHello {
                node_id: "node-a".to_string(),
                peer_node_id: format!("node-b-{i}"),
                session_token: token,
            };
            let response = transport.handle_hello(hello);
            assert!(matches!(response, RelayHelloResponse::Accepted(_)));
        }

        // Try to create 3rd session - should be rejected
        let token = make_valid_token(&signing_key, "node-a", "node-b-3", 60);
        let hello = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b-3".to_string(),
            session_token: token,
        };

        let response = transport.handle_hello(hello);
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
    }

    #[test]
    fn test_rate_limit_drops_silently() {
        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);
        transport.rate_limiter.max_pps = 5; // Very low limit

        let token_a = make_valid_token(&signing_key, "node-a", "node-b", 60);
        let token_b = make_valid_token(&signing_key, "node-b", "node-a", 60);

        let hello_a = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token_a,
        };

        let hello_b = RelayHello {
            node_id: "node-b".to_string(),
            peer_node_id: "node-a".to_string(),
            session_token: token_b,
        };

        let sid_a = match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            _ => panic!("expected accepted"),
        };

        let _ = transport.handle_hello(hello_b);

        // Send packets up to limit
        for _ in 0..5 {
            let result = transport.forward_packet(sid_a, b"test", "0.0.0.0:0".parse().unwrap());
            assert!(result.is_ok());
        }

        // Excess packets should return Ok(None) - silent drop
        let result = transport.forward_packet(sid_a, b"test", "0.0.0.0:0".parse().unwrap());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), None);

        // Session should still exist
        assert_eq!(transport.sessions.len(), 2);
    }

    #[test]
    fn test_idle_session_cleanup() {
        use std::thread;
        use std::time::Duration;

        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token_a = make_valid_token(&signing_key, "node-a", "node-b", 60);
        let token_b = make_valid_token(&signing_key, "node-b", "node-a", 60);

        let hello_a = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token_a,
        };

        let hello_b = RelayHello {
            node_id: "node-b".to_string(),
            peer_node_id: "node-a".to_string(),
            session_token: token_b,
        };

        transport.handle_hello(hello_a);
        transport.handle_hello(hello_b);

        assert_eq!(transport.sessions.len(), 2);

        // Simulate idle by manually setting last_packet_at
        for session in transport.sessions.values_mut() {
            session.last_packet_at =
                Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }

        transport.cleanup_idle_sessions();

        assert_eq!(transport.sessions.len(), 0);
    }

    #[test]
    fn test_half_open_session_cleanup() {
        use std::time::Duration;

        let (signing_key, verifying_key) = make_test_keypair();
        let mut transport = RelayTransport::new(verifying_key, 8, 90);

        let token_a = make_valid_token(&signing_key, "node-a", "node-b", 60);

        let hello_a = RelayHello {
            node_id: "node-a".to_string(),
            peer_node_id: "node-b".to_string(),
            session_token: token_a,
        };

        transport.handle_hello(hello_a);

        assert_eq!(transport.sessions.len(), 1);

        // Simulate half-open timeout by manually setting established_at
        for session in transport.sessions.values_mut() {
            session.established_at =
                Instant::now() - Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS + 1);
        }

        transport.cleanup_idle_sessions();

        // Half-open session should be garbage collected
        assert_eq!(transport.sessions.len(), 0);
    }
}
