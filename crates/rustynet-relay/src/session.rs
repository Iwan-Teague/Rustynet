#![forbid(unsafe_code)]

//! Relay session tracking and pairing logic.

use std::net::SocketAddr;
use std::time::Instant;

use rand::TryRngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .expect("os randomness unavailable for relay session id");
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for SessionId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone)]
pub struct RelaySession {
    pub session_id: SessionId,
    pub node_id: String,
    pub peer_node_id: String,
    pub allocated_port: u16,
    pub hello_source_addr: SocketAddr,
    pub bound_peer_addr: Option<SocketAddr>,
    pub expires_at_unix: u64,
    pub established_at: Instant,
    pub last_packet_at: Instant,
}

impl RelaySession {
    pub fn is_paired_with(&self, other: &RelaySession) -> bool {
        self.node_id == other.peer_node_id && self.peer_node_id == other.node_id
    }
}
