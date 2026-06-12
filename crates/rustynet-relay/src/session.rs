#![forbid(unsafe_code)]

//! Relay session tracking and pairing logic.

use std::net::SocketAddr;
use std::time::Instant;

use rand::TryRngCore;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId([u8; 16]);

/// Errors surfaced by [`SessionId::try_generate`]. The only failure mode
/// today is kernel CSPRNG unavailability; we keep this in a dedicated error
/// type so callers must explicitly handle the fail-closed path instead of
/// panicking inside a long-running relay process.
#[derive(Debug)]
pub struct SessionIdRandomnessError {
    pub source: String,
}

impl std::fmt::Display for SessionIdRandomnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "kernel CSPRNG unavailable while generating relay session id: {}",
            self.source
        )
    }
}

impl std::error::Error for SessionIdRandomnessError {}

impl SessionId {
    /// Mint a fresh random session id from the kernel CSPRNG (`OsRng`).
    ///
    /// Returns `Err(SessionIdRandomnessError)` if the OS randomness source
    /// cannot fill the buffer. We never fall back to a non-CSPRNG source:
    /// the session id namespaces the relay forwarding map, so a predictable
    /// id lets one peer hijack another's relay session. Fail-closed is
    /// strictly safer than degraded entropy here.
    pub fn try_generate() -> Result<Self, SessionIdRandomnessError> {
        let mut id = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut id)
            .map_err(|err| SessionIdRandomnessError {
                source: err.to_string(),
            })?;
        Ok(Self(id))
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
    /// Cached id of the paired (reverse-direction) session, filled on
    /// first successful pair resolution so the per-frame forward path
    /// avoids rebuilding the owned `(String, String)` pair-index key.
    /// Purely a cache: it is re-validated against the live session map
    /// on every use (a session and its pair-index entry are always
    /// removed together, so a stale entry can only point at a removed
    /// session, never at the wrong live one) and the forward path
    /// falls back to the authoritative `node_pair_index` lookup on a
    /// miss.
    pub paired_session_id: Option<SessionId>,
}

impl RelaySession {
    pub fn is_paired_with(&self, other: &RelaySession) -> bool {
        self.node_id == other.peer_node_id && self.peer_node_id == other.node_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_generate_returns_distinct_high_entropy_ids() {
        // 64 successive generations should all be unique under a healthy
        // CSPRNG. A regression that fell back to a counter or zeroed buffer
        // would collapse to a small set of ids.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let id = SessionId::try_generate().expect("OsRng available in test env");
            assert!(
                seen.insert(*id.as_bytes()),
                "duplicate session id from CSPRNG"
            );
        }
    }

    #[test]
    fn session_id_randomness_error_displays_source() {
        // Pin the error type's `Display` shape so future log redactors do not
        // accidentally drop the inner kernel error and lose forensic info.
        let err = SessionIdRandomnessError {
            source: "getrandom syscall returned EAGAIN".to_owned(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("getrandom syscall returned EAGAIN"));
        assert!(rendered.contains("CSPRNG"));
        assert!(rendered.contains("relay session id"));
    }
}
