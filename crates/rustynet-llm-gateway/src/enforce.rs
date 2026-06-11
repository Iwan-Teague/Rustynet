//! Per-peer model / quota / rate enforcement (LLM design §7).
//!
//! Scopes come from the owner-signed policy
//! (`rustynet_policy::LlmAccessScope`) and only ever *narrow* an
//! existing `Decision::Allow` — enforcement here never grants
//! anything. All state is deterministic: callers supply `now_unix`,
//! so behaviour is fully unit-testable and replayable.

use std::collections::BTreeMap;
use std::fmt;

use rustynet_policy::LlmAccessScope;

/// Length of the token-quota accounting window.
pub const QUOTA_WINDOW_SECONDS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnforceError {
    /// Peer asked for a model outside its signed allow-list.
    ModelNotAllowed { model: String },
    /// Peer exhausted its token quota for the current window.
    TokenQuotaExhausted { used: u64, limit: u64 },
    /// Peer exceeded its request-rate ceiling.
    RateLimited { requests_in_minute: u32, limit: u32 },
}

impl fmt::Display for EnforceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnforceError::ModelNotAllowed { model } => {
                write!(f, "model {model:?} not in the peer's signed allow-list")
            }
            EnforceError::TokenQuotaExhausted { used, limit } => {
                write!(f, "token quota exhausted: {used}/{limit} in window")
            }
            EnforceError::RateLimited {
                requests_in_minute,
                limit,
            } => write!(
                f,
                "rate limited: {requests_in_minute}/{limit} requests in minute"
            ),
        }
    }
}

impl std::error::Error for EnforceError {}

/// Per-peer running counters. Deterministic windows keyed off the
/// caller-supplied clock.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PeerCounters {
    window_start_unix: u64,
    tokens_in_window: u64,
    minute_start_unix: u64,
    requests_in_minute: u32,
}

/// Gateway-side enforcement state for all peers. One instance per
/// gateway process; entries are dropped when a peer's sessions are
/// severed.
#[derive(Debug, Default)]
pub struct EnforcementState {
    peers: BTreeMap<String, PeerCounters>,
}

impl EnforcementState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Gate a new completion request. Checks the model allow-list
    /// and the request rate; token accounting happens as the stream
    /// produces tokens ([`Self::record_tokens`]).
    pub fn admit_request(
        &mut self,
        peer_node_id: &str,
        scope: Option<&LlmAccessScope>,
        model: &str,
        now_unix: u64,
    ) -> Result<(), EnforceError> {
        let Some(scope) = scope else {
            // No scope entry: the grant is unrestricted (the grant
            // itself was the authorisation; scoping is optional).
            return Ok(());
        };
        if !scope.permits_model(model) {
            return Err(EnforceError::ModelNotAllowed {
                model: model.to_owned(),
            });
        }
        let counters = self.peers.entry(peer_node_id.to_owned()).or_default();
        if now_unix.saturating_sub(counters.minute_start_unix) >= 60 {
            counters.minute_start_unix = now_unix;
            counters.requests_in_minute = 0;
        }
        if let Some(limit) = scope.max_requests_per_minute {
            if counters.requests_in_minute >= limit {
                return Err(EnforceError::RateLimited {
                    requests_in_minute: counters.requests_in_minute,
                    limit,
                });
            }
        }
        counters.requests_in_minute = counters.requests_in_minute.saturating_add(1);

        if now_unix.saturating_sub(counters.window_start_unix) >= QUOTA_WINDOW_SECONDS {
            counters.window_start_unix = now_unix;
            counters.tokens_in_window = 0;
        }
        if let Some(limit) = scope.max_tokens_per_window {
            if counters.tokens_in_window >= limit {
                return Err(EnforceError::TokenQuotaExhausted {
                    used: counters.tokens_in_window,
                    limit,
                });
            }
        }
        Ok(())
    }

    /// Account generated tokens against the peer's window and
    /// report whether the stream must be cut for quota exhaustion
    /// (`Err` ⇒ sever the stream now).
    pub fn record_tokens(
        &mut self,
        peer_node_id: &str,
        scope: Option<&LlmAccessScope>,
        token_count: u64,
        now_unix: u64,
    ) -> Result<(), EnforceError> {
        let counters = self.peers.entry(peer_node_id.to_owned()).or_default();
        if now_unix.saturating_sub(counters.window_start_unix) >= QUOTA_WINDOW_SECONDS {
            counters.window_start_unix = now_unix;
            counters.tokens_in_window = 0;
        }
        counters.tokens_in_window = counters.tokens_in_window.saturating_add(token_count);
        if let Some(scope) = scope {
            if let Some(limit) = scope.max_tokens_per_window {
                if counters.tokens_in_window > limit {
                    return Err(EnforceError::TokenQuotaExhausted {
                        used: counters.tokens_in_window,
                        limit,
                    });
                }
            }
        }
        Ok(())
    }

    /// Token/usage accounting for the `usage` operation (counts
    /// only).
    pub fn tokens_used_in_window(&self, peer_node_id: &str) -> u64 {
        self.peers
            .get(peer_node_id)
            .map(|c| c.tokens_in_window)
            .unwrap_or(0)
    }

    /// Drop a peer's counters (sessions severed / peer revoked).
    pub fn forget_peer(&mut self, peer_node_id: &str) {
        self.peers.remove(peer_node_id);
    }

    /// Filter a model listing down to what the peer's scope
    /// permits (`list-models` shows only invocable models).
    pub fn visible_models<'a>(
        scope: Option<&LlmAccessScope>,
        node_models: &'a [String],
    ) -> Vec<&'a String> {
        node_models
            .iter()
            .filter(|model| scope.map(|s| s.permits_model(model)).unwrap_or(true))
            .collect()
    }
}
