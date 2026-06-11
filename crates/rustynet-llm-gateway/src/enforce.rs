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
        if let Some(limit) = scope.max_requests_per_minute
            && counters.requests_in_minute >= limit
        {
            return Err(EnforceError::RateLimited {
                requests_in_minute: counters.requests_in_minute,
                limit,
            });
        }
        counters.requests_in_minute = counters.requests_in_minute.saturating_add(1);

        if now_unix.saturating_sub(counters.window_start_unix) >= QUOTA_WINDOW_SECONDS {
            counters.window_start_unix = now_unix;
            counters.tokens_in_window = 0;
        }
        if let Some(limit) = scope.max_tokens_per_window
            && counters.tokens_in_window >= limit
        {
            return Err(EnforceError::TokenQuotaExhausted {
                used: counters.tokens_in_window,
                limit,
            });
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
        if let Some(scope) = scope
            && let Some(limit) = scope.max_tokens_per_window
            && counters.tokens_in_window > limit
        {
            return Err(EnforceError::TokenQuotaExhausted {
                used: counters.tokens_in_window,
                limit,
            });
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

#[cfg(test)]
mod tests {
    use super::*;

    const PEER: &str = "node:laptop-1";
    const NOW: u64 = 1_750_000_000;

    fn scope(
        allowed_models: Option<Vec<&str>>,
        max_tokens_per_window: Option<u64>,
        max_requests_per_minute: Option<u32>,
    ) -> LlmAccessScope {
        LlmAccessScope {
            allowed_models: allowed_models
                .map(|models| models.into_iter().map(str::to_owned).collect()),
            max_tokens_per_window,
            max_requests_per_minute,
        }
    }

    #[test]
    fn no_scope_admits_any_model_without_quota_or_rate() {
        let mut state = EnforcementState::new();
        // Far more requests than any plausible rate limit, any model.
        for i in 0..1000 {
            state
                .admit_request(PEER, None, &format!("model-{i}"), NOW)
                .expect("no scope ⇒ unrestricted grant");
        }
        // Token recording never severs without a scope either.
        state
            .record_tokens(PEER, None, u32::MAX as u64, NOW)
            .expect("no scope ⇒ no token quota");
    }

    #[test]
    fn model_outside_allow_list_refused() {
        let mut state = EnforcementState::new();
        let scope = scope(Some(vec!["a"]), None, None);
        state
            .admit_request(PEER, Some(&scope), "a", NOW)
            .expect("allowed model admits");
        let err = state
            .admit_request(PEER, Some(&scope), "b", NOW)
            .expect_err("model outside allow-list must be refused");
        assert_eq!(
            err,
            EnforceError::ModelNotAllowed {
                model: "b".to_owned()
            }
        );
    }

    #[test]
    fn rate_limit_trips_on_third_request_and_resets_after_minute() {
        let mut state = EnforcementState::new();
        let scope = scope(None, None, Some(2));
        state
            .admit_request(PEER, Some(&scope), "a", NOW)
            .expect("first request admits");
        state
            .admit_request(PEER, Some(&scope), "a", NOW)
            .expect("second request admits");
        let err = state
            .admit_request(PEER, Some(&scope), "a", NOW)
            .expect_err("third request in the same minute must be rate-limited");
        assert_eq!(
            err,
            EnforceError::RateLimited {
                requests_in_minute: 2,
                limit: 2
            }
        );
        // Advancing the clock by a full minute resets the window.
        state
            .admit_request(PEER, Some(&scope), "a", NOW + 60)
            .expect("rate window resets after 60s");
    }

    #[test]
    fn token_quota_severs_stream_and_window_resets() {
        let mut state = EnforcementState::new();
        let scope = scope(None, Some(10), None);
        state
            .record_tokens(PEER, Some(&scope), 6, NOW)
            .expect("under quota");
        let err = state
            .record_tokens(PEER, Some(&scope), 6, NOW)
            .expect_err("crossing the quota must sever the stream");
        assert_eq!(
            err,
            EnforceError::TokenQuotaExhausted {
                used: 12,
                limit: 10
            }
        );
        // A new request while exhausted is refused at admission too.
        let admit_err = state
            .admit_request(PEER, Some(&scope), "a", NOW)
            .expect_err("exhausted quota refuses new requests");
        assert!(matches!(
            admit_err,
            EnforceError::TokenQuotaExhausted { .. }
        ));
        // After the accounting window passes, the quota resets.
        state
            .record_tokens(PEER, Some(&scope), 6, NOW + QUOTA_WINDOW_SECONDS)
            .expect("quota window resets after QUOTA_WINDOW_SECONDS");
        assert_eq!(state.tokens_used_in_window(PEER), 6);
    }

    #[test]
    fn visible_models_filters_by_scope() {
        let node_models = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let scope = scope(Some(vec!["a", "c"]), None, None);
        let visible = EnforcementState::visible_models(Some(&scope), &node_models);
        assert_eq!(visible, vec![&"a".to_owned(), &"c".to_owned()]);
        // No scope ⇒ everything visible.
        let all = EnforcementState::visible_models(None, &node_models);
        assert_eq!(all.len(), 3);
        // Empty allow-list ⇒ nothing visible (deny posture).
        let empty = scope_empty();
        assert!(EnforcementState::visible_models(Some(&empty), &node_models).is_empty());
    }

    fn scope_empty() -> LlmAccessScope {
        LlmAccessScope {
            allowed_models: Some(Vec::new()),
            max_tokens_per_window: None,
            max_requests_per_minute: None,
        }
    }

    #[test]
    fn forget_peer_clears_counters() {
        let mut state = EnforcementState::new();
        let scope = scope(None, Some(100), None);
        state
            .record_tokens(PEER, Some(&scope), 42, NOW)
            .expect("under quota");
        assert_eq!(state.tokens_used_in_window(PEER), 42);
        state.forget_peer(PEER);
        assert_eq!(state.tokens_used_in_window(PEER), 0);
    }

    #[test]
    fn tokens_used_in_window_accounting() {
        let mut state = EnforcementState::new();
        assert_eq!(state.tokens_used_in_window(PEER), 0);
        state
            .record_tokens(PEER, None, 3, NOW)
            .expect("no quota without scope");
        state
            .record_tokens(PEER, None, 4, NOW + 1)
            .expect("no quota without scope");
        assert_eq!(state.tokens_used_in_window(PEER), 7);
        // Accounting is per-peer.
        assert_eq!(state.tokens_used_in_window("node:laptop-2"), 0);
    }
}
