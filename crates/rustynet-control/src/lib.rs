#![forbid(unsafe_code)]

pub mod admin;
pub mod ga;
pub mod operations;
pub mod persistence;
pub mod scale;

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rustynet_policy::PolicySet;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthRateLimitConfig {
    pub ip_burst: u32,
    pub ip_refill_per_minute: u32,
    pub identity_burst: u32,
    pub identity_refill_per_15_min: u32,
}

impl Default for AuthRateLimitConfig {
    fn default() -> Self {
        Self {
            ip_burst: 20,
            ip_refill_per_minute: 10,
            identity_burst: 10,
            identity_refill_per_15_min: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutConfig {
    pub initial_backoff_secs: u64,
    pub max_backoff_secs: u64,
}

impl Default for LockoutConfig {
    fn default() -> Self {
        Self {
            initial_backoff_secs: 30,
            max_backoff_secs: 15 * 60,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPolicy {
    pub token_lifetime_secs: u64,
    pub clock_skew_tolerance_secs: u64,
}

impl Default for ReplayPolicy {
    fn default() -> Self {
        Self {
            token_lifetime_secs: 5 * 60,
            clock_skew_tolerance_secs: 90,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TokenClaims {
    pub subject: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
}

impl fmt::Debug for TokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenClaims")
            .field("subject", &"REDACTED")
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("nonce", &"REDACTED")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPlaneTlsVersion {
    Tls12,
    Tls13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPlaneTransportPolicy {
    pub minimum_tls: ControlPlaneTlsVersion,
    pub require_signed_control_data: bool,
}

impl Default for ControlPlaneTransportPolicy {
    fn default() -> Self {
        Self {
            minimum_tls: ControlPlaneTlsVersion::Tls13,
            require_signed_control_data: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportPolicyError {
    TlsVersionRejected,
    UnsignedControlDataRejected,
}

impl fmt::Display for TransportPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportPolicyError::TlsVersionRejected => f.write_str("tls version rejected"),
            TransportPolicyError::UnsignedControlDataRejected => {
                f.write_str("unsigned control data rejected")
            }
        }
    }
}

impl std::error::Error for TransportPolicyError {}

impl ControlPlaneTransportPolicy {
    pub fn validate_negotiated_tls(
        &self,
        negotiated: ControlPlaneTlsVersion,
    ) -> Result<(), TransportPolicyError> {
        if self.minimum_tls == ControlPlaneTlsVersion::Tls13
            && negotiated != ControlPlaneTlsVersion::Tls13
        {
            return Err(TransportPolicyError::TlsVersionRejected);
        }
        Ok(())
    }

    pub fn validate_control_data_signature(
        &self,
        signature_present: bool,
    ) -> Result<(), TransportPolicyError> {
        if self.require_signed_control_data && !signature_present {
            return Err(TransportPolicyError::UnsignedControlDataRejected);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseAlert {
    pub source_ip: String,
    pub identity: String,
    pub endpoint: String,
    pub reason: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbuseAlertPolicy {
    pub threshold: u32,
    pub window_secs: u64,
}

impl Default for AbuseAlertPolicy {
    fn default() -> Self {
        Self {
            threshold: 5,
            window_secs: 60,
        }
    }
}

#[derive(Debug, Default)]
pub struct ApiAbuseMonitor {
    policy: AbuseAlertPolicy,
    failures: HashMap<(String, String, String), Vec<u64>>,
    alerts: Mutex<Vec<AbuseAlert>>,
}

impl ApiAbuseMonitor {
    pub fn new(policy: AbuseAlertPolicy) -> Self {
        Self {
            policy,
            failures: HashMap::new(),
            alerts: Mutex::new(Vec::new()),
        }
    }

    pub fn record_failure(
        &mut self,
        source_ip: &str,
        identity: &str,
        endpoint: &str,
        reason: &str,
        now_unix: u64,
    ) -> Result<bool, AuthError> {
        let key = (
            source_ip.to_string(),
            identity.to_string(),
            endpoint.to_string(),
        );
        let history = self.failures.entry(key).or_default();
        let window_start = now_unix.saturating_sub(self.policy.window_secs);
        history.retain(|entry| *entry >= window_start);
        history.push(now_unix);

        if history.len() as u32 >= self.policy.threshold {
            let mut guard = self.alerts.lock().map_err(|_| AuthError::Internal)?;
            guard.push(AbuseAlert {
                source_ip: source_ip.to_string(),
                identity: identity.to_string(),
                endpoint: endpoint.to_string(),
                reason: reason.to_string(),
                timestamp_unix: now_unix,
            });
            return Ok(true);
        }

        Ok(false)
    }

    pub fn alerts(&self) -> Result<Vec<AbuseAlert>, AuthError> {
        let guard = self.alerts.lock().map_err(|_| AuthError::Internal)?;
        Ok(guard.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    RateLimited,
    LockedOutUntil(u64),
    ReplayDetected,
    InvalidTokenLifetime,
    TokenExpired,
    TokenNotYetValid,
    Internal,
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::RateLimited => f.write_str("rate limited"),
            AuthError::LockedOutUntil(ts) => write!(f, "identity locked out until {ts}"),
            AuthError::ReplayDetected => f.write_str("replay detected"),
            AuthError::InvalidTokenLifetime => f.write_str("invalid token lifetime"),
            AuthError::TokenExpired => f.write_str("token expired"),
            AuthError::TokenNotYetValid => f.write_str("token not yet valid"),
            AuthError::Internal => f.write_str("internal auth guard error"),
        }
    }
}

impl std::error::Error for AuthError {}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    last_refill_unix: u64,
}

impl Bucket {
    fn new(capacity: u32, now_unix: u64) -> Self {
        Self {
            tokens: f64::from(capacity),
            last_refill_unix: now_unix,
        }
    }

    fn consume(
        &mut self,
        now_unix: u64,
        capacity: u32,
        refill_per_second: f64,
    ) -> Result<(), AuthError> {
        let elapsed = now_unix.saturating_sub(self.last_refill_unix);
        self.last_refill_unix = now_unix;

        let refill = (elapsed as f64) * refill_per_second;
        self.tokens = (self.tokens + refill).min(f64::from(capacity));

        if self.tokens < 1.0 {
            return Err(AuthError::RateLimited);
        }

        self.tokens -= 1.0;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct LockoutState {
    consecutive_failures: u32,
    locked_until_unix: u64,
}

impl LockoutState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            locked_until_unix: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub endpoint: String,
    pub source_ip: String,
    pub identity: String,
    pub failure_class: String,
    pub limiter_decision: String,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone)]
pub struct AuthSurfaceGuard {
    rate_config: AuthRateLimitConfig,
    lockout_config: LockoutConfig,
    replay_policy: ReplayPolicy,
    ip_buckets: HashMap<String, Bucket>,
    identity_buckets: HashMap<String, Bucket>,
    lockouts: HashMap<String, LockoutState>,
    seen_nonces: HashMap<String, u64>,
    event_log: Arc<Mutex<Vec<SecurityEvent>>>,
}

impl Default for AuthSurfaceGuard {
    fn default() -> Self {
        Self::new(
            AuthRateLimitConfig::default(),
            LockoutConfig::default(),
            ReplayPolicy::default(),
        )
    }
}

impl AuthSurfaceGuard {
    pub fn new(
        rate_config: AuthRateLimitConfig,
        lockout_config: LockoutConfig,
        replay_policy: ReplayPolicy,
    ) -> Self {
        Self {
            rate_config,
            lockout_config,
            replay_policy,
            ip_buckets: HashMap::new(),
            identity_buckets: HashMap::new(),
            lockouts: HashMap::new(),
            seen_nonces: HashMap::new(),
            event_log: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn authorize_attempt(
        &mut self,
        endpoint: &str,
        source_ip: &str,
        identity: &str,
        now_unix: u64,
    ) -> Result<(), AuthError> {
        let locked_until = {
            let lockout = self
                .lockouts
                .entry(identity.to_string())
                .or_insert_with(LockoutState::new);
            lockout.locked_until_unix
        };

        if now_unix < locked_until {
            self.record_event(SecurityEvent {
                endpoint: endpoint.to_string(),
                source_ip: source_ip.to_string(),
                identity: identity.to_string(),
                failure_class: "lockout".to_string(),
                limiter_decision: "denied_locked".to_string(),
                timestamp_unix: now_unix,
            })?;
            return Err(AuthError::LockedOutUntil(locked_until));
        }

        let ip_bucket = self
            .ip_buckets
            .entry(source_ip.to_string())
            .or_insert_with(|| Bucket::new(self.rate_config.ip_burst, now_unix));
        ip_bucket.consume(
            now_unix,
            self.rate_config.ip_burst,
            f64::from(self.rate_config.ip_refill_per_minute) / 60.0,
        )?;

        let identity_bucket = self
            .identity_buckets
            .entry(identity.to_string())
            .or_insert_with(|| Bucket::new(self.rate_config.identity_burst, now_unix));
        identity_bucket.consume(
            now_unix,
            self.rate_config.identity_burst,
            f64::from(self.rate_config.identity_refill_per_15_min) / (15.0 * 60.0),
        )?;

        Ok(())
    }

    pub fn register_failure(&mut self, identity: &str, now_unix: u64) {
        let lockout = self
            .lockouts
            .entry(identity.to_string())
            .or_insert_with(LockoutState::new);

        lockout.consecutive_failures = lockout.consecutive_failures.saturating_add(1);
        let exponent = lockout.consecutive_failures.saturating_sub(1).min(30);
        let mut backoff = self
            .lockout_config
            .initial_backoff_secs
            .saturating_mul(2_u64.saturating_pow(exponent));
        backoff = backoff.min(self.lockout_config.max_backoff_secs);
        lockout.locked_until_unix = now_unix.saturating_add(backoff);
    }

    pub fn register_success(&mut self, identity: &str) {
        let lockout = self
            .lockouts
            .entry(identity.to_string())
            .or_insert_with(LockoutState::new);
        lockout.consecutive_failures = 0;
        lockout.locked_until_unix = 0;
    }

    pub fn validate_token_and_nonce(
        &mut self,
        claims: &TokenClaims,
        now_unix: u64,
    ) -> Result<(), AuthError> {
        if claims.expires_at_unix <= claims.issued_at_unix {
            return Err(AuthError::InvalidTokenLifetime);
        }

        let lifetime = claims.expires_at_unix.saturating_sub(claims.issued_at_unix);
        if lifetime > self.replay_policy.token_lifetime_secs {
            return Err(AuthError::InvalidTokenLifetime);
        }

        if now_unix
            > claims
                .expires_at_unix
                .saturating_add(self.replay_policy.clock_skew_tolerance_secs)
        {
            return Err(AuthError::TokenExpired);
        }

        if now_unix.saturating_add(self.replay_policy.clock_skew_tolerance_secs)
            < claims.issued_at_unix
        {
            return Err(AuthError::TokenNotYetValid);
        }

        self.prune_nonce_store(now_unix);

        if self.seen_nonces.contains_key(&claims.nonce) {
            return Err(AuthError::ReplayDetected);
        }

        self.seen_nonces
            .insert(claims.nonce.clone(), claims.expires_at_unix);
        Ok(())
    }

    pub fn security_events(&self) -> Result<Vec<SecurityEvent>, AuthError> {
        let events = self.event_log.lock().map_err(|_| AuthError::Internal)?;
        Ok(events.clone())
    }

    fn record_event(&self, event: SecurityEvent) -> Result<(), AuthError> {
        let mut events = self.event_log.lock().map_err(|_| AuthError::Internal)?;
        events.push(event);
        Ok(())
    }

    fn prune_nonce_store(&mut self, now_unix: u64) {
        self.seen_nonces.retain(|_, expires_at| {
            expires_at.saturating_add(self.replay_policy.clock_skew_tolerance_secs) >= now_unix
        });
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrowawayCredentialState {
    Created,
    Used,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialKind {
    Throwaway,
    Reusable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ThrowawayCredential {
    pub id: String,
    pub creator: String,
    pub scope: String,
    pub kind: CredentialKind,
    pub storage_policy: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub max_uses: u8,
    pub uses: u8,
    pub state: ThrowawayCredentialState,
}

impl fmt::Debug for ThrowawayCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThrowawayCredential")
            .field("id", &"REDACTED")
            .field("creator", &self.creator)
            .field("scope", &self.scope)
            .field("kind", &self.kind)
            .field("storage_policy", &"REDACTED")
            .field("created_at_unix", &self.created_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("max_uses", &self.max_uses)
            .field("uses", &self.uses)
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialError {
    AlreadyExists,
    NotFound,
    AlreadyConsumed,
    Expired,
    Revoked,
    InvalidStateTransition,
    ScopeTooBroad,
    TtlTooLong,
    StoragePolicyViolation,
    InvalidMaxUses,
    Internal,
}

impl fmt::Display for CredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CredentialError::AlreadyExists => f.write_str("credential already exists"),
            CredentialError::NotFound => f.write_str("credential not found"),
            CredentialError::AlreadyConsumed => f.write_str("credential already consumed"),
            CredentialError::Expired => f.write_str("credential expired"),
            CredentialError::Revoked => f.write_str("credential revoked"),
            CredentialError::InvalidStateTransition => f.write_str("invalid lifecycle transition"),
            CredentialError::ScopeTooBroad => f.write_str("reusable credential scope is too broad"),
            CredentialError::TtlTooLong => f.write_str("reusable credential ttl is too long"),
            CredentialError::StoragePolicyViolation => {
                f.write_str("reusable credential storage policy violation")
            }
            CredentialError::InvalidMaxUses => f.write_str("invalid reusable credential max uses"),
            CredentialError::Internal => f.write_str("internal credential store error"),
        }
    }
}

impl std::error::Error for CredentialError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialAuditEvent {
    pub credential_id: String,
    pub from_state: Option<ThrowawayCredentialState>,
    pub to_state: ThrowawayCredentialState,
    pub timestamp_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRevocationEvent {
    pub credential_id: String,
    pub generation: u64,
    pub revoked_at_unix: u64,
}

#[derive(Debug, Default)]
pub struct ThrowawayCredentialStore {
    credentials: Mutex<HashMap<String, ThrowawayCredential>>,
    audit_events: Mutex<Vec<CredentialAuditEvent>>,
    revocation_generation: Mutex<u64>,
    revocation_events: Mutex<Vec<CredentialRevocationEvent>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReusableCredentialPolicy {
    pub max_ttl_secs: u64,
    pub min_max_uses: u8,
    pub max_max_uses: u8,
}

impl Default for ReusableCredentialPolicy {
    fn default() -> Self {
        Self {
            max_ttl_secs: 24 * 60 * 60,
            min_max_uses: 2,
            max_max_uses: 25,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReusableCredentialRequest {
    pub id: String,
    pub creator: String,
    pub scope: String,
    pub created_at_unix: u64,
    pub ttl_secs: u64,
    pub max_uses: u8,
    pub storage_reference: String,
}

impl ThrowawayCredentialStore {
    pub fn create(
        &self,
        id: String,
        creator: String,
        scope: String,
        created_at_unix: u64,
        ttl_secs: u64,
    ) -> Result<ThrowawayCredential, CredentialError> {
        let expires_at_unix = created_at_unix.saturating_add(ttl_secs);
        let credential = ThrowawayCredential {
            id: id.clone(),
            creator,
            scope,
            kind: CredentialKind::Throwaway,
            storage_policy: "throwaway_default".to_string(),
            created_at_unix,
            expires_at_unix,
            max_uses: 1,
            uses: 0,
            state: ThrowawayCredentialState::Created,
        };

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        if guard.contains_key(&id) {
            return Err(CredentialError::AlreadyExists);
        }

        guard.insert(id.clone(), credential.clone());
        drop(guard);

        self.record_audit_event(CredentialAuditEvent {
            credential_id: id,
            from_state: None,
            to_state: ThrowawayCredentialState::Created,
            timestamp_unix: created_at_unix,
        })?;

        Ok(credential)
    }

    pub fn create_reusable(
        &self,
        request: ReusableCredentialRequest,
        policy: ReusableCredentialPolicy,
    ) -> Result<ThrowawayCredential, CredentialError> {
        if !is_strict_automation_scope(&request.scope) {
            return Err(CredentialError::ScopeTooBroad);
        }
        if request.ttl_secs > policy.max_ttl_secs {
            return Err(CredentialError::TtlTooLong);
        }
        if request.max_uses < policy.min_max_uses || request.max_uses > policy.max_max_uses {
            return Err(CredentialError::InvalidMaxUses);
        }
        if !request.storage_reference.starts_with("vault://") {
            return Err(CredentialError::StoragePolicyViolation);
        }

        let expires_at_unix = request.created_at_unix.saturating_add(request.ttl_secs);
        let credential = ThrowawayCredential {
            id: request.id.clone(),
            creator: request.creator,
            scope: request.scope,
            kind: CredentialKind::Reusable,
            storage_policy: request.storage_reference,
            created_at_unix: request.created_at_unix,
            expires_at_unix,
            max_uses: request.max_uses,
            uses: 0,
            state: ThrowawayCredentialState::Created,
        };

        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        if guard.contains_key(&request.id) {
            return Err(CredentialError::AlreadyExists);
        }

        guard.insert(request.id.clone(), credential.clone());
        drop(guard);

        self.record_audit_event(CredentialAuditEvent {
            credential_id: request.id,
            from_state: None,
            to_state: ThrowawayCredentialState::Created,
            timestamp_unix: request.created_at_unix,
        })?;

        Ok(credential)
    }

    pub fn consume(&self, id: &str, now_unix: u64) -> Result<ThrowawayCredential, CredentialError> {
        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        let credential = guard.get_mut(id).ok_or(CredentialError::NotFound)?;

        match credential.state {
            ThrowawayCredentialState::Created => {}
            ThrowawayCredentialState::Used => return Err(CredentialError::AlreadyConsumed),
            ThrowawayCredentialState::Expired => return Err(CredentialError::Expired),
            ThrowawayCredentialState::Revoked => return Err(CredentialError::Revoked),
        }

        if now_unix > credential.expires_at_unix {
            credential.state = ThrowawayCredentialState::Expired;
            drop(guard);
            self.record_audit_event(CredentialAuditEvent {
                credential_id: id.to_string(),
                from_state: Some(ThrowawayCredentialState::Created),
                to_state: ThrowawayCredentialState::Expired,
                timestamp_unix: now_unix,
            })?;
            return Err(CredentialError::Expired);
        }

        if credential.uses >= credential.max_uses {
            credential.state = ThrowawayCredentialState::Used;
            return Err(CredentialError::AlreadyConsumed);
        }

        credential.uses = credential.uses.saturating_add(1);
        credential.state = if credential.uses >= credential.max_uses {
            ThrowawayCredentialState::Used
        } else {
            ThrowawayCredentialState::Created
        };
        let to_state = credential.state;
        let snapshot = credential.clone();
        drop(guard);

        self.record_audit_event(CredentialAuditEvent {
            credential_id: id.to_string(),
            from_state: Some(ThrowawayCredentialState::Created),
            to_state,
            timestamp_unix: now_unix,
        })?;

        Ok(snapshot)
    }

    pub fn revoke(&self, id: &str, now_unix: u64) -> Result<(), CredentialError> {
        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        let credential = guard.get_mut(id).ok_or(CredentialError::NotFound)?;

        match credential.state {
            ThrowawayCredentialState::Created => {
                credential.state = ThrowawayCredentialState::Revoked;
            }
            ThrowawayCredentialState::Used
            | ThrowawayCredentialState::Expired
            | ThrowawayCredentialState::Revoked => {
                return Err(CredentialError::InvalidStateTransition);
            }
        }

        drop(guard);
        let generation = self.increment_revocation_generation()?;
        self.record_revocation_event(CredentialRevocationEvent {
            credential_id: id.to_string(),
            generation,
            revoked_at_unix: now_unix,
        })?;
        self.record_audit_event(CredentialAuditEvent {
            credential_id: id.to_string(),
            from_state: Some(ThrowawayCredentialState::Created),
            to_state: ThrowawayCredentialState::Revoked,
            timestamp_unix: now_unix,
        })?;

        Ok(())
    }

    pub fn expire_stale(&self, now_unix: u64) -> Result<usize, CredentialError> {
        let mut guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        let mut expired_ids = Vec::new();

        for (id, credential) in &mut *guard {
            if credential.state == ThrowawayCredentialState::Created
                && now_unix > credential.expires_at_unix
            {
                credential.state = ThrowawayCredentialState::Expired;
                expired_ids.push(id.clone());
            }
        }
        drop(guard);

        for id in &expired_ids {
            self.record_audit_event(CredentialAuditEvent {
                credential_id: id.clone(),
                from_state: Some(ThrowawayCredentialState::Created),
                to_state: ThrowawayCredentialState::Expired,
                timestamp_unix: now_unix,
            })?;
        }

        Ok(expired_ids.len())
    }

    pub fn get(&self, id: &str) -> Result<Option<ThrowawayCredential>, CredentialError> {
        let guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        Ok(guard.get(id).cloned())
    }

    pub fn audit_events(&self) -> Result<Vec<CredentialAuditEvent>, CredentialError> {
        let events = self
            .audit_events
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        Ok(events.clone())
    }

    fn record_audit_event(&self, event: CredentialAuditEvent) -> Result<(), CredentialError> {
        let mut guard = self
            .audit_events
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        guard.push(event);
        Ok(())
    }

    fn increment_revocation_generation(&self) -> Result<u64, CredentialError> {
        let mut guard = self
            .revocation_generation
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        *guard = guard.saturating_add(1);
        Ok(*guard)
    }

    fn record_revocation_event(
        &self,
        event: CredentialRevocationEvent,
    ) -> Result<(), CredentialError> {
        let mut guard = self
            .revocation_events
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        guard.push(event);
        Ok(())
    }

    pub fn revocation_generation(&self) -> Result<u64, CredentialError> {
        let guard = self
            .revocation_generation
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        Ok(*guard)
    }

    pub fn revocations_since(
        &self,
        generation: u64,
    ) -> Result<Vec<CredentialRevocationEvent>, CredentialError> {
        let guard = self
            .revocation_events
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        Ok(guard
            .iter()
            .filter(|event| event.generation > generation)
            .cloned()
            .collect())
    }

    pub fn is_revoked(&self, id: &str) -> Result<bool, CredentialError> {
        let guard = self
            .credentials
            .lock()
            .map_err(|_| CredentialError::Internal)?;
        Ok(matches!(
            guard.get(id),
            Some(ThrowawayCredential {
                state: ThrowawayCredentialState::Revoked,
                ..
            })
        ))
    }
}

fn is_strict_automation_scope(scope: &str) -> bool {
    let scope = scope.trim();
    if scope.is_empty() {
        return false;
    }
    if scope.contains('*') || scope.contains(' ') {
        return false;
    }
    scope.starts_with("tag:")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustState {
    pub generation: u64,
    pub signing_fingerprint: String,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStateError {
    Missing,
    Corrupt,
    InvalidFormat,
    PersistFailure,
    IntegrityMismatch,
}

impl fmt::Display for TrustStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustStateError::Missing => f.write_str("trust state missing"),
            TrustStateError::Corrupt => f.write_str("trust state corrupt"),
            TrustStateError::InvalidFormat => f.write_str("trust state invalid format"),
            TrustStateError::PersistFailure => f.write_str("trust state persist failure"),
            TrustStateError::IntegrityMismatch => f.write_str("trust state integrity mismatch"),
        }
    }
}

impl std::error::Error for TrustStateError {}

pub fn persist_trust_state(
    path: impl AsRef<Path>,
    state: &TrustState,
) -> Result<(), TrustStateError> {
    let payload = trust_state_payload(state);
    let digest = hex_sha256(payload.as_bytes());
    let body = format!("{payload}digest={digest}\n");

    std::fs::write(path, body).map_err(|_| TrustStateError::PersistFailure)
}

pub fn load_trust_state(path: impl AsRef<Path>) -> Result<TrustState, TrustStateError> {
    let content = std::fs::read_to_string(path).map_err(|_| TrustStateError::Missing)?;
    let mut generation: Option<u64> = None;
    let mut fingerprint: Option<String> = None;
    let mut updated_at: Option<u64> = None;
    let mut digest: Option<String> = None;

    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TrustStateError::InvalidFormat);
        };

        match key {
            "version" => {
                if value != "1" {
                    return Err(TrustStateError::InvalidFormat);
                }
            }
            "generation" => {
                generation = value.parse::<u64>().ok();
            }
            "signing_fingerprint" => {
                fingerprint = Some(value.to_string());
            }
            "updated_at_unix" => {
                updated_at = value.parse::<u64>().ok();
            }
            "digest" => {
                digest = Some(value.to_string());
            }
            _ => return Err(TrustStateError::InvalidFormat),
        }
    }

    let state = TrustState {
        generation: generation.ok_or(TrustStateError::Corrupt)?,
        signing_fingerprint: fingerprint.ok_or(TrustStateError::Corrupt)?,
        updated_at_unix: updated_at.ok_or(TrustStateError::Corrupt)?,
    };

    let expected_digest = digest.ok_or(TrustStateError::Corrupt)?;
    let payload = trust_state_payload(&state);
    let actual_digest = hex_sha256(payload.as_bytes());

    if actual_digest != expected_digest {
        return Err(TrustStateError::IntegrityMismatch);
    }

    Ok(state)
}

fn trust_state_payload(state: &TrustState) -> String {
    format!(
        "version=1\ngeneration={}\nsigning_fingerprint={}\nupdated_at_unix={}\n",
        state.generation, state.signing_fingerprint, state.updated_at_unix
    )
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyCheckRequest {
    pub source: String,
    pub destination: String,
    pub protocol: String,
}

#[derive(Debug, Default)]
pub struct PolicyGuard {
    allow_rules: HashSet<(String, String, String)>,
}

impl PolicyGuard {
    pub fn allow(
        &mut self,
        source: impl Into<String>,
        destination: impl Into<String>,
        protocol: impl Into<String>,
    ) {
        self.allow_rules
            .insert((source.into(), destination.into(), protocol.into()));
    }

    pub fn evaluate(&self, request: &PolicyCheckRequest) -> PolicyDecision {
        if self.allow_rules.contains(&(
            request.source.clone(),
            request.destination.clone(),
            request.protocol.clone(),
        )) {
            return PolicyDecision::Allow;
        }

        PolicyDecision::Deny
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMetadata {
    pub node_id: String,
    pub hostname: String,
    pub os: String,
    pub tags: Vec<String>,
    pub owner: String,
    pub last_seen_unix: u64,
    pub public_key: [u8; 32],
}

#[derive(Debug, Default)]
pub struct NodeRegistry {
    nodes: Mutex<HashMap<String, NodeMetadata>>,
}

impl NodeRegistry {
    pub fn upsert(&self, node: NodeMetadata) -> Result<(), ControlPlaneError> {
        let mut guard = self.nodes.lock().map_err(|_| ControlPlaneError::Internal)?;
        guard.insert(node.node_id.clone(), node);
        Ok(())
    }

    pub fn get(&self, node_id: &str) -> Result<Option<NodeMetadata>, ControlPlaneError> {
        let guard = self.nodes.lock().map_err(|_| ControlPlaneError::Internal)?;
        Ok(guard.get(node_id).cloned())
    }

    pub fn list(&self) -> Result<Vec<NodeMetadata>, ControlPlaneError> {
        let guard = self.nodes.lock().map_err(|_| ControlPlaneError::Internal)?;
        Ok(guard.values().cloned().collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentRequest {
    pub credential_id: String,
    pub node_id: String,
    pub hostname: String,
    pub os: String,
    pub tags: Vec<String>,
    pub owner: String,
    pub public_key: [u8; 32],
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentResponse {
    pub node_id: String,
    pub access_token: TokenClaims,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPeerMap {
    pub payload: String,
    pub signature: String,
    pub generated_at_unix: u64,
}

#[derive(Debug)]
pub struct ControlPlanePersistence {
    store: Mutex<persistence::SqliteStore>,
}

impl ControlPlanePersistence {
    pub fn open_sqlite(path: impl AsRef<Path>) -> Result<Self, persistence::PersistenceError> {
        let store = persistence::SqliteStore::open(path)?;
        store.apply_migrations()?;
        Ok(Self {
            store: Mutex::new(store),
        })
    }

    pub fn open_in_memory() -> Result<Self, persistence::PersistenceError> {
        let store = persistence::SqliteStore::open_in_memory()?;
        store.apply_migrations()?;
        Ok(Self {
            store: Mutex::new(store),
        })
    }

    pub fn upsert_user(
        &self,
        user: &persistence::UserRow,
    ) -> Result<(), persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.upsert_user(user)
    }

    pub fn upsert_node(
        &self,
        node: &persistence::NodeRow,
    ) -> Result<(), persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.upsert_node(node)
    }

    pub fn insert_credential(
        &self,
        credential: &persistence::CredentialRow,
    ) -> Result<(), persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.insert_credential(credential)
    }

    pub fn consume_single_use_credential(
        &self,
        credential_id: &str,
        now_unix: u64,
    ) -> Result<bool, persistence::PersistenceError> {
        let mut guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.consume_single_use_credential(credential_id, now_unix)
    }

    pub fn insert_credential_audit_event(
        &self,
        credential_id: &str,
        from_state: Option<&str>,
        to_state: &str,
        event_at_unix: u64,
        actor_user_id: &str,
    ) -> Result<(), persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.insert_credential_audit_event(
            credential_id,
            from_state,
            to_state,
            event_at_unix,
            actor_user_id,
        )
    }

    pub fn credential_state(
        &self,
        credential_id: &str,
    ) -> Result<Option<String>, persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.credential_state(credential_id)
    }

    pub fn user_exists(&self, user_id: &str) -> Result<bool, persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.user_exists(user_id)
    }

    pub fn node_exists(&self, node_id: &str) -> Result<bool, persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.node_exists(node_id)
    }

    pub fn credential_audit_event_count(
        &self,
        credential_id: &str,
    ) -> Result<u64, persistence::PersistenceError> {
        let guard = self.store.lock().map_err(|_| {
            persistence::PersistenceError::InvariantViolation("persistence lock poisoned")
        })?;
        guard.credential_audit_event_count(credential_id)
    }
}

#[derive(Debug)]
pub struct ControlPlaneCore {
    pub auth_guard: AuthSurfaceGuard,
    pub credentials: ThrowawayCredentialStore,
    pub nodes: NodeRegistry,
    pub policy: PolicySet,
    transport_policy: ControlPlaneTransportPolicy,
    signing_secret: Vec<u8>,
}

impl ControlPlaneCore {
    pub fn new(signing_secret: Vec<u8>, policy: PolicySet) -> Self {
        Self {
            auth_guard: AuthSurfaceGuard::default(),
            credentials: ThrowawayCredentialStore::default(),
            nodes: NodeRegistry::default(),
            policy,
            transport_policy: ControlPlaneTransportPolicy::default(),
            signing_secret,
        }
    }

    pub fn transport_policy(&self) -> ControlPlaneTransportPolicy {
        self.transport_policy
    }

    pub fn validate_transport_security(
        &self,
        negotiated_tls: ControlPlaneTlsVersion,
        signature_present: bool,
    ) -> Result<(), TransportPolicyError> {
        self.transport_policy
            .validate_negotiated_tls(negotiated_tls)?;
        self.transport_policy
            .validate_control_data_signature(signature_present)
    }

    pub fn enroll_with_throwaway(
        &self,
        request: EnrollmentRequest,
    ) -> Result<EnrollmentResponse, ControlPlaneError> {
        self.credentials
            .consume(&request.credential_id, request.now_unix)
            .map_err(ControlPlaneError::Credential)?;

        let node = NodeMetadata {
            node_id: request.node_id.clone(),
            hostname: request.hostname,
            os: request.os,
            tags: request.tags,
            owner: request.owner.clone(),
            last_seen_unix: request.now_unix,
            public_key: request.public_key,
        };

        self.nodes.upsert(node)?;

        let token = TokenClaims {
            subject: request.owner,
            issued_at_unix: request.now_unix,
            expires_at_unix: request
                .now_unix
                .saturating_add(ReplayPolicy::default().token_lifetime_secs),
            nonce: format!("nonce-{}-{}", request.node_id, request.now_unix),
        };

        Ok(EnrollmentResponse {
            node_id: request.node_id,
            access_token: token,
        })
    }

    pub fn enroll_with_throwaway_and_persist(
        &self,
        request: EnrollmentRequest,
        persistence: &ControlPlanePersistence,
    ) -> Result<EnrollmentResponse, ControlPlaneError> {
        let response = self.enroll_with_throwaway(request.clone())?;
        let owner = request.owner.clone();
        let credential_id = request.credential_id.clone();

        let user_row = persistence::UserRow {
            user_id: owner.clone(),
            email: owner.clone(),
            mfa_enabled: false,
            updated_at_unix: request.now_unix,
            created_at_unix: request.now_unix,
        };
        persistence
            .upsert_user(&user_row)
            .map_err(ControlPlaneError::Persistence)?;

        let node_row = persistence::NodeRow {
            node_id: request.node_id.clone(),
            owner_user_id: owner.clone(),
            hostname: request.hostname.clone(),
            os: request.os.clone(),
            tags_csv: request.tags.join(","),
            public_key_hex: hex_bytes(&request.public_key),
            last_seen_unix: request.now_unix,
            updated_at_unix: request.now_unix,
            created_at_unix: request.now_unix,
        };
        persistence
            .upsert_node(&node_row)
            .map_err(ControlPlaneError::Persistence)?;

        let credential_row = persistence::CredentialRow {
            credential_id: credential_id.clone(),
            creator_user_id: owner.clone(),
            scope: "tag:enrollment".to_string(),
            credential_kind: "throwaway".to_string(),
            state: "used".to_string(),
            max_uses: 1,
            uses: 1,
            expires_at_unix: request.now_unix,
            created_at_unix: request.now_unix,
            updated_at_unix: request.now_unix,
            storage_policy: "throwaway_default".to_string(),
        };
        persistence
            .insert_credential(&credential_row)
            .map_err(ControlPlaneError::Persistence)?;
        persistence
            .insert_credential_audit_event(
                &credential_id,
                Some("created"),
                "used",
                request.now_unix,
                &owner,
            )
            .map_err(ControlPlaneError::Persistence)?;

        Ok(response)
    }

    pub fn signed_peer_map(&self, now_unix: u64) -> Result<SignedPeerMap, ControlPlaneError> {
        let mut peers = self.nodes.list()?;
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));

        let mut payload = String::new();
        for peer in &peers {
            payload.push_str(&format!(
                "{}|{}|{}|{}|{}|{}\n",
                peer.node_id,
                peer.hostname,
                peer.os,
                peer.owner,
                peer.last_seen_unix,
                hex_bytes(&peer.public_key)
            ));
        }

        let signature = self.sign_payload(&payload);
        Ok(SignedPeerMap {
            payload,
            signature,
            generated_at_unix: now_unix,
        })
    }

    pub fn verify_signed_peer_map(&self, map: &SignedPeerMap) -> bool {
        self.sign_payload(&map.payload) == map.signature
    }

    fn sign_payload(&self, payload: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.signing_secret.as_slice());
        hasher.update(payload.as_bytes());
        let digest = hasher.finalize();
        hex_bytes(digest.as_slice())
    }
}

#[derive(Debug)]
pub enum ControlPlaneError {
    Credential(CredentialError),
    Auth(AuthError),
    Trust(TrustStateError),
    Persistence(persistence::PersistenceError),
    Internal,
}

impl fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlPlaneError::Credential(err) => write!(f, "credential error: {err}"),
            ControlPlaneError::Auth(err) => write!(f, "auth error: {err}"),
            ControlPlaneError::Trust(err) => write!(f, "trust error: {err}"),
            ControlPlaneError::Persistence(err) => write!(f, "persistence error: {err}"),
            ControlPlaneError::Internal => f.write_str("control-plane internal error"),
        }
    }
}

impl std::error::Error for ControlPlaneError {}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::{
        AbuseAlertPolicy, ApiAbuseMonitor, AuthError, AuthRateLimitConfig, AuthSurfaceGuard,
        ControlPlaneCore, ControlPlanePersistence, ControlPlaneTlsVersion, CredentialError,
        EnrollmentRequest, LockoutConfig, PolicyCheckRequest, PolicyDecision, PolicyGuard,
        ReplayPolicy, ReusableCredentialPolicy, ReusableCredentialRequest,
        ThrowawayCredentialState, ThrowawayCredentialStore, TokenClaims, TransportPolicyError,
        TrustState, load_trust_state, persist_trust_state,
    };
    use rustynet_crypto::{AlgorithmPolicy, CompatibilityException, CryptoAlgorithm};
    use rustynet_policy::PolicySet;

    #[test]
    fn auth_rate_limit_enforces_per_ip_limits() {
        let mut guard = AuthSurfaceGuard::new(
            AuthRateLimitConfig {
                ip_burst: 2,
                ip_refill_per_minute: 0,
                identity_burst: 10,
                identity_refill_per_15_min: 0,
            },
            LockoutConfig::default(),
            ReplayPolicy::default(),
        );

        assert!(
            guard
                .authorize_attempt("/auth/login", "198.51.100.5", "alice", 100)
                .is_ok()
        );
        assert!(
            guard
                .authorize_attempt("/auth/login", "198.51.100.5", "alice", 100)
                .is_ok()
        );

        let blocked = guard.authorize_attempt("/auth/login", "198.51.100.5", "alice", 100);
        assert_eq!(blocked.err(), Some(AuthError::RateLimited));
    }

    #[test]
    fn auth_lockout_applies_exponential_backoff() {
        let mut guard = AuthSurfaceGuard::new(
            AuthRateLimitConfig::default(),
            LockoutConfig {
                initial_backoff_secs: 10,
                max_backoff_secs: 60,
            },
            ReplayPolicy::default(),
        );

        guard.register_failure("alice", 100);
        let blocked = guard.authorize_attempt("/auth/login", "198.51.100.5", "alice", 105);
        match blocked {
            Err(AuthError::LockedOutUntil(until)) => assert_eq!(until, 110),
            other => panic!("unexpected lockout result: {other:?}"),
        }

        guard.register_success("alice");
        assert!(
            guard
                .authorize_attempt("/auth/login", "198.51.100.5", "alice", 120)
                .is_ok()
        );
    }

    #[test]
    fn replay_protection_rejects_nonce_reuse() {
        let mut guard = AuthSurfaceGuard::default();
        let claims = TokenClaims {
            subject: "alice".to_string(),
            issued_at_unix: 100,
            expires_at_unix: 120,
            nonce: "nonce-1".to_string(),
        };

        assert!(guard.validate_token_and_nonce(&claims, 110).is_ok());
        let replay = guard.validate_token_and_nonce(&claims, 111);
        assert_eq!(replay.err(), Some(AuthError::ReplayDetected));
    }

    #[test]
    fn throwaway_credential_lifecycle_and_audit_events() {
        let store = ThrowawayCredentialStore::default();
        let created = store
            .create(
                "cred-1".to_string(),
                "alice".to_string(),
                "tag:servers".to_string(),
                100,
                30,
            )
            .expect("credential should be created");
        assert_eq!(created.state, ThrowawayCredentialState::Created);

        let consumed = store
            .consume("cred-1", 110)
            .expect("consume should succeed exactly once");
        assert_eq!(consumed.state, ThrowawayCredentialState::Used);

        let second = store.consume("cred-1", 111);
        assert_eq!(second.err(), Some(CredentialError::AlreadyConsumed));

        let events = store
            .audit_events()
            .expect("audit events should be readable");
        assert!(
            events
                .iter()
                .any(|event| event.to_state == ThrowawayCredentialState::Created)
        );
        assert!(
            events
                .iter()
                .any(|event| event.to_state == ThrowawayCredentialState::Used)
        );
    }

    #[test]
    fn throwaway_credential_atomic_single_use_under_concurrency() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ThrowawayCredentialStore::default());
        store
            .create(
                "cred-race".to_string(),
                "alice".to_string(),
                "tag:servers".to_string(),
                200,
                120,
            )
            .expect("credential should be created");

        let mut handles = Vec::new();
        for _ in 0..16 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                store.consume("cred-race", 210).is_ok()
            }));
        }

        let mut success_count = 0usize;
        for handle in handles {
            if handle.join().expect("thread should join") {
                success_count += 1;
            }
        }

        assert_eq!(success_count, 1);
    }

    #[test]
    fn trust_state_persist_and_integrity_check() {
        let unique = format!(
            "rustynet-trust-state-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);

        let state = TrustState {
            generation: 7,
            signing_fingerprint: "ed25519:abc123".to_string(),
            updated_at_unix: 1_000,
        };

        persist_trust_state(&path, &state).expect("persist should succeed");
        let loaded = load_trust_state(&path).expect("load should succeed");
        assert_eq!(loaded, state);

        let mut tampered = std::fs::read_to_string(&path).expect("should read state file");
        tampered = tampered.replace("generation=7", "generation=8");
        std::fs::write(&path, tampered).expect("should write tampered state");

        let err = load_trust_state(&path).expect_err("tampered state must fail integrity check");
        assert!(matches!(err, super::TrustStateError::IntegrityMismatch));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_guard_defaults_to_deny() {
        let guard = PolicyGuard::default();
        let decision = guard.evaluate(&PolicyCheckRequest {
            source: "group:family".to_string(),
            destination: "tag:servers".to_string(),
            protocol: "tcp".to_string(),
        });
        assert_eq!(decision, PolicyDecision::Deny);
    }

    #[test]
    fn algorithm_policy_expiry_behavior_is_enforced() {
        let policy = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Sha1,
            expires_unix_seconds: 150,
        }])
        .expect("exception should be valid");

        assert!(policy.validate(CryptoAlgorithm::Sha1, 149).is_ok());
        assert!(policy.validate(CryptoAlgorithm::Sha1, 151).is_err());
    }

    #[test]
    fn enrollment_is_single_use_and_registers_node() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        core.credentials
            .create(
                "cred-enroll".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        let response = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-enroll".to_string(),
                node_id: "node-1".to_string(),
                hostname: "mini-pc-1".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                public_key: [3; 32],
                now_unix: 120,
            })
            .expect("enrollment should succeed");

        assert_eq!(response.node_id, "node-1");
        let node = core
            .nodes
            .get("node-1")
            .expect("registry access should succeed")
            .expect("node should exist");
        assert_eq!(node.hostname, "mini-pc-1");

        let second = core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-enroll".to_string(),
            node_id: "node-2".to_string(),
            hostname: "mini-pc-2".to_string(),
            os: "linux".to_string(),
            tags: vec!["servers".to_string()],
            owner: "alice@example.local".to_string(),
            public_key: [4; 32],
            now_unix: 125,
        });
        assert!(second.is_err());
    }

    #[test]
    fn signed_peer_map_detects_tampering() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        core.credentials
            .create(
                "cred-sign".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-sign".to_string(),
            node_id: "node-sign".to_string(),
            hostname: "mini-pc-sign".to_string(),
            os: "linux".to_string(),
            tags: vec!["servers".to_string()],
            owner: "alice@example.local".to_string(),
            public_key: [8; 32],
            now_unix: 120,
        })
        .expect("enrollment should succeed");

        let mut peer_map = core
            .signed_peer_map(130)
            .expect("peer map generation should succeed");
        assert!(core.verify_signed_peer_map(&peer_map));

        peer_map.payload.push_str("tampered-line\n");
        assert!(!core.verify_signed_peer_map(&peer_map));
    }

    #[test]
    fn reusable_credential_requires_strict_scope_ttl_and_vault_storage() {
        let store = ThrowawayCredentialStore::default();
        let policy = ReusableCredentialPolicy::default();

        let invalid_scope = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-1".to_string(),
                creator: "admin".to_string(),
                scope: "*".to_string(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-1".to_string(),
            },
            policy,
        );
        assert_eq!(invalid_scope.err(), Some(CredentialError::ScopeTooBroad));

        let invalid_storage = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-2".to_string(),
                creator: "admin".to_string(),
                scope: "tag:servers".to_string(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "plaintext://bad".to_string(),
            },
            policy,
        );
        assert_eq!(
            invalid_storage.err(),
            Some(CredentialError::StoragePolicyViolation)
        );

        let invalid_ttl = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-3".to_string(),
                creator: "admin".to_string(),
                scope: "tag:servers".to_string(),
                created_at_unix: 100,
                ttl_secs: policy.max_ttl_secs + 1,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-3".to_string(),
            },
            policy,
        );
        assert_eq!(invalid_ttl.err(), Some(CredentialError::TtlTooLong));
    }

    #[test]
    fn reusable_credential_can_be_consumed_multiple_times_within_limit() {
        let store = ThrowawayCredentialStore::default();
        let policy = ReusableCredentialPolicy::default();
        let reusable = store
            .create_reusable(
                ReusableCredentialRequest {
                    id: "reusable-ok".to_string(),
                    creator: "admin".to_string(),
                    scope: "tag:automation".to_string(),
                    created_at_unix: 100,
                    ttl_secs: 600,
                    max_uses: 3,
                    storage_reference: "vault://rustynet/reusable-ok".to_string(),
                },
                policy,
            )
            .expect("reusable credential should be created");
        assert_eq!(reusable.max_uses, 3);

        assert!(store.consume("reusable-ok", 110).is_ok());
        assert!(store.consume("reusable-ok", 111).is_ok());
        assert!(store.consume("reusable-ok", 112).is_ok());
        let exhausted = store.consume("reusable-ok", 113);
        assert_eq!(exhausted.err(), Some(CredentialError::AlreadyConsumed));
    }

    #[test]
    fn reusable_credential_scope_requires_tag_prefix() {
        let store = ThrowawayCredentialStore::default();
        let policy = ReusableCredentialPolicy::default();
        let result = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-bad-scope".to_string(),
                creator: "admin".to_string(),
                scope: "group:all-admins".to_string(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-bad-scope".to_string(),
            },
            policy,
        );
        assert_eq!(result.err(), Some(CredentialError::ScopeTooBroad));
    }

    #[test]
    fn revocation_events_are_generation_tracked() {
        let store = ThrowawayCredentialStore::default();
        store
            .create(
                "cred-revoked".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        let before = store
            .revocation_generation()
            .expect("generation should be readable");
        assert_eq!(before, 0);

        store
            .revoke("cred-revoked", 120)
            .expect("credential should be revoked");
        assert!(
            store
                .is_revoked("cred-revoked")
                .expect("revocation status should be readable")
        );

        let after = store
            .revocation_generation()
            .expect("generation should be readable");
        assert_eq!(after, 1);

        let events = store
            .revocations_since(0)
            .expect("revocations should be readable");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].credential_id, "cred-revoked");
        assert_eq!(events[0].generation, 1);
    }

    #[test]
    fn transport_policy_rejects_tls12_and_unsigned_control_data() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());

        let tls_reject = core.validate_transport_security(ControlPlaneTlsVersion::Tls12, true);
        assert_eq!(
            tls_reject.err(),
            Some(TransportPolicyError::TlsVersionRejected)
        );

        let sig_reject = core.validate_transport_security(ControlPlaneTlsVersion::Tls13, false);
        assert_eq!(
            sig_reject.err(),
            Some(TransportPolicyError::UnsignedControlDataRejected)
        );
    }

    #[test]
    fn enrollment_persists_user_node_and_audit_event() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        let persistence = ControlPlanePersistence::open_in_memory()
            .expect("in-memory persistence should be available");

        persistence
            .upsert_user(&super::persistence::UserRow {
                user_id: "admin".to_string(),
                email: "admin@example.local".to_string(),
                mfa_enabled: false,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("admin user should be persisted");

        core.credentials
            .create(
                "cred-persist".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        let response = core
            .enroll_with_throwaway_and_persist(
                EnrollmentRequest {
                    credential_id: "cred-persist".to_string(),
                    node_id: "node-persist".to_string(),
                    hostname: "mini-pc-persist".to_string(),
                    os: "linux".to_string(),
                    tags: vec!["servers".to_string()],
                    owner: "alice@example.local".to_string(),
                    public_key: [7; 32],
                    now_unix: 150,
                },
                &persistence,
            )
            .expect("enrollment should succeed");

        assert_eq!(response.node_id, "node-persist");
        assert!(
            persistence
                .user_exists("alice@example.local")
                .expect("user lookup should succeed")
        );
        assert!(
            persistence
                .node_exists("node-persist")
                .expect("node lookup should succeed")
        );
        let audit_count = persistence
            .credential_audit_event_count("cred-persist")
            .expect("audit count should be readable");
        assert_eq!(audit_count, 1);
    }

    #[test]
    fn api_abuse_monitor_emits_alert_after_threshold() {
        let mut monitor = ApiAbuseMonitor::new(AbuseAlertPolicy {
            threshold: 3,
            window_secs: 30,
        });

        assert!(
            !monitor
                .record_failure("198.51.100.10", "alice", "/auth/login", "rate_limited", 100)
                .expect("first event should record")
        );
        assert!(
            !monitor
                .record_failure("198.51.100.10", "alice", "/auth/login", "rate_limited", 101)
                .expect("second event should record")
        );
        assert!(
            monitor
                .record_failure("198.51.100.10", "alice", "/auth/login", "rate_limited", 102)
                .expect("third event should trigger alert")
        );

        let alerts = monitor.alerts().expect("alerts should be readable");
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].source_ip, "198.51.100.10");
    }

    #[test]
    fn token_claims_debug_redacts_sensitive_fields() {
        let claims = TokenClaims {
            subject: "alice@example.local".to_string(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            nonce: "nonce-secret".to_string(),
        };
        let rendered = format!("{claims:?}");
        assert!(!rendered.contains("alice@example.local"));
        assert!(!rendered.contains("nonce-secret"));
        assert!(rendered.contains("REDACTED"));
    }

    #[test]
    fn throwaway_credential_debug_redacts_sensitive_fields() {
        let credential = ThrowawayCredentialStore::default()
            .create(
                "cred-redact".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("cred-redact"));
        assert!(!rendered.contains("throwaway_default"));
        assert!(rendered.contains("REDACTED"));
    }
}
