#![forbid(unsafe_code)]

pub mod admin;
pub mod ga;
pub mod membership;
pub mod operations;
pub mod persistence;
pub mod scale;

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
#[cfg(unix)]
use nix::unistd::Uid;
use rand::RngCore;
pub use rustynet_dns_zone::{DnsRecordType, DnsTargetAddrKind, SignedDnsZoneBundle};
use rustynet_dns_zone::{
    DnsZoneError, DnsZoneRecordInput, build_signed_dns_zone_bundle,
    render_signed_dns_zone_bundle_wire, verify_signed_dns_zone_bundle as verify_dns_zone_bundle,
};
use rustynet_policy::{AccessRequest, Decision as PolicyEngineDecision, PolicySet, Protocol};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const SIGNING_SEED_HKDF_SALT_V1: &[u8] = b"rustynet-control-signing-seed-hkdf-salt-v1";
const ASSIGNMENT_SIGNING_SEED_INFO_V1: &[u8] = b"rustynet-control-assignment-signing-v1";
const DNS_ZONE_SIGNING_SEED_INFO_V1: &[u8] = b"rustynet-control-dns-zone-signing-v1";
const ACCESS_TOKEN_SIGNING_SEED_INFO_V1: &[u8] = b"rustynet-control-access-token-signing-v1";
const ENDPOINT_HINT_SIGNING_SEED_INFO_V1: &[u8] = b"rustynet-control-endpoint-hint-signing-v1";

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

#[derive(Clone, PartialEq, Eq)]
pub struct SignedTokenClaims {
    pub claims: TokenClaims,
    pub signature_hex: String,
}

impl fmt::Debug for SignedTokenClaims {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedTokenClaims")
            .field("claims", &self.claims)
            .field("signature_hex", &"REDACTED")
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
    TokenSignatureInvalid,
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
            AuthError::TokenSignatureInvalid => f.write_str("token signature invalid"),
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
    PermissionDenied,
    KeyUnavailable,
}

impl fmt::Display for TrustStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustStateError::Missing => f.write_str("trust state missing"),
            TrustStateError::Corrupt => f.write_str("trust state corrupt"),
            TrustStateError::InvalidFormat => f.write_str("trust state invalid format"),
            TrustStateError::PersistFailure => f.write_str("trust state persist failure"),
            TrustStateError::IntegrityMismatch => f.write_str("trust state integrity mismatch"),
            TrustStateError::PermissionDenied => f.write_str("trust state permission denied"),
            TrustStateError::KeyUnavailable => f.write_str("trust state integrity key unavailable"),
        }
    }
}

impl std::error::Error for TrustStateError {}

pub fn persist_trust_state(
    path: impl AsRef<Path>,
    state: &TrustState,
) -> Result<(), TrustStateError> {
    let path = path.as_ref();
    ensure_secure_parent_directory(path)?;
    let key_path = trust_state_key_path(path);
    let key = load_or_create_trust_state_mac_key(&key_path)?;
    let payload = trust_state_payload(state);
    let mac = compute_trust_state_mac(payload.as_bytes(), &key)?;
    let body = format!("{payload}mac={mac}\n");
    atomic_write_secure(path, body.as_bytes(), 0o600)?;
    validate_secure_file(path, "trust state", 0o077)?;
    Ok(())
}

pub fn load_trust_state(path: impl AsRef<Path>) -> Result<TrustState, TrustStateError> {
    let path = path.as_ref();
    validate_secure_file(path, "trust state", 0o077)?;
    let content = fs::read_to_string(path).map_err(|_| TrustStateError::Missing)?;
    let mut generation: Option<u64> = None;
    let mut fingerprint: Option<String> = None;
    let mut updated_at: Option<u64> = None;
    let mut version: Option<u8> = None;
    let mut mac: Option<String> = None;

    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TrustStateError::InvalidFormat);
        };

        match key {
            "version" => {
                version = value.parse::<u8>().ok();
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
            "mac" => {
                mac = Some(value.to_string());
            }
            _ => return Err(TrustStateError::InvalidFormat),
        }
    }
    if version != Some(2) {
        return Err(TrustStateError::InvalidFormat);
    }

    let state = TrustState {
        generation: generation.ok_or(TrustStateError::Corrupt)?,
        signing_fingerprint: fingerprint.ok_or(TrustStateError::Corrupt)?,
        updated_at_unix: updated_at.ok_or(TrustStateError::Corrupt)?,
    };

    let expected_mac = mac.ok_or(TrustStateError::Corrupt)?;
    let payload = trust_state_payload(&state);
    let key_path = trust_state_key_path(path);
    let key = load_trust_state_mac_key(&key_path)?;
    verify_trust_state_mac(payload.as_bytes(), &key, expected_mac.as_str())?;

    Ok(state)
}

fn trust_state_payload(state: &TrustState) -> String {
    format!(
        "version=2\ngeneration={}\nsigning_fingerprint={}\nupdated_at_unix={}\n",
        state.generation, state.signing_fingerprint, state.updated_at_unix
    )
}

fn trust_state_key_path(path: &Path) -> std::path::PathBuf {
    let mut out = path.as_os_str().to_os_string();
    out.push(".integrity.key");
    std::path::PathBuf::from(out)
}

fn load_or_create_trust_state_mac_key(path: &Path) -> Result<[u8; 32], TrustStateError> {
    if path.exists() {
        return load_trust_state_mac_key(path);
    }
    ensure_secure_parent_directory(path)?;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let body = format!("{}\n", hex_bytes(&key));
    atomic_write_secure(path, body.as_bytes(), 0o600)?;
    validate_secure_file(path, "trust state integrity key", 0o077)?;
    Ok(key)
}

fn load_trust_state_mac_key(path: &Path) -> Result<[u8; 32], TrustStateError> {
    validate_secure_file(path, "trust state integrity key", 0o077)
        .map_err(|_| TrustStateError::KeyUnavailable)?;
    let mut content = fs::read_to_string(path).map_err(|_| TrustStateError::KeyUnavailable)?;
    let mut key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or(TrustStateError::KeyUnavailable)?
        .to_string();
    content.zeroize();
    let key = decode_hex_to_fixed::<32>(&key_line).map_err(|_| TrustStateError::InvalidFormat)?;
    key_line.zeroize();
    Ok(key)
}

fn compute_trust_state_mac(payload: &[u8], key: &[u8; 32]) -> Result<String, TrustStateError> {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| TrustStateError::KeyUnavailable)?;
    mac.update(payload);
    Ok(hex_bytes(mac.finalize().into_bytes().as_slice()))
}

fn verify_trust_state_mac(
    payload: &[u8],
    key: &[u8; 32],
    mac_hex: &str,
) -> Result<(), TrustStateError> {
    let expected =
        decode_hex_to_fixed::<32>(mac_hex).map_err(|_| TrustStateError::InvalidFormat)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|_| TrustStateError::KeyUnavailable)?;
    mac.update(payload);
    mac.verify_slice(&expected)
        .map_err(|_| TrustStateError::IntegrityMismatch)?;
    Ok(())
}

fn ensure_secure_parent_directory(path: &Path) -> Result<(), TrustStateError> {
    let Some(parent) = path.parent() else {
        return Err(TrustStateError::PersistFailure);
    };
    if parent.exists() {
        let metadata = fs::symlink_metadata(parent).map_err(|_| TrustStateError::PersistFailure)?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(TrustStateError::PermissionDenied);
        }
        #[cfg(unix)]
        {
            let metadata = fs::metadata(parent).map_err(|_| TrustStateError::PersistFailure)?;
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(TrustStateError::PermissionDenied);
            }
            let owner_uid = metadata.uid();
            let expected_uid = Uid::effective().as_raw();
            if owner_uid != expected_uid {
                return Err(TrustStateError::PermissionDenied);
            }
        }
        return Ok(());
    }
    fs::create_dir_all(parent).map_err(|_| TrustStateError::PersistFailure)?;
    #[cfg(unix)]
    {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|_| TrustStateError::PersistFailure)?;
    }
    Ok(())
}

fn atomic_write_secure(path: &Path, body: &[u8], mode: u32) -> Result<(), TrustStateError> {
    ensure_secure_parent_directory(path)?;
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|_| TrustStateError::PersistFailure)?;
        if metadata.file_type().is_symlink() {
            return Err(TrustStateError::PermissionDenied);
        }
    }
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(mode);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|_| TrustStateError::PersistFailure)?;
    if temp.write_all(body).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustStateError::PersistFailure);
    }
    if temp.sync_all().is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustStateError::PersistFailure);
    }
    if fs::rename(&temp_path, path).is_err() {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustStateError::PersistFailure);
    }
    if let Some(parent) = path.parent() {
        let parent_dir = fs::File::open(parent).map_err(|_| TrustStateError::PersistFailure)?;
        parent_dir
            .sync_all()
            .map_err(|_| TrustStateError::PersistFailure)?;
    }
    Ok(())
}

fn validate_secure_file(
    path: &Path,
    label: &str,
    disallowed_mode_mask: u32,
) -> Result<(), TrustStateError> {
    let link_metadata = fs::symlink_metadata(path).map_err(|_| TrustStateError::Missing)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
        return Err(TrustStateError::PermissionDenied);
    }
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path).map_err(|_| TrustStateError::Missing)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & disallowed_mode_mask != 0 {
            return Err(TrustStateError::PermissionDenied);
        }
        let owner_uid = metadata.uid();
        let expected_uid = Uid::effective().as_raw();
        if owner_uid != expected_uid {
            return Err(TrustStateError::PermissionDenied);
        }
    }
    let _ = label;
    Ok(())
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
    pub endpoint: String,
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
    pub endpoint: String,
    pub public_key: [u8; 32],
    pub now_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentResponse {
    pub node_id: String,
    pub access_token: SignedTokenClaims,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPeerMap {
    pub payload: String,
    pub signature: String,
    pub generated_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointHintCandidateType {
    Host,
    ServerReflexive,
    Relay,
}

impl EndpointHintCandidateType {
    fn as_str(self) -> &'static str {
        match self {
            EndpointHintCandidateType::Host => "host",
            EndpointHintCandidateType::ServerReflexive => "srflx",
            EndpointHintCandidateType::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHintCandidate {
    pub candidate_type: EndpointHintCandidateType,
    pub endpoint: String,
    pub relay_id: Option<String>,
    pub priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointHintBundleRequest {
    pub source_node_id: String,
    pub target_node_id: String,
    pub generated_at_unix: u64,
    pub ttl_secs: u64,
    pub nonce: u64,
    pub candidates: Vec<EndpointHintCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEndpointHintBundle {
    pub payload: String,
    pub signature_hex: String,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub source_node_id: String,
    pub target_node_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoTunnelRouteKind {
    Mesh,
    ExitNodeLan,
    ExitNodeDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoTunnelPeer {
    pub node_id: String,
    pub endpoint: String,
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoTunnelRoute {
    pub destination_cidr: String,
    pub via_node: String,
    pub kind: AutoTunnelRouteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AutoTunnelBundleRequest {
    pub node_id: String,
    pub generated_at_unix: u64,
    pub ttl_secs: u64,
    pub nonce: u64,
    pub mesh_cidr: String,
    pub exit_node_id: Option<String>,
    pub lan_routes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAutoTunnelBundle {
    pub payload: String,
    pub signature_hex: String,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub node_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecordRequest {
    pub label: String,
    pub target_node_id: String,
    pub ttl_secs: u64,
    pub rr_type: DnsRecordType,
    pub target_addr_kind: DnsTargetAddrKind,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDnsZoneBundleRequest {
    pub zone_name: String,
    pub subject_node_id: String,
    pub generated_at_unix: u64,
    pub ttl_secs: u64,
    pub nonce: u64,
    pub records: Vec<DnsRecordRequest>,
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
    assignment_signing_key: SigningKey,
    assignment_verifying_key: [u8; 32],
    dns_zone_signing_key: SigningKey,
    dns_zone_verifying_key: [u8; 32],
    endpoint_hint_signing_key: SigningKey,
    endpoint_hint_verifying_key: [u8; 32],
    access_token_signing_key: SigningKey,
    access_token_verifying_key: [u8; 32],
}

impl ControlPlaneCore {
    pub fn new(mut signing_secret: Vec<u8>, policy: PolicySet) -> Self {
        let mut assignment_seed =
            derive_signing_seed(ASSIGNMENT_SIGNING_SEED_INFO_V1, &signing_secret);
        let mut dns_zone_seed = derive_signing_seed(DNS_ZONE_SIGNING_SEED_INFO_V1, &signing_secret);
        let mut endpoint_hint_seed =
            derive_signing_seed(ENDPOINT_HINT_SIGNING_SEED_INFO_V1, &signing_secret);
        let mut access_token_seed =
            derive_signing_seed(ACCESS_TOKEN_SIGNING_SEED_INFO_V1, &signing_secret);
        signing_secret.zeroize();

        let assignment_signing_key = SigningKey::from_bytes(&assignment_seed);
        assignment_seed.zeroize();
        let assignment_verifying_key = *assignment_signing_key.verifying_key().as_bytes();
        let dns_zone_signing_key = SigningKey::from_bytes(&dns_zone_seed);
        dns_zone_seed.zeroize();
        let dns_zone_verifying_key = *dns_zone_signing_key.verifying_key().as_bytes();
        let endpoint_hint_signing_key = SigningKey::from_bytes(&endpoint_hint_seed);
        endpoint_hint_seed.zeroize();
        let endpoint_hint_verifying_key = *endpoint_hint_signing_key.verifying_key().as_bytes();
        let access_token_signing_key = SigningKey::from_bytes(&access_token_seed);
        access_token_seed.zeroize();
        let access_token_verifying_key = *access_token_signing_key.verifying_key().as_bytes();
        Self {
            auth_guard: AuthSurfaceGuard::default(),
            credentials: ThrowawayCredentialStore::default(),
            nodes: NodeRegistry::default(),
            policy,
            transport_policy: ControlPlaneTransportPolicy::default(),
            assignment_signing_key,
            assignment_verifying_key,
            dns_zone_signing_key,
            dns_zone_verifying_key,
            endpoint_hint_signing_key,
            endpoint_hint_verifying_key,
            access_token_signing_key,
            access_token_verifying_key,
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
            endpoint: request.endpoint,
            last_seen_unix: request.now_unix,
            public_key: request.public_key,
        };

        self.nodes.upsert(node)?;

        let token_claims = TokenClaims {
            subject: request.owner,
            issued_at_unix: request.now_unix,
            expires_at_unix: request
                .now_unix
                .saturating_add(ReplayPolicy::default().token_lifetime_secs),
            nonce: random_nonce_hex(16),
        };
        let token = self.sign_access_token(&token_claims);

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
        let consumed = persistence
            .consume_single_use_credential(&request.credential_id, request.now_unix)
            .map_err(ControlPlaneError::Persistence)?;
        if !consumed {
            let credential_state = persistence
                .credential_state(&request.credential_id)
                .map_err(ControlPlaneError::Persistence)?;
            return Err(ControlPlaneError::Credential(
                map_persisted_credential_state_to_error(credential_state.as_deref()),
            ));
        }

        match self
            .credentials
            .consume(&request.credential_id, request.now_unix)
        {
            Ok(_) | Err(CredentialError::NotFound) => {}
            Err(err) => return Err(ControlPlaneError::Credential(err)),
        }

        let node = NodeMetadata {
            node_id: request.node_id.clone(),
            hostname: request.hostname.clone(),
            os: request.os.clone(),
            tags: request.tags.clone(),
            owner: request.owner.clone(),
            endpoint: request.endpoint.clone(),
            last_seen_unix: request.now_unix,
            public_key: request.public_key,
        };
        self.nodes.upsert(node)?;

        let token_claims = TokenClaims {
            subject: request.owner.clone(),
            issued_at_unix: request.now_unix,
            expires_at_unix: request
                .now_unix
                .saturating_add(ReplayPolicy::default().token_lifetime_secs),
            nonce: random_nonce_hex(16),
        };
        let token = self.sign_access_token(&token_claims);

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

        persistence
            .insert_credential_audit_event(
                &credential_id,
                Some("created"),
                "used",
                request.now_unix,
                &owner,
            )
            .map_err(ControlPlaneError::Persistence)?;

        Ok(EnrollmentResponse {
            node_id: request.node_id,
            access_token: token,
        })
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

        let signature = self.sign_peer_map_payload(&payload);
        Ok(SignedPeerMap {
            payload,
            signature,
            generated_at_unix: now_unix,
        })
    }

    pub fn verify_signed_peer_map(&self, map: &SignedPeerMap) -> bool {
        self.verify_peer_map_signature(&map.payload, &map.signature)
    }

    pub fn assignment_verifier_key_hex(&self) -> String {
        hex_bytes(&self.assignment_verifying_key)
    }

    pub fn dns_zone_verifier_key_hex(&self) -> String {
        hex_bytes(&self.dns_zone_verifying_key)
    }

    pub fn access_token_verifier_key_hex(&self) -> String {
        hex_bytes(&self.access_token_verifying_key)
    }

    pub fn endpoint_hint_verifier_key_hex(&self) -> String {
        hex_bytes(&self.endpoint_hint_verifying_key)
    }

    pub fn verify_access_token(&self, token: &SignedTokenClaims) -> bool {
        let signature_bytes = match decode_hex_to_fixed::<64>(&token.signature_hex) {
            Ok(bytes) => bytes,
            Err(()) => return false,
        };
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = match VerifyingKey::from_bytes(&self.access_token_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        let payload = token_claims_payload(&token.claims);
        verifying_key.verify(payload.as_bytes(), &signature).is_ok()
    }

    pub fn validate_signed_token_and_nonce(
        &self,
        guard: &mut AuthSurfaceGuard,
        token: &SignedTokenClaims,
        now_unix: u64,
    ) -> Result<(), AuthError> {
        if !self.verify_access_token(token) {
            return Err(AuthError::TokenSignatureInvalid);
        }
        guard.validate_token_and_nonce(&token.claims, now_unix)
    }

    pub fn signed_auto_tunnel_bundle(
        &self,
        request: AutoTunnelBundleRequest,
    ) -> Result<SignedAutoTunnelBundle, ControlPlaneError> {
        if request.ttl_secs == 0 {
            return Err(ControlPlaneError::Assignment(
                "auto-tunnel ttl must be greater than zero".to_string(),
            ));
        }
        if request.ttl_secs > 24 * 60 * 60 {
            return Err(ControlPlaneError::Assignment(
                "auto-tunnel ttl exceeds max supported value".to_string(),
            ));
        }
        if !is_valid_ipv4_or_ipv6_cidr(&request.mesh_cidr) {
            return Err(ControlPlaneError::Assignment(
                "mesh cidr is invalid".to_string(),
            ));
        }

        let target = self.nodes.get(&request.node_id)?.ok_or_else(|| {
            ControlPlaneError::Assignment("requested node does not exist".to_string())
        })?;
        if target.endpoint.parse::<SocketAddr>().is_err() {
            return Err(ControlPlaneError::Assignment(
                "requested node endpoint is invalid".to_string(),
            ));
        }

        let expires_at_unix = request.generated_at_unix.saturating_add(request.ttl_secs);

        let mut peers = self.nodes.list()?;
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let tunnel_assignments =
            Self::deterministic_tunnel_assignments(peers.iter().map(|peer| peer.node_id.as_str()))?;
        let target_cidr = tunnel_assignments
            .get(target.node_id.as_str())
            .cloned()
            .ok_or_else(|| {
                ControlPlaneError::Assignment(
                    "requested node assignment is unavailable".to_string(),
                )
            })?;

        let mut selected_peers = Vec::new();
        let mut bundle_routes = Vec::new();
        for peer in peers
            .iter()
            .filter(|candidate| candidate.node_id != target.node_id)
        {
            if !self.policy_allows_node_pair(&target, peer) {
                continue;
            }
            if peer.endpoint.parse::<SocketAddr>().is_err() {
                continue;
            }

            let peer_cidr = tunnel_assignments
                .get(peer.node_id.as_str())
                .cloned()
                .ok_or_else(|| {
                    ControlPlaneError::Assignment(format!(
                        "peer assignment is unavailable: {}",
                        peer.node_id
                    ))
                })?;
            selected_peers.push((peer.clone(), peer_cidr.clone()));
            bundle_routes.push(AutoTunnelRoute {
                destination_cidr: peer_cidr,
                via_node: peer.node_id.clone(),
                kind: AutoTunnelRouteKind::Mesh,
            });
        }

        if let Some(exit_node_id) = request.exit_node_id.as_deref() {
            let exit_node = self.nodes.get(exit_node_id)?.ok_or_else(|| {
                ControlPlaneError::Assignment("exit node does not exist".to_string())
            })?;
            if !self.policy_allows_node_pair(&target, &exit_node) {
                return Err(ControlPlaneError::Assignment(
                    "exit node denied by policy".to_string(),
                ));
            }
            bundle_routes.push(AutoTunnelRoute {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: exit_node.node_id.clone(),
                kind: AutoTunnelRouteKind::ExitNodeDefault,
            });
            for cidr in &request.lan_routes {
                if !is_valid_ipv4_or_ipv6_cidr(cidr) {
                    return Err(ControlPlaneError::Assignment(
                        "lan route cidr is invalid".to_string(),
                    ));
                }
                bundle_routes.push(AutoTunnelRoute {
                    destination_cidr: cidr.clone(),
                    via_node: exit_node.node_id.clone(),
                    kind: AutoTunnelRouteKind::ExitNodeLan,
                });
            }
        }

        let mut peer_allowed_ips = HashMap::<String, BTreeSet<String>>::new();
        for (peer, peer_cidr) in &selected_peers {
            peer_allowed_ips
                .entry(peer.node_id.clone())
                .or_default()
                .insert(peer_cidr.clone());
        }
        for route in &bundle_routes {
            if let Some(allowed_ips) = peer_allowed_ips.get_mut(route.via_node.as_str()) {
                allowed_ips.insert(route.destination_cidr.clone());
            }
        }

        let mut bundle_peers = Vec::with_capacity(selected_peers.len());
        for (peer, _peer_cidr) in selected_peers {
            let allowed_ips = peer_allowed_ips
                .remove(peer.node_id.as_str())
                .map(|ips| ips.into_iter().collect::<Vec<_>>())
                .unwrap_or_default();
            bundle_peers.push(AutoTunnelPeer {
                node_id: peer.node_id,
                endpoint: peer.endpoint,
                public_key: peer.public_key,
                allowed_ips,
            });
        }

        let payload = serialize_auto_tunnel_payload(
            &AutoTunnelPayloadHeader {
                node_id: &target.node_id,
                mesh_cidr: &request.mesh_cidr,
                assigned_cidr: &target_cidr,
                generated_at_unix: request.generated_at_unix,
                expires_at_unix,
                nonce: request.nonce,
            },
            &bundle_peers,
            &bundle_routes,
        );
        let signature = self.assignment_signing_key.sign(payload.as_bytes());

        Ok(SignedAutoTunnelBundle {
            payload,
            signature_hex: hex_bytes(&signature.to_bytes()),
            generated_at_unix: request.generated_at_unix,
            expires_at_unix,
            node_id: request.node_id,
        })
    }

    pub fn signed_dns_zone_bundle(
        &self,
        request: SignedDnsZoneBundleRequest,
    ) -> Result<SignedDnsZoneBundle, ControlPlaneError> {
        let subject = self
            .nodes
            .get(&request.subject_node_id)?
            .ok_or_else(|| ControlPlaneError::Dns("subject node does not exist".to_string()))?;

        let mut peers = self.nodes.list()?;
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let tunnel_assignments =
            Self::deterministic_tunnel_assignments(peers.iter().map(|peer| peer.node_id.as_str()))?;

        let mut canonical_records = Vec::with_capacity(request.records.len());

        for record in request.records {
            let target = self
                .nodes
                .get(&record.target_node_id)?
                .ok_or_else(|| ControlPlaneError::Dns("target node does not exist".to_string()))?;
            if target.node_id != subject.node_id && !self.policy_allows_node_pair(&subject, &target)
            {
                return Err(ControlPlaneError::Dns(
                    "dns record target denied by policy".to_string(),
                ));
            }

            let expected_cidr =
                tunnel_assignments
                    .get(target.node_id.as_str())
                    .ok_or_else(|| {
                        ControlPlaneError::Dns("target node assignment is unavailable".to_string())
                    })?;
            let expected_ip = host_ip_from_host_cidr(expected_cidr.as_str()).ok_or_else(|| {
                ControlPlaneError::Dns("target node assignment must be a host cidr".to_string())
            })?;
            canonical_records.push(DnsZoneRecordInput {
                label: record.label,
                target_node_id: target.node_id.clone(),
                rr_type: record.rr_type,
                target_addr_kind: record.target_addr_kind,
                expected_ip,
                ttl_secs: record.ttl_secs,
                aliases: record.aliases,
            });
        }

        build_signed_dns_zone_bundle(
            &self.dns_zone_signing_key,
            request.zone_name.as_str(),
            subject.node_id.as_str(),
            request.generated_at_unix,
            request.ttl_secs,
            request.nonce,
            &canonical_records,
        )
        .map_err(map_dns_zone_error)
    }

    pub fn signed_endpoint_hint_bundle(
        &self,
        request: EndpointHintBundleRequest,
    ) -> Result<SignedEndpointHintBundle, ControlPlaneError> {
        if request.ttl_secs == 0 {
            return Err(ControlPlaneError::Traversal(
                "endpoint hint ttl must be greater than zero".to_string(),
            ));
        }
        if request.ttl_secs > 120 {
            return Err(ControlPlaneError::Traversal(
                "endpoint hint ttl exceeds max supported value".to_string(),
            ));
        }
        if request.generated_at_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "generated_at_unix must be greater than zero".to_string(),
            ));
        }
        if request.candidates.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints require at least one candidate".to_string(),
            ));
        }
        if request.candidates.len() > 8 {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints exceed max candidate count".to_string(),
            ));
        }

        let source = self.nodes.get(&request.source_node_id)?.ok_or_else(|| {
            ControlPlaneError::Traversal("source node does not exist".to_string())
        })?;
        let target = self.nodes.get(&request.target_node_id)?.ok_or_else(|| {
            ControlPlaneError::Traversal("target node does not exist".to_string())
        })?;
        if !self.policy_allows_node_pair(&source, &target) {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints denied by policy".to_string(),
            ));
        }

        let expires_at_unix = request.generated_at_unix.saturating_add(request.ttl_secs);
        if request.generated_at_unix >= expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "invalid generated/expires ordering".to_string(),
            ));
        }

        let mut seen_candidates = HashSet::new();
        for candidate in &request.candidates {
            let endpoint = candidate.endpoint.parse::<SocketAddr>().map_err(|_| {
                ControlPlaneError::Traversal("candidate endpoint is invalid".to_string())
            })?;
            if endpoint.port() == 0 {
                return Err(ControlPlaneError::Traversal(
                    "candidate endpoint port must be non-zero".to_string(),
                ));
            }
            if matches!(candidate.candidate_type, EndpointHintCandidateType::Relay) {
                let relay_id = candidate.relay_id.as_deref().unwrap_or("").trim();
                if relay_id.is_empty() {
                    return Err(ControlPlaneError::Traversal(
                        "relay candidates require relay_id".to_string(),
                    ));
                }
            } else if candidate.relay_id.is_some() {
                return Err(ControlPlaneError::Traversal(
                    "relay_id is only valid for relay candidates".to_string(),
                ));
            }

            let relay_key = candidate
                .relay_id
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_string();
            let uniqueness = format!(
                "{}|{}|{}",
                candidate.candidate_type.as_str(),
                endpoint,
                relay_key
            );
            if !seen_candidates.insert(uniqueness) {
                return Err(ControlPlaneError::Traversal(
                    "duplicate endpoint hint candidate".to_string(),
                ));
            }
        }

        let payload = serialize_endpoint_hint_payload(
            request.source_node_id.as_str(),
            request.target_node_id.as_str(),
            request.generated_at_unix,
            expires_at_unix,
            request.nonce,
            &request.candidates,
        )?;
        let signature = self.endpoint_hint_signing_key.sign(payload.as_bytes());

        Ok(SignedEndpointHintBundle {
            payload,
            signature_hex: hex_bytes(&signature.to_bytes()),
            generated_at_unix: request.generated_at_unix,
            expires_at_unix,
            source_node_id: request.source_node_id,
            target_node_id: request.target_node_id,
        })
    }

    pub fn verify_signed_endpoint_hint_bundle(&self, bundle: &SignedEndpointHintBundle) -> bool {
        if bundle.generated_at_unix >= bundle.expires_at_unix {
            return false;
        }
        let signature_bytes = match decode_hex_to_fixed::<64>(&bundle.signature_hex) {
            Ok(bytes) => bytes,
            Err(()) => return false,
        };
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = match VerifyingKey::from_bytes(&self.endpoint_hint_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verifying_key
            .verify(bundle.payload.as_bytes(), &signature)
            .is_ok()
    }

    pub fn signed_endpoint_hint_bundle_to_wire(bundle: &SignedEndpointHintBundle) -> String {
        format!("{}signature={}\n", bundle.payload, bundle.signature_hex)
    }

    pub fn verify_signed_dns_zone_bundle(&self, bundle: &SignedDnsZoneBundle) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.dns_zone_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verify_dns_zone_bundle(bundle, &verifying_key).is_ok()
    }

    pub fn signed_dns_zone_bundle_to_wire(bundle: &SignedDnsZoneBundle) -> String {
        render_signed_dns_zone_bundle_wire(bundle)
    }

    pub fn verify_signed_auto_tunnel_bundle(&self, bundle: &SignedAutoTunnelBundle) -> bool {
        if bundle.generated_at_unix > bundle.expires_at_unix {
            return false;
        }
        let signature_bytes = match decode_hex_to_fixed::<64>(&bundle.signature_hex) {
            Ok(bytes) => bytes,
            Err(()) => return false,
        };
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = match VerifyingKey::from_bytes(&self.assignment_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verifying_key
            .verify(bundle.payload.as_bytes(), &signature)
            .is_ok()
    }

    pub fn signed_auto_tunnel_bundle_to_wire(bundle: &SignedAutoTunnelBundle) -> String {
        format!("{}signature={}\n", bundle.payload, bundle.signature_hex)
    }

    fn deterministic_tunnel_assignments<'a>(
        node_ids: impl Iterator<Item = &'a str>,
    ) -> Result<HashMap<String, String>, ControlPlaneError> {
        const MAX_OFFSET: u32 = 0x3f_ffff;
        let mut ordered_ids = node_ids.map(ToOwned::to_owned).collect::<Vec<String>>();
        ordered_ids.sort();
        ordered_ids.dedup();

        if ordered_ids.len() as u32 > MAX_OFFSET {
            return Err(ControlPlaneError::Assignment(
                "no available tunnel cidr assignment remains".to_string(),
            ));
        }

        let mut used_offsets = HashSet::new();
        let mut assignments = HashMap::with_capacity(ordered_ids.len());
        for node_id in ordered_ids {
            let mut offset = Self::deterministic_offset_for_node_id(node_id.as_str());
            let start = offset;
            loop {
                if used_offsets.insert(offset) {
                    assignments.insert(node_id, Self::cidr_from_offset(offset));
                    break;
                }
                offset = if offset == MAX_OFFSET { 1 } else { offset + 1 };
                if offset == start {
                    return Err(ControlPlaneError::Assignment(
                        "no available tunnel cidr assignment remains".to_string(),
                    ));
                }
            }
        }

        Ok(assignments)
    }

    fn deterministic_offset_for_node_id(node_id: &str) -> u32 {
        const MAX_OFFSET: u32 = 0x3f_ffff;
        let digest = sha256_digest(node_id.as_bytes());
        let raw = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
        (raw % MAX_OFFSET) + 1
    }

    fn cidr_from_offset(offset: u32) -> String {
        let second_octet = 64 + ((offset >> 16) & 0x3f);
        let third_octet = (offset >> 8) & 0xff;
        let fourth_octet = offset & 0xff;
        format!("100.{second_octet}.{third_octet}.{fourth_octet}/32")
    }

    fn policy_allows_node_pair(&self, source: &NodeMetadata, destination: &NodeMetadata) -> bool {
        let source_selectors = selectors_for_node(source);
        let destination_selectors = selectors_for_node(destination);
        for src in &source_selectors {
            for dst in &destination_selectors {
                for protocol in [Protocol::Any, Protocol::Udp, Protocol::Tcp] {
                    let decision = self.policy.evaluate(&AccessRequest {
                        src: src.clone(),
                        dst: dst.clone(),
                        protocol,
                    });
                    if decision == PolicyEngineDecision::Allow {
                        return true;
                    }
                }
            }
        }
        false
    }

    fn sign_peer_map_payload(&self, payload: &str) -> String {
        let signature = self.assignment_signing_key.sign(payload.as_bytes());
        hex_bytes(&signature.to_bytes())
    }

    fn sign_access_token(&self, claims: &TokenClaims) -> SignedTokenClaims {
        let payload = token_claims_payload(claims);
        let signature = self.access_token_signing_key.sign(payload.as_bytes());
        SignedTokenClaims {
            claims: claims.clone(),
            signature_hex: hex_bytes(&signature.to_bytes()),
        }
    }

    fn verify_peer_map_signature(&self, payload: &str, signature_hex: &str) -> bool {
        let signature_bytes = match decode_hex_to_fixed::<64>(signature_hex) {
            Ok(bytes) => bytes,
            Err(()) => return false,
        };
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = match VerifyingKey::from_bytes(&self.assignment_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verifying_key.verify(payload.as_bytes(), &signature).is_ok()
    }
}

#[derive(Debug)]
pub enum ControlPlaneError {
    Credential(CredentialError),
    Auth(AuthError),
    Trust(TrustStateError),
    Persistence(persistence::PersistenceError),
    Assignment(String),
    Dns(String),
    Traversal(String),
    Internal,
}

impl fmt::Display for ControlPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlPlaneError::Credential(err) => write!(f, "credential error: {err}"),
            ControlPlaneError::Auth(err) => write!(f, "auth error: {err}"),
            ControlPlaneError::Trust(err) => write!(f, "trust error: {err}"),
            ControlPlaneError::Persistence(err) => write!(f, "persistence error: {err}"),
            ControlPlaneError::Assignment(err) => write!(f, "assignment error: {err}"),
            ControlPlaneError::Dns(err) => write!(f, "dns error: {err}"),
            ControlPlaneError::Traversal(err) => write!(f, "traversal error: {err}"),
            ControlPlaneError::Internal => f.write_str("control-plane internal error"),
        }
    }
}

impl std::error::Error for ControlPlaneError {}

fn derive_signing_seed(domain: &[u8], secret: &[u8]) -> [u8; 32] {
    let mut seed = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(SIGNING_SEED_HKDF_SALT_V1), secret);
    hkdf.expand(domain, &mut seed)
        .expect("hkdf expand length is fixed and valid");
    seed
}

fn map_persisted_credential_state_to_error(state: Option<&str>) -> CredentialError {
    match state {
        Some("revoked") => CredentialError::Revoked,
        Some("expired") => CredentialError::Expired,
        Some("used") | Some("created") | Some(_) => CredentialError::AlreadyConsumed,
        None => CredentialError::NotFound,
    }
}

fn map_dns_zone_error(err: DnsZoneError) -> ControlPlaneError {
    ControlPlaneError::Dns(err.to_string())
}

fn random_nonce_hex(length_bytes: usize) -> String {
    let mut nonce = vec![0u8; length_bytes];
    rand::rngs::OsRng.fill_bytes(nonce.as_mut_slice());
    let encoded = hex_bytes(nonce.as_slice());
    nonce.zeroize();
    encoded
}

fn sha256_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn token_claims_payload(claims: &TokenClaims) -> String {
    format!(
        "version=1\nsubject={}\nissued_at_unix={}\nexpires_at_unix={}\nnonce={}\n",
        claims.subject, claims.issued_at_unix, claims.expires_at_unix, claims.nonce
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], ()> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(());
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_hex_nibble(raw[index * 2])?;
        let lo = decode_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

fn selectors_for_node(node: &NodeMetadata) -> Vec<String> {
    let mut selectors = vec![
        format!("node:{}", node.node_id),
        format!("user:{}", node.owner),
    ];
    for tag in &node.tags {
        selectors.push(format!("tag:{tag}"));
    }
    selectors
}

struct AutoTunnelPayloadHeader<'a> {
    node_id: &'a str,
    mesh_cidr: &'a str,
    assigned_cidr: &'a str,
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
}

fn serialize_auto_tunnel_payload(
    header: &AutoTunnelPayloadHeader<'_>,
    peers: &[AutoTunnelPeer],
    routes: &[AutoTunnelRoute],
) -> String {
    let mut payload = String::new();
    payload.push_str("version=1\n");
    payload.push_str(&format!("node_id={}\n", header.node_id));
    payload.push_str(&format!("mesh_cidr={}\n", header.mesh_cidr));
    payload.push_str(&format!("assigned_cidr={}\n", header.assigned_cidr));
    payload.push_str(&format!("generated_at_unix={}\n", header.generated_at_unix));
    payload.push_str(&format!("expires_at_unix={}\n", header.expires_at_unix));
    payload.push_str(&format!("nonce={}\n", header.nonce));
    payload.push_str(&format!("peer_count={}\n", peers.len()));
    for (index, peer) in peers.iter().enumerate() {
        payload.push_str(&format!("peer.{index}.node_id={}\n", peer.node_id));
        payload.push_str(&format!("peer.{index}.endpoint={}\n", peer.endpoint));
        payload.push_str(&format!(
            "peer.{index}.public_key_hex={}\n",
            hex_bytes(&peer.public_key)
        ));
        payload.push_str(&format!(
            "peer.{index}.allowed_ips={}\n",
            peer.allowed_ips.join(",")
        ));
    }
    payload.push_str(&format!("route_count={}\n", routes.len()));
    for (index, route) in routes.iter().enumerate() {
        payload.push_str(&format!(
            "route.{index}.destination_cidr={}\n",
            route.destination_cidr
        ));
        payload.push_str(&format!("route.{index}.via_node={}\n", route.via_node));
        let kind = match route.kind {
            AutoTunnelRouteKind::Mesh => "mesh",
            AutoTunnelRouteKind::ExitNodeLan => "exit_lan",
            AutoTunnelRouteKind::ExitNodeDefault => "exit_default",
        };
        payload.push_str(&format!("route.{index}.kind={kind}\n"));
    }
    payload
}

fn host_ip_from_host_cidr(value: &str) -> Option<String> {
    let (ip, prefix) = value.split_once('/')?;
    if prefix != "32" && prefix != "128" {
        return None;
    }
    Some(ip.to_string())
}

fn serialize_endpoint_hint_payload(
    source_node_id: &str,
    target_node_id: &str,
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
    candidates: &[EndpointHintCandidate],
) -> Result<String, ControlPlaneError> {
    let mut ordered = candidates.to_vec();
    ordered.sort_by(|left, right| {
        right
            .priority
            .cmp(&left.priority)
            .then(
                left.candidate_type
                    .as_str()
                    .cmp(right.candidate_type.as_str()),
            )
            .then(left.endpoint.cmp(&right.endpoint))
            .then(
                left.relay_id
                    .as_deref()
                    .unwrap_or("")
                    .cmp(right.relay_id.as_deref().unwrap_or("")),
            )
    });

    let mut payload = String::new();
    payload.push_str("version=1\n");
    payload.push_str("path_policy=direct_preferred_relay_allowed\n");
    payload.push_str(&format!("source_node_id={source_node_id}\n"));
    payload.push_str(&format!("target_node_id={target_node_id}\n"));
    payload.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
    payload.push_str(&format!("expires_at_unix={expires_at_unix}\n"));
    payload.push_str(&format!("nonce={nonce}\n"));
    payload.push_str(&format!("candidate_count={}\n", ordered.len()));
    for (index, candidate) in ordered.iter().enumerate() {
        let endpoint = candidate.endpoint.parse::<SocketAddr>().map_err(|_| {
            ControlPlaneError::Traversal(
                "candidate endpoint failed canonical serialization".to_string(),
            )
        })?;
        if endpoint.port() == 0 {
            return Err(ControlPlaneError::Traversal(
                "candidate endpoint port must be non-zero".to_string(),
            ));
        }

        let family = if endpoint.ip().is_ipv4() {
            "ipv4"
        } else {
            "ipv6"
        };
        let relay_id = candidate.relay_id.as_deref().unwrap_or("").trim();
        if matches!(candidate.candidate_type, EndpointHintCandidateType::Relay) {
            if relay_id.is_empty() {
                return Err(ControlPlaneError::Traversal(
                    "relay candidates require relay_id".to_string(),
                ));
            }
        } else if !relay_id.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "relay_id is only valid for relay candidates".to_string(),
            ));
        }

        payload.push_str(&format!(
            "candidate.{index}.type={}\n",
            candidate.candidate_type.as_str()
        ));
        payload.push_str(&format!("candidate.{index}.addr={}\n", endpoint.ip()));
        payload.push_str(&format!("candidate.{index}.port={}\n", endpoint.port()));
        payload.push_str(&format!("candidate.{index}.family={family}\n"));
        payload.push_str(&format!("candidate.{index}.relay_id={relay_id}\n"));
        payload.push_str(&format!(
            "candidate.{index}.priority={}\n",
            candidate.priority
        ));
    }
    Ok(payload)
}

fn is_valid_ipv4_or_ipv6_cidr(value: &str) -> bool {
    let Some((ip_part, prefix_part)) = value.split_once('/') else {
        return false;
    };
    if ip_part.parse::<std::net::IpAddr>().is_err() {
        return false;
    }
    let Ok(prefix) = prefix_part.parse::<u8>() else {
        return false;
    };
    if ip_part.contains(':') {
        prefix <= 128
    } else {
        prefix <= 32
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ACCESS_TOKEN_SIGNING_SEED_INFO_V1, ASSIGNMENT_SIGNING_SEED_INFO_V1, AbuseAlertPolicy,
        ApiAbuseMonitor, AuthError, AuthRateLimitConfig, AuthSurfaceGuard, AutoTunnelBundleRequest,
        ControlPlaneCore, ControlPlanePersistence, ControlPlaneTlsVersion, CredentialError,
        DnsRecordRequest, DnsRecordType, DnsTargetAddrKind, ENDPOINT_HINT_SIGNING_SEED_INFO_V1,
        EndpointHintBundleRequest, EndpointHintCandidate, EndpointHintCandidateType,
        EnrollmentRequest, LockoutConfig, PolicyCheckRequest, PolicyDecision, PolicyGuard,
        ReplayPolicy, ReusableCredentialPolicy, ReusableCredentialRequest,
        SignedDnsZoneBundleRequest, ThrowawayCredentialState, ThrowawayCredentialStore,
        TokenClaims, TransportPolicyError, TrustState, derive_signing_seed, hex_bytes,
        load_trust_state, persist_trust_state,
    };
    use rustynet_crypto::{AlgorithmPolicy, CompatibilityException, CryptoAlgorithm};
    use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};

    fn payload_field(payload: &str, key: &str) -> Option<String> {
        payload.lines().find_map(|line| {
            let (line_key, value) = line.split_once('=')?;
            if line_key == key {
                Some(value.to_string())
            } else {
                None
            }
        })
    }

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
        let unique_dir = format!(
            "rustynet-trust-state-dir-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let test_dir = std::env::temp_dir().join(unique_dir);
        std::fs::create_dir_all(&test_dir).expect("test directory should be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&test_dir, std::fs::Permissions::from_mode(0o700))
                .expect("test directory permissions should be set");
        }
        let path = test_dir.join("trust.state");

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
        let _ = std::fs::remove_file(format!("{}.integrity.key", path.display()));
        let _ = std::fs::remove_dir(&test_dir);
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
    fn algorithm_policy_rejects_compatibility_exceptions() {
        let result = AlgorithmPolicy::with_exceptions(vec![CompatibilityException {
            algorithm: CryptoAlgorithm::Sha1,
            expires_unix_seconds: 150,
        }]);
        assert!(result.is_err());

        let policy = AlgorithmPolicy::default();
        assert!(policy.validate(CryptoAlgorithm::Sha1, 149).is_err());
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
                endpoint: "198.51.100.10:51820".to_string(),
                public_key: [3; 32],
                now_unix: 120,
            })
            .expect("enrollment should succeed");

        assert_eq!(response.node_id, "node-1");
        assert!(core.verify_access_token(&response.access_token));
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
            endpoint: "198.51.100.11:51820".to_string(),
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
            endpoint: "198.51.100.20:51820".to_string(),
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
    fn auto_tunnel_bundle_is_centrally_assigned_and_signed() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        core.credentials
            .create(
                "cred-node-a".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");
        core.credentials
            .create(
                "cred-node-b".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-node-a".to_string(),
            node_id: "node-a".to_string(),
            hostname: "node-a".to_string(),
            os: "linux".to_string(),
            tags: vec!["servers".to_string()],
            owner: "alice@example.local".to_string(),
            endpoint: "198.51.100.40:51820".to_string(),
            public_key: [41; 32],
            now_unix: 120,
        })
        .expect("enrollment should succeed");
        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-node-b".to_string(),
            node_id: "node-b".to_string(),
            hostname: "node-b".to_string(),
            os: "linux".to_string(),
            tags: vec!["servers".to_string()],
            owner: "alice@example.local".to_string(),
            endpoint: "198.51.100.41:51820".to_string(),
            public_key: [42; 32],
            now_unix: 121,
        })
        .expect("enrollment should succeed");

        let bundle = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_string(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 11,
                mesh_cidr: "100.64.0.0/10".to_string(),
                exit_node_id: Some("node-b".to_string()),
                lan_routes: vec!["192.168.1.0/24".to_string()],
            })
            .expect("auto tunnel bundle should be emitted");

        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        assert_eq!(
            payload_field(&bundle.payload, "node_id").as_deref(),
            Some("node-a")
        );
        assert_eq!(
            payload_field(&bundle.payload, "route_count").as_deref(),
            Some("3")
        );
        assert_eq!(
            payload_field(&bundle.payload, "peer_count").as_deref(),
            Some("1")
        );
        let peer_allowed_ips = payload_field(&bundle.payload, "peer.0.allowed_ips")
            .expect("peer allowed ips should be present");
        assert!(peer_allowed_ips.contains("0.0.0.0/0"));
        assert!(peer_allowed_ips.contains("192.168.1.0/24"));

        let wire = ControlPlaneCore::signed_auto_tunnel_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));

        let mut tampered = bundle.clone();
        tampered.payload.push_str("peer.99.node_id=tampered\n");
        assert!(!core.verify_signed_auto_tunnel_bundle(&tampered));
    }

    #[test]
    fn auto_tunnel_bundle_is_policy_gated_and_assignment_is_stable() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "node:node-a".to_string(),
                dst: "node:node-b".to_string(),
                protocol: Protocol::Udp,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.50:51820", [51; 32]),
            ("cred-b", "node-b", "198.51.100.51:51820", [52; 32]),
            ("cred-c", "node-c", "198.51.100.52:51820", [53; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_string(),
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: endpoint.to_string(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let first = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_string(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 22,
                mesh_cidr: "100.64.0.0/10".to_string(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");
        let second = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_string(),
                generated_at_unix: 201,
                ttl_secs: 300,
                nonce: 23,
                mesh_cidr: "100.64.0.0/10".to_string(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");

        assert_eq!(
            payload_field(&first.payload, "assigned_cidr"),
            payload_field(&second.payload, "assigned_cidr")
        );
        assert_eq!(
            payload_field(&first.payload, "peer_count").as_deref(),
            Some("1")
        );
        assert!(first.payload.contains("peer.0.node_id=node-b"));
        assert!(!first.payload.contains("node-c"));
    }

    #[test]
    fn auto_tunnel_bundle_assignments_are_consistent_across_targets() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.50:51820", [51; 32]),
            ("cred-b", "node-b", "198.51.100.51:51820", [52; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_string(),
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: endpoint.to_string(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle_a = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_string(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 31,
                mesh_cidr: "100.64.0.0/10".to_string(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");
        let bundle_b = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-b".to_string(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 32,
                mesh_cidr: "100.64.0.0/10".to_string(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");

        let assigned_a =
            payload_field(&bundle_a.payload, "assigned_cidr").expect("assigned cidr for node-a");
        let assigned_b =
            payload_field(&bundle_b.payload, "assigned_cidr").expect("assigned cidr for node-b");
        assert_ne!(assigned_a, assigned_b);
        assert_eq!(
            payload_field(&bundle_a.payload, "peer.0.allowed_ips"),
            Some(assigned_b.clone())
        );
        assert_eq!(
            payload_field(&bundle_b.payload, "peer.0.allowed_ips"),
            Some(assigned_a.clone())
        );
    }

    #[test]
    fn dns_zone_bundle_is_signed_and_tamper_detected() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.50:51820", [51; 32]),
            ("cred-b", "node-b", "198.51.100.51:51820", [52; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_string(),
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: endpoint.to_string(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle = core
            .signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
                zone_name: "rustynet".to_string(),
                subject_node_id: "node-a".to_string(),
                generated_at_unix: 200,
                ttl_secs: 120,
                nonce: 41,
                records: vec![DnsRecordRequest {
                    label: "nas".to_string(),
                    target_node_id: "node-b".to_string(),
                    ttl_secs: 60,
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    aliases: vec!["storage".to_string()],
                }],
            })
            .expect("dns zone bundle should be emitted");

        assert!(core.verify_signed_dns_zone_bundle(&bundle));
        assert_eq!(
            payload_field(&bundle.payload, "zone_name").as_deref(),
            Some("rustynet")
        );
        assert_eq!(
            payload_field(&bundle.payload, "record.0.fqdn").as_deref(),
            Some("nas.rustynet")
        );
        let expected_ip =
            payload_field(&bundle.payload, "record.0.expected_ip").expect("expected_ip present");
        assert!(expected_ip.parse::<std::net::Ipv4Addr>().is_ok());

        let wire = ControlPlaneCore::signed_dns_zone_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));

        let mut tampered = bundle.clone();
        tampered
            .payload
            .push_str("record.9.fqdn=tampered.rustynet\n");
        assert!(!core.verify_signed_dns_zone_bundle(&tampered));
    }

    #[test]
    fn dns_zone_bundle_is_policy_gated_and_alias_collisions_are_rejected() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "node:node-a".to_string(),
                dst: "node:node-b".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.50:51820", [51; 32]),
            ("cred-b", "node-b", "198.51.100.51:51820", [52; 32]),
            ("cred-c", "node-c", "198.51.100.52:51820", [53; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_string(),
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: endpoint.to_string(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let denied = core.signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
            zone_name: "rustynet".to_string(),
            subject_node_id: "node-a".to_string(),
            generated_at_unix: 200,
            ttl_secs: 120,
            nonce: 42,
            records: vec![DnsRecordRequest {
                label: "db".to_string(),
                target_node_id: "node-c".to_string(),
                ttl_secs: 60,
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                aliases: Vec::new(),
            }],
        });
        assert!(matches!(denied, Err(super::ControlPlaneError::Dns(_))));

        let collision = core.signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
            zone_name: "rustynet".to_string(),
            subject_node_id: "node-a".to_string(),
            generated_at_unix: 200,
            ttl_secs: 120,
            nonce: 43,
            records: vec![
                DnsRecordRequest {
                    label: "nas".to_string(),
                    target_node_id: "node-b".to_string(),
                    ttl_secs: 60,
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    aliases: vec!["storage".to_string()],
                },
                DnsRecordRequest {
                    label: "storage".to_string(),
                    target_node_id: "node-b".to_string(),
                    ttl_secs: 60,
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    aliases: Vec::new(),
                },
            ],
        });
        assert!(matches!(collision, Err(super::ControlPlaneError::Dns(_))));
    }

    #[test]
    fn endpoint_hint_bundle_is_signed_and_tamper_detected() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.70:51820", [70; 32]),
            ("cred-b", "node-b", "198.51.100.71:51820", [71; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_string(),
                node_id: node_id.to_string(),
                hostname: node_id.to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: endpoint.to_string(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle = core
            .signed_endpoint_hint_bundle(EndpointHintBundleRequest {
                source_node_id: "node-a".to_string(),
                target_node_id: "node-b".to_string(),
                generated_at_unix: 200,
                ttl_secs: 60,
                nonce: 7,
                candidates: vec![
                    EndpointHintCandidate {
                        candidate_type: EndpointHintCandidateType::Host,
                        endpoint: "10.0.0.3:51820".to_string(),
                        relay_id: None,
                        priority: 10,
                    },
                    EndpointHintCandidate {
                        candidate_type: EndpointHintCandidateType::Relay,
                        endpoint: "203.0.113.44:443".to_string(),
                        relay_id: Some("relay-eu-1".to_string()),
                        priority: 20,
                    },
                ],
            })
            .expect("endpoint hint bundle should be issued");

        assert!(core.verify_signed_endpoint_hint_bundle(&bundle));
        assert_eq!(
            payload_field(&bundle.payload, "candidate_count").as_deref(),
            Some("2")
        );
        assert_eq!(
            payload_field(&bundle.payload, "candidate.0.type").as_deref(),
            Some("relay")
        );
        assert_eq!(
            payload_field(&bundle.payload, "candidate.0.relay_id").as_deref(),
            Some("relay-eu-1")
        );

        let wire = ControlPlaneCore::signed_endpoint_hint_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));

        let mut tampered = bundle.clone();
        tampered.payload.push_str("candidate.99.type=relay\n");
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_bundle_enforces_policy_and_candidate_validation() {
        let deny_all = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-a", "node-a", "198.51.100.80:51820", [80; 32]),
            ("cred-b", "node-b", "198.51.100.81:51820", [81; 32]),
        ] {
            deny_all
                .credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            deny_all
                .enroll_with_throwaway(EnrollmentRequest {
                    credential_id: credential_id.to_string(),
                    node_id: node_id.to_string(),
                    hostname: node_id.to_string(),
                    os: "linux".to_string(),
                    tags: vec!["servers".to_string()],
                    owner: "alice@example.local".to_string(),
                    endpoint: endpoint.to_string(),
                    public_key,
                    now_unix: 120,
                })
                .expect("enrollment should succeed");
        }
        let denied = deny_all.signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: "node-a".to_string(),
            target_node_id: "node-b".to_string(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 1,
            candidates: vec![EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Host,
                endpoint: "10.0.0.2:51820".to_string(),
                relay_id: None,
                priority: 1,
            }],
        });
        assert!(
            denied
                .expect_err("policy must deny source->target endpoint hints")
                .to_string()
                .contains("denied by policy")
        );

        let allow_all = ControlPlaneCore::new(
            b"control-secret".to_vec(),
            PolicySet {
                rules: vec![PolicyRule {
                    src: "*".to_string(),
                    dst: "*".to_string(),
                    protocol: Protocol::Any,
                    action: RuleAction::Allow,
                }],
            },
        );
        for (credential_id, node_id, endpoint, public_key) in [
            ("cred-c", "node-c", "198.51.100.82:51820", [82; 32]),
            ("cred-d", "node-d", "198.51.100.83:51820", [83; 32]),
        ] {
            allow_all
                .credentials
                .create(
                    credential_id.to_string(),
                    "admin".to_string(),
                    "tag:servers".to_string(),
                    100,
                    60,
                )
                .expect("credential should be created");
            allow_all
                .enroll_with_throwaway(EnrollmentRequest {
                    credential_id: credential_id.to_string(),
                    node_id: node_id.to_string(),
                    hostname: node_id.to_string(),
                    os: "linux".to_string(),
                    tags: vec!["servers".to_string()],
                    owner: "alice@example.local".to_string(),
                    endpoint: endpoint.to_string(),
                    public_key,
                    now_unix: 120,
                })
                .expect("enrollment should succeed");
        }

        let duplicate = allow_all.signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: "node-c".to_string(),
            target_node_id: "node-d".to_string(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 2,
            candidates: vec![
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Host,
                    endpoint: "10.2.0.2:51820".to_string(),
                    relay_id: None,
                    priority: 100,
                },
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Host,
                    endpoint: "10.2.0.2:51820".to_string(),
                    relay_id: None,
                    priority: 1,
                },
            ],
        });
        assert!(
            duplicate
                .expect_err("duplicate endpoint candidates must fail")
                .to_string()
                .contains("duplicate endpoint hint candidate")
        );

        let relay_missing_id = allow_all.signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: "node-c".to_string(),
            target_node_id: "node-d".to_string(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 3,
            candidates: vec![EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Relay,
                endpoint: "203.0.113.55:443".to_string(),
                relay_id: None,
                priority: 1,
            }],
        });
        assert!(
            relay_missing_id
                .expect_err("relay candidates without relay_id must fail")
                .to_string()
                .contains("relay candidates require relay_id")
        );
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
        persistence
            .insert_credential(&super::persistence::CredentialRow {
                credential_id: "cred-persist".to_string(),
                creator_user_id: "admin".to_string(),
                scope: "tag:servers".to_string(),
                credential_kind: "throwaway".to_string(),
                state: "created".to_string(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 160,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_string(),
            })
            .expect("credential should be persisted before enrollment");
        persistence
            .insert_credential_audit_event("cred-persist", None, "created", 100, "admin")
            .expect("credential creation audit event should be persisted");

        let response = core
            .enroll_with_throwaway_and_persist(
                EnrollmentRequest {
                    credential_id: "cred-persist".to_string(),
                    node_id: "node-persist".to_string(),
                    hostname: "mini-pc-persist".to_string(),
                    os: "linux".to_string(),
                    tags: vec!["servers".to_string()],
                    owner: "alice@example.local".to_string(),
                    endpoint: "198.51.100.30:51820".to_string(),
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
        assert_eq!(audit_count, 2);
    }

    #[test]
    fn persisted_enrollment_rejects_missing_persisted_credential() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        let persistence = ControlPlanePersistence::open_in_memory()
            .expect("in-memory persistence should be available");

        core.credentials
            .create(
                "cred-missing-db".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("in-memory credential should be created");

        let result = core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-missing-db".to_string(),
                node_id: "node-missing-db".to_string(),
                hostname: "node-missing-db".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.31:51820".to_string(),
                public_key: [9; 32],
                now_unix: 150,
            },
            &persistence,
        );

        assert!(matches!(
            result,
            Err(super::ControlPlaneError::Credential(
                CredentialError::NotFound
            ))
        ));
    }

    #[test]
    fn persisted_enrollment_enforces_single_use_in_persistence() {
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
                "cred-persist-once".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");
        persistence
            .insert_credential(&super::persistence::CredentialRow {
                credential_id: "cred-persist-once".to_string(),
                creator_user_id: "admin".to_string(),
                scope: "tag:servers".to_string(),
                credential_kind: "throwaway".to_string(),
                state: "created".to_string(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 160,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_string(),
            })
            .expect("credential should be persisted");

        core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-persist-once".to_string(),
                node_id: "node-persist-once-a".to_string(),
                hostname: "node-persist-once-a".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.33:51820".to_string(),
                public_key: [11; 32],
                now_unix: 150,
            },
            &persistence,
        )
        .expect("first enrollment should succeed");

        let second = core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-persist-once".to_string(),
                node_id: "node-persist-once-b".to_string(),
                hostname: "node-persist-once-b".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.34:51820".to_string(),
                public_key: [12; 32],
                now_unix: 151,
            },
            &persistence,
        );
        assert!(matches!(
            second,
            Err(super::ControlPlaneError::Credential(
                CredentialError::AlreadyConsumed
            ))
        ));
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
    fn signed_token_claims_are_verified_and_replay_guarded() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        core.credentials
            .create(
                "cred-token".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        let response = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token".to_string(),
                node_id: "node-token".to_string(),
                hostname: "mini-pc-token".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.60:51820".to_string(),
                public_key: [60; 32],
                now_unix: 120,
            })
            .expect("enrollment should succeed");

        assert!(core.verify_access_token(&response.access_token));

        let mut guard = AuthSurfaceGuard::default();
        assert!(
            core.validate_signed_token_and_nonce(&mut guard, &response.access_token, 121)
                .is_ok()
        );
        let replay = core.validate_signed_token_and_nonce(&mut guard, &response.access_token, 122);
        assert_eq!(replay.err(), Some(AuthError::ReplayDetected));

        let mut tampered = response.access_token.clone();
        tampered.claims.subject = "mallory@example.local".to_string();
        let tampered_result = core.validate_signed_token_and_nonce(&mut guard, &tampered, 123);
        assert_eq!(
            tampered_result.err(),
            Some(AuthError::TokenSignatureInvalid)
        );
    }

    #[test]
    fn enrollment_tokens_use_randomized_nonce_values() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet::default());
        core.credentials
            .create(
                "cred-token-a".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");
        core.credentials
            .create(
                "cred-token-b".to_string(),
                "admin".to_string(),
                "tag:servers".to_string(),
                100,
                60,
            )
            .expect("credential should be created");

        let token_a = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token-a".to_string(),
                node_id: "node-token-a".to_string(),
                hostname: "mini-pc-token-a".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.60:51820".to_string(),
                public_key: [61; 32],
                now_unix: 120,
            })
            .expect("first enrollment should succeed")
            .access_token;
        let token_b = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token-b".to_string(),
                node_id: "node-token-b".to_string(),
                hostname: "mini-pc-token-b".to_string(),
                os: "linux".to_string(),
                tags: vec!["servers".to_string()],
                owner: "alice@example.local".to_string(),
                endpoint: "198.51.100.61:51820".to_string(),
                public_key: [62; 32],
                now_unix: 120,
            })
            .expect("second enrollment should succeed")
            .access_token;

        assert_eq!(token_a.claims.nonce.len(), 32);
        assert_eq!(token_b.claims.nonce.len(), 32);
        assert!(
            token_a
                .claims
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert!(
            token_b
                .claims
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
        assert_ne!(token_a.claims.nonce, token_b.claims.nonce);
    }

    #[test]
    fn signing_seed_derivation_uses_stable_hkdf_vectors() {
        let assignment_seed =
            derive_signing_seed(ASSIGNMENT_SIGNING_SEED_INFO_V1, b"control-secret");
        let endpoint_seed =
            derive_signing_seed(ENDPOINT_HINT_SIGNING_SEED_INFO_V1, b"control-secret");
        let access_seed = derive_signing_seed(ACCESS_TOKEN_SIGNING_SEED_INFO_V1, b"control-secret");
        assert_eq!(
            hex_bytes(&assignment_seed),
            "823450eb42a8e622264f36041cc7c2bbe1f39b90eabb622f1b73c35aa496764a"
        );
        assert_eq!(
            hex_bytes(&endpoint_seed),
            "45c6b4a8cf265219f296bb670a1cb8dfbe077a6dee3689540d346a4d6cdeb513"
        );
        assert_eq!(
            hex_bytes(&access_seed),
            "8ae34416e7e185594a0cd9e154b8ae2885e2f70e0e9470bfeb4ab128fb42aac4"
        );
        assert_ne!(assignment_seed, access_seed);
        assert_ne!(assignment_seed, endpoint_seed);
        assert_ne!(endpoint_seed, access_seed);
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
