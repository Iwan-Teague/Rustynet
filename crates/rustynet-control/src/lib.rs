#![forbid(unsafe_code)]

pub mod admin;
pub mod enrollment;
pub mod ga;
pub mod membership;
pub mod operations;
pub mod persistence;
pub mod role_audit;
pub mod role_presets;
pub mod roles;
pub mod scale;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
use rand::TryRngCore;
pub use rustynet_dns_zone::{DnsRecordType, DnsTargetAddrKind, SignedDnsZoneBundle};
use rustynet_dns_zone::{
    DnsZoneError, DnsZoneRecordInput, build_signed_dns_zone_bundle,
    render_signed_dns_zone_bundle_wire, verify_signed_dns_zone_bundle as verify_dns_zone_bundle,
};
use rustynet_policy::{AccessRequest, Decision as PolicyEngineDecision, PolicySet, Protocol};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::roles::{RoleCapability, role_capability_csv};

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

impl TokenClaims {
    pub fn ct_eq(&self, other: &TokenClaims) -> bool {
        use subtle::ConstantTimeEq;
        self.subject
            .as_bytes()
            .ct_eq(other.subject.as_bytes())
            .unwrap_u8()
            == 1
            && self
                .nonce
                .as_bytes()
                .ct_eq(other.nonce.as_bytes())
                .unwrap_u8()
                == 1
            && self.issued_at_unix == other.issued_at_unix
            && self.expires_at_unix == other.expires_at_unix
    }
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

impl SignedTokenClaims {
    pub fn ct_eq(&self, other: &SignedTokenClaims) -> bool {
        use subtle::ConstantTimeEq;
        self.claims.ct_eq(&other.claims)
            && self
                .signature_hex
                .as_bytes()
                .ct_eq(other.signature_hex.as_bytes())
                .unwrap_u8()
                == 1
    }
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
            source_ip.to_owned(),
            identity.to_owned(),
            endpoint.to_owned(),
        );
        let history = self.failures.entry(key).or_default();
        let window_start = now_unix.saturating_sub(self.policy.window_secs);
        history.retain(|entry| *entry >= window_start);
        history.push(now_unix);

        if history.len() as u32 >= self.policy.threshold {
            let mut guard = self.alerts.lock().map_err(|_| AuthError::Internal)?;
            guard.push(AbuseAlert {
                source_ip: source_ip.to_owned(),
                identity: identity.to_owned(),
                endpoint: endpoint.to_owned(),
                reason: reason.to_owned(),
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
                .entry(identity.to_owned())
                .or_insert_with(LockoutState::new);
            lockout.locked_until_unix
        };

        if now_unix < locked_until {
            self.record_event(SecurityEvent {
                endpoint: endpoint.to_owned(),
                source_ip: source_ip.to_owned(),
                identity: identity.to_owned(),
                failure_class: "lockout".to_owned(),
                limiter_decision: "denied_locked".to_owned(),
                timestamp_unix: now_unix,
            })?;
            return Err(AuthError::LockedOutUntil(locked_until));
        }

        let ip_bucket = self
            .ip_buckets
            .entry(source_ip.to_owned())
            .or_insert_with(|| Bucket::new(self.rate_config.ip_burst, now_unix));
        ip_bucket.consume(
            now_unix,
            self.rate_config.ip_burst,
            f64::from(self.rate_config.ip_refill_per_minute) / 60.0,
        )?;

        let identity_bucket = self
            .identity_buckets
            .entry(identity.to_owned())
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
            .entry(identity.to_owned())
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
            .entry(identity.to_owned())
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
            storage_policy: "throwaway_default".to_owned(),
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
                credential_id: id.to_owned(),
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
            credential_id: id.to_owned(),
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
            credential_id: id.to_owned(),
            generation,
            revoked_at_unix: now_unix,
        })?;
        self.record_audit_event(CredentialAuditEvent {
            credential_id: id.to_owned(),
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
                fingerprint = Some(value.to_owned());
            }
            "updated_at_unix" => {
                updated_at = value.parse::<u64>().ok();
            }
            "mac" => {
                mac = Some(value.to_owned());
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
    rand::rngs::OsRng
        .try_fill_bytes(&mut key)
        .map_err(|_| TrustStateError::KeyUnavailable)?;
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
        .to_owned();
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
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .map_err(|_| TrustStateError::PersistFailure)?;
    Ok(())
}

fn atomic_write_secure(
    path: &Path,
    body: &[u8],
    #[cfg_attr(not(unix), allow(unused_variables))] mode: u32,
) -> Result<(), TrustStateError> {
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
    options.mode(mode);
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
    let _ = disallowed_mode_mask;
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
    pub capabilities: Vec<RoleCapability>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFleetNodeDescriptor {
    pub relay_id: String,
    pub region: String,
    pub endpoint: String,
    pub priority: u16,
    pub capacity: u32,
    pub enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFleetBundleRequest {
    pub generated_at_unix: u64,
    pub ttl_secs: u64,
    pub nonce: u64,
    pub relays: Vec<RelayFleetNodeDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRelayFleetBundle {
    pub payload: String,
    pub signature_hex: String,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: u64,
    pub relay_count: usize,
    pub relays: Vec<RelayFleetNodeDescriptor>,
}

pub fn parse_signed_relay_fleet_bundle_wire(
    wire: &str,
) -> Result<SignedRelayFleetBundle, ControlPlaneError> {
    let (payload, signature_hex) = split_signed_relay_fleet_wire(wire)?;
    let fields = parse_relay_fleet_payload_fields(payload.as_str())?;
    let generated_at_unix = parse_relay_fleet_required_u64(&fields, "generated_at_unix")?;
    let expires_at_unix = parse_relay_fleet_required_u64(&fields, "expires_at_unix")?;
    let nonce = parse_relay_fleet_required_u64(&fields, "nonce")?;
    let relay_count = parse_relay_fleet_required_usize(&fields, "relay_count")?;
    if parse_relay_fleet_required_u64(&fields, "version")? != 1 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle unsupported version".to_owned(),
        ));
    }
    if generated_at_unix == 0 || generated_at_unix >= expires_at_unix {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle invalid generated/expires ordering".to_owned(),
        ));
    }
    if expires_at_unix.saturating_sub(generated_at_unix) > 300 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle ttl exceeds max supported value".to_owned(),
        ));
    }
    if nonce == 0 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle nonce must be greater than zero".to_owned(),
        ));
    }
    if relay_count == 0 || relay_count > 64 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle relay_count out of range".to_owned(),
        ));
    }
    let relays = parse_relay_fleet_descriptors(&fields, relay_count)?;
    let expected_payload =
        serialize_relay_fleet_payload(generated_at_unix, expires_at_unix, nonce, &relays)?;
    if expected_payload != payload {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle payload is not canonical".to_owned(),
        ));
    }
    Ok(SignedRelayFleetBundle {
        payload,
        signature_hex,
        generated_at_unix,
        expires_at_unix,
        nonce,
        relay_count,
        relays,
    })
}

pub fn verify_signed_relay_fleet_bundle_with_key(
    bundle: &SignedRelayFleetBundle,
    verifying_key: &VerifyingKey,
) -> bool {
    if bundle.generated_at_unix >= bundle.expires_at_unix {
        return false;
    }
    if bundle
        .expires_at_unix
        .saturating_sub(bundle.generated_at_unix)
        > 300
    {
        return false;
    }
    if bundle.relay_count == 0 || bundle.relay_count > 64 {
        return false;
    }
    if bundle.relays.len() != bundle.relay_count {
        return false;
    }
    if relay_fleet_payload_u64(bundle.payload.as_str(), "version") != Some(1) {
        return false;
    }
    if relay_fleet_payload_u64(bundle.payload.as_str(), "generated_at_unix")
        != Some(bundle.generated_at_unix)
    {
        return false;
    }
    if relay_fleet_payload_u64(bundle.payload.as_str(), "expires_at_unix")
        != Some(bundle.expires_at_unix)
    {
        return false;
    }
    if relay_fleet_payload_u64(bundle.payload.as_str(), "nonce") != Some(bundle.nonce) {
        return false;
    }
    let Some(payload_count) = relay_fleet_payload_usize(bundle.payload.as_str(), "relay_count")
    else {
        return false;
    };
    if payload_count != bundle.relay_count {
        return false;
    }
    let expected_payload = match serialize_relay_fleet_payload(
        bundle.generated_at_unix,
        bundle.expires_at_unix,
        bundle.nonce,
        &bundle.relays,
    ) {
        Ok(payload) => payload,
        Err(_) => return false,
    };
    if expected_payload != bundle.payload {
        return false;
    }
    let signature_bytes = match decode_hex_to_fixed::<64>(&bundle.signature_hex) {
        Ok(bytes) => bytes,
        Err(()) => return false,
    };
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(bundle.payload.as_bytes(), &signature)
        .is_ok()
}

#[derive(Clone, PartialEq, Eq)]
pub struct TraversalCoordinationRecord {
    pub session_id: [u8; 16],
    pub probe_start_unix: u64,
    pub node_a: String,
    pub node_b: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 16],
}

impl fmt::Debug for TraversalCoordinationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TraversalCoordinationRecord")
            .field("session_id", &"REDACTED")
            .field("probe_start_unix", &self.probe_start_unix)
            .field("node_a", &self.node_a)
            .field("node_b", &self.node_b)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("nonce", &"REDACTED")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SignedTraversalCoordinationRecord {
    pub payload: String,
    pub signature_hex: String,
    pub session_id: [u8; 16],
    pub probe_start_unix: u64,
    pub node_a: String,
    pub node_b: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 16],
}

impl fmt::Debug for SignedTraversalCoordinationRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedTraversalCoordinationRecord")
            .field("payload", &"REDACTED")
            .field("signature_hex", &"REDACTED")
            .field("session_id", &"REDACTED")
            .field("probe_start_unix", &self.probe_start_unix)
            .field("node_a", &self.node_a)
            .field("node_b", &self.node_b)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("nonce", &"REDACTED")
            .finish()
    }
}

/// The only accepted scope value for a relay session token.
/// A token with any other scope value must be rejected at the relay.
pub const RELAY_TOKEN_SCOPE: &str = "forward_ciphertext_only";

/// Maximum relay session token TTL accepted by relay servers.
pub const MAX_RELAY_SESSION_TOKEN_TTL_SECS: u64 = 120;

/// Convert an operator-facing relay label into the 16-byte relay id carried in
/// signed relay session tokens.
pub fn canonical_relay_id_from_label(label: &str) -> Result<[u8; 16], String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err("relay_id must not be empty".to_owned());
    }
    if !trimmed.is_ascii() {
        return Err("relay_id must be ASCII".to_owned());
    }
    if !is_single_line_payload_value(trimmed) {
        return Err("relay_id must be a single-line payload value".to_owned());
    }
    if trimmed.len() > 16 {
        return Err("relay_id must be at most 16 ASCII bytes".to_owned());
    }
    let mut relay_id = [0u8; 16];
    relay_id[..trimmed.len()].copy_from_slice(trimmed.as_bytes());
    Ok(relay_id)
}

/// Signed relay session token issued by the control plane.
///
/// `PartialEq`/`Eq` are intentionally **not** derived to prevent accidental
/// non-constant-time comparisons on secret fields (`nonce`, `relay_id`,
/// `signature`).  Use [`RelaySessionToken::ct_eq`] when comparing tokens
/// for equality.
#[derive(Clone)]
pub struct RelaySessionToken {
    pub node_id: String,
    pub peer_node_id: String,
    pub relay_id: [u8; 16],
    /// Must equal [`RELAY_TOKEN_SCOPE`].  Present in the signed payload.
    pub scope: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySessionTokenRequest {
    pub node_id: String,
    pub peer_node_id: String,
    pub relay_id: String,
    pub requested_at_unix: u64,
    pub ttl_secs: u64,
}

impl fmt::Debug for RelaySessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelaySessionToken")
            .field("node_id", &self.node_id)
            .field("peer_node_id", &self.peer_node_id)
            .field("relay_id", &"REDACTED")
            .field("scope", &self.scope)
            .field("issued_at_unix", &self.issued_at_unix)
            .field("expires_at_unix", &self.expires_at_unix)
            .field("nonce", &"REDACTED")
            .field("signature", &"REDACTED")
            .finish()
    }
}

impl RelaySessionToken {
    /// Create and sign a new relay session token.
    ///
    /// Scope is fixed to [`RELAY_TOKEN_SCOPE`].  The nonce is drawn from
    /// `OsRng`.  The returned token has a valid signature over its canonical
    /// payload.
    pub fn sign(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Self {
        // **Security**: previously used `.expect(...)` which would
        // panic the daemon on a pre-UNIX_EPOCH clock (broken RTC,
        // misconfigured NTP, operator-run clock rollback). Now
        // returns 0 on failure. The resulting token has
        // `issued_at = 0, expires_at = ttl_secs`, which a relay with
        // a healthy clock will reject as already-expired (it sees
        // `expires_at < now`) — fail-closed against the relay
        // accepting bogus tokens. If both client and relay have a
        // failed clock the token is honoured for at most
        // `MAX_RELAY_TTL_SECS` seconds, which is the operator-
        // configured cap on relay-session lifetime.
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::sign_at(
            signing_key,
            node_id,
            peer_node_id,
            relay_id,
            now_unix,
            ttl_secs,
        )
    }

    pub fn sign_at(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        relay_id: [u8; 16],
        issued_at_unix: u64,
        ttl_secs: u64,
    ) -> Self {
        // Legacy panicking entry point retained for test fixtures; production
        // code paths must call `try_sign_at` so a CSPRNG failure surfaces as
        // a structured error instead of crashing the long-running daemon.
        match Self::try_sign_at(
            signing_key,
            node_id,
            peer_node_id,
            relay_id,
            issued_at_unix,
            ttl_secs,
        ) {
            Ok(token) => token,
            Err(err) => panic!("os randomness unavailable for relay token nonce: {err}"),
        }
    }

    /// Fallible relay session token minting.
    ///
    /// Returns `Err(RelayTokenMintError)` when the kernel CSPRNG cannot fill
    /// the nonce buffer. We MUST fail closed here: the nonce is the
    /// anti-replay key for the relay's nonce store, so a predictable or
    /// degraded-entropy nonce would let an attacker replay a captured token
    /// or collide with another peer's session. Production callers (notably
    /// `LocalRelaySessionTokenIssuer::issue_token`) propagate this through
    /// their own `Result` type so a transient OS-randomness fault no longer
    /// panics the daemon.
    pub fn try_sign_at(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        relay_id: [u8; 16],
        issued_at_unix: u64,
        ttl_secs: u64,
    ) -> Result<Self, RelayTokenMintError> {
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|err| RelayTokenMintError {
                source: err.to_string(),
            })?;
        let mut token = Self {
            node_id: node_id.to_owned(),
            peer_node_id: peer_node_id.to_owned(),
            relay_id,
            scope: RELAY_TOKEN_SCOPE.to_owned(),
            issued_at_unix,
            expires_at_unix: issued_at_unix.saturating_add(ttl_secs),
            nonce,
            signature: [0u8; 64],
        };
        let payload = token.canonical_payload();
        let sig = signing_key.sign(payload.as_bytes());
        token.signature = sig.to_bytes();
        Ok(token)
    }

    /// Fallible analogue of [`RelaySessionToken::sign`]. See
    /// [`RelaySessionToken::try_sign_at`] for the fail-closed rationale.
    pub fn try_sign(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        relay_id: [u8; 16],
        ttl_secs: u64,
    ) -> Result<Self, RelayTokenMintError> {
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self::try_sign_at(
            signing_key,
            node_id,
            peer_node_id,
            relay_id,
            now_unix,
            ttl_secs,
        )
    }
}

/// Error surfaced by [`RelaySessionToken::try_sign_at`] / [`RelaySessionToken::try_sign`]
/// when the kernel CSPRNG is unavailable for nonce minting. Kept in its own
/// type so callers must explicitly translate to their own error space rather
/// than papering over the failure.
#[derive(Debug)]
pub struct RelayTokenMintError {
    pub source: String,
}

impl fmt::Display for RelayTokenMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "kernel CSPRNG unavailable while minting relay session token nonce: {}",
            self.source
        )
    }
}

impl std::error::Error for RelayTokenMintError {}

impl RelaySessionToken {
    pub fn verify_signature(&self, verifying_key: &VerifyingKey) -> Result<(), String> {
        let payload = self.canonical_payload();
        let signature = Signature::from_bytes(&self.signature);
        verifying_key
            .verify(payload.as_bytes(), &signature)
            .map_err(|e| format!("signature verification failed: {e}"))?;
        Ok(())
    }

    /// Canonical signed payload.  All fields that appear here are covered by
    /// the signature.  **Changing this format is a breaking change.**
    pub fn canonical_payload(&self) -> String {
        format!(
            "version=1\nnode_id={}\npeer_node_id={}\nrelay_id={}\nscope={}\nissued_at_unix={}\nexpires_at_unix={}\nnonce={}\n",
            self.node_id,
            self.peer_node_id,
            hex_bytes(&self.relay_id),
            self.scope,
            self.issued_at_unix,
            self.expires_at_unix,
            hex_bytes(&self.nonce),
        )
    }

    pub fn is_expired(&self, now_unix: u64, clock_skew_tolerance_secs: u64) -> bool {
        now_unix
            > self
                .expires_at_unix
                .saturating_add(clock_skew_tolerance_secs)
    }

    pub fn ttl_secs(&self) -> u64 {
        self.expires_at_unix.saturating_sub(self.issued_at_unix)
    }

    /// Constant-time equality check covering all fields, including secret
    /// fields (`nonce`, `relay_id`, `signature`).
    ///
    /// Do **not** use `==` (which is not available; `PartialEq` is not
    /// derived) for auth-path comparisons.
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq;
        let nonce_eq: bool = self.nonce.ct_eq(&other.nonce).into();
        let sig_eq: bool = self.signature.ct_eq(&other.signature).into();
        let relay_eq: bool = self.relay_id.ct_eq(&other.relay_id).into();
        let node_eq: bool = self
            .node_id
            .as_bytes()
            .ct_eq(other.node_id.as_bytes())
            .into();
        let peer_eq: bool = self
            .peer_node_id
            .as_bytes()
            .ct_eq(other.peer_node_id.as_bytes())
            .into();
        let scope_eq: bool = self.scope.as_bytes().ct_eq(other.scope.as_bytes()).into();
        let issued_eq = self.issued_at_unix == other.issued_at_unix;
        let expires_eq = self.expires_at_unix == other.expires_at_unix;
        nonce_eq & sig_eq & relay_eq & node_eq & peer_eq & scope_eq & issued_eq & expires_eq
    }
}

pub fn relay_session_token_to_wire(token: &RelaySessionToken) -> String {
    format!(
        "{}signature={}\n",
        token.canonical_payload(),
        hex_bytes(&token.signature)
    )
}

pub fn parse_relay_session_token_wire(wire: &str) -> Result<RelaySessionToken, ControlPlaneError> {
    if wire.trim().is_empty() {
        return Err(ControlPlaneError::Traversal(
            "relay session token wire is empty".to_owned(),
        ));
    }

    let mut payload = String::new();
    let mut fields = BTreeMap::new();
    let mut seen_keys = BTreeSet::new();
    let mut signature_hex: Option<String> = None;

    for line in wire.lines() {
        if signature_hex.is_some() {
            return Err(ControlPlaneError::Traversal(
                "relay session token signature must be the final line".to_owned(),
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "relay session token line missing key/value separator".to_owned(),
            ));
        };
        if !is_allowed_relay_session_token_key(key) {
            return Err(ControlPlaneError::Traversal(format!(
                "relay session token key is not allowed: {key}"
            )));
        }
        if key == "signature" {
            let value = value.trim();
            if value.is_empty() {
                return Err(ControlPlaneError::Traversal(
                    "relay session token signature must not be empty".to_owned(),
                ));
            }
            signature_hex = Some(value.to_owned());
            continue;
        }
        if !seen_keys.insert(key.to_owned()) {
            return Err(ControlPlaneError::Traversal(format!(
                "relay session token duplicate key: {key}"
            )));
        }
        fields.insert(key.to_owned(), value.to_owned());
        payload.push_str(line);
        payload.push('\n');
    }

    let signature_hex = signature_hex.ok_or_else(|| {
        ControlPlaneError::Traversal("relay session token missing signature".to_owned())
    })?;
    let version = required_relay_token_field(&fields, "version")?;
    if version != "1" {
        return Err(ControlPlaneError::Traversal(
            "relay session token version must be 1".to_owned(),
        ));
    }
    let scope = required_relay_token_field(&fields, "scope")?;
    if scope != RELAY_TOKEN_SCOPE {
        return Err(ControlPlaneError::Traversal(
            "relay session token scope is invalid".to_owned(),
        ));
    }
    let node_id = required_relay_token_field(&fields, "node_id")?.to_owned();
    let peer_node_id = required_relay_token_field(&fields, "peer_node_id")?.to_owned();
    if node_id.is_empty() || peer_node_id.is_empty() {
        return Err(ControlPlaneError::Traversal(
            "relay session token node ids must not be empty".to_owned(),
        ));
    }
    if node_id == peer_node_id {
        return Err(ControlPlaneError::Traversal(
            "relay session token requires distinct node and peer".to_owned(),
        ));
    }

    let relay_id = decode_hex_to_fixed::<16>(required_relay_token_field(&fields, "relay_id")?)
        .map_err(|_| ControlPlaneError::Traversal("relay session token relay_id invalid".into()))?;
    let nonce = decode_hex_to_fixed::<16>(required_relay_token_field(&fields, "nonce")?)
        .map_err(|_| ControlPlaneError::Traversal("relay session token nonce invalid".into()))?;
    if nonce == [0u8; 16] {
        return Err(ControlPlaneError::Traversal(
            "relay session token nonce must not be all zero".to_owned(),
        ));
    }
    let signature = decode_hex_to_fixed::<64>(&signature_hex).map_err(|_| {
        ControlPlaneError::Traversal("relay session token signature invalid".to_owned())
    })?;
    let issued_at_unix =
        parse_relay_token_u64(required_relay_token_field(&fields, "issued_at_unix")?)?;
    let expires_at_unix =
        parse_relay_token_u64(required_relay_token_field(&fields, "expires_at_unix")?)?;
    if issued_at_unix == 0 || expires_at_unix <= issued_at_unix {
        return Err(ControlPlaneError::Traversal(
            "relay session token timestamps are invalid".to_owned(),
        ));
    }

    let token = RelaySessionToken {
        node_id,
        peer_node_id,
        relay_id,
        scope: scope.to_owned(),
        issued_at_unix,
        expires_at_unix,
        nonce,
        signature,
    };
    if token.ttl_secs() > MAX_RELAY_SESSION_TOKEN_TTL_SECS {
        return Err(ControlPlaneError::Traversal(format!(
            "relay session token ttl exceeds max supported value ({MAX_RELAY_SESSION_TOKEN_TTL_SECS})"
        )));
    }
    if token.canonical_payload() != payload {
        return Err(ControlPlaneError::Traversal(
            "relay session token payload is not canonical".to_owned(),
        ));
    }
    Ok(token)
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
    pub capabilities: Vec<RoleCapability>,
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
    pub endpoint_hint_verifying_key: [u8; 32],
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
            capabilities: vec![RoleCapability::Client],
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
            // Fail-closed on CSPRNG unavailability: a predictable token nonce
            // would collapse the per-token uniqueness invariant on which the
            // replay store relies.
            nonce: try_random_nonce_hex(16).map_err(|_| ControlPlaneError::Internal)?,
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
            capabilities: vec![RoleCapability::Client],
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
            // Fail-closed on CSPRNG unavailability: see analogous comment in
            // `enroll_with_throwaway`.
            nonce: try_random_nonce_hex(16).map_err(|_| ControlPlaneError::Internal)?,
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
        // NOTE: peer-map's wire format is `node_id|hostname|os|owner|last_seen|pubkey\n`
        // line records — there is no `version=N` line to gate on.  A version
        // prefix would be a wire-format change that breaks compatibility with
        // existing peer maps and is tracked as a separate followup.  Until
        // that wire bump, this verifier relies on signature verification and
        // the controlled construction path (`signed_peer_map`) to enforce
        // the format.  Do NOT add a `payload_field_matches` gate here without
        // a coordinated wire-format change.
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
                "auto-tunnel ttl must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs > 24 * 60 * 60 {
            return Err(ControlPlaneError::Assignment(
                "auto-tunnel ttl exceeds max supported value".to_owned(),
            ));
        }
        if !is_valid_ipv4_or_ipv6_cidr(&request.mesh_cidr) {
            return Err(ControlPlaneError::Assignment(
                "mesh cidr is invalid".to_owned(),
            ));
        }

        let target = self.nodes.get(&request.node_id)?.ok_or_else(|| {
            ControlPlaneError::Assignment("requested node does not exist".to_owned())
        })?;
        validate_assignment_node_capabilities(&target)?;
        if target.endpoint.parse::<SocketAddr>().is_err() {
            return Err(ControlPlaneError::Assignment(
                "requested node endpoint is invalid".to_owned(),
            ));
        }
        if !request.lan_routes.is_empty() && request.exit_node_id.is_none() {
            return Err(ControlPlaneError::Assignment(
                "lan routes require an explicit exit node".to_owned(),
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
                ControlPlaneError::Assignment("requested node assignment is unavailable".to_owned())
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
            validate_assignment_node_capabilities(peer)?;
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

        let mut signed_exit_node_id = None;
        let mut signed_exit_capabilities = Vec::new();
        if let Some(exit_node_id) = request.exit_node_id.as_deref() {
            let exit_node = self.nodes.get(exit_node_id)?.ok_or_else(|| {
                ControlPlaneError::Assignment("exit node does not exist".to_owned())
            })?;
            validate_assignment_exit_provider(&exit_node)?;
            validate_assignment_exit_client(&target)?;
            if !self.policy_allows_node_pair(&target, &exit_node) {
                return Err(ControlPlaneError::Assignment(
                    "exit node denied by policy".to_owned(),
                ));
            }
            signed_exit_node_id = Some(exit_node.node_id.clone());
            signed_exit_capabilities = exit_node.capabilities.clone();
            bundle_routes.push(AutoTunnelRoute {
                destination_cidr: "0.0.0.0/0".to_owned(),
                via_node: exit_node.node_id.clone(),
                kind: AutoTunnelRouteKind::ExitNodeDefault,
            });
            for cidr in &request.lan_routes {
                if !is_valid_ipv4_or_ipv6_cidr(cidr) {
                    return Err(ControlPlaneError::Assignment(
                        "lan route cidr is invalid".to_owned(),
                    ));
                }
                if is_default_route_cidr(cidr) {
                    return Err(ControlPlaneError::Assignment(
                        "lan route cidr must not be a default route".to_owned(),
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
                capabilities: peer.capabilities,
                endpoint: peer.endpoint,
                public_key: peer.public_key,
                allowed_ips,
            });
        }

        let payload = serialize_auto_tunnel_payload(
            &AutoTunnelPayloadHeader {
                node_id: &target.node_id,
                node_capabilities: &target.capabilities,
                mesh_cidr: &request.mesh_cidr,
                assigned_cidr: &target_cidr,
                exit_node_id: signed_exit_node_id.as_deref(),
                exit_node_capabilities: &signed_exit_capabilities,
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
            .ok_or_else(|| ControlPlaneError::Dns("subject node does not exist".to_owned()))?;

        let mut peers = self.nodes.list()?;
        peers.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let tunnel_assignments =
            Self::deterministic_tunnel_assignments(peers.iter().map(|peer| peer.node_id.as_str()))?;

        let mut canonical_records = Vec::with_capacity(request.records.len());

        for record in request.records {
            let target = self
                .nodes
                .get(&record.target_node_id)?
                .ok_or_else(|| ControlPlaneError::Dns("target node does not exist".to_owned()))?;
            if target.node_id != subject.node_id && !self.policy_allows_node_pair(&subject, &target)
            {
                return Err(ControlPlaneError::Dns(
                    "dns record target denied by policy".to_owned(),
                ));
            }

            let expected_cidr =
                tunnel_assignments
                    .get(target.node_id.as_str())
                    .ok_or_else(|| {
                        ControlPlaneError::Dns("target node assignment is unavailable".to_owned())
                    })?;
            let expected_ip = host_ip_from_host_cidr(expected_cidr.as_str()).ok_or_else(|| {
                ControlPlaneError::Dns("target node assignment must be a host cidr".to_owned())
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
                "endpoint hint ttl must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs > 86400 {
            return Err(ControlPlaneError::Traversal(
                "endpoint hint ttl exceeds max supported value".to_owned(),
            ));
        }
        if request.generated_at_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "generated_at_unix must be greater than zero".to_owned(),
            ));
        }
        if request.candidates.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints require at least one candidate".to_owned(),
            ));
        }
        if request.candidates.len() > 8 {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints exceed max candidate count".to_owned(),
            ));
        }
        if !is_valid_node_id_text(request.source_node_id.as_str()) {
            return Err(ControlPlaneError::Traversal(
                "endpoint hint source_node_id must not be empty".to_owned(),
            ));
        }
        if !is_valid_node_id_text(request.target_node_id.as_str()) {
            return Err(ControlPlaneError::Traversal(
                "endpoint hint target_node_id must not be empty".to_owned(),
            ));
        }
        if request.source_node_id.trim() == request.target_node_id.trim() {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints require distinct source and target".to_owned(),
            ));
        }

        let source = self
            .nodes
            .get(&request.source_node_id)?
            .ok_or_else(|| ControlPlaneError::Traversal("source node does not exist".to_owned()))?;
        let target = self
            .nodes
            .get(&request.target_node_id)?
            .ok_or_else(|| ControlPlaneError::Traversal("target node does not exist".to_owned()))?;
        if !self.policy_allows_node_pair(&source, &target) {
            return Err(ControlPlaneError::Traversal(
                "endpoint hints denied by policy".to_owned(),
            ));
        }

        let expires_at_unix = request.generated_at_unix.saturating_add(request.ttl_secs);
        if request.generated_at_unix >= expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "invalid generated/expires ordering".to_owned(),
            ));
        }

        let mut seen_candidates = HashSet::new();
        for candidate in &request.candidates {
            let endpoint = candidate.endpoint.parse::<SocketAddr>().map_err(|_| {
                ControlPlaneError::Traversal("candidate endpoint is invalid".to_owned())
            })?;
            if endpoint.port() == 0 {
                return Err(ControlPlaneError::Traversal(
                    "candidate endpoint port must be non-zero".to_owned(),
                ));
            }
            if matches!(candidate.candidate_type, EndpointHintCandidateType::Relay) {
                let relay_id = candidate.relay_id.as_deref().unwrap_or("").trim();
                if relay_id.is_empty() {
                    return Err(ControlPlaneError::Traversal(
                        "relay candidates require relay_id".to_owned(),
                    ));
                }
                canonical_relay_id_from_label(relay_id).map_err(ControlPlaneError::Traversal)?;
            } else if candidate.relay_id.is_some() {
                return Err(ControlPlaneError::Traversal(
                    "relay_id is only valid for relay candidates".to_owned(),
                ));
            }

            let relay_key = candidate
                .relay_id
                .as_deref()
                .unwrap_or("")
                .trim()
                .to_owned();
            let uniqueness = format!(
                "{}|{}|{}",
                candidate.candidate_type.as_str(),
                endpoint,
                relay_key
            );
            if !seen_candidates.insert(uniqueness) {
                return Err(ControlPlaneError::Traversal(
                    "duplicate endpoint hint candidate".to_owned(),
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

    pub fn signed_relay_fleet_bundle(
        &self,
        request: RelayFleetBundleRequest,
    ) -> Result<SignedRelayFleetBundle, ControlPlaneError> {
        if request.generated_at_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "relay fleet generated_at_unix must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs == 0 {
            return Err(ControlPlaneError::Traversal(
                "relay fleet ttl must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs > 300 {
            return Err(ControlPlaneError::Traversal(
                "relay fleet ttl exceeds max supported value".to_owned(),
            ));
        }
        if request.nonce == 0 {
            return Err(ControlPlaneError::Traversal(
                "relay fleet nonce must be greater than zero".to_owned(),
            ));
        }
        if request.relays.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "relay fleet requires at least one relay".to_owned(),
            ));
        }
        if request.relays.len() > 64 {
            return Err(ControlPlaneError::Traversal(
                "relay fleet exceeds max relay count".to_owned(),
            ));
        }
        let expires_at_unix = request.generated_at_unix.saturating_add(request.ttl_secs);
        if request.generated_at_unix >= expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "relay fleet invalid generated/expires ordering".to_owned(),
            ));
        }

        let mut seen_relay_ids = HashSet::new();
        let mut seen_endpoints = HashSet::new();
        for relay in &request.relays {
            validate_relay_fleet_node_descriptor(relay)?;
            let relay_id = relay.relay_id.trim().to_owned();
            if !seen_relay_ids.insert(relay_id) {
                return Err(ControlPlaneError::Traversal(
                    "duplicate relay fleet relay_id".to_owned(),
                ));
            }
            let endpoint = relay.endpoint.parse::<SocketAddr>().map_err(|_| {
                ControlPlaneError::Traversal("relay fleet endpoint is invalid".to_owned())
            })?;
            if !seen_endpoints.insert(endpoint) {
                return Err(ControlPlaneError::Traversal(
                    "duplicate relay fleet endpoint".to_owned(),
                ));
            }
        }

        let payload = serialize_relay_fleet_payload(
            request.generated_at_unix,
            expires_at_unix,
            request.nonce,
            &request.relays,
        )?;
        let signature = self.endpoint_hint_signing_key.sign(payload.as_bytes());
        Ok(SignedRelayFleetBundle {
            payload,
            signature_hex: hex_bytes(&signature.to_bytes()),
            generated_at_unix: request.generated_at_unix,
            expires_at_unix,
            nonce: request.nonce,
            relay_count: request.relays.len(),
            relays: sorted_relay_fleet_descriptors(&request.relays),
        })
    }

    pub fn issue_relay_session_token(
        &self,
        request: RelaySessionTokenRequest,
    ) -> Result<RelaySessionToken, ControlPlaneError> {
        if request.requested_at_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "relay token requested_at_unix must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs == 0 {
            return Err(ControlPlaneError::Traversal(
                "relay token ttl must be greater than zero".to_owned(),
            ));
        }
        if request.ttl_secs > MAX_RELAY_SESSION_TOKEN_TTL_SECS {
            return Err(ControlPlaneError::Traversal(format!(
                "relay token ttl exceeds max supported value ({MAX_RELAY_SESSION_TOKEN_TTL_SECS})"
            )));
        }
        if request.node_id == request.peer_node_id {
            return Err(ControlPlaneError::Traversal(
                "relay token requires distinct node and peer".to_owned(),
            ));
        }
        let relay_id = canonical_relay_id_from_label(&request.relay_id)
            .map_err(ControlPlaneError::Traversal)?;

        let source = self.nodes.get(&request.node_id)?.ok_or_else(|| {
            ControlPlaneError::Traversal("relay token source node does not exist".to_owned())
        })?;
        let target = self.nodes.get(&request.peer_node_id)?.ok_or_else(|| {
            ControlPlaneError::Traversal("relay token peer node does not exist".to_owned())
        })?;
        if !self.policy_allows_node_pair(&source, &target) {
            return Err(ControlPlaneError::Traversal(
                "relay token denied by policy".to_owned(),
            ));
        }

        Ok(RelaySessionToken::sign_at(
            &self.endpoint_hint_signing_key,
            request.node_id.as_str(),
            request.peer_node_id.as_str(),
            relay_id,
            request.requested_at_unix,
            request.ttl_secs,
        ))
    }

    pub fn signed_traversal_coordination_record(
        &self,
        record: TraversalCoordinationRecord,
    ) -> Result<SignedTraversalCoordinationRecord, ControlPlaneError> {
        if record.issued_at_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "coordination issued_at_unix must be greater than zero".to_owned(),
            ));
        }
        if record.probe_start_unix == 0 {
            return Err(ControlPlaneError::Traversal(
                "coordination probe_start_unix must be greater than zero".to_owned(),
            ));
        }
        if record.issued_at_unix >= record.expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "coordination expires_at_unix must be greater than issued_at_unix".to_owned(),
            ));
        }
        if record.expires_at_unix.saturating_sub(record.issued_at_unix) > 86400 {
            return Err(ControlPlaneError::Traversal(
                "coordination ttl exceeds max supported value".to_owned(),
            ));
        }
        if record.probe_start_unix > record.expires_at_unix {
            return Err(ControlPlaneError::Traversal(
                "coordination probe_start_unix must not exceed expires_at_unix".to_owned(),
            ));
        }
        if record.node_a.trim() == record.node_b.trim() {
            return Err(ControlPlaneError::Traversal(
                "coordination requires distinct node_a and node_b".to_owned(),
            ));
        }
        if !is_valid_node_id_text(record.node_a.as_str()) {
            return Err(ControlPlaneError::Traversal(
                "coordination node_a must not be empty".to_owned(),
            ));
        }
        if !is_valid_node_id_text(record.node_b.as_str()) {
            return Err(ControlPlaneError::Traversal(
                "coordination node_b must not be empty".to_owned(),
            ));
        }

        if record.session_id.iter().all(|value| *value == 0) {
            return Err(ControlPlaneError::Traversal(
                "coordination session_id must not be all zeros".to_owned(),
            ));
        }
        if record.nonce.iter().all(|value| *value == 0) {
            return Err(ControlPlaneError::Traversal(
                "coordination nonce must not be all zeros".to_owned(),
            ));
        }

        let node_a = self.nodes.get(record.node_a.as_str())?.ok_or_else(|| {
            ControlPlaneError::Traversal("coordination node_a does not exist".to_owned())
        })?;
        let node_b = self.nodes.get(record.node_b.as_str())?.ok_or_else(|| {
            ControlPlaneError::Traversal("coordination node_b does not exist".to_owned())
        })?;
        if !self.policy_allows_node_pair(&node_a, &node_b) {
            return Err(ControlPlaneError::Traversal(
                "coordination denied by policy".to_owned(),
            ));
        }

        let payload = serialize_traversal_coordination_payload(&record)?;
        let signature = self.endpoint_hint_signing_key.sign(payload.as_bytes());
        Ok(SignedTraversalCoordinationRecord {
            payload,
            signature_hex: hex_bytes(&signature.to_bytes()),
            session_id: record.session_id,
            probe_start_unix: record.probe_start_unix,
            node_a: record.node_a,
            node_b: record.node_b,
            issued_at_unix: record.issued_at_unix,
            expires_at_unix: record.expires_at_unix,
            nonce: record.nonce,
        })
    }

    pub fn verify_signed_endpoint_hint_bundle(&self, bundle: &SignedEndpointHintBundle) -> bool {
        if bundle.generated_at_unix == 0 {
            return false;
        }
        if bundle.generated_at_unix >= bundle.expires_at_unix {
            return false;
        }
        if bundle
            .expires_at_unix
            .saturating_sub(bundle.generated_at_unix)
            > 86400
        {
            return false;
        }
        if !is_valid_node_id_text(bundle.source_node_id.as_str())
            || !is_valid_node_id_text(bundle.target_node_id.as_str())
        {
            return false;
        }
        if bundle.source_node_id.trim() == bundle.target_node_id.trim() {
            return false;
        }
        // Reject any payload that does not declare the only currently
        // supported wire version.  Without this, a future version=2
        // bundle signed by the same key could silently verify against
        // this verifier and a v1-only consumer could parse the v2 bytes
        // under v1 assumptions.  Same vulnerability class as the outer-
        // vs-payload mismatches handled below.
        if !endpoint_hint_payload_field_matches(&bundle.payload, "version", "1") {
            return false;
        }
        // Cross-check that the outer struct fields a downstream consumer
        // might trust actually match the bytes that were signed.  Without
        // this, an attacker (or buggy emitter) could pair a valid signed
        // payload for `node-a -> node-b` with an outer struct claiming
        // `node-evil -> node-victim` and the verifier would still return
        // true.
        if !endpoint_hint_payload_field_matches(
            &bundle.payload,
            "source_node_id",
            bundle.source_node_id.trim(),
        ) {
            return false;
        }
        if !endpoint_hint_payload_field_matches(
            &bundle.payload,
            "target_node_id",
            bundle.target_node_id.trim(),
        ) {
            return false;
        }
        if !endpoint_hint_payload_field_matches(
            &bundle.payload,
            "generated_at_unix",
            &bundle.generated_at_unix.to_string(),
        ) {
            return false;
        }
        if !endpoint_hint_payload_field_matches(
            &bundle.payload,
            "expires_at_unix",
            &bundle.expires_at_unix.to_string(),
        ) {
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

    pub fn verify_signed_traversal_coordination_record(
        &self,
        record: &SignedTraversalCoordinationRecord,
    ) -> bool {
        if record.issued_at_unix >= record.expires_at_unix {
            return false;
        }
        if record.expires_at_unix.saturating_sub(record.issued_at_unix) > 86400 {
            return false;
        }
        if record.probe_start_unix > record.expires_at_unix {
            return false;
        }
        if record.node_a.trim() == record.node_b.trim() {
            return false;
        }
        if !is_valid_node_id_text(record.node_a.as_str())
            || !is_valid_node_id_text(record.node_b.as_str())
        {
            return false;
        }
        if record.session_id.iter().all(|value| *value == 0) {
            return false;
        }
        if record.nonce.iter().all(|value| *value == 0) {
            return false;
        }
        // Explicit version gate.  The canonical-payload comparison below
        // already enforces version=1 implicitly (the canonical builder
        // always emits version=1), but pinning the contract here keeps
        // the gate visible and prevents a future regression that allows
        // alternative canonical forms from silently accepting a payload
        // signed under a different version assumption.
        if !endpoint_hint_payload_field_matches(&record.payload, "version", "1") {
            return false;
        }

        let expected_payload =
            match serialize_traversal_coordination_payload(&TraversalCoordinationRecord {
                session_id: record.session_id,
                probe_start_unix: record.probe_start_unix,
                node_a: record.node_a.clone(),
                node_b: record.node_b.clone(),
                issued_at_unix: record.issued_at_unix,
                expires_at_unix: record.expires_at_unix,
                nonce: record.nonce,
            }) {
                Ok(payload) => payload,
                Err(_) => return false,
            };
        if expected_payload != record.payload {
            return false;
        }

        let signature_bytes = match decode_hex_to_fixed::<64>(&record.signature_hex) {
            Ok(bytes) => bytes,
            Err(()) => return false,
        };
        let signature = Signature::from_bytes(&signature_bytes);
        let verifying_key = match VerifyingKey::from_bytes(&self.endpoint_hint_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verifying_key
            .verify(record.payload.as_bytes(), &signature)
            .is_ok()
    }

    pub fn verify_signed_relay_fleet_bundle(&self, bundle: &SignedRelayFleetBundle) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.endpoint_hint_verifying_key) {
            Ok(key) => key,
            Err(_) => return false,
        };
        verify_signed_relay_fleet_bundle_with_key(bundle, &verifying_key)
    }

    pub fn signed_endpoint_hint_bundle_to_wire(bundle: &SignedEndpointHintBundle) -> String {
        format!("{}signature={}\n", bundle.payload, bundle.signature_hex)
    }

    pub fn signed_relay_fleet_bundle_to_wire(bundle: &SignedRelayFleetBundle) -> String {
        format!("{}signature={}\n", bundle.payload, bundle.signature_hex)
    }

    pub fn verify_signed_dns_zone_bundle(&self, bundle: &SignedDnsZoneBundle) -> bool {
        // Reject any payload that does not declare the only currently
        // supported wire version.  The dns-zone wire parser already
        // gates version=1, but a `SignedDnsZoneBundle` value can be
        // constructed without going through the wire parser (e.g. via
        // the builder or a deserializer), so the verifier itself must
        // enforce the version explicitly.
        if !endpoint_hint_payload_field_matches(&bundle.payload, "version", "1") {
            return false;
        }
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
        // Reject any payload that does not declare the only currently
        // supported wire version.  Without this, a future version=2
        // bundle signed by the same key could silently verify and a
        // v1-only consumer could parse the v2 bytes under v1 assumptions.
        if !auto_tunnel_payload_field_matches(&bundle.payload, "version", "1") {
            return false;
        }
        // Cross-check that the outer struct fields a downstream consumer
        // might trust actually match the bytes that were signed.  Without
        // this, an attacker (or buggy emitter) could pair a valid signed
        // payload for `node-a` with an outer struct claiming `node-evil`
        // and the verifier would still return true.  The endpoint-hint
        // verifier applies the same pattern.
        if !auto_tunnel_payload_field_matches(&bundle.payload, "node_id", bundle.node_id.as_str()) {
            return false;
        }
        if !auto_tunnel_payload_field_matches(
            &bundle.payload,
            "generated_at_unix",
            &bundle.generated_at_unix.to_string(),
        ) {
            return false;
        }
        if !auto_tunnel_payload_field_matches(
            &bundle.payload,
            "expires_at_unix",
            &bundle.expires_at_unix.to_string(),
        ) {
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
                "no available tunnel cidr assignment remains".to_owned(),
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
                        "no available tunnel cidr assignment remains".to_owned(),
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

/// Derive the traversal endpoint-hint signing key from the control-plane
/// signing secret.
///
/// Relay session tokens are bound to the same verifier as traversal hints, so
/// runtime code can use this helper to issue relay tokens that verify against
/// the pinned traversal verifier key.
pub fn derive_endpoint_hint_signing_key(mut signing_secret: Vec<u8>) -> SigningKey {
    let mut seed = derive_signing_seed(ENDPOINT_HINT_SIGNING_SEED_INFO_V1, &signing_secret);
    signing_secret.zeroize();
    let signing_key = SigningKey::from_bytes(&seed);
    seed.zeroize();
    signing_key
}

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

/// Fallible nonce minter for control-plane tokens.
///
/// Control-plane nonces gate token replay protection (the issued access-token
/// nonce is unique-by-construction over the token lifetime). A CSPRNG failure
/// during enrollment must NOT panic the control-plane process — that would
/// take down the entire enrollment surface — and must NOT degrade to a
/// predictable nonce — that would collapse token uniqueness. We surface a
/// structured error so callers translate to `ControlPlaneError::Internal` and
/// the operator can retry once the CSPRNG recovers.
fn try_random_nonce_hex(length_bytes: usize) -> Result<String, ControlPlaneNonceMintError> {
    let mut nonce = vec![0u8; length_bytes];
    rand::rngs::OsRng
        .try_fill_bytes(nonce.as_mut_slice())
        .map_err(|err| ControlPlaneNonceMintError {
            source: err.to_string(),
        })?;
    let encoded = hex_bytes(nonce.as_slice());
    nonce.zeroize();
    Ok(encoded)
}

/// Error surfaced by [`try_random_nonce_hex`] when the kernel CSPRNG cannot
/// fill the nonce buffer.
#[derive(Debug)]
pub struct ControlPlaneNonceMintError {
    pub source: String,
}

impl fmt::Display for ControlPlaneNonceMintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "kernel CSPRNG unavailable while minting control-plane nonce: {}",
            self.source
        )
    }
}

impl std::error::Error for ControlPlaneNonceMintError {}

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

fn is_allowed_relay_session_token_key(key: &str) -> bool {
    matches!(
        key,
        "version"
            | "node_id"
            | "peer_node_id"
            | "relay_id"
            | "scope"
            | "issued_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "signature"
    )
}

fn required_relay_token_field<'a>(
    fields: &'a BTreeMap<String, String>,
    key: &str,
) -> Result<&'a str, ControlPlaneError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| ControlPlaneError::Traversal(format!("relay session token missing {key}")))
}

fn parse_relay_token_u64(value: &str) -> Result<u64, ControlPlaneError> {
    value.parse::<u64>().map_err(|_| {
        ControlPlaneError::Traversal("relay session token timestamp is invalid".to_owned())
    })
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

fn is_valid_node_id_text(value: &str) -> bool {
    !value.trim().is_empty()
}

fn validate_assignment_node_capabilities(node: &NodeMetadata) -> Result<(), ControlPlaneError> {
    if node.capabilities.is_empty() {
        return Err(ControlPlaneError::Assignment(format!(
            "node {} has no role capabilities",
            node.node_id
        )));
    }
    Ok(())
}

fn validate_assignment_exit_client(node: &NodeMetadata) -> Result<(), ControlPlaneError> {
    if node.capabilities.contains(&RoleCapability::BlindExit) {
        return Err(ControlPlaneError::Assignment(format!(
            "node {} with blind_exit capability cannot consume exit traffic",
            node.node_id
        )));
    }
    if !node.capabilities.contains(&RoleCapability::Client)
        && !node.capabilities.contains(&RoleCapability::Anchor)
    {
        return Err(ControlPlaneError::Assignment(format!(
            "node {} must carry client or anchor capability to consume exit traffic",
            node.node_id
        )));
    }
    Ok(())
}

fn validate_assignment_exit_provider(node: &NodeMetadata) -> Result<(), ControlPlaneError> {
    validate_assignment_node_capabilities(node)?;
    if !node.capabilities.contains(&RoleCapability::ExitServer) {
        return Err(ControlPlaneError::Assignment(format!(
            "exit node {} lacks exit_server capability",
            node.node_id
        )));
    }
    Ok(())
}

fn is_default_route_cidr(cidr: &str) -> bool {
    matches!(cidr.trim(), "0.0.0.0/0" | "::/0")
}

struct AutoTunnelPayloadHeader<'a> {
    node_id: &'a str,
    node_capabilities: &'a [RoleCapability],
    mesh_cidr: &'a str,
    assigned_cidr: &'a str,
    exit_node_id: Option<&'a str>,
    exit_node_capabilities: &'a [RoleCapability],
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
    payload.push_str(&format!(
        "node_capabilities={}\n",
        role_capability_csv(header.node_capabilities)
    ));
    payload.push_str(&format!("mesh_cidr={}\n", header.mesh_cidr));
    payload.push_str(&format!("assigned_cidr={}\n", header.assigned_cidr));
    payload.push_str(&format!(
        "exit_node_id={}\n",
        header.exit_node_id.unwrap_or("")
    ));
    payload.push_str(&format!(
        "exit_node_capabilities={}\n",
        role_capability_csv(header.exit_node_capabilities)
    ));
    payload.push_str("traffic_route_policy=mesh_or_relay_or_exit_node\n");
    payload.push_str(&format!("generated_at_unix={}\n", header.generated_at_unix));
    payload.push_str(&format!("expires_at_unix={}\n", header.expires_at_unix));
    payload.push_str(&format!("nonce={}\n", header.nonce));
    payload.push_str(&format!("peer_count={}\n", peers.len()));
    for (index, peer) in peers.iter().enumerate() {
        payload.push_str(&format!("peer.{index}.node_id={}\n", peer.node_id));
        payload.push_str(&format!(
            "peer.{index}.capabilities={}\n",
            role_capability_csv(&peer.capabilities)
        ));
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

/// Look up the first occurrence of `key=` in an auto-tunnel payload and
/// confirm the value matches `expected`.  Returns `false` if the key is
/// absent or the value differs.  Used by the verifier to cross-check outer
/// struct fields (`node_id`, `generated_at_unix`, `expires_at_unix`)
/// against the signed payload bytes; without this, an attacker holding a
/// valid signed bundle could re-frame the outer struct and the verifier
/// would still return true.
fn auto_tunnel_payload_field_matches(payload: &str, key: &str, expected: &str) -> bool {
    for line in payload.lines() {
        let Some((line_key, line_value)) = line.split_once('=') else {
            continue;
        };
        if line_key == key {
            return line_value == expected;
        }
    }
    false
}

fn host_ip_from_host_cidr(value: &str) -> Option<String> {
    let (ip, prefix) = value.split_once('/')?;
    if prefix != "32" && prefix != "128" {
        return None;
    }
    Some(ip.to_owned())
}

/// Look up the first occurrence of `key=` in an endpoint-hint payload and
/// confirm the value matches `expected`.  Returns `false` if the key is
/// absent or the value differs.  Used by the verifier to cross-check outer
/// struct fields against the signed payload bytes.
fn endpoint_hint_payload_field_matches(payload: &str, key: &str, expected: &str) -> bool {
    for line in payload.lines() {
        let Some((line_key, line_value)) = line.split_once('=') else {
            continue;
        };
        if line_key == key {
            return line_value == expected;
        }
    }
    false
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
                "candidate endpoint failed canonical serialization".to_owned(),
            )
        })?;
        if endpoint.port() == 0 {
            return Err(ControlPlaneError::Traversal(
                "candidate endpoint port must be non-zero".to_owned(),
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
                    "relay candidates require relay_id".to_owned(),
                ));
            }
            canonical_relay_id_from_label(relay_id).map_err(ControlPlaneError::Traversal)?;
        } else if !relay_id.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "relay_id is only valid for relay candidates".to_owned(),
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

fn validate_relay_fleet_node_descriptor(
    relay: &RelayFleetNodeDescriptor,
) -> Result<(), ControlPlaneError> {
    let relay_id = relay.relay_id.trim();
    if !is_single_line_payload_value(relay_id) {
        return Err(ControlPlaneError::Traversal(
            "relay fleet relay_id must be a single-line payload value".to_owned(),
        ));
    }
    canonical_relay_id_from_label(relay_id).map_err(ControlPlaneError::Traversal)?;
    let region = relay.region.trim();
    if region.is_empty() {
        return Err(ControlPlaneError::Traversal(
            "relay fleet region must not be empty".to_owned(),
        ));
    }
    if !region.is_ascii() || region.len() > 64 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet region must be bounded ASCII".to_owned(),
        ));
    }
    if !is_single_line_payload_value(region) {
        return Err(ControlPlaneError::Traversal(
            "relay fleet region must be a single-line payload value".to_owned(),
        ));
    }
    let endpoint = relay
        .endpoint
        .parse::<SocketAddr>()
        .map_err(|_| ControlPlaneError::Traversal("relay fleet endpoint is invalid".to_owned()))?;
    if endpoint.port() == 0 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet endpoint port must be non-zero".to_owned(),
        ));
    }
    if endpoint.ip().is_unspecified() || endpoint.ip().is_loopback() || endpoint.ip().is_multicast()
    {
        return Err(ControlPlaneError::Traversal(
            "relay fleet endpoint must not use special transport address".to_owned(),
        ));
    }
    if relay.capacity == 0 {
        return Err(ControlPlaneError::Traversal(
            "relay fleet capacity must be greater than zero".to_owned(),
        ));
    }
    Ok(())
}

fn is_single_line_payload_value(value: &str) -> bool {
    !value.is_empty()
        && !value
            .bytes()
            .any(|byte| matches!(byte, b'\n' | b'\r' | b'='))
}

fn sorted_relay_fleet_descriptors(
    relays: &[RelayFleetNodeDescriptor],
) -> Vec<RelayFleetNodeDescriptor> {
    let mut relays = relays.to_vec();
    relays.sort_by(|left, right| {
        left.relay_id
            .trim()
            .cmp(right.relay_id.trim())
            .then(left.endpoint.cmp(&right.endpoint))
    });
    relays
}

fn serialize_relay_fleet_payload(
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
    relays: &[RelayFleetNodeDescriptor],
) -> Result<String, ControlPlaneError> {
    let relays = sorted_relay_fleet_descriptors(relays);

    let mut payload = String::new();
    payload.push_str("version=1\n");
    payload.push_str(&format!("generated_at_unix={generated_at_unix}\n"));
    payload.push_str(&format!("expires_at_unix={expires_at_unix}\n"));
    payload.push_str(&format!("nonce={nonce}\n"));
    payload.push_str(&format!("relay_count={}\n", relays.len()));
    for (index, relay) in relays.iter().enumerate() {
        validate_relay_fleet_node_descriptor(relay)?;
        let endpoint = relay.endpoint.parse::<SocketAddr>().map_err(|_| {
            ControlPlaneError::Traversal("relay fleet endpoint is invalid".to_owned())
        })?;
        payload.push_str(&format!("relay.{index}.id={}\n", relay.relay_id.trim()));
        payload.push_str(&format!("relay.{index}.region={}\n", relay.region.trim()));
        payload.push_str(&format!("relay.{index}.addr={}\n", endpoint.ip()));
        payload.push_str(&format!("relay.{index}.port={}\n", endpoint.port()));
        payload.push_str(&format!("relay.{index}.priority={}\n", relay.priority));
        payload.push_str(&format!("relay.{index}.capacity={}\n", relay.capacity));
        payload.push_str(&format!("relay.{index}.enabled={}\n", relay.enabled));
    }
    Ok(payload)
}

fn split_signed_relay_fleet_wire(wire: &str) -> Result<(String, String), ControlPlaneError> {
    if wire.trim().is_empty() {
        return Err(ControlPlaneError::Traversal(
            "relay fleet bundle wire is empty".to_owned(),
        ));
    }
    let mut payload = String::new();
    let mut signature_hex: Option<String> = None;
    for line in wire.lines() {
        if signature_hex.is_some() {
            return Err(ControlPlaneError::Traversal(
                "relay fleet bundle signature must be the final line".to_owned(),
            ));
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "relay fleet bundle line missing key/value separator".to_owned(),
            ));
        };
        if key == "signature" {
            if value.trim().is_empty() {
                return Err(ControlPlaneError::Traversal(
                    "relay fleet bundle signature must not be empty".to_owned(),
                ));
            }
            signature_hex = Some(value.trim().to_owned());
        } else {
            payload.push_str(line);
            payload.push('\n');
        }
    }
    let signature_hex = signature_hex.ok_or_else(|| {
        ControlPlaneError::Traversal("relay fleet bundle missing signature".to_owned())
    })?;
    Ok((payload, signature_hex))
}

fn parse_relay_fleet_payload_fields(
    payload: &str,
) -> Result<BTreeMap<String, String>, ControlPlaneError> {
    let mut fields = BTreeMap::new();
    for line in payload.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(ControlPlaneError::Traversal(
                "relay fleet payload line missing key/value separator".to_owned(),
            ));
        };
        if key.is_empty() {
            return Err(ControlPlaneError::Traversal(
                "relay fleet payload key must not be empty".to_owned(),
            ));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(ControlPlaneError::Traversal(format!(
                "duplicate relay fleet payload key {key}"
            )));
        }
    }
    Ok(fields)
}

fn parse_relay_fleet_required_u64(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<u64, ControlPlaneError> {
    fields
        .get(key)
        .ok_or_else(|| ControlPlaneError::Traversal(format!("missing relay fleet field {key}")))?
        .parse::<u64>()
        .map_err(|_| ControlPlaneError::Traversal(format!("invalid relay fleet field {key}")))
}

fn parse_relay_fleet_required_usize(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<usize, ControlPlaneError> {
    fields
        .get(key)
        .ok_or_else(|| ControlPlaneError::Traversal(format!("missing relay fleet field {key}")))?
        .parse::<usize>()
        .map_err(|_| ControlPlaneError::Traversal(format!("invalid relay fleet field {key}")))
}

fn parse_relay_fleet_required_string(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<String, ControlPlaneError> {
    fields
        .get(key)
        .cloned()
        .ok_or_else(|| ControlPlaneError::Traversal(format!("missing relay fleet field {key}")))
}

fn parse_relay_fleet_required_bool(
    fields: &BTreeMap<String, String>,
    key: &str,
) -> Result<bool, ControlPlaneError> {
    match fields.get(key).map(String::as_str) {
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(ControlPlaneError::Traversal(format!(
            "invalid relay fleet field {key}"
        ))),
        None => Err(ControlPlaneError::Traversal(format!(
            "missing relay fleet field {key}"
        ))),
    }
}

fn parse_relay_fleet_descriptors(
    fields: &BTreeMap<String, String>,
    relay_count: usize,
) -> Result<Vec<RelayFleetNodeDescriptor>, ControlPlaneError> {
    let expected_global = [
        "version",
        "generated_at_unix",
        "expires_at_unix",
        "nonce",
        "relay_count",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    let mut expected_keys = expected_global;
    let mut relays = Vec::with_capacity(relay_count);
    for index in 0..relay_count {
        let id_key = format!("relay.{index}.id");
        let region_key = format!("relay.{index}.region");
        let addr_key = format!("relay.{index}.addr");
        let port_key = format!("relay.{index}.port");
        let priority_key = format!("relay.{index}.priority");
        let capacity_key = format!("relay.{index}.capacity");
        let enabled_key = format!("relay.{index}.enabled");
        for key in [
            &id_key,
            &region_key,
            &addr_key,
            &port_key,
            &priority_key,
            &capacity_key,
            &enabled_key,
        ] {
            expected_keys.insert((*key).clone());
        }
        let relay_id = parse_relay_fleet_required_string(fields, &id_key)?;
        let region = parse_relay_fleet_required_string(fields, &region_key)?;
        let addr = parse_relay_fleet_required_string(fields, &addr_key)?;
        let port = parse_relay_fleet_required_u64(fields, &port_key)?;
        let priority = parse_relay_fleet_required_u64(fields, &priority_key)?;
        let capacity = parse_relay_fleet_required_u64(fields, &capacity_key)?;
        let enabled = parse_relay_fleet_required_bool(fields, &enabled_key)?;
        let ip = addr
            .parse::<std::net::IpAddr>()
            .map_err(|_| ControlPlaneError::Traversal("invalid relay fleet address".to_owned()))?;
        let port = u16::try_from(port)
            .map_err(|_| ControlPlaneError::Traversal("invalid relay fleet port".to_owned()))?;
        let endpoint = SocketAddr::new(ip, port).to_string();
        let relay = RelayFleetNodeDescriptor {
            relay_id,
            region,
            endpoint,
            priority: u16::try_from(priority).map_err(|_| {
                ControlPlaneError::Traversal("invalid relay fleet priority".to_owned())
            })?,
            capacity: u32::try_from(capacity).map_err(|_| {
                ControlPlaneError::Traversal("invalid relay fleet capacity".to_owned())
            })?,
            enabled,
        };
        validate_relay_fleet_node_descriptor(&relay)?;
        relays.push(relay);
    }
    for key in fields.keys() {
        if !expected_keys.contains(key) {
            return Err(ControlPlaneError::Traversal(format!(
                "unknown relay fleet payload key {key}"
            )));
        }
    }
    validate_relay_fleet_descriptor_set(&relays)?;
    Ok(relays)
}

fn validate_relay_fleet_descriptor_set(
    relays: &[RelayFleetNodeDescriptor],
) -> Result<(), ControlPlaneError> {
    let mut seen_relay_ids = HashSet::new();
    let mut seen_endpoints = HashSet::new();
    for relay in relays {
        validate_relay_fleet_node_descriptor(relay)?;
        let relay_id = relay.relay_id.trim().to_owned();
        if !seen_relay_ids.insert(relay_id) {
            return Err(ControlPlaneError::Traversal(
                "duplicate relay fleet relay_id".to_owned(),
            ));
        }
        let endpoint = relay.endpoint.parse::<SocketAddr>().map_err(|_| {
            ControlPlaneError::Traversal("relay fleet endpoint is invalid".to_owned())
        })?;
        if !seen_endpoints.insert(endpoint) {
            return Err(ControlPlaneError::Traversal(
                "duplicate relay fleet endpoint".to_owned(),
            ));
        }
    }
    Ok(())
}

fn relay_fleet_payload_u64(payload: &str, key: &str) -> Option<u64> {
    payload.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
            .and_then(|value| value.parse::<u64>().ok())
    })
}

fn relay_fleet_payload_usize(payload: &str, key: &str) -> Option<usize> {
    payload.lines().find_map(|line| {
        line.strip_prefix(key)
            .and_then(|value| value.strip_prefix('='))
            .and_then(|value| value.parse::<usize>().ok())
    })
}

fn serialize_traversal_coordination_payload(
    record: &TraversalCoordinationRecord,
) -> Result<String, ControlPlaneError> {
    if !is_valid_node_id_text(record.node_a.as_str())
        || !is_valid_node_id_text(record.node_b.as_str())
    {
        return Err(ControlPlaneError::Traversal(
            "coordination node ids must not be empty".to_owned(),
        ));
    }
    if record.node_a.trim() == record.node_b.trim() {
        return Err(ControlPlaneError::Traversal(
            "coordination requires distinct nodes".to_owned(),
        ));
    }
    if record.issued_at_unix >= record.expires_at_unix {
        return Err(ControlPlaneError::Traversal(
            "coordination expires_at_unix must be greater than issued_at_unix".to_owned(),
        ));
    }
    if record.expires_at_unix.saturating_sub(record.issued_at_unix) > 86400 {
        return Err(ControlPlaneError::Traversal(
            "coordination ttl exceeds max supported value".to_owned(),
        ));
    }
    if record.probe_start_unix > record.expires_at_unix {
        return Err(ControlPlaneError::Traversal(
            "coordination probe_start_unix must not exceed expires_at_unix".to_owned(),
        ));
    }
    if record.session_id.iter().all(|value| *value == 0) {
        return Err(ControlPlaneError::Traversal(
            "coordination session_id must not be all zeros".to_owned(),
        ));
    }
    if record.nonce.iter().all(|value| *value == 0) {
        return Err(ControlPlaneError::Traversal(
            "coordination nonce must not be all zeros".to_owned(),
        ));
    }

    let mut payload = String::new();
    payload.push_str("version=1\n");
    payload.push_str("type=traversal_coordination\n");
    payload.push_str(&format!(
        "session_id={}\n",
        hex_bytes(record.session_id.as_slice())
    ));
    payload.push_str(&format!("probe_start_unix={}\n", record.probe_start_unix));
    payload.push_str(&format!("node_a={}\n", record.node_a.trim()));
    payload.push_str(&format!("node_b={}\n", record.node_b.trim()));
    payload.push_str(&format!("issued_at_unix={}\n", record.issued_at_unix));
    payload.push_str(&format!("expires_at_unix={}\n", record.expires_at_unix));
    payload.push_str(&format!("nonce={}\n", hex_bytes(record.nonce.as_slice())));
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
        EnrollmentRequest, LockoutConfig, MAX_RELAY_SESSION_TOKEN_TTL_SECS, PolicyCheckRequest,
        PolicyDecision, PolicyGuard, RELAY_TOKEN_SCOPE, RelayFleetBundleRequest,
        RelayFleetNodeDescriptor, RelaySessionToken, RelaySessionTokenRequest, ReplayPolicy,
        ReusableCredentialPolicy, ReusableCredentialRequest, RoleCapability,
        SignedAutoTunnelBundle, SignedDnsZoneBundleRequest, SignedTokenClaims,
        ThrowawayCredentialState, ThrowawayCredentialStore, TokenClaims, TransportPolicyError,
        TraversalCoordinationRecord, TrustState, auto_tunnel_payload_field_matches,
        canonical_relay_id_from_label, derive_endpoint_hint_signing_key, derive_signing_seed,
        hex_bytes, load_trust_state, parse_relay_session_token_wire,
        parse_signed_relay_fleet_bundle_wire, persist_trust_state, relay_session_token_to_wire,
    };
    use ed25519_dalek::SigningKey;
    use rustynet_crypto::{AlgorithmPolicy, CompatibilityException, CryptoAlgorithm};
    use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};

    fn payload_field(payload: &str, key: &str) -> Option<String> {
        payload.lines().find_map(|line| {
            let (line_key, value) = line.split_once('=')?;
            (line_key == key).then(|| value.to_owned())
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
            subject: "alice".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 120,
            nonce: "nonce-1".to_owned(),
        };

        assert!(guard.validate_token_and_nonce(&claims, 110).is_ok());
        let replay = guard.validate_token_and_nonce(&claims, 111);
        assert_eq!(replay.err(), Some(AuthError::ReplayDetected));
    }

    #[test]
    fn token_claims_ct_eq() {
        let a = TokenClaims {
            subject: "alice".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 120,
            nonce: "nonce-1".to_owned(),
        };
        let b = TokenClaims {
            subject: "alice".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 120,
            nonce: "nonce-1".to_owned(),
        };
        assert!(a.ct_eq(&b));

        let mut c = b.clone();
        c.nonce = "nonce-2".to_owned();
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn signed_token_claims_ct_eq() {
        let claims = TokenClaims {
            subject: "alice".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 120,
            nonce: "nonce-1".to_owned(),
        };
        let a = SignedTokenClaims {
            claims: claims.clone(),
            signature_hex: "deadbeef".to_owned(),
        };
        let b = SignedTokenClaims {
            claims,
            signature_hex: "deadbeef".to_owned(),
        };
        assert!(a.ct_eq(&b));

        let mut c = b.clone();
        c.signature_hex = "cafebabe".to_owned();
        assert!(!a.ct_eq(&c));
    }

    #[test]
    fn throwaway_credential_lifecycle_and_audit_events() {
        let store = ThrowawayCredentialStore::default();
        let created = store
            .create(
                "cred-1".to_owned(),
                "alice".to_owned(),
                "tag:servers".to_owned(),
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
                "cred-race".to_owned(),
                "alice".to_owned(),
                "tag:servers".to_owned(),
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
                .expect("test directory permissions should be set")
        };
        let path = test_dir.join("trust.state");

        let state = TrustState {
            generation: 7,
            signing_fingerprint: "ed25519:abc123".to_owned(),
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
            source: "group:family".to_owned(),
            destination: "tag:servers".to_owned(),
            protocol: "tcp".to_owned(),
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
                "cred-enroll".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");

        let response = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-enroll".to_owned(),
                node_id: "node-1".to_owned(),
                hostname: "mini-pc-1".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.10:51820".to_owned(),
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
            credential_id: "cred-enroll".to_owned(),
            node_id: "node-2".to_owned(),
            hostname: "mini-pc-2".to_owned(),
            os: "linux".to_owned(),
            tags: vec!["servers".to_owned()],
            owner: "alice@example.local".to_owned(),
            endpoint: "198.51.100.11:51820".to_owned(),
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
                "cred-sign".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");

        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-sign".to_owned(),
            node_id: "node-sign".to_owned(),
            hostname: "mini-pc-sign".to_owned(),
            os: "linux".to_owned(),
            tags: vec!["servers".to_owned()],
            owner: "alice@example.local".to_owned(),
            endpoint: "198.51.100.20:51820".to_owned(),
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
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);

        core.credentials
            .create(
                "cred-node-a".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        core.credentials
            .create(
                "cred-node-b".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");

        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-node-a".to_owned(),
            node_id: "node-a".to_owned(),
            hostname: "node-a".to_owned(),
            os: "linux".to_owned(),
            tags: vec!["servers".to_owned()],
            owner: "alice@example.local".to_owned(),
            endpoint: "198.51.100.40:51820".to_owned(),
            public_key: [41; 32],
            now_unix: 120,
        })
        .expect("enrollment should succeed");
        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: "cred-node-b".to_owned(),
            node_id: "node-b".to_owned(),
            hostname: "node-b".to_owned(),
            os: "linux".to_owned(),
            tags: vec!["servers".to_owned()],
            owner: "alice@example.local".to_owned(),
            endpoint: "198.51.100.41:51820".to_owned(),
            public_key: [42; 32],
            now_unix: 121,
        })
        .expect("enrollment should succeed");
        let mut exit_node = core
            .nodes
            .get("node-b")
            .expect("node registry access should succeed")
            .expect("exit node should exist");
        exit_node.capabilities = vec![RoleCapability::Anchor, RoleCapability::ExitServer];
        core.nodes
            .upsert(exit_node)
            .expect("exit role capability update should succeed");

        let bundle = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 11,
                mesh_cidr: "100.64.0.0/10".to_owned(),
                exit_node_id: Some("node-b".to_owned()),
                lan_routes: vec!["192.168.1.0/24".to_owned()],
            })
            .expect("auto tunnel bundle should be emitted");

        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        assert_eq!(
            payload_field(&bundle.payload, "node_id").as_deref(),
            Some("node-a")
        );
        assert_eq!(
            payload_field(&bundle.payload, "node_capabilities").as_deref(),
            Some("client")
        );
        assert_eq!(
            payload_field(&bundle.payload, "exit_node_id").as_deref(),
            Some("node-b")
        );
        assert_eq!(
            payload_field(&bundle.payload, "exit_node_capabilities").as_deref(),
            Some("anchor,exit_server")
        );
        assert_eq!(
            payload_field(&bundle.payload, "traffic_route_policy").as_deref(),
            Some("mesh_or_relay_or_exit_node")
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
        assert_eq!(
            payload_field(&bundle.payload, "peer.0.capabilities").as_deref(),
            Some("anchor,exit_server")
        );
        assert!(peer_allowed_ips.contains("0.0.0.0/0"));
        assert!(peer_allowed_ips.contains("192.168.1.0/24"));

        let wire = ControlPlaneCore::signed_auto_tunnel_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));

        let mut tampered = bundle.clone();
        tampered.payload.push_str("peer.99.node_id=tampered\n");
        assert!(!core.verify_signed_auto_tunnel_bundle(&tampered));
    }

    #[test]
    fn auto_tunnel_bundle_rejects_lan_routes_without_exit_node() {
        let core = auto_tunnel_test_core();
        let err = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                lan_routes: vec!["192.168.1.0/24".to_owned()],
                ..auto_tunnel_request()
            })
            .expect_err("lan routes must require explicit exit node");
        assert!(format!("{err}").contains("lan routes require an explicit exit node"));
    }

    #[test]
    fn auto_tunnel_bundle_rejects_exit_node_without_exit_server_capability() {
        let core = auto_tunnel_test_core();
        let err = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                exit_node_id: Some("node-b".to_owned()),
                ..auto_tunnel_request()
            })
            .expect_err("exit provider must carry exit_server capability");
        assert!(format!("{err}").contains("lacks exit_server capability"));
    }

    #[test]
    fn auto_tunnel_bundle_is_policy_gated_and_assignment_is_stable() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "node:node-a".to_owned(),
                dst: "node:node-b".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let first = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 22,
                mesh_cidr: "100.64.0.0/10".to_owned(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");
        let second = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_owned(),
                generated_at_unix: 201,
                ttl_secs: 300,
                nonce: 23,
                mesh_cidr: "100.64.0.0/10".to_owned(),
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
                src: "*".to_owned(),
                dst: "*".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle_a = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-a".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 31,
                mesh_cidr: "100.64.0.0/10".to_owned(),
                exit_node_id: None,
                lan_routes: Vec::new(),
            })
            .expect("bundle should be generated");
        let bundle_b = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-b".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 300,
                nonce: 32,
                mesh_cidr: "100.64.0.0/10".to_owned(),
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

    /// Build an allow-all `ControlPlaneCore` with two enrolled nodes
    /// `node-a` and `node-b` so auto-tunnel verifier tests can issue
    /// bundles without re-pasting enrollment boilerplate.
    fn auto_tunnel_test_core() -> ControlPlaneCore {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            ("at-cred-a", "node-a", "198.51.100.80:51820", [80; 32]),
            ("at-cred-b", "node-b", "198.51.100.81:51820", [81; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }
        core
    }

    fn auto_tunnel_request() -> AutoTunnelBundleRequest {
        AutoTunnelBundleRequest {
            node_id: "node-a".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 300,
            nonce: 17,
            mesh_cidr: "100.64.0.0/10".to_owned(),
            exit_node_id: None,
            lan_routes: Vec::new(),
        }
    }

    #[test]
    fn auto_tunnel_verifier_accepts_unmodified_bundle() {
        // Regression guard: the cross-check pattern must not break the
        // happy path.  An untouched signer-emitted bundle must verify.
        let core = auto_tunnel_test_core();
        let bundle = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle should be emitted");
        assert!(
            core.verify_signed_auto_tunnel_bundle(&bundle),
            "unmodified signer output must verify"
        );
    }

    #[test]
    fn auto_tunnel_verifier_rejects_outer_node_id_mismatched_to_payload() {
        // Real security gap: a bundle signed for node-a paired with an
        // outer struct claiming node-evil must fail verification, not
        // silently mislead a downstream consumer reading bundle.node_id.
        let core = auto_tunnel_test_core();
        let mut bundle = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle should be emitted");
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        bundle.node_id = "node-evil".to_owned();
        assert!(
            !core.verify_signed_auto_tunnel_bundle(&bundle),
            "outer node_id mismatched to signed payload must fail"
        );
    }

    #[test]
    fn auto_tunnel_verifier_rejects_outer_generated_at_mismatched_to_payload() {
        let core = auto_tunnel_test_core();
        let mut bundle = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle should be emitted");
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        // Pick a value that still satisfies generated_at <= expires_at so
        // we exercise the cross-check, not the temporal-order gate.
        bundle.generated_at_unix = bundle.generated_at_unix.saturating_sub(1);
        assert!(
            !core.verify_signed_auto_tunnel_bundle(&bundle),
            "outer generated_at_unix mismatched to signed payload must fail"
        );
    }

    #[test]
    fn auto_tunnel_verifier_rejects_outer_expires_at_mismatched_to_payload() {
        let core = auto_tunnel_test_core();
        let mut bundle = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle should be emitted");
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        bundle.expires_at_unix = bundle.expires_at_unix.saturating_add(1);
        assert!(
            !core.verify_signed_auto_tunnel_bundle(&bundle),
            "outer expires_at_unix mismatched to signed payload must fail"
        );
    }

    #[test]
    fn auto_tunnel_verifier_rejects_payload_swap_with_valid_signature() {
        // A second, fully-valid signed bundle for node-b cannot be paired
        // with an outer struct claiming node-a — the payload's node_id
        // line will not match outer.node_id even though the signature
        // still verifies the payload bytes.
        let core = auto_tunnel_test_core();
        let bundle_a = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle a should be emitted");
        let bundle_b = core
            .signed_auto_tunnel_bundle(AutoTunnelBundleRequest {
                node_id: "node-b".to_owned(),
                ..auto_tunnel_request()
            })
            .expect("auto tunnel bundle b should be emitted");
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle_a));
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle_b));
        let frankenbundle = SignedAutoTunnelBundle {
            payload: bundle_b.payload.clone(),
            signature_hex: bundle_b.signature_hex.clone(),
            generated_at_unix: bundle_b.generated_at_unix,
            expires_at_unix: bundle_b.expires_at_unix,
            // Outer-struct lie: claim this bundle is for node-a.
            node_id: bundle_a.node_id.clone(),
        };
        assert!(
            !core.verify_signed_auto_tunnel_bundle(&frankenbundle),
            "swapped payload with mismatched outer node_id must fail"
        );
    }

    #[test]
    fn auto_tunnel_payload_field_matches_helper_handles_edge_cases() {
        // Pin the never-default-true contract.  A missing key MUST return
        // false; otherwise an attacker could strip the line from the
        // payload and bypass the cross-check.
        let payload = "version=1\n\
            node_id=node-a\n\
            generated_at_unix=200\n\
            expires_at_unix=500\n\
            no-equals-sign-line\n";
        // Exact match.
        assert!(auto_tunnel_payload_field_matches(
            payload, "node_id", "node-a"
        ));
        // Mismatched value rejects.
        assert!(!auto_tunnel_payload_field_matches(
            payload, "node_id", "node-b"
        ));
        // Missing key rejects (NEVER defaults to true).
        assert!(!auto_tunnel_payload_field_matches(
            payload,
            "absent_key",
            "anything"
        ));
        // Empty payload rejects (NEVER defaults to true).
        assert!(!auto_tunnel_payload_field_matches("", "node_id", "node-a"));
        // Numeric value compared as exact string.
        assert!(auto_tunnel_payload_field_matches(
            payload,
            "generated_at_unix",
            "200"
        ));
        assert!(!auto_tunnel_payload_field_matches(
            payload,
            "generated_at_unix",
            "200 "
        ));
        // Lines without `=` must be skipped (not crash, not match).
        assert!(!auto_tunnel_payload_field_matches(
            payload,
            "no-equals-sign-line",
            ""
        ));
    }

    #[test]
    fn dns_zone_bundle_is_signed_and_tamper_detected() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle = core
            .signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
                zone_name: "rustynet".to_owned(),
                subject_node_id: "node-a".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 120,
                nonce: 41,
                records: vec![DnsRecordRequest {
                    label: "nas".to_owned(),
                    target_node_id: "node-b".to_owned(),
                    ttl_secs: 60,
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    aliases: vec!["storage".to_owned()],
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
                src: "node:node-a".to_owned(),
                dst: "node:node-b".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let denied = core.signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
            zone_name: "rustynet".to_owned(),
            subject_node_id: "node-a".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 120,
            nonce: 42,
            records: vec![DnsRecordRequest {
                label: "db".to_owned(),
                target_node_id: "node-c".to_owned(),
                ttl_secs: 60,
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                aliases: Vec::new(),
            }],
        });
        assert!(matches!(denied, Err(super::ControlPlaneError::Dns(_))));

        let collision = core.signed_dns_zone_bundle(SignedDnsZoneBundleRequest {
            zone_name: "rustynet".to_owned(),
            subject_node_id: "node-a".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 120,
            nonce: 43,
            records: vec![
                DnsRecordRequest {
                    label: "nas".to_owned(),
                    target_node_id: "node-b".to_owned(),
                    ttl_secs: 60,
                    rr_type: DnsRecordType::A,
                    target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                    aliases: vec!["storage".to_owned()],
                },
                DnsRecordRequest {
                    label: "storage".to_owned(),
                    target_node_id: "node-b".to_owned(),
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
                src: "*".to_owned(),
                dst: "*".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let bundle = core
            .signed_endpoint_hint_bundle(EndpointHintBundleRequest {
                source_node_id: "node-a".to_owned(),
                target_node_id: "node-b".to_owned(),
                generated_at_unix: 200,
                ttl_secs: 60,
                nonce: 7,
                candidates: vec![
                    EndpointHintCandidate {
                        candidate_type: EndpointHintCandidateType::Host,
                        endpoint: "10.0.0.3:51820".to_owned(),
                        relay_id: None,
                        priority: 10,
                    },
                    EndpointHintCandidate {
                        candidate_type: EndpointHintCandidateType::Relay,
                        endpoint: "203.0.113.44:443".to_owned(),
                        relay_id: Some("relay-eu-1".to_owned()),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            deny_all
                .enroll_with_throwaway(EnrollmentRequest {
                    credential_id: credential_id.to_owned(),
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec!["servers".to_owned()],
                    owner: "alice@example.local".to_owned(),
                    endpoint: endpoint.to_owned(),
                    public_key,
                    now_unix: 120,
                })
                .expect("enrollment should succeed");
        }
        let denied = deny_all.signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 1,
            candidates: vec![EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Host,
                endpoint: "10.0.0.2:51820".to_owned(),
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
                    src: "*".to_owned(),
                    dst: "*".to_owned(),
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
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            allow_all
                .enroll_with_throwaway(EnrollmentRequest {
                    credential_id: credential_id.to_owned(),
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec!["servers".to_owned()],
                    owner: "alice@example.local".to_owned(),
                    endpoint: endpoint.to_owned(),
                    public_key,
                    now_unix: 120,
                })
                .expect("enrollment should succeed");
        }

        let duplicate = allow_all.signed_endpoint_hint_bundle(EndpointHintBundleRequest {
            source_node_id: "node-c".to_owned(),
            target_node_id: "node-d".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 2,
            candidates: vec![
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Host,
                    endpoint: "10.2.0.2:51820".to_owned(),
                    relay_id: None,
                    priority: 100,
                },
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Host,
                    endpoint: "10.2.0.2:51820".to_owned(),
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
            source_node_id: "node-c".to_owned(),
            target_node_id: "node-d".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 3,
            candidates: vec![EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Relay,
                endpoint: "203.0.113.55:443".to_owned(),
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

        for relay_id in ["relay-éu-1", "relay-label-too-long", "relay\nx", "relay=x"] {
            let err = allow_all
                .signed_endpoint_hint_bundle(EndpointHintBundleRequest {
                    source_node_id: "node-c".to_owned(),
                    target_node_id: "node-d".to_owned(),
                    generated_at_unix: 200,
                    ttl_secs: 60,
                    nonce: 4,
                    candidates: vec![EndpointHintCandidate {
                        candidate_type: EndpointHintCandidateType::Relay,
                        endpoint: "203.0.113.55:443".to_owned(),
                        relay_id: Some(relay_id.to_owned()),
                        priority: 1,
                    }],
                })
                .expect_err("non-canonical relay candidate id must fail closed");
            assert!(
                err.to_string().contains("relay_id"),
                "unexpected error for relay_id={relay_id:?}: {err}"
            );
        }
    }

    #[test]
    fn relay_fleet_bundle_is_signed_sorted_and_tamper_detected() {
        let core = allow_all_control_plane();
        let bundle = core
            .signed_relay_fleet_bundle(RelayFleetBundleRequest {
                generated_at_unix: 300,
                ttl_secs: 60,
                nonce: 9,
                relays: vec![
                    RelayFleetNodeDescriptor {
                        relay_id: "relay-us-1".to_owned(),
                        region: "us-east".to_owned(),
                        endpoint: "203.0.113.45:443".to_owned(),
                        priority: 20,
                        capacity: 1024,
                        enabled: true,
                    },
                    RelayFleetNodeDescriptor {
                        relay_id: "relay-eu-1".to_owned(),
                        region: "eu-west".to_owned(),
                        endpoint: "203.0.113.44:443".to_owned(),
                        priority: 10,
                        capacity: 2048,
                        enabled: true,
                    },
                ],
            })
            .expect("relay fleet bundle should issue");

        assert!(core.verify_signed_relay_fleet_bundle(&bundle));
        assert_eq!(bundle.generated_at_unix, 300);
        assert_eq!(bundle.expires_at_unix, 360);
        assert_eq!(bundle.nonce, 9);
        assert_eq!(bundle.relay_count, 2);
        assert_eq!(
            payload_field(&bundle.payload, "relay_count").as_deref(),
            Some("2")
        );
        assert_eq!(
            payload_field(&bundle.payload, "relay.0.id").as_deref(),
            Some("relay-eu-1")
        );
        assert_eq!(
            payload_field(&bundle.payload, "relay.0.port").as_deref(),
            Some("443")
        );
        let wire = ControlPlaneCore::signed_relay_fleet_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));
        let parsed =
            parse_signed_relay_fleet_bundle_wire(&wire).expect("relay fleet wire should parse");
        assert_eq!(parsed.generated_at_unix, bundle.generated_at_unix);
        assert_eq!(parsed.expires_at_unix, bundle.expires_at_unix);
        assert_eq!(parsed.nonce, bundle.nonce);
        assert_eq!(parsed.relay_count, bundle.relay_count);
        assert_eq!(parsed.relays, bundle.relays);
        assert!(core.verify_signed_relay_fleet_bundle(&parsed));

        let mut tampered = bundle.clone();
        tampered.payload = tampered
            .payload
            .replace("relay.0.capacity=2048", "relay.0.capacity=1");
        assert!(!core.verify_signed_relay_fleet_bundle(&tampered));

        let mut metadata_tampered = bundle.clone();
        metadata_tampered.nonce = 10;
        assert!(!core.verify_signed_relay_fleet_bundle(&metadata_tampered));
    }

    #[test]
    fn relay_fleet_bundle_rejects_unsafe_or_ambiguous_entries() {
        let core = allow_all_control_plane();
        let nonce_err = core
            .signed_relay_fleet_bundle(RelayFleetBundleRequest {
                generated_at_unix: 300,
                ttl_secs: 60,
                nonce: 0,
                relays: vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-eu-1".to_owned(),
                    region: "eu-west".to_owned(),
                    endpoint: "203.0.113.44:443".to_owned(),
                    priority: 10,
                    capacity: 1,
                    enabled: true,
                }],
            })
            .expect_err("zero relay fleet nonce must fail closed");
        assert!(nonce_err.to_string().contains("nonce"));

        for (relays, expected) in [
            (
                vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-éu-1".to_owned(),
                    region: "eu-west".to_owned(),
                    endpoint: "203.0.113.44:443".to_owned(),
                    priority: 10,
                    capacity: 1,
                    enabled: true,
                }],
                "ASCII",
            ),
            (
                vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-eu-1".to_owned(),
                    region: "eu\nwest".to_owned(),
                    endpoint: "203.0.113.44:443".to_owned(),
                    priority: 10,
                    capacity: 1,
                    enabled: true,
                }],
                "single-line payload value",
            ),
            (
                vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-eu-1".to_owned(),
                    region: String::new(),
                    endpoint: "203.0.113.44:443".to_owned(),
                    priority: 10,
                    capacity: 1,
                    enabled: true,
                }],
                "region",
            ),
            (
                vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-eu-1".to_owned(),
                    region: "eu-west".to_owned(),
                    endpoint: "127.0.0.1:443".to_owned(),
                    priority: 10,
                    capacity: 1,
                    enabled: true,
                }],
                "special transport address",
            ),
            (
                vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-eu-1".to_owned(),
                    region: "eu-west".to_owned(),
                    endpoint: "203.0.113.44:443".to_owned(),
                    priority: 10,
                    capacity: 0,
                    enabled: true,
                }],
                "capacity",
            ),
            (
                vec![
                    RelayFleetNodeDescriptor {
                        relay_id: "relay-eu-1".to_owned(),
                        region: "eu-west".to_owned(),
                        endpoint: "203.0.113.44:443".to_owned(),
                        priority: 10,
                        capacity: 1,
                        enabled: true,
                    },
                    RelayFleetNodeDescriptor {
                        relay_id: " relay-eu-1 ".to_owned(),
                        region: "eu-west".to_owned(),
                        endpoint: "203.0.113.45:443".to_owned(),
                        priority: 20,
                        capacity: 1,
                        enabled: true,
                    },
                ],
                "duplicate relay fleet relay_id",
            ),
            (
                vec![
                    RelayFleetNodeDescriptor {
                        relay_id: "relay-eu-1".to_owned(),
                        region: "eu-west".to_owned(),
                        endpoint: "203.0.113.44:443".to_owned(),
                        priority: 10,
                        capacity: 1,
                        enabled: true,
                    },
                    RelayFleetNodeDescriptor {
                        relay_id: "relay-eu-2".to_owned(),
                        region: "eu-west".to_owned(),
                        endpoint: "203.0.113.44:443".to_owned(),
                        priority: 20,
                        capacity: 1,
                        enabled: true,
                    },
                ],
                "duplicate relay fleet endpoint",
            ),
        ] {
            let err = core
                .signed_relay_fleet_bundle(RelayFleetBundleRequest {
                    generated_at_unix: 300,
                    ttl_secs: 60,
                    nonce: 10,
                    relays,
                })
                .expect_err("invalid relay fleet entry must fail closed");
            assert!(
                err.to_string().contains(expected),
                "expected '{expected}' in '{err}'"
            );
        }
    }

    /// Build an allow-all `ControlPlaneCore` with two enrolled nodes
    /// `node-a` and `node-b` so endpoint-hint tests can issue bundles
    /// without re-pasting enrollment boilerplate.
    fn endpoint_hint_test_core() -> ControlPlaneCore {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            ("eh-cred-a", "node-a", "198.51.100.90:51820", [90; 32]),
            ("eh-cred-b", "node-b", "198.51.100.91:51820", [91; 32]),
        ] {
            core.credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }
        core
    }

    fn endpoint_hint_request() -> EndpointHintBundleRequest {
        EndpointHintBundleRequest {
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 17,
            candidates: vec![EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Host,
                endpoint: "10.0.0.5:51820".to_owned(),
                relay_id: None,
                priority: 10,
            }],
        }
    }

    #[test]
    fn endpoint_hint_signer_rejects_self_addressed_bundle() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.target_node_id = "node-a".to_owned();
        let result = core.signed_endpoint_hint_bundle(request);
        assert!(
            result
                .expect_err("self-addressed endpoint hints must fail")
                .to_string()
                .contains("distinct source and target")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_self_addressed_with_whitespace() {
        // Trim-equality must reject `"node-a"` vs `" node-a "` to prevent
        // bypass of the distinct-source-target check.
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.source_node_id = " node-a ".to_owned();
        request.target_node_id = "node-a".to_owned();
        let result = core.signed_endpoint_hint_bundle(request);
        // Either node-not-found (untrimmed lookup) or distinct-source-target
        // is acceptable; the only unacceptable outcome is a successfully
        // issued self-addressed bundle.
        assert!(
            result.is_err(),
            "whitespace-padded self-addressed hints must be rejected"
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_empty_node_ids() {
        let core = endpoint_hint_test_core();
        let mut empty_source = endpoint_hint_request();
        empty_source.source_node_id = String::new();
        assert!(core.signed_endpoint_hint_bundle(empty_source).is_err());

        let mut whitespace_target = endpoint_hint_request();
        whitespace_target.target_node_id = "   ".to_owned();
        assert!(core.signed_endpoint_hint_bundle(whitespace_target).is_err());
    }

    #[test]
    fn endpoint_hint_signer_rejects_zero_generated_at() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.generated_at_unix = 0;
        let result = core.signed_endpoint_hint_bundle(request);
        assert!(
            result
                .expect_err("generated_at_unix=0 must fail")
                .to_string()
                .contains("generated_at_unix must be greater than zero")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_zero_ttl() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.ttl_secs = 0;
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("ttl=0 must fail")
                .to_string()
                .contains("ttl must be greater than zero")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_ttl_above_max() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.ttl_secs = 86401;
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("ttl=86401 must fail")
                .to_string()
                .contains("ttl exceeds max supported value")
        );
    }

    #[test]
    fn endpoint_hint_signer_accepts_ttl_at_max_boundary() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.ttl_secs = 86400;
        let bundle = core
            .signed_endpoint_hint_bundle(request)
            .expect("ttl=86400 (boundary) must succeed");
        assert!(core.verify_signed_endpoint_hint_bundle(&bundle));
        assert_eq!(bundle.expires_at_unix - bundle.generated_at_unix, 86400);
    }

    #[test]
    fn endpoint_hint_signer_rejects_empty_candidates() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates.clear();
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("empty candidates must fail")
                .to_string()
                .contains("at least one candidate")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_too_many_candidates() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates = (0..9u16)
            .map(|i| EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Host,
                endpoint: format!("10.0.0.{}:51820", i + 10),
                relay_id: None,
                priority: i,
            })
            .collect();
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("9 candidates must fail")
                .to_string()
                .contains("exceed max candidate count")
        );
    }

    #[test]
    fn endpoint_hint_signer_accepts_max_candidates_at_boundary() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates = (0..8u16)
            .map(|i| EndpointHintCandidate {
                candidate_type: EndpointHintCandidateType::Host,
                endpoint: format!("10.0.0.{}:51820", i + 10),
                relay_id: None,
                priority: i,
            })
            .collect();
        let bundle = core
            .signed_endpoint_hint_bundle(request)
            .expect("8 candidates (boundary) must succeed");
        assert!(core.verify_signed_endpoint_hint_bundle(&bundle));
        assert_eq!(
            payload_field(&bundle.payload, "candidate_count").as_deref(),
            Some("8")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_zero_port() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates[0].endpoint = "10.0.0.5:0".to_owned();
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("port=0 must fail")
                .to_string()
                .contains("port must be non-zero")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_unparseable_endpoint() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates[0].endpoint = "not-an-address".to_owned();
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("invalid endpoint must fail")
                .to_string()
                .contains("invalid")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_relay_id_on_non_relay_candidate() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates[0].relay_id = Some("relay-eu-1".to_owned());
        request.candidates[0].candidate_type = EndpointHintCandidateType::Host;
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("relay_id on host candidate must fail")
                .to_string()
                .contains("only valid for relay candidates")
        );
    }

    #[test]
    fn endpoint_hint_signer_rejects_whitespace_only_relay_id() {
        let core = endpoint_hint_test_core();
        let mut request = endpoint_hint_request();
        request.candidates = vec![EndpointHintCandidate {
            candidate_type: EndpointHintCandidateType::Relay,
            endpoint: "203.0.113.55:443".to_owned(),
            relay_id: Some("   ".to_owned()),
            priority: 1,
        }];
        assert!(
            core.signed_endpoint_hint_bundle(request)
                .expect_err("whitespace-only relay_id must fail")
                .to_string()
                .contains("relay candidates require relay_id")
        );
    }

    #[test]
    fn endpoint_hint_signer_payload_pins_canonical_ordering() {
        // Pin priority-desc, then type-asc, then endpoint-asc, then
        // relay_id-asc.  Re-arranging input must produce identical bytes.
        let core = endpoint_hint_test_core();
        let request_a = EndpointHintBundleRequest {
            source_node_id: "node-a".to_owned(),
            target_node_id: "node-b".to_owned(),
            generated_at_unix: 200,
            ttl_secs: 60,
            nonce: 1,
            candidates: vec![
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Host,
                    endpoint: "10.0.0.4:51820".to_owned(),
                    relay_id: None,
                    priority: 5,
                },
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::Relay,
                    endpoint: "203.0.113.10:443".to_owned(),
                    relay_id: Some("relay-eu-1".to_owned()),
                    priority: 30,
                },
                EndpointHintCandidate {
                    candidate_type: EndpointHintCandidateType::ServerReflexive,
                    endpoint: "198.51.100.5:54321".to_owned(),
                    relay_id: None,
                    priority: 30,
                },
            ],
        };
        let mut request_b = request_a.clone();
        request_b.candidates.reverse();
        let bundle_a = core
            .signed_endpoint_hint_bundle(request_a)
            .expect("bundle a must succeed");
        let bundle_b = core
            .signed_endpoint_hint_bundle(request_b)
            .expect("bundle b must succeed");
        assert_eq!(
            bundle_a.payload, bundle_b.payload,
            "payload must be order-independent (canonical sort)"
        );
        // Highest priority must come first; tie broken by type-asc
        // ('relay' < 'srflx').
        assert_eq!(
            payload_field(&bundle_a.payload, "candidate.0.type").as_deref(),
            Some("relay")
        );
        assert_eq!(
            payload_field(&bundle_a.payload, "candidate.1.type").as_deref(),
            Some("srflx")
        );
        assert_eq!(
            payload_field(&bundle_a.payload, "candidate.2.type").as_deref(),
            Some("host")
        );
    }

    #[test]
    fn endpoint_hint_signer_payload_pins_required_fields_and_order() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let lines: Vec<&str> = bundle.payload.lines().collect();
        assert_eq!(lines[0], "version=1");
        assert_eq!(lines[1], "path_policy=direct_preferred_relay_allowed");
        assert!(lines[2].starts_with("source_node_id="));
        assert!(lines[3].starts_with("target_node_id="));
        assert!(lines[4].starts_with("generated_at_unix="));
        assert!(lines[5].starts_with("expires_at_unix="));
        assert!(lines[6].starts_with("nonce="));
        assert!(lines[7].starts_with("candidate_count="));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_zero_generated_at() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle;
        tampered.generated_at_unix = 0;
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_generated_at_eq_expires_at() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.expires_at_unix = tampered.generated_at_unix;
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_generated_at_gt_expires_at() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.expires_at_unix = tampered.generated_at_unix - 1;
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_ttl_window_above_max() {
        // The signer caps TTL at 86400s.  The verifier MUST also enforce
        // this bound — otherwise an attacker who reuses a leaked signing
        // key could mint arbitrarily long-lived bundles.
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.expires_at_unix = tampered.generated_at_unix + 86401;
        assert!(
            !core.verify_signed_endpoint_hint_bundle(&tampered),
            "verifier must reject TTL window > 86400s"
        );
    }

    #[test]
    fn endpoint_hint_verifier_rejects_self_addressed_outer_struct() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.target_node_id = tampered.source_node_id.clone();
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_empty_node_id_in_outer_struct() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut empty_source = bundle.clone();
        empty_source.source_node_id = String::new();
        assert!(!core.verify_signed_endpoint_hint_bundle(&empty_source));

        let mut empty_target = bundle.clone();
        empty_target.target_node_id = "   ".to_owned();
        assert!(!core.verify_signed_endpoint_hint_bundle(&empty_target));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_outer_source_mismatched_to_payload() {
        // Attacker takes a valid signed bundle for `node-a -> node-b` and
        // reframes the outer struct as `node-evil -> node-b`.  Without the
        // cross-check, a downstream consumer that trusts
        // `bundle.source_node_id` would be misled.
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.source_node_id = "node-evil".to_owned();
        assert!(
            !core.verify_signed_endpoint_hint_bundle(&tampered),
            "outer source_node_id must match payload"
        );
    }

    #[test]
    fn endpoint_hint_verifier_rejects_outer_target_mismatched_to_payload() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.target_node_id = "node-evil".to_owned();
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_outer_generated_at_mismatched_to_payload() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        // Move forward but stay inside the 300s window so we don't trip
        // the TTL bound first.
        tampered.generated_at_unix = bundle.generated_at_unix + 1;
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_outer_expires_at_mismatched_to_payload() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.expires_at_unix = bundle.expires_at_unix + 1;
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_payload_with_swapped_source_target() {
        // If only the payload's source/target lines are swapped, the
        // signature naturally breaks AND the cross-check between outer
        // struct and payload fails — both layers catch it.
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.payload = tampered
            .payload
            .replace("source_node_id=node-a", "source_node_id=node-b-swap-tmp")
            .replace("target_node_id=node-b", "target_node_id=node-a")
            .replace("source_node_id=node-b-swap-tmp", "source_node_id=node-b");
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_corrupt_signature_hex() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered.signature_hex = "not-hex".to_owned();
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_short_signature_hex() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        tampered
            .signature_hex
            .truncate(tampered.signature_hex.len() - 2);
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_tampered_payload_byte() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        let mut tampered = bundle.clone();
        // Flip the last visible byte of the version line.
        tampered.payload = tampered.payload.replacen("version=1", "version=2", 1);
        assert!(!core.verify_signed_endpoint_hint_bundle(&tampered));
    }

    #[test]
    fn endpoint_hint_verifier_rejects_signature_from_wrong_signing_key() {
        // A bundle signed by a different control plane (different signing
        // secret) must not verify against this core's verifying key.
        let core_a = endpoint_hint_test_core();
        let policy_b = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core_b = ControlPlaneCore::new(b"different-secret".to_vec(), policy_b);
        for (credential_id, node_id, endpoint, public_key) in [
            ("eh-cred-a", "node-a", "198.51.100.92:51820", [92; 32]),
            ("eh-cred-b", "node-b", "198.51.100.93:51820", [93; 32]),
        ] {
            core_b
                .credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core_b
                .enroll_with_throwaway(EnrollmentRequest {
                    credential_id: credential_id.to_owned(),
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec!["servers".to_owned()],
                    owner: "alice@example.local".to_owned(),
                    endpoint: endpoint.to_owned(),
                    public_key,
                    now_unix: 120,
                })
                .expect("enrollment should succeed");
        }
        let bundle_b = core_b
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed under core_b");
        // Sanity: verifies under its own core.
        assert!(core_b.verify_signed_endpoint_hint_bundle(&bundle_b));
        // But MUST NOT verify under a different core.
        assert!(
            !core_a.verify_signed_endpoint_hint_bundle(&bundle_b),
            "bundle signed with different key must not verify"
        );
    }

    #[test]
    fn endpoint_hint_verifier_accepts_unmodified_bundle() {
        let core = endpoint_hint_test_core();
        let bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        // Round-trip the wire form to confirm verifier accepts identical
        // bytes.
        let wire = ControlPlaneCore::signed_endpoint_hint_bundle_to_wire(&bundle);
        assert!(wire.contains("signature="));
        assert!(wire.starts_with("version=1\n"));
        assert!(core.verify_signed_endpoint_hint_bundle(&bundle));
    }

    #[test]
    fn endpoint_hint_payload_field_matches_helper_handles_edge_cases() {
        // Direct unit test of the cross-check helper used by the verifier.
        let payload = "version=1\nsource_node_id=node-a\ntarget_node_id=node-b\n";
        assert!(super::endpoint_hint_payload_field_matches(
            payload,
            "source_node_id",
            "node-a",
        ));
        assert!(!super::endpoint_hint_payload_field_matches(
            payload,
            "source_node_id",
            "node-b",
        ));
        // Missing key MUST be rejected — never default to `true`.
        assert!(!super::endpoint_hint_payload_field_matches(
            payload,
            "absent_key",
            "anything",
        ));
        // Empty-value match still requires presence of the key.
        assert!(!super::endpoint_hint_payload_field_matches(
            payload, "absent", "",
        ));
        // Lines without `=` must be skipped, not split spuriously.
        let weird = "version=1\nno-equals-line\nsource_node_id=node-a\n";
        assert!(super::endpoint_hint_payload_field_matches(
            weird,
            "source_node_id",
            "node-a",
        ));
    }

    // ─── Signed-bundle version=N gates (slice 11) ────────────────────────────
    //
    // Every signed-bundle verifier must reject a payload whose `version=` line
    // is not the current canonical version.  Without this gate, a future
    // version=N+1 bundle signed by the same key could silently verify and a
    // version=N-only consumer would parse the new bytes under old assumptions.
    // These tests pin the gate by mutating the payload's version line on a
    // valid signer-emitted bundle and asserting the verifier rejects.  The
    // version check is positioned BEFORE signature verification in each
    // verifier (see comments above each `*_payload_field_matches(... "version"
    // ...)` call), so the rejection path here is the version gate itself.

    #[test]
    fn endpoint_hint_verifier_rejects_payload_with_unknown_version() {
        let core = endpoint_hint_test_core();
        let mut bundle = core
            .signed_endpoint_hint_bundle(endpoint_hint_request())
            .expect("bundle must succeed");
        assert!(core.verify_signed_endpoint_hint_bundle(&bundle));
        bundle.payload = bundle.payload.replacen("version=1", "version=2", 1);
        assert!(
            !core.verify_signed_endpoint_hint_bundle(&bundle),
            "endpoint-hint verifier must reject unknown version even with otherwise valid bundle"
        );
    }

    #[test]
    fn auto_tunnel_verifier_rejects_payload_with_unknown_version() {
        let core = auto_tunnel_test_core();
        let mut bundle = core
            .signed_auto_tunnel_bundle(auto_tunnel_request())
            .expect("auto tunnel bundle should be emitted");
        assert!(core.verify_signed_auto_tunnel_bundle(&bundle));
        bundle.payload = bundle.payload.replacen("version=1", "version=2", 1);
        assert!(
            !core.verify_signed_auto_tunnel_bundle(&bundle),
            "auto-tunnel verifier must reject unknown version even with otherwise valid bundle"
        );
    }

    #[test]
    fn dns_zone_verifier_rejects_payload_with_unknown_version() {
        let core = endpoint_hint_test_core();
        let request = SignedDnsZoneBundleRequest {
            zone_name: "rustynet".to_owned(),
            subject_node_id: "node-a".to_owned(),
            generated_at_unix: 1_000,
            ttl_secs: 60,
            nonce: 7,
            records: vec![DnsRecordRequest {
                label: "host".to_owned(),
                target_node_id: "node-a".to_owned(),
                ttl_secs: 30,
                rr_type: DnsRecordType::A,
                target_addr_kind: DnsTargetAddrKind::MeshIpv4,
                aliases: vec![],
            }],
        };
        let mut bundle = core
            .signed_dns_zone_bundle(request)
            .expect("dns zone bundle should be emitted");
        assert!(core.verify_signed_dns_zone_bundle(&bundle));
        bundle.payload = bundle.payload.replacen("version=1", "version=2", 1);
        assert!(
            !core.verify_signed_dns_zone_bundle(&bundle),
            "dns-zone verifier must reject unknown version even with otherwise valid bundle"
        );
    }

    #[test]
    fn relay_fleet_verifier_rejects_payload_with_unknown_version() {
        let core = endpoint_hint_test_core();
        let mut bundle = core
            .signed_relay_fleet_bundle(RelayFleetBundleRequest {
                generated_at_unix: 300,
                ttl_secs: 60,
                nonce: 9,
                relays: vec![RelayFleetNodeDescriptor {
                    relay_id: "relay-us-1".to_owned(),
                    region: "us-east".to_owned(),
                    endpoint: "203.0.113.45:443".to_owned(),
                    priority: 20,
                    capacity: 1024,
                    enabled: true,
                }],
            })
            .expect("relay fleet bundle should issue");
        assert!(core.verify_signed_relay_fleet_bundle(&bundle));
        bundle.payload = bundle.payload.replacen("version=1", "version=2", 1);
        assert!(
            !core.verify_signed_relay_fleet_bundle(&bundle),
            "relay-fleet verifier must reject unknown version even with otherwise valid bundle"
        );
    }

    // NOTE: peer_map_verifier_rejects_payload_with_unknown_version is
    // intentionally NOT included.  Peer-map's wire format is line-pipe-
    // delimited (`node_id|hostname|...`), not `version=N\nkey=value\n`,
    // so a payload-field version gate cannot be added without a wire-
    // format change.  Tracked as a future followup.

    #[test]
    fn traversal_coordination_record_verifier_rejects_payload_with_unknown_version() {
        // Use the same enrollment + signing pattern as the existing
        // `traversal_coordination_record_is_signed_and_tamper_detected`
        // test below, then mutate the payload's version line.
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            (
                "coord-cred-x",
                "coord-node-x",
                "198.51.100.180:51820",
                [180; 32],
            ),
            (
                "coord-cred-y",
                "coord-node-y",
                "198.51.100.181:51820",
                [181; 32],
            ),
        ] {
            core.credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("node enrollment should succeed");
        }
        let mut record = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [0x33; 16],
                probe_start_unix: 205,
                node_a: "coord-node-x".to_owned(),
                node_b: "coord-node-y".to_owned(),
                issued_at_unix: 200,
                expires_at_unix: 225,
                nonce: [0x44; 16],
            })
            .expect("coordination record should sign");
        assert!(core.verify_signed_traversal_coordination_record(&record));
        record.payload = record.payload.replacen("version=1", "version=2", 1);
        assert!(
            !core.verify_signed_traversal_coordination_record(&record),
            "coordination-record verifier must reject unknown version"
        );
    }

    #[test]
    fn traversal_coordination_record_is_signed_and_tamper_detected() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "*".to_owned(),
                dst: "*".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            (
                "coord-cred-a",
                "coord-node-a",
                "198.51.100.170:51820",
                [170; 32],
            ),
            (
                "coord-cred-b",
                "coord-node-b",
                "198.51.100.171:51820",
                [171; 32],
            ),
        ] {
            core.credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let signed = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [0x11; 16],
                probe_start_unix: 205,
                node_a: "coord-node-a".to_owned(),
                node_b: "coord-node-b".to_owned(),
                issued_at_unix: 200,
                expires_at_unix: 225,
                nonce: [0x22; 16],
            })
            .expect("coordination record should be issued");
        assert!(core.verify_signed_traversal_coordination_record(&signed));

        let mut tampered_payload = signed.clone();
        tampered_payload.payload.push_str("node_b=coord-node-c\n");
        assert!(!core.verify_signed_traversal_coordination_record(&tampered_payload));

        let mut tampered_signature = signed.clone();
        tampered_signature.signature_hex = "00".repeat(64);
        assert!(!core.verify_signed_traversal_coordination_record(&tampered_signature));
    }

    #[test]
    fn traversal_coordination_record_enforces_validation_rules() {
        let policy = PolicySet {
            rules: vec![PolicyRule {
                src: "node:coord-node-a".to_owned(),
                dst: "node:coord-node-b".to_owned(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
            }],
        };
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), policy);
        for (credential_id, node_id, endpoint, public_key) in [
            (
                "coord-cred-c",
                "coord-node-a",
                "198.51.100.172:51820",
                [172; 32],
            ),
            (
                "coord-cred-d",
                "coord-node-b",
                "198.51.100.173:51820",
                [173; 32],
            ),
        ] {
            core.credentials
                .create(
                    credential_id.to_owned(),
                    "admin".to_owned(),
                    "tag:servers".to_owned(),
                    100,
                    60,
                )
                .expect("credential should be created");
            core.enroll_with_throwaway(EnrollmentRequest {
                credential_id: credential_id.to_owned(),
                node_id: node_id.to_owned(),
                hostname: node_id.to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: endpoint.to_owned(),
                public_key,
                now_unix: 120,
            })
            .expect("enrollment should succeed");
        }

        let ttl_error = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [0x33; 16],
                probe_start_unix: 205,
                node_a: "coord-node-a".to_owned(),
                node_b: "coord-node-b".to_owned(),
                issued_at_unix: 200,
                expires_at_unix: 200 + 86401,
                nonce: [0x44; 16],
            })
            .expect_err("ttl > 86400s must be rejected");
        assert!(ttl_error.to_string().contains("ttl exceeds"));

        let node_error = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [0x33; 16],
                probe_start_unix: 205,
                node_a: "coord-node-a".to_owned(),
                node_b: "missing-node".to_owned(),
                issued_at_unix: 200,
                expires_at_unix: 225,
                nonce: [0x44; 16],
            })
            .expect_err("missing node must be rejected");
        assert!(node_error.to_string().contains("does not exist"));

        let same_node_error = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [0x33; 16],
                probe_start_unix: 205,
                node_a: "coord-node-a".to_owned(),
                node_b: "coord-node-a".to_owned(),
                issued_at_unix: 200,
                expires_at_unix: 225,
                nonce: [0x44; 16],
            })
            .expect_err("same node ids must be rejected");
        assert!(same_node_error.to_string().contains("distinct"));
    }

    #[test]
    fn traversal_coordination_record_debug_redacts_sensitive_fields() {
        let record = TraversalCoordinationRecord {
            session_id: [0x55; 16],
            probe_start_unix: 210,
            node_a: "node-a".to_owned(),
            node_b: "node-b".to_owned(),
            issued_at_unix: 200,
            expires_at_unix: 220,
            nonce: [0x66; 16],
        };
        let rendered = format!("{record:?}");
        assert!(rendered.contains("REDACTED"));
        assert!(!rendered.contains("55"));
        assert!(!rendered.contains("66"));
    }

    #[test]
    fn reusable_credential_requires_strict_scope_ttl_and_vault_storage() {
        let store = ThrowawayCredentialStore::default();
        let policy = ReusableCredentialPolicy::default();

        let invalid_scope = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-1".to_owned(),
                creator: "admin".to_owned(),
                scope: "*".to_owned(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-1".to_owned(),
            },
            policy,
        );
        assert_eq!(invalid_scope.err(), Some(CredentialError::ScopeTooBroad));

        let invalid_storage = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-2".to_owned(),
                creator: "admin".to_owned(),
                scope: "tag:servers".to_owned(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "plaintext://bad".to_owned(),
            },
            policy,
        );
        assert_eq!(
            invalid_storage.err(),
            Some(CredentialError::StoragePolicyViolation)
        );

        let invalid_ttl = store.create_reusable(
            ReusableCredentialRequest {
                id: "reusable-3".to_owned(),
                creator: "admin".to_owned(),
                scope: "tag:servers".to_owned(),
                created_at_unix: 100,
                ttl_secs: policy.max_ttl_secs + 1,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-3".to_owned(),
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
                    id: "reusable-ok".to_owned(),
                    creator: "admin".to_owned(),
                    scope: "tag:automation".to_owned(),
                    created_at_unix: 100,
                    ttl_secs: 600,
                    max_uses: 3,
                    storage_reference: "vault://rustynet/reusable-ok".to_owned(),
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
                id: "reusable-bad-scope".to_owned(),
                creator: "admin".to_owned(),
                scope: "group:all-admins".to_owned(),
                created_at_unix: 100,
                ttl_secs: 600,
                max_uses: 3,
                storage_reference: "vault://rustynet/reusable-bad-scope".to_owned(),
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
                "cred-revoked".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
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
                user_id: "admin".to_owned(),
                email: "admin@example.local".to_owned(),
                mfa_enabled: false,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("admin user should be persisted");

        core.credentials
            .create(
                "cred-persist".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        persistence
            .insert_credential(&super::persistence::CredentialRow {
                credential_id: "cred-persist".to_owned(),
                creator_user_id: "admin".to_owned(),
                scope: "tag:servers".to_owned(),
                credential_kind: "throwaway".to_owned(),
                state: "created".to_owned(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 160,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_owned(),
            })
            .expect("credential should be persisted before enrollment");
        persistence
            .insert_credential_audit_event("cred-persist", None, "created", 100, "admin")
            .expect("credential creation audit event should be persisted");

        let response = core
            .enroll_with_throwaway_and_persist(
                EnrollmentRequest {
                    credential_id: "cred-persist".to_owned(),
                    node_id: "node-persist".to_owned(),
                    hostname: "mini-pc-persist".to_owned(),
                    os: "linux".to_owned(),
                    tags: vec!["servers".to_owned()],
                    owner: "alice@example.local".to_owned(),
                    endpoint: "198.51.100.30:51820".to_owned(),
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
                "cred-missing-db".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("in-memory credential should be created");

        let result = core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-missing-db".to_owned(),
                node_id: "node-missing-db".to_owned(),
                hostname: "node-missing-db".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.31:51820".to_owned(),
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
                user_id: "admin".to_owned(),
                email: "admin@example.local".to_owned(),
                mfa_enabled: false,
                created_at_unix: 100,
                updated_at_unix: 100,
            })
            .expect("admin user should be persisted");

        core.credentials
            .create(
                "cred-persist-once".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        persistence
            .insert_credential(&super::persistence::CredentialRow {
                credential_id: "cred-persist-once".to_owned(),
                creator_user_id: "admin".to_owned(),
                scope: "tag:servers".to_owned(),
                credential_kind: "throwaway".to_owned(),
                state: "created".to_owned(),
                max_uses: 1,
                uses: 0,
                expires_at_unix: 160,
                created_at_unix: 100,
                updated_at_unix: 100,
                storage_policy: "throwaway_default".to_owned(),
            })
            .expect("credential should be persisted");

        core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-persist-once".to_owned(),
                node_id: "node-persist-once-a".to_owned(),
                hostname: "node-persist-once-a".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.33:51820".to_owned(),
                public_key: [11; 32],
                now_unix: 150,
            },
            &persistence,
        )
        .expect("first enrollment should succeed");

        let second = core.enroll_with_throwaway_and_persist(
            EnrollmentRequest {
                credential_id: "cred-persist-once".to_owned(),
                node_id: "node-persist-once-b".to_owned(),
                hostname: "node-persist-once-b".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.34:51820".to_owned(),
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
            subject: "alice@example.local".to_owned(),
            issued_at_unix: 100,
            expires_at_unix: 200,
            nonce: "nonce-secret".to_owned(),
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
                "cred-token".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");

        let response = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token".to_owned(),
                node_id: "node-token".to_owned(),
                hostname: "mini-pc-token".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.60:51820".to_owned(),
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
        tampered.claims.subject = "mallory@example.local".to_owned();
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
                "cred-token-a".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        core.credentials
            .create(
                "cred-token-b".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");

        let token_a = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token-a".to_owned(),
                node_id: "node-token-a".to_owned(),
                hostname: "mini-pc-token-a".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.60:51820".to_owned(),
                public_key: [61; 32],
                now_unix: 120,
            })
            .expect("first enrollment should succeed")
            .access_token;
        let token_b = core
            .enroll_with_throwaway(EnrollmentRequest {
                credential_id: "cred-token-b".to_owned(),
                node_id: "node-token-b".to_owned(),
                hostname: "mini-pc-token-b".to_owned(),
                os: "linux".to_owned(),
                tags: vec!["servers".to_owned()],
                owner: "alice@example.local".to_owned(),
                endpoint: "198.51.100.61:51820".to_owned(),
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
                "cred-redact".to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        let rendered = format!("{credential:?}");
        assert!(!rendered.contains("cred-redact"));
        assert!(!rendered.contains("throwaway_default"));
        assert!(rendered.contains("REDACTED"));
    }

    // ── RelaySessionToken tests ───────────────────────────────────────────────
    //
    // These tests verify the relay session token signing, verification,
    // expiry, and constant-time comparison behavior.

    #[test]
    fn relay_id_label_canonicalization_is_shared_and_bounded() {
        let relay_id = canonical_relay_id_from_label(" relay-eu-1 ").expect("valid relay label");
        let mut expected = [0u8; 16];
        expected[..10].copy_from_slice(b"relay-eu-1");
        assert_eq!(relay_id, expected);
    }

    #[test]
    fn relay_id_label_canonicalization_rejects_ambiguous_labels() {
        assert!(canonical_relay_id_from_label("").is_err());
        assert!(canonical_relay_id_from_label("   ").is_err());
        assert!(canonical_relay_id_from_label("relay-éu-1").is_err());
        assert!(canonical_relay_id_from_label("relay-label-too-long").is_err());
        assert!(canonical_relay_id_from_label("relay\nx").is_err());
        assert!(canonical_relay_id_from_label("relay=x").is_err());
        // CR also breaks the single-line payload format and must be rejected.
        assert!(canonical_relay_id_from_label("relay\rx").is_err());
    }

    #[test]
    fn relay_id_label_canonicalization_is_case_sensitive() {
        // Case-different labels must canonicalize to *different* relay IDs.
        // If we ever lowercased silently, two operators with "Relay-EU-1" and
        // "relay-eu-1" would collide and one's signed-fleet membership could
        // be impersonated by the other.
        let upper = canonical_relay_id_from_label("Relay-EU-1").expect("upper-case label valid");
        let lower = canonical_relay_id_from_label("relay-eu-1").expect("lower-case label valid");
        let mixed = canonical_relay_id_from_label("Relay-eu-1").expect("mixed-case label valid");
        assert_ne!(upper, lower, "case-different labels must not collide");
        assert_ne!(upper, mixed);
        assert_ne!(lower, mixed);
    }

    #[test]
    fn relay_id_label_canonicalization_zero_pads_short_labels() {
        // A short label must be zero-padded out to 16 bytes.  Any non-zero tail
        // byte would mean two different short labels could collide if their
        // tails happened to overlap with another label's body bytes.
        let id = canonical_relay_id_from_label("relay-a").expect("short label valid");
        assert_eq!(&id[..7], b"relay-a");
        assert!(
            id[7..].iter().all(|&b| b == 0),
            "short relay-id label must zero-pad the tail; got {id:?}"
        );

        // Two short labels must produce identifiers that differ only in the
        // body bytes (and have identical zero tails).
        let a = canonical_relay_id_from_label("relay-a").expect("short label A valid");
        let b = canonical_relay_id_from_label("relay-b").expect("short label B valid");
        assert_ne!(a, b);
        assert_eq!(a[7..], b[7..]);
    }

    #[test]
    fn relay_id_label_canonicalization_accepts_exact_16_byte_label() {
        // Exactly 16 ASCII bytes is the boundary; anything larger must fail.
        let exact = "relay-region-001"; // 16 bytes
        assert_eq!(exact.len(), 16);
        let id = canonical_relay_id_from_label(exact).expect("16-byte label must be accepted");
        assert_eq!(&id[..], exact.as_bytes());

        // 17 bytes — even by a single character — must fail closed.
        let too_long = "relay-region-0001"; // 17 bytes
        assert_eq!(too_long.len(), 17);
        assert!(canonical_relay_id_from_label(too_long).is_err());
    }

    #[test]
    fn relay_id_label_canonicalization_distinguishes_internal_whitespace_from_concatenation() {
        // A label with an internal space must not collide with the same label
        // without the space — this guards against subtle ambiguity if an
        // operator types "relay 1" but the routing layer expects "relay1".
        let spaced = canonical_relay_id_from_label("relay 1").expect("internal-space label valid");
        let joined = canonical_relay_id_from_label("relay1").expect("no-space label valid");
        assert_ne!(spaced, joined);
        // The internal space is preserved in the canonical bytes.
        assert_eq!(&spaced[..7], b"relay 1");
    }

    fn allow_all_control_plane() -> ControlPlaneCore {
        ControlPlaneCore::new(
            b"control-secret".to_vec(),
            PolicySet {
                rules: vec![PolicyRule {
                    src: "*".to_owned(),
                    dst: "*".to_owned(),
                    protocol: Protocol::Any,
                    action: RuleAction::Allow,
                }],
            },
        )
    }

    fn enroll_relay_token_test_node(
        core: &ControlPlaneCore,
        credential_id: &str,
        node_id: &str,
        public_key_byte: u8,
    ) {
        core.credentials
            .create(
                credential_id.to_owned(),
                "admin".to_owned(),
                "tag:servers".to_owned(),
                100,
                60,
            )
            .expect("credential should be created");
        core.enroll_with_throwaway(EnrollmentRequest {
            credential_id: credential_id.to_owned(),
            node_id: node_id.to_owned(),
            hostname: node_id.to_owned(),
            os: "linux".to_owned(),
            tags: vec!["servers".to_owned()],
            owner: "alice@example.local".to_owned(),
            endpoint: format!("198.51.100.{public_key_byte}:51820"),
            public_key: [public_key_byte; 32],
            now_unix: 120,
        })
        .expect("node enrollment should succeed");
    }

    #[test]
    fn control_plane_issues_policy_authorized_relay_session_token() {
        let core = allow_all_control_plane();
        enroll_relay_token_test_node(&core, "cred-a", "node-a", 70);
        enroll_relay_token_test_node(&core, "cred-b", "node-b", 71);

        let token = core
            .issue_relay_session_token(RelaySessionTokenRequest {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: " relay-eu-1 ".to_owned(),
                requested_at_unix: 500,
                ttl_secs: 60,
            })
            .expect("authorized relay token should issue");
        let verifier = ed25519_dalek::VerifyingKey::from_bytes(&core.endpoint_hint_verifying_key)
            .expect("endpoint hint verifier should parse");

        assert_eq!(token.node_id, "node-a");
        assert_eq!(token.peer_node_id, "node-b");
        assert_eq!(token.issued_at_unix, 500);
        assert_eq!(token.expires_at_unix, 560);
        assert_eq!(
            token.relay_id,
            canonical_relay_id_from_label("relay-eu-1").expect("relay id should canonicalize")
        );
        token
            .verify_signature(&verifier)
            .expect("relay token must verify with endpoint-hint verifier");
    }

    #[test]
    fn relay_session_token_wire_round_trip_is_canonical() {
        let core = allow_all_control_plane();
        enroll_relay_token_test_node(&core, "cred-a", "node-a", 70);
        enroll_relay_token_test_node(&core, "cred-b", "node-b", 71);

        let token = core
            .issue_relay_session_token(RelaySessionTokenRequest {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: "relay-eu-1".to_owned(),
                requested_at_unix: 500,
                ttl_secs: 60,
            })
            .expect("authorized relay token should issue");
        let wire = relay_session_token_to_wire(&token);
        let parsed = parse_relay_session_token_wire(&wire).expect("canonical token should parse");

        assert!(token.ct_eq(&parsed));
        assert_eq!(wire, relay_session_token_to_wire(&parsed));
    }

    #[test]
    fn relay_session_token_wire_rejects_tamper_and_noncanonical_shape() {
        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign_at(&sk, "node-a", "node-b", [0xAA; 16], 500, 60);
        let wire = relay_session_token_to_wire(&token);

        let tampered = wire.replace("peer_node_id=node-b", "peer_node_id=node-c");
        assert!(
            parse_relay_session_token_wire(&tampered)
                .expect("parser only checks shape; signature verifier checks tamper")
                .verify_signature(&sk.verifying_key())
                .is_err()
        );

        let duplicate = wire.replace("scope=", "scope=forward_ciphertext_only\nscope=");
        let err =
            parse_relay_session_token_wire(&duplicate).expect_err("duplicate key must fail closed");
        assert!(err.to_string().contains("duplicate key"));

        let trailing = format!("{wire}extra=value\n");
        let err =
            parse_relay_session_token_wire(&trailing).expect_err("signature must be final line");
        assert!(err.to_string().contains("final line"));

        let noncanonical = wire.replace("relay_id=aaaaaaaa", "relay_id=AAAAAAAA");
        let err = parse_relay_session_token_wire(&noncanonical)
            .expect_err("uppercase hex is not canonical");
        assert!(err.to_string().contains("canonical"));
    }

    #[test]
    fn control_plane_rejects_policy_denied_relay_session_token() {
        let core = ControlPlaneCore::new(b"control-secret".to_vec(), PolicySet { rules: vec![] });
        enroll_relay_token_test_node(&core, "cred-a", "node-a", 70);
        enroll_relay_token_test_node(&core, "cred-b", "node-b", 71);

        let err = core
            .issue_relay_session_token(RelaySessionTokenRequest {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: "relay-eu-1".to_owned(),
                requested_at_unix: 500,
                ttl_secs: 60,
            })
            .expect_err("policy denied relay token must fail closed");

        assert!(err.to_string().contains("denied by policy"));
    }

    #[test]
    fn control_plane_rejects_invalid_relay_session_token_requests() {
        let core = allow_all_control_plane();
        enroll_relay_token_test_node(&core, "cred-a", "node-a", 70);
        enroll_relay_token_test_node(&core, "cred-b", "node-b", 71);

        for (request, expected) in [
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "node-b".to_owned(),
                    relay_id: "relay-eu-1".to_owned(),
                    requested_at_unix: 0,
                    ttl_secs: 60,
                },
                "requested_at_unix",
            ),
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "node-b".to_owned(),
                    relay_id: "relay-eu-1".to_owned(),
                    requested_at_unix: 500,
                    ttl_secs: 0,
                },
                "ttl",
            ),
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "node-b".to_owned(),
                    relay_id: "relay-eu-1".to_owned(),
                    requested_at_unix: 500,
                    ttl_secs: MAX_RELAY_SESSION_TOKEN_TTL_SECS + 1,
                },
                "ttl exceeds",
            ),
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "node-a".to_owned(),
                    relay_id: "relay-eu-1".to_owned(),
                    requested_at_unix: 500,
                    ttl_secs: 60,
                },
                "distinct",
            ),
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "node-b".to_owned(),
                    relay_id: "relay-éu-1".to_owned(),
                    requested_at_unix: 500,
                    ttl_secs: 60,
                },
                "ASCII",
            ),
            (
                RelaySessionTokenRequest {
                    node_id: "node-a".to_owned(),
                    peer_node_id: "missing-peer".to_owned(),
                    relay_id: "relay-eu-1".to_owned(),
                    requested_at_unix: 500,
                    ttl_secs: 60,
                },
                "peer node does not exist",
            ),
        ] {
            let err = core
                .issue_relay_session_token(request)
                .expect_err("invalid relay token request must fail closed");
            assert!(
                err.to_string().contains(expected),
                "expected error containing '{expected}', got '{err}'"
            );
        }
    }

    #[test]
    fn relay_session_token_sign_and_verify() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let vk = sk.verifying_key();

        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        // Signature must be valid
        assert!(
            token.verify_signature(&vk).is_ok(),
            "token signature must verify with correct key"
        );

        // Scope must be set correctly
        assert_eq!(token.scope, RELAY_TOKEN_SCOPE);
        assert_eq!(token.scope, "forward_ciphertext_only");
    }

    #[test]
    fn derive_endpoint_hint_signing_key_matches_control_plane_verifier() {
        let signing_secret = vec![9u8; 32];
        let core = ControlPlaneCore::new(signing_secret.clone(), PolicySet { rules: Vec::new() });
        let derived = derive_endpoint_hint_signing_key(signing_secret);
        assert_eq!(
            derived.verifying_key().as_bytes(),
            &core.endpoint_hint_verifying_key
        );
    }

    #[test]
    fn relay_session_token_rejects_wrong_key() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let wrong_sk = SigningKey::from_bytes(&[2u8; 32]);
        let wrong_vk = wrong_sk.verifying_key();

        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        // Verification with wrong key must fail
        assert!(
            token.verify_signature(&wrong_vk).is_err(),
            "token signature must not verify with wrong key"
        );
    }

    #[test]
    fn relay_session_token_rejects_tampered_signature() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let vk = sk.verifying_key();

        let mut token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);
        token.signature[0] ^= 0xFF; // Flip bits in signature

        assert!(
            token.verify_signature(&vk).is_err(),
            "tampered signature must fail verification"
        );
    }

    #[test]
    fn relay_session_token_expiry_check() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token should not be expired immediately
        assert!(
            !token.is_expired(now_unix, 0),
            "fresh token must not be expired"
        );

        // Token should be expired after TTL
        assert!(
            token.is_expired(now_unix + 120, 0),
            "token must be expired after TTL"
        );

        // Clock skew tolerance should extend validity
        assert!(
            !token.is_expired(now_unix + 70, 30),
            "token with 30s skew tolerance must not be expired at 70s"
        );
    }

    #[test]
    fn relay_session_token_ttl_calculation() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 120);

        assert_eq!(token.ttl_secs(), 120, "TTL must match requested value");
    }

    #[test]
    fn relay_session_token_ct_eq_same_tokens() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        // Same token compared to itself must be ct_eq
        assert!(token.ct_eq(&token), "token must be ct_eq to itself");

        // Clone must also be ct_eq
        let clone = token.clone();
        assert!(token.ct_eq(&clone), "cloned token must be ct_eq");
    }

    #[test]
    fn relay_session_token_ct_eq_different_nonces() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token_a = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);
        let token_b = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        // Different nonces mean tokens are not ct_eq even if other fields match
        assert!(
            !token_a.ct_eq(&token_b),
            "tokens with different nonces must not be ct_eq"
        );
    }

    #[test]
    fn relay_session_token_ct_eq_different_fields() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token_a = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);
        let token_c = RelaySessionToken::sign(&sk, "node-a", "node-c", [0xAA; 16], 60);

        assert!(
            !token_a.ct_eq(&token_c),
            "tokens with different peer_node_id must not be ct_eq"
        );
    }

    #[test]
    fn relay_session_token_canonical_payload_is_deterministic() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        let payload1 = token.canonical_payload();
        let payload2 = token.canonical_payload();

        assert_eq!(
            payload1, payload2,
            "canonical_payload must be deterministic"
        );

        // Canonical payload must contain all signed fields
        assert!(payload1.contains("version=1"));
        assert!(payload1.contains("node_id=node-a"));
        assert!(payload1.contains("peer_node_id=node-b"));
        assert!(payload1.contains(&format!("relay_id={}", hex_bytes(&[0xAA; 16]))));
        assert!(payload1.contains("scope=forward_ciphertext_only"));
    }

    #[test]
    fn relay_session_token_debug_redacts_sensitive_fields() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        let rendered = format!("{token:?}");

        // Debug output must redact sensitive fields
        assert!(rendered.contains("REDACTED"), "debug must contain REDACTED");
        assert!(
            !rendered.contains("aaaa"),
            "debug must not contain raw relay_id hex"
        );
        // node_id and peer_node_id are semi-public, so they may appear
        assert!(rendered.contains("node-a"), "debug should show node_id");
        assert!(
            rendered.contains("node-b"),
            "debug should show peer_node_id"
        );
    }

    #[test]
    fn relay_session_token_nonce_is_random() {
        use ed25519_dalek::SigningKey;

        let sk = SigningKey::from_bytes(&[1u8; 32]);
        let token_a = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);
        let token_b = RelaySessionToken::sign(&sk, "node-a", "node-b", [0xAA; 16], 60);

        // Each token must have a unique nonce (extremely unlikely to collide)
        assert_ne!(
            token_a.nonce, token_b.nonce,
            "nonces must be unique per token"
        );
    }

    /// Regression: the production relay-token issuer must call the fallible
    /// `try_sign` variant so a CSPRNG failure surfaces as a structured error
    /// rather than crashing the daemon. We pin this with a source-grep so a
    /// future refactor cannot silently route production traffic back through
    /// the panicking entry point.
    #[test]
    fn relay_session_token_issuer_uses_try_sign_in_production() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let relay_client = crate_root
            .parent()
            .expect("crates dir")
            .join("rustynetd/src/relay_client.rs");
        let body = std::fs::read_to_string(&relay_client).expect("relay_client source readable");
        // Locate the `LocalRelaySessionTokenIssuer::issue_token` impl block.
        let start = body
            .find("impl RelaySessionTokenIssuer for LocalRelaySessionTokenIssuer")
            .expect("LocalRelaySessionTokenIssuer must remain the production issuer");
        let window_end = (start + 4_000).min(body.len());
        let window = &body[start..window_end];
        assert!(
            window.contains("RelaySessionToken::try_sign("),
            "LocalRelaySessionTokenIssuer must invoke `try_sign` so the daemon \
             surfaces CSPRNG faults via RelayClientError::TokenSigning instead \
             of panicking"
        );
        assert!(
            !window.contains("RelaySessionToken::sign("),
            "LocalRelaySessionTokenIssuer must NOT invoke the panicking `sign` \
             entry point"
        );
    }

    /// Regression: `try_random_nonce_hex` must remain the only path that
    /// enrollment flows reach. The panicking legacy `random_nonce_hex` was
    /// removed; this test fires if a future change reintroduces it.
    #[test]
    fn enrollment_uses_try_random_nonce_hex() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body = std::fs::read_to_string(crate_root.join("src/lib.rs"))
            .expect("rustynet-control lib source readable");
        // Locate the enrollment functions.
        for fn_name in [
            "fn enroll_with_throwaway(",
            "fn enroll_with_throwaway_and_persist(",
        ] {
            let start = body
                .find(fn_name)
                .unwrap_or_else(|| panic!("enrollment fn `{fn_name}` missing"));
            // Take the next ~4000 chars as the window covering the body.
            let window_end = (start + 4_000).min(body.len());
            let window = &body[start..window_end];
            assert!(
                window.contains("try_random_nonce_hex("),
                "enrollment `{fn_name}` must mint nonces via `try_random_nonce_hex`"
            );
            // Build the panicking-fn name from chunks so this test's own source
            // does not match the negative grep.
            let panicking_name = ["random_nonce_", "hex("].concat();
            assert!(
                !window.contains(&panicking_name) || window.contains("try_random_nonce_hex("),
                "enrollment `{fn_name}` must not call the legacy panicking nonce minter"
            );
        }
    }

    #[test]
    fn try_random_nonce_hex_emits_distinct_high_entropy_values() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..64 {
            let nonce = super::try_random_nonce_hex(16).expect("OsRng available in test env");
            assert_eq!(nonce.len(), 32, "16 bytes hex-encoded is 32 chars");
            assert!(
                seen.insert(nonce),
                "control-plane nonce collision from CSPRNG"
            );
        }
    }

    #[test]
    fn relay_token_mint_error_displays_inner_source() {
        let err = super::RelayTokenMintError {
            source: "getrandom syscall returned EAGAIN".to_owned(),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("getrandom syscall returned EAGAIN"));
        assert!(rendered.contains("CSPRNG"));
        assert!(rendered.contains("relay session token nonce"));
    }
}
