#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

use subtle::ConstantTimeEq;

use crate::{TrustStateError, load_trust_state};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneReplica {
    pub id: String,
    pub healthy: bool,
    pub policy_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HaError {
    NoHealthyReplica,
}

impl fmt::Display for HaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HaError::NoHealthyReplica => f.write_str("no healthy replica"),
        }
    }
}

impl std::error::Error for HaError {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HaCluster {
    replicas: Vec<ControlPlaneReplica>,
    active_replica: Option<String>,
}

impl HaCluster {
    pub fn new(replicas: Vec<ControlPlaneReplica>) -> Self {
        Self {
            replicas,
            active_replica: None,
        }
    }

    pub fn elect_active(&mut self) -> Result<String, HaError> {
        let mut healthy = self
            .replicas
            .iter()
            .filter(|entry| entry.healthy)
            .cloned()
            .collect::<Vec<_>>();
        healthy.sort_by(|left, right| {
            right
                .policy_generation
                .cmp(&left.policy_generation)
                .then(left.id.cmp(&right.id))
        });
        let selected = healthy
            .first()
            .map(|entry| entry.id.clone())
            .ok_or(HaError::NoHealthyReplica)?;
        self.active_replica = Some(selected.clone());
        Ok(selected)
    }

    pub fn mark_unhealthy(&mut self, replica_id: &str) {
        if let Some(replica) = self
            .replicas
            .iter_mut()
            .find(|entry| entry.id == replica_id)
        {
            replica.healthy = false;
        }
        // Fail closed: if the marked replica IS the active one, the
        // stale pointer must not survive — callers reading
        // active_replica() would otherwise keep routing to a dead
        // node until someone happens to call failover().
        if self.active_replica.as_deref() == Some(replica_id) {
            self.active_replica = None;
        }
    }

    pub fn failover(&mut self) -> Result<String, HaError> {
        if let Some(active) = self.active_replica.clone() {
            self.mark_unhealthy(&active);
        }
        self.elect_active()
    }

    pub fn active_replica(&self) -> Option<&str> {
        self.active_replica.as_deref()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantRole {
    Viewer,
    DelegatedAdmin,
    GlobalAdmin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantAction {
    ViewResources,
    MutatePolicy,
    ManageUsers,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantError {
    UnknownPrincipal,
    CrossTenantDenied,
    Unauthorized,
}

impl fmt::Display for TenantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TenantError::UnknownPrincipal => f.write_str("unknown principal"),
            TenantError::CrossTenantDenied => f.write_str("cross-tenant access denied"),
            TenantError::Unauthorized => f.write_str("unauthorized"),
        }
    }
}

impl std::error::Error for TenantError {}

#[derive(Debug, Clone, Default)]
pub struct TenantBoundaryGuard {
    principals: BTreeMap<String, (String, TenantRole)>,
}

impl TenantBoundaryGuard {
    pub fn register_principal(
        &mut self,
        principal: impl Into<String>,
        tenant: impl Into<String>,
        role: TenantRole,
    ) -> Result<(), TenantError> {
        // Fail closed on absent trust state (POL-03): an empty
        // principal or tenant id is not an identity and must never
        // enter the registry.
        let principal_id: String = principal.into();
        let tenant_id: String = tenant.into();
        if principal_id.trim().is_empty() || tenant_id.trim().is_empty() {
            return Err(TenantError::UnknownPrincipal);
        }
        self.principals.insert(principal_id, (tenant_id, role));
        Ok(())
    }

    pub fn authorize(
        &self,
        principal: &str,
        target_tenant: &str,
        action: TenantAction,
    ) -> Result<(), TenantError> {
        let (principal_tenant, role) = self
            .principals
            .get(principal)
            .ok_or(TenantError::UnknownPrincipal)?;

        if *role != TenantRole::GlobalAdmin && principal_tenant != target_tenant {
            return Err(TenantError::CrossTenantDenied);
        }

        match role {
            TenantRole::Viewer => {
                if action == TenantAction::ViewResources {
                    Ok(())
                } else {
                    Err(TenantError::Unauthorized)
                }
            }
            TenantRole::DelegatedAdmin => {
                if action == TenantAction::ManageUsers {
                    Err(TenantError::Unauthorized)
                } else {
                    Ok(())
                }
            }
            TenantRole::GlobalAdmin => Ok(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OidcClaims {
    pub issuer: String,
    pub audience: String,
    pub subject: String,
    pub mfa_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnterpriseAuthConfig {
    pub issuer: String,
    pub allowed_audiences: BTreeSet<String>,
    pub require_mfa: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnterpriseAuthError {
    InvalidIssuer,
    InvalidAudience,
    InvalidSubject,
    MfaRequired,
}

impl fmt::Display for EnterpriseAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnterpriseAuthError::InvalidIssuer => f.write_str("invalid issuer"),
            EnterpriseAuthError::InvalidAudience => f.write_str("invalid audience"),
            EnterpriseAuthError::InvalidSubject => f.write_str("invalid subject"),
            EnterpriseAuthError::MfaRequired => f.write_str("mfa required"),
        }
    }
}

impl std::error::Error for EnterpriseAuthError {}

impl EnterpriseAuthConfig {
    pub fn validate_claims(&self, claims: &OidcClaims) -> Result<(), EnterpriseAuthError> {
        // OIDC core: `sub` MUST be a non-empty value identifying the
        // principal. An empty (or whitespace) subject is an invalid
        // token — never an anonymous-but-valid identity.
        if claims.subject.trim().is_empty() {
            return Err(EnterpriseAuthError::InvalidSubject);
        }
        if claims.issuer != self.issuer {
            return Err(EnterpriseAuthError::InvalidIssuer);
        }
        if !self.allowed_audiences.contains(&claims.audience) {
            return Err(EnterpriseAuthError::InvalidAudience);
        }
        if self.require_mfa && !claims.mfa_present {
            return Err(EnterpriseAuthError::MfaRequired);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TrustHardeningConfig {
    pub enabled: bool,
    pub break_glass_secret: String,
}

// RSA-0016: hand-written redacting Debug so a `{:?}` / structured-log of the
// config can never surface the plaintext break-glass secret (a derived Debug
// would print it verbatim).
impl fmt::Debug for TrustHardeningConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustHardeningConfig")
            .field("enabled", &self.enabled)
            .field("break_glass_secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustHardeningError {
    TrustState(TrustStateError),
    UnauthorizedKey,
    BreakGlassSecretInvalid,
}

impl fmt::Display for TrustHardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustHardeningError::TrustState(err) => write!(f, "trust state error: {err}"),
            TrustHardeningError::UnauthorizedKey => f.write_str("unauthorized key"),
            TrustHardeningError::BreakGlassSecretInvalid => {
                f.write_str("break-glass secret invalid")
            }
        }
    }
}

impl std::error::Error for TrustHardeningError {}

pub fn authorize_trusted_key(
    config: &TrustHardeningConfig,
    trust_state_path: impl AsRef<Path>,
    presented_fingerprint: &str,
) -> Result<(), TrustHardeningError> {
    if !config.enabled {
        return Ok(());
    }
    let trust_state =
        load_trust_state(trust_state_path).map_err(TrustHardeningError::TrustState)?;
    // Constant-time compare (RSA-0016 standard, same as break-glass
    // below): the fingerprint is the authorization-decision input, so
    // a plain `!=` short-circuit would let a caller probe it
    // byte-by-byte through timing.
    let matches: bool = trust_state
        .signing_fingerprint
        .as_bytes()
        .ct_eq(presented_fingerprint.as_bytes())
        .into();
    if !matches {
        return Err(TrustHardeningError::UnauthorizedKey);
    }
    Ok(())
}

pub fn disable_trust_hardening(
    config: &mut TrustHardeningConfig,
    submitted_break_glass_secret: &str,
) -> Result<(), TrustHardeningError> {
    // RSA-0016: constant-time compare so the break-glass secret cannot be
    // recovered byte-by-byte via a timing oracle (a plain `!=` short-circuits on
    // the first differing byte). Mirrors admin.rs's CSRF-token compare. ct_eq on
    // unequal-length slices returns 0 in constant time w.r.t. content.
    let matches: bool = submitted_break_glass_secret
        .as_bytes()
        .ct_eq(config.break_glass_secret.as_bytes())
        .into();
    if !matches {
        return Err(TrustHardeningError::BreakGlassSecretInvalid);
    }
    config.enabled = false;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{TrustState, persist_trust_state};

    use super::{
        ControlPlaneReplica, EnterpriseAuthConfig, EnterpriseAuthError, HaCluster, HaError,
        OidcClaims, TenantAction, TenantBoundaryGuard, TenantError, TenantRole,
        TrustHardeningConfig, TrustHardeningError, authorize_trusted_key, disable_trust_hardening,
    };

    #[test]
    fn marking_active_replica_unhealthy_clears_stale_active_pointer() {
        // Adversarial finding: mark_unhealthy previously left
        // active_replica pointing at the dead node, so callers polling
        // active_replica() kept routing to an unhealthy replica.
        let mut cluster = HaCluster::new(vec![
            ControlPlaneReplica {
                id: "cp-a".to_owned(),
                healthy: true,
                policy_generation: 1,
            },
            ControlPlaneReplica {
                id: "cp-b".to_owned(),
                healthy: true,
                policy_generation: 1,
            },
        ]);
        let active = cluster.elect_active().expect("elect");
        assert_eq!(active, "cp-a");
        assert_eq!(cluster.active_replica(), Some("cp-a"));

        cluster.mark_unhealthy("cp-a");
        assert_eq!(
            cluster.active_replica(),
            None,
            "stale active pointer must be cleared when the active replica dies"
        );

        // Recovery: failover re-elects the surviving replica.
        let next = cluster.failover().expect("failover to survivor");
        assert_eq!(next, "cp-b");
        assert_eq!(cluster.active_replica(), Some("cp-b"));
    }

    #[test]
    fn elect_active_breaks_generation_ties_by_replica_id() {
        // Deterministic leader choice: equal policy generations must
        // resolve by LOWEST replica id regardless of insertion order —
        // otherwise two daemons restarting could elect different
        // actives from identical state (split-brain).
        let mk = |ids: &[&str]| {
            HaCluster::new(
                ids.iter()
                    .map(|id| ControlPlaneReplica {
                        id: id.to_string(),
                        healthy: true,
                        policy_generation: 7,
                    })
                    .collect(),
            )
        };

        let inserted_b_first = mk(&["cp-b", "cp-a"]).elect_active().expect("elect");
        let inserted_a_first = mk(&["cp-a", "cp-b"]).elect_active().expect("elect");

        assert_eq!(inserted_b_first, "cp-a");
        assert_eq!(inserted_a_first, "cp-a");
        assert_eq!(
            inserted_b_first, inserted_a_first,
            "identical state must elect an identical leader"
        );
    }

    #[test]
    fn ha_cluster_fails_over_to_next_healthy_replica() {
        let mut cluster = HaCluster::new(vec![
            ControlPlaneReplica {
                id: "replica-a".to_owned(),
                healthy: true,
                policy_generation: 10,
            },
            ControlPlaneReplica {
                id: "replica-b".to_owned(),
                healthy: true,
                policy_generation: 9,
            },
        ]);

        let first = cluster
            .elect_active()
            .expect("initial election should work");
        assert_eq!(first, "replica-a");
        let second = cluster
            .failover()
            .expect("failover should select alternate");
        assert_eq!(second, "replica-b");
    }

    #[test]
    fn ha_cluster_rejects_when_no_healthy_replica_exists() {
        let mut cluster = HaCluster::new(vec![ControlPlaneReplica {
            id: "replica-a".to_owned(),
            healthy: false,
            policy_generation: 1,
        }]);
        assert_eq!(
            cluster.elect_active().err(),
            Some(HaError::NoHealthyReplica)
        );
    }

    #[test]
    fn tenant_guard_enforces_isolation_and_delegated_admin_limits() {
        let mut guard = TenantBoundaryGuard::default();
        guard
            .register_principal("alice", "tenant-a", TenantRole::DelegatedAdmin)
            .expect("valid principal registration");
        guard
            .register_principal("bob", "tenant-b", TenantRole::Viewer)
            .expect("valid principal registration");
        guard
            .register_principal("root", "global", TenantRole::GlobalAdmin)
            .expect("valid principal registration");

        assert!(
            guard
                .authorize("alice", "tenant-a", TenantAction::MutatePolicy)
                .is_ok()
        );
        assert_eq!(
            guard
                .authorize("alice", "tenant-a", TenantAction::ManageUsers)
                .err(),
            Some(TenantError::Unauthorized)
        );
        assert_eq!(
            guard
                .authorize("alice", "tenant-b", TenantAction::ViewResources)
                .err(),
            Some(TenantError::CrossTenantDenied)
        );
        assert!(
            guard
                .authorize("root", "tenant-b", TenantAction::ManageUsers)
                .is_ok()
        );
    }

    #[test]
    fn register_principal_rejects_blank_principal_or_tenant() {
        // Fail closed at registration: an empty principal or tenant
        // id is absent trust state (POL-03) and must never enter the
        // registry — a ghost identity that later authorizes actions.
        let mut guard = TenantBoundaryGuard::default();
        assert_eq!(
            guard
                .register_principal("", "tenant-a", TenantRole::DelegatedAdmin)
                .err(),
            Some(TenantError::UnknownPrincipal)
        );
        assert_eq!(
            guard
                .register_principal("alice", "", TenantRole::DelegatedAdmin)
                .err(),
            Some(TenantError::UnknownPrincipal)
        );
        // Control: valid ids still register.
        guard
            .register_principal("alice", "tenant-a", TenantRole::DelegatedAdmin)
            .expect("valid registration");
    }

    #[test]
    fn enterprise_auth_rejects_empty_subject_claims() {
        // OIDC core: `sub` MUST identify the principal and be
        // non-empty. An empty or whitespace-only subject must fail
        // closed as InvalidSubject, never authorize.
        let config = EnterpriseAuthConfig {
            issuer: "https://idp.example".to_owned(),
            allowed_audiences: BTreeSet::from(["rustynet".to_owned()]),
            require_mfa: false,
        };
        let mk = |subject: &str| OidcClaims {
            issuer: "https://idp.example".to_owned(),
            audience: "rustynet".to_owned(),
            subject: subject.to_owned(),
            mfa_present: false,
        };

        assert_eq!(
            config.validate_claims(&mk("")).err(),
            Some(EnterpriseAuthError::InvalidSubject)
        );
        assert_eq!(
            config.validate_claims(&mk("   ")).err(),
            Some(EnterpriseAuthError::InvalidSubject)
        );

        // Control: a real subject with the same config authorizes.
        assert!(config.validate_claims(&mk("alice@example.local")).is_ok());
    }

    #[test]
    fn unknown_principal_is_denied_not_silently_defaulted() {
        // Fail-closed on identity: a principal that was never
        // registered has NO tenant and NO role. Every action against
        // every tenant must be refused with UnknownPrincipal — the
        // guard must never invent a default (least-privilege or
        // otherwise) for an identity it has never seen.
        let mut guard = TenantBoundaryGuard::default();
        guard
            .register_principal("alice", "tenant-a", TenantRole::DelegatedAdmin)
            .expect("valid principal registration");

        let actions = [
            TenantAction::ViewResources,
            TenantAction::MutatePolicy,
            TenantAction::ManageUsers,
        ];
        for action in actions {
            assert_eq!(
                guard.authorize("mallory", "tenant-a", action).err(),
                Some(TenantError::UnknownPrincipal),
                "unregistered principal {action:?} must be refused"
            );
        }
    }

    #[test]
    fn enterprise_auth_validates_issuer_audience_and_mfa() {
        let config = EnterpriseAuthConfig {
            issuer: "https://id.example.local".to_owned(),
            allowed_audiences: BTreeSet::from(["rustynet-control".to_owned()]),
            require_mfa: true,
        };
        let ok = OidcClaims {
            issuer: "https://id.example.local".to_owned(),
            audience: "rustynet-control".to_owned(),
            subject: "alice".to_owned(),
            mfa_present: true,
        };
        assert!(config.validate_claims(&ok).is_ok());

        let missing_mfa = OidcClaims {
            mfa_present: false,
            ..ok.clone()
        };
        assert_eq!(
            config.validate_claims(&missing_mfa).err(),
            Some(EnterpriseAuthError::MfaRequired)
        );
    }

    #[test]
    fn trust_hardening_fails_closed_when_state_missing_or_mismatched() {
        let config = TrustHardeningConfig {
            enabled: true,
            break_glass_secret: "break-glass".to_owned(),
        };
        let unique_dir = format!(
            "rustynet-trust-hardening-dir-{}",
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

        let missing_path = test_dir.join("missing.state");
        let missing = authorize_trusted_key(&config, &missing_path, "ed25519:abc");
        match missing.err() {
            Some(TrustHardeningError::TrustState(_)) => {}
            other => panic!("unexpected missing-state result: {other:?}"),
        }

        let path = test_dir.join("trust.state");
        persist_trust_state(
            &path,
            &TrustState {
                generation: 1,
                signing_fingerprint: "ed25519:trusted".to_owned(),
                updated_at_unix: 100,
            },
        )
        .expect("trust state should persist");

        assert_eq!(
            authorize_trusted_key(&config, &path, "ed25519:other").err(),
            Some(TrustHardeningError::UnauthorizedKey)
        );
        assert!(authorize_trusted_key(&config, &path, "ed25519:trusted").is_ok());

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(format!("{}.integrity.key", path.display()));
        let _ = std::fs::remove_dir(&test_dir);
    }

    #[test]
    fn trust_hardening_disable_requires_break_glass_secret() {
        let mut config = TrustHardeningConfig {
            enabled: true,
            break_glass_secret: "break-glass".to_owned(),
        };
        assert_eq!(
            disable_trust_hardening(&mut config, "bad-secret").err(),
            Some(TrustHardeningError::BreakGlassSecretInvalid)
        );
        disable_trust_hardening(&mut config, "break-glass")
            .expect("valid break-glass should disable");
        assert!(!config.enabled);
    }

    #[test]
    fn trust_hardening_disable_rejects_wrong_length_secret_constant_time() {
        // RSA-0016: a different-length submission must also be rejected (the
        // ct_eq path returns 0 for unequal lengths), not just a same-length
        // mismatch.
        let mut config = TrustHardeningConfig {
            enabled: true,
            break_glass_secret: "break-glass".to_owned(),
        };
        assert_eq!(
            disable_trust_hardening(&mut config, "x").err(),
            Some(TrustHardeningError::BreakGlassSecretInvalid)
        );
        assert!(config.enabled, "a wrong secret must not disable hardening");
    }

    #[test]
    fn trust_hardening_config_debug_redacts_break_glass_secret() {
        // RSA-0016: the secret must never appear in Debug output.
        let config = TrustHardeningConfig {
            enabled: true,
            break_glass_secret: "super-secret-break-glass-value".to_owned(),
        };
        let rendered = format!("{config:?}");
        assert!(
            !rendered.contains("super-secret-break-glass-value"),
            "Debug must not surface the break-glass secret: {rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
