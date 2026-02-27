#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;

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
    ) {
        self.principals
            .insert(principal.into(), (tenant.into(), role));
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
    MfaRequired,
}

impl fmt::Display for EnterpriseAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EnterpriseAuthError::InvalidIssuer => f.write_str("invalid issuer"),
            EnterpriseAuthError::InvalidAudience => f.write_str("invalid audience"),
            EnterpriseAuthError::MfaRequired => f.write_str("mfa required"),
        }
    }
}

impl std::error::Error for EnterpriseAuthError {}

impl EnterpriseAuthConfig {
    pub fn validate_claims(&self, claims: &OidcClaims) -> Result<(), EnterpriseAuthError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustHardeningConfig {
    pub enabled: bool,
    pub break_glass_secret: String,
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
    if trust_state.signing_fingerprint != presented_fingerprint {
        return Err(TrustHardeningError::UnauthorizedKey);
    }
    Ok(())
}

pub fn disable_trust_hardening(
    config: &mut TrustHardeningConfig,
    submitted_break_glass_secret: &str,
) -> Result<(), TrustHardeningError> {
    if submitted_break_glass_secret != config.break_glass_secret {
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
    fn ha_cluster_fails_over_to_next_healthy_replica() {
        let mut cluster = HaCluster::new(vec![
            ControlPlaneReplica {
                id: "replica-a".to_string(),
                healthy: true,
                policy_generation: 10,
            },
            ControlPlaneReplica {
                id: "replica-b".to_string(),
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
            id: "replica-a".to_string(),
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
        guard.register_principal("alice", "tenant-a", TenantRole::DelegatedAdmin);
        guard.register_principal("bob", "tenant-b", TenantRole::Viewer);
        guard.register_principal("root", "global", TenantRole::GlobalAdmin);

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
    fn enterprise_auth_validates_issuer_audience_and_mfa() {
        let config = EnterpriseAuthConfig {
            issuer: "https://id.example.local".to_string(),
            allowed_audiences: BTreeSet::from(["rustynet-control".to_string()]),
            require_mfa: true,
        };
        let ok = OidcClaims {
            issuer: "https://id.example.local".to_string(),
            audience: "rustynet-control".to_string(),
            subject: "alice".to_string(),
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
            break_glass_secret: "break-glass".to_string(),
        };
        let missing_path = std::env::temp_dir().join("rustynet-trust-hardening-missing");
        let missing = authorize_trusted_key(&config, &missing_path, "ed25519:abc");
        match missing.err() {
            Some(TrustHardeningError::TrustState(_)) => {}
            other => panic!("unexpected missing-state result: {other:?}"),
        }

        let unique = format!(
            "rustynet-trust-hardening-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        persist_trust_state(
            &path,
            &TrustState {
                generation: 1,
                signing_fingerprint: "ed25519:trusted".to_string(),
                updated_at_unix: 100,
            },
        )
        .expect("trust state should persist");

        assert_eq!(
            authorize_trusted_key(&config, &path, "ed25519:other").err(),
            Some(TrustHardeningError::UnauthorizedKey)
        );
        assert!(authorize_trusted_key(&config, &path, "ed25519:trusted").is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn trust_hardening_disable_requires_break_glass_secret() {
        let mut config = TrustHardeningConfig {
            enabled: true,
            break_glass_secret: "break-glass".to_string(),
        };
        assert_eq!(
            disable_trust_hardening(&mut config, "bad-secret").err(),
            Some(TrustHardeningError::BreakGlassSecretInvalid)
        );
        disable_trust_hardening(&mut config, "break-glass")
            .expect("valid break-glass should disable");
        assert!(!config.enabled);
    }
}
