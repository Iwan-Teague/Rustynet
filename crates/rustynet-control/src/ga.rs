#![forbid(unsafe_code)]

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityDecision {
    Supported,
    Deprecated,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityPolicyError {
    InvalidSupportWindow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityPolicy {
    pub minimum_supported_client: ApiVersion,
    pub latest_server: ApiVersion,
    pub deprecation_window_days: u32,
}

impl CompatibilityPolicy {
    pub fn validate_configuration(&self) -> Result<(), CompatibilityPolicyError> {
        if self.minimum_supported_client > self.latest_server || self.deprecation_window_days == 0 {
            return Err(CompatibilityPolicyError::InvalidSupportWindow);
        }
        Ok(())
    }

    pub fn evaluate(&self, client_version: ApiVersion) -> CompatibilityDecision {
        if self.validate_configuration().is_err() {
            return CompatibilityDecision::Unsupported;
        }

        if client_version.major != self.latest_server.major {
            return CompatibilityDecision::Unsupported;
        }

        if client_version < self.minimum_supported_client {
            return CompatibilityDecision::Unsupported;
        }

        if client_version.minor < self.latest_server.minor {
            return CompatibilityDecision::Deprecated;
        }

        CompatibilityDecision::Supported
    }

    pub fn is_supported(&self, client_version: ApiVersion) -> bool {
        matches!(
            self.evaluate(client_version),
            CompatibilityDecision::Supported | CompatibilityDecision::Deprecated
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmLifecycle {
    Allowed,
    Deprecated,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoDeprecationRecord {
    pub algorithm: String,
    pub deprecates_at_unix: u64,
    pub removal_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoDeprecationError {
    DuplicateAlgorithm,
    InvalidDeprecationWindow,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CryptoDeprecationCalendar {
    pub records: Vec<CryptoDeprecationRecord>,
}

impl CryptoDeprecationCalendar {
    pub fn validate(&self) -> Result<(), CryptoDeprecationError> {
        let mut names = BTreeSet::new();
        for record in &self.records {
            if record.algorithm.trim().is_empty() {
                return Err(CryptoDeprecationError::InvalidDeprecationWindow);
            }
            if record.removal_at_unix <= record.deprecates_at_unix {
                return Err(CryptoDeprecationError::InvalidDeprecationWindow);
            }
            if !names.insert(record.algorithm.to_ascii_lowercase()) {
                return Err(CryptoDeprecationError::DuplicateAlgorithm);
            }
        }
        Ok(())
    }

    pub fn lifecycle_for(&self, algorithm: &str, now_unix: u64) -> AlgorithmLifecycle {
        if self.validate().is_err() {
            return AlgorithmLifecycle::Denied;
        }

        let normalized = algorithm.to_ascii_lowercase();
        let Some(record) = self
            .records
            .iter()
            .find(|entry| entry.algorithm.to_ascii_lowercase() == normalized)
        else {
            return AlgorithmLifecycle::Allowed;
        };

        if now_unix >= record.removal_at_unix {
            return AlgorithmLifecycle::Denied;
        }
        if now_unix >= record.deprecates_at_unix {
            return AlgorithmLifecycle::Deprecated;
        }

        AlgorithmLifecycle::Allowed
    }

    pub fn denied_algorithms(&self, now_unix: u64) -> Vec<String> {
        if self.validate().is_err() {
            return self
                .records
                .iter()
                .map(|record| record.algorithm.to_ascii_lowercase())
                .collect();
        }

        self.records
            .iter()
            .filter(|record| now_unix >= record.removal_at_unix)
            .map(|record| record.algorithm.to_ascii_lowercase())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityExceptionError {
    MissingRiskAcceptance,
    NotEnabled,
    Expired,
    InvalidTtl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InsecureCompatibilityException {
    pub mode: String,
    pub risk_acceptance_id: String,
    pub approved_by: String,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub enabled: bool,
}

impl InsecureCompatibilityException {
    pub fn validate_active(&self, now_unix: u64) -> Result<(), CompatibilityExceptionError> {
        if self.risk_acceptance_id.trim().is_empty() || self.approved_by.trim().is_empty() {
            return Err(CompatibilityExceptionError::MissingRiskAcceptance);
        }
        if !self.enabled {
            return Err(CompatibilityExceptionError::NotEnabled);
        }
        if self.expires_at_unix <= self.created_at_unix {
            return Err(CompatibilityExceptionError::InvalidTtl);
        }
        if now_unix > self.expires_at_unix {
            return Err(CompatibilityExceptionError::Expired);
        }
        Ok(())
    }

    pub fn is_active(&self, now_unix: u64) -> bool {
        self.validate_active(now_unix).is_ok()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ErrorBudgetGate {
    pub availability_slo_percent: f64,
    pub measured_availability_percent: f64,
    pub max_error_budget_consumed_percent: f64,
    pub measured_error_budget_consumed_percent: f64,
}

impl ErrorBudgetGate {
    pub fn passes(&self) -> bool {
        self.measured_availability_percent >= self.availability_slo_percent
            && self.measured_error_budget_consumed_percent <= self.max_error_budget_consumed_percent
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PerformanceBudgetSnapshot {
    pub idle_cpu_percent: f64,
    pub idle_memory_mb: f64,
    pub reconnect_seconds: f64,
    pub route_apply_p95_seconds: f64,
    pub throughput_overhead_percent: f64,
    pub soak_test_hours: f64,
}

impl PerformanceBudgetSnapshot {
    pub fn passes(&self) -> bool {
        self.idle_cpu_percent <= 2.0
            && self.idle_memory_mb <= 120.0
            && self.reconnect_seconds <= 5.0
            && self.route_apply_p95_seconds <= 2.0
            && self.throughput_overhead_percent <= 15.0
            && self.soak_test_hours >= 24.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisasterRecoveryValidation {
    pub region_count: u8,
    pub rpo_target_minutes: u32,
    pub rto_target_minutes: u32,
    pub measured_rpo_minutes: u32,
    pub measured_rto_minutes: u32,
    pub restore_integrity_verified: bool,
}

impl DisasterRecoveryValidation {
    pub fn passes(&self) -> bool {
        self.region_count >= 2
            && self.measured_rpo_minutes <= self.rpo_target_minutes
            && self.measured_rto_minutes <= self.rto_target_minutes
            && self.restore_integrity_verified
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendAgilityValidation {
    pub default_backend: String,
    pub additional_backend_paths: u8,
    pub conformance_passed: bool,
    pub security_review_complete: bool,
    pub wireguard_is_adapter_boundary: bool,
    pub protocol_leakage_detected: bool,
}

impl BackendAgilityValidation {
    pub fn passes(&self) -> bool {
        self.default_backend.eq_ignore_ascii_case("wireguard")
            && self.additional_backend_paths >= 1
            && self.conformance_passed
            && self.security_review_complete
            && self.wireguard_is_adapter_boundary
            && !self.protocol_leakage_detected
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GaReleaseReadiness {
    pub compatibility_ok: bool,
    pub error_budget_gate: ErrorBudgetGate,
    pub performance_budget: PerformanceBudgetSnapshot,
    pub dr_validation: DisasterRecoveryValidation,
    pub backend_agility: BackendAgilityValidation,
    pub incident_drill_completed: bool,
    pub oncall_readiness_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GaGateFailure {
    Compatibility,
    ErrorBudget,
    PerformanceBudget,
    DisasterRecovery,
    BackendAgility,
    IncidentDrill,
    OnCallReadiness,
}

impl GaReleaseReadiness {
    pub fn evaluate(&self) -> Result<(), GaGateFailure> {
        if !self.compatibility_ok {
            return Err(GaGateFailure::Compatibility);
        }
        if !self.error_budget_gate.passes() {
            return Err(GaGateFailure::ErrorBudget);
        }
        if !self.performance_budget.passes() {
            return Err(GaGateFailure::PerformanceBudget);
        }
        if !self.dr_validation.passes() {
            return Err(GaGateFailure::DisasterRecovery);
        }
        if !self.backend_agility.passes() {
            return Err(GaGateFailure::BackendAgility);
        }
        if !self.incident_drill_completed {
            return Err(GaGateFailure::IncidentDrill);
        }
        if !self.oncall_readiness_confirmed {
            return Err(GaGateFailure::OnCallReadiness);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AlgorithmLifecycle, ApiVersion, BackendAgilityValidation, CompatibilityDecision,
        CompatibilityExceptionError, CompatibilityPolicy, CompatibilityPolicyError,
        CryptoDeprecationCalendar, CryptoDeprecationRecord, DisasterRecoveryValidation,
        ErrorBudgetGate, GaGateFailure, GaReleaseReadiness, InsecureCompatibilityException,
        PerformanceBudgetSnapshot,
    };

    #[test]
    fn compatibility_policy_blocks_outdated_or_cross_major_clients() {
        let policy = CompatibilityPolicy {
            minimum_supported_client: ApiVersion { major: 1, minor: 2 },
            latest_server: ApiVersion { major: 1, minor: 8 },
            deprecation_window_days: 90,
        };

        assert_eq!(
            policy.evaluate(ApiVersion { major: 1, minor: 8 }),
            CompatibilityDecision::Supported
        );
        assert_eq!(
            policy.evaluate(ApiVersion { major: 1, minor: 3 }),
            CompatibilityDecision::Deprecated
        );
        assert_eq!(
            policy.evaluate(ApiVersion { major: 1, minor: 1 }),
            CompatibilityDecision::Unsupported
        );
        assert_eq!(
            policy.evaluate(ApiVersion { major: 2, minor: 0 }),
            CompatibilityDecision::Unsupported
        );
        assert!(policy.is_supported(ApiVersion { major: 1, minor: 2 }));
    }

    #[test]
    fn compatibility_policy_rejects_invalid_window() {
        let policy = CompatibilityPolicy {
            minimum_supported_client: ApiVersion { major: 2, minor: 0 },
            latest_server: ApiVersion { major: 1, minor: 9 },
            deprecation_window_days: 0,
        };

        assert_eq!(
            policy.validate_configuration().err(),
            Some(CompatibilityPolicyError::InvalidSupportWindow)
        );
        assert_eq!(
            policy.evaluate(ApiVersion { major: 1, minor: 9 }),
            CompatibilityDecision::Unsupported
        );
    }

    #[test]
    fn crypto_calendar_enforces_deny_after_removal() {
        let calendar = CryptoDeprecationCalendar {
            records: vec![CryptoDeprecationRecord {
                algorithm: "sha1".to_string(),
                deprecates_at_unix: 100,
                removal_at_unix: 200,
            }],
        };

        assert_eq!(
            calendar.lifecycle_for("sha1", 50),
            AlgorithmLifecycle::Allowed
        );
        assert_eq!(
            calendar.lifecycle_for("sha1", 150),
            AlgorithmLifecycle::Deprecated
        );
        assert_eq!(
            calendar.lifecycle_for("sha1", 250),
            AlgorithmLifecycle::Denied
        );
        assert_eq!(calendar.denied_algorithms(250), vec!["sha1".to_string()]);
    }

    #[test]
    fn insecure_compatibility_exception_requires_explicit_active_risk_acceptance() {
        let exception = InsecureCompatibilityException {
            mode: "legacy-handshake".to_string(),
            risk_acceptance_id: "SEC-EX-014".to_string(),
            approved_by: "security-owner".to_string(),
            created_at_unix: 100,
            expires_at_unix: 120,
            enabled: true,
        };
        assert!(exception.is_active(120));
        assert!(!exception.is_active(121));

        let invalid = InsecureCompatibilityException {
            mode: "legacy-handshake".to_string(),
            risk_acceptance_id: "".to_string(),
            approved_by: "".to_string(),
            created_at_unix: 100,
            expires_at_unix: 120,
            enabled: true,
        };

        assert_eq!(
            invalid.validate_active(110).err(),
            Some(CompatibilityExceptionError::MissingRiskAcceptance)
        );
    }

    #[test]
    fn ga_release_gate_fails_closed_when_any_condition_is_unmet() {
        let readiness = GaReleaseReadiness {
            compatibility_ok: true,
            error_budget_gate: ErrorBudgetGate {
                availability_slo_percent: 99.9,
                measured_availability_percent: 99.95,
                max_error_budget_consumed_percent: 100.0,
                measured_error_budget_consumed_percent: 70.0,
            },
            performance_budget: PerformanceBudgetSnapshot {
                idle_cpu_percent: 1.2,
                idle_memory_mb: 64.0,
                reconnect_seconds: 3.0,
                route_apply_p95_seconds: 1.2,
                throughput_overhead_percent: 11.0,
                soak_test_hours: 24.2,
            },
            dr_validation: DisasterRecoveryValidation {
                region_count: 2,
                rpo_target_minutes: 15,
                rto_target_minutes: 60,
                measured_rpo_minutes: 8,
                measured_rto_minutes: 42,
                restore_integrity_verified: true,
            },
            backend_agility: BackendAgilityValidation {
                default_backend: "wireguard".to_string(),
                additional_backend_paths: 1,
                conformance_passed: true,
                security_review_complete: true,
                wireguard_is_adapter_boundary: true,
                protocol_leakage_detected: false,
            },
            incident_drill_completed: true,
            oncall_readiness_confirmed: true,
        };

        assert!(readiness.evaluate().is_ok());

        let failing = GaReleaseReadiness {
            backend_agility: BackendAgilityValidation {
                protocol_leakage_detected: true,
                ..readiness.backend_agility.clone()
            },
            ..readiness
        };
        assert_eq!(
            failing.evaluate().err(),
            Some(GaGateFailure::BackendAgility)
        );
    }

    #[test]
    fn performance_budget_enforces_phase9_targets() {
        let pass = PerformanceBudgetSnapshot {
            idle_cpu_percent: 1.9,
            idle_memory_mb: 80.0,
            reconnect_seconds: 4.5,
            route_apply_p95_seconds: 1.9,
            throughput_overhead_percent: 12.0,
            soak_test_hours: 24.0,
        };
        assert!(pass.passes());

        let fail = PerformanceBudgetSnapshot {
            idle_cpu_percent: 2.2,
            ..pass
        };
        assert!(!fail.passes());
    }
}
