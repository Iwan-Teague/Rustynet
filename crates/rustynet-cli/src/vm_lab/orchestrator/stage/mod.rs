#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;

pub mod active_exit;
pub mod admin_issue;
pub mod anchor_validation;
pub mod authenticode_validation;
pub mod blind_exit;
pub mod cleanup;
pub mod collect_pubkeys;
pub mod deploy_relay;
pub mod distribute_assignments;
pub mod distribute_dns_zone;
pub mod distribute_membership;
pub mod distribute_traversal;
pub mod dns_failclosed_validation;
pub mod enforce_runtime;
pub mod exit_handoff;
pub mod final_cleanup;
pub mod install;
pub mod key_custody_validation;
pub mod membership_init;
pub mod mesh_status_validation;
pub mod preflight;
pub mod relay_validation;
pub mod role_switch_matrix;
pub mod runtime_acls_validation;
pub mod security_audit_validation;
pub mod service_hardening_validation;
pub mod source_archive;
pub mod traffic_test_matrix;
pub mod validate_runtime;
pub mod verify_ssh;

/// Enumerated stage IDs — not a String alias.
/// Matches the 16 stages from the bash orchestrator plus cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum StageId {
    Preflight,
    PrepareSourceArchive,
    VerifySshReachability,
    CleanupHosts,
    BootstrapHosts,
    CollectPubkeys,
    MembershipInit,
    DistributeMembership,
    AnchorValidation,
    AdminIssue,
    BlindExit,
    DistributeAssignments,
    DistributeTraversal,
    DistributeDnsZone,
    EnforceBaselineRuntime,
    ValidateBaselineRuntime,
    SecurityAuditValidation,
    DnsFailclosedValidation,
    RuntimeAclsValidation,
    ServiceHardeningValidation,
    KeyCustodyValidation,
    MeshStatusValidation,
    AuthenticodeValidation,
    DeployRelayService,
    RelayValidation,
    TrafficTestMatrix,
    RoleSwitchMatrix,
    ExitHandoff,
    ActiveExit,
    Cleanup,
}

impl StageId {
    /// Every variant, in pipeline order — the drift gate asserts each is
    /// registered in `live_lab_stage_registry` (finding 1D).
    pub const ALL: [StageId; 30] = [
        StageId::Preflight,
        StageId::PrepareSourceArchive,
        StageId::VerifySshReachability,
        StageId::CleanupHosts,
        StageId::BootstrapHosts,
        StageId::CollectPubkeys,
        StageId::MembershipInit,
        StageId::DistributeMembership,
        StageId::AnchorValidation,
        StageId::AdminIssue,
        StageId::BlindExit,
        StageId::DistributeAssignments,
        StageId::DistributeTraversal,
        StageId::DistributeDnsZone,
        StageId::EnforceBaselineRuntime,
        StageId::ValidateBaselineRuntime,
        StageId::SecurityAuditValidation,
        StageId::DnsFailclosedValidation,
        StageId::RuntimeAclsValidation,
        StageId::ServiceHardeningValidation,
        StageId::KeyCustodyValidation,
        StageId::MeshStatusValidation,
        StageId::AuthenticodeValidation,
        StageId::DeployRelayService,
        StageId::RelayValidation,
        StageId::TrafficTestMatrix,
        StageId::RoleSwitchMatrix,
        StageId::ExitHandoff,
        StageId::ActiveExit,
        StageId::Cleanup,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            StageId::Preflight => "preflight",
            StageId::PrepareSourceArchive => "prepare_source_archive",
            StageId::VerifySshReachability => "verify_ssh_reachability",
            StageId::CleanupHosts => "cleanup_hosts",
            StageId::BootstrapHosts => "bootstrap_hosts",
            StageId::CollectPubkeys => "collect_pubkeys",
            StageId::MembershipInit => "membership_init",
            StageId::DistributeMembership => "distribute_membership",
            StageId::AnchorValidation => "anchor_validation",
            StageId::AdminIssue => "admin_issue",
            StageId::BlindExit => "blind_exit",
            StageId::DistributeAssignments => "distribute_assignments",
            StageId::DistributeTraversal => "distribute_traversal",
            StageId::DistributeDnsZone => "distribute_dns_zone",
            StageId::EnforceBaselineRuntime => "enforce_baseline_runtime",
            StageId::ValidateBaselineRuntime => "validate_baseline_runtime",
            StageId::SecurityAuditValidation => "security_audit_validation",
            StageId::DnsFailclosedValidation => "dns_failclosed_validation",
            StageId::RuntimeAclsValidation => "runtime_acls_validation",
            StageId::ServiceHardeningValidation => "service_hardening_validation",
            StageId::KeyCustodyValidation => "key_custody_validation",
            StageId::MeshStatusValidation => "mesh_status_validation",
            StageId::AuthenticodeValidation => "authenticode_validation",
            StageId::DeployRelayService => "deploy_relay_service",
            StageId::RelayValidation => "relay_validation",
            StageId::TrafficTestMatrix => "traffic_test_matrix",
            StageId::RoleSwitchMatrix => "role_switch_matrix",
            StageId::ExitHandoff => "exit_handoff",
            StageId::ActiveExit => "active_exit",
            StageId::Cleanup => "cleanup",
        }
    }
}

impl std::fmt::Display for StageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TryFrom<&str> for StageId {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        StageId::ALL
            .iter()
            .find(|s| s.as_str() == value)
            .cloned()
            .ok_or_else(|| format!("unknown Rust-native stage: '{}'", value))
    }
}

/// How a stage fans out across nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageFanout {
    /// Execute once for the whole lab (e.g. membership-init on exit node).
    Once,
    /// Execute once per role-matched node.
    PerNode,
}

/// One stage in the orchestration pipeline. One impl per stage file.
pub trait OrchestrationStage: Send + Sync {
    fn id(&self) -> StageId;
    fn name(&self) -> &str;

    /// Stages that must pass before this one runs.
    /// Failure or skip of a dependency triggers skip-cascade on this stage.
    fn dependencies(&self) -> &[StageId];

    /// Which roles this stage operates on. Empty slice = all roles.
    fn applies_to_roles(&self) -> &[NodeRole];

    fn fanout(&self) -> StageFanout;

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome;

    /// Teardown stages that MUST run even when an earlier stage failed —
    /// exempt from dependency skip-cascade so this run's own killswitch / exit
    /// NAT residue is always removed from the guests (leaving residue is a
    /// release-blocker per the operating contract). An `always_run` stage is
    /// still ordered after its [`dependencies`](Self::dependencies) and is
    /// still honored by an explicit `--skip-stage`; it is only exempt from
    /// being *cascade*-skipped because a dependency failed. Default `false`.
    fn always_run(&self) -> bool {
        false
    }
}
