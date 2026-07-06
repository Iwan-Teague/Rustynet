#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;

pub mod active_exit;
pub mod admin_issue;
pub mod anchor_validation;
pub mod authenticode_validation;
pub mod blind_exit;
pub mod blind_exit_dataplane_validation;
pub mod chaos;
pub mod cleanup;
pub mod collect_pubkeys;
pub mod cross_network;
pub mod deploy_relay;
pub mod distribute_assignments;
pub mod distribute_dns_zone;
pub mod distribute_membership;
pub mod distribute_traversal;
pub mod dns_failclosed_validation;
pub mod enforce_runtime;
pub mod exit_demotion_residue_validation;
pub mod exit_dns_failclosed_validation;
pub mod exit_handoff;
pub mod exit_nat_lifecycle_validation;
pub mod final_cleanup;
pub mod install;
pub mod ipv6_leak_validation;
pub mod key_custody_validation;
pub mod live_anchor;
pub mod live_enrollment_restart_validation;
pub mod live_extended_soak_validation;
pub mod live_key_custody_validation;
pub mod live_lan_toggle_validation;
pub mod live_managed_dns_validation;
pub mod live_mixed_topology_validation;
pub mod live_network_flap_validation;
pub mod live_reboot_recovery_validation;
pub mod live_secrets_not_in_logs_validation;
pub mod live_two_hop_validation;
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
    Ipv6LeakValidation,
    LiveAnchor,
    LiveTwoHopValidation,
    LiveManagedDnsValidation,
    LiveNetworkFlapValidation,
    LiveRebootRecoveryValidation,
    LiveSecretsNotInLogsValidation,
    LiveKeyCustodyValidation,
    LiveEnrollmentRestartValidation,
    LiveLanToggleValidation,
    LiveMixedTopologyValidation,
    LiveExtendedSoakValidation,
    CrossNetworkPreflight,
    CrossNetworkDirectRemoteExit,
    CrossNetworkNodeNetworkSwitch,
    CrossNetworkRelayRemoteExit,
    CrossNetworkFailbackRoaming,
    CrossNetworkControllerSwitch,
    CrossNetworkTraversalAdversarial,
    CrossNetworkRemoteExitDns,
    CrossNetworkRemoteExitSoak,
    CrossNetworkNatClassification,
    CrossNetworkNatMatrix,
    ChaosClockAttack,
    ChaosCrashRecovery,
    ChaosDaemonFault,
    ChaosDaemonSigstopSigcont,
    ChaosMembershipAdversarial,
    ChaosNetworkImpairment,
    ChaosPrivilegedBoundary,
    ChaosResourceExhaustion,
    ChaosSignedStateAdversarial,
    DeployRelayService,
    RelayValidation,
    TrafficTestMatrix,
    RoleSwitchMatrix,
    ExitHandoff,
    ActiveExit,
    ExitDemotionResidueValidation,
    ExitDnsFailclosedValidation,
    ExitNatLifecycleValidation,
    BlindExitDataplaneValidation,
    Cleanup,
}

impl StageId {
    /// Every variant, in pipeline order — the drift gate asserts each is
    /// registered in `live_lab_stage_registry` (finding 1D).
    pub const ALL: [StageId; 66] = [
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
        StageId::Ipv6LeakValidation,
        StageId::DeployRelayService,
        StageId::RelayValidation,
        StageId::TrafficTestMatrix,
        StageId::RoleSwitchMatrix,
        StageId::ExitHandoff,
        StageId::ActiveExit,
        StageId::ExitDemotionResidueValidation,
        StageId::ExitDnsFailclosedValidation,
        StageId::ExitNatLifecycleValidation,
        StageId::BlindExitDataplaneValidation,
        StageId::LiveAnchor,
        StageId::LiveTwoHopValidation,
        StageId::LiveManagedDnsValidation,
        StageId::LiveNetworkFlapValidation,
        StageId::LiveRebootRecoveryValidation,
        StageId::LiveSecretsNotInLogsValidation,
        StageId::LiveKeyCustodyValidation,
        StageId::LiveEnrollmentRestartValidation,
        StageId::LiveLanToggleValidation,
        StageId::LiveMixedTopologyValidation,
        StageId::LiveExtendedSoakValidation,
        StageId::CrossNetworkPreflight,
        StageId::CrossNetworkDirectRemoteExit,
        StageId::CrossNetworkNodeNetworkSwitch,
        StageId::CrossNetworkRelayRemoteExit,
        StageId::CrossNetworkFailbackRoaming,
        StageId::CrossNetworkControllerSwitch,
        StageId::CrossNetworkTraversalAdversarial,
        StageId::CrossNetworkRemoteExitDns,
        StageId::CrossNetworkRemoteExitSoak,
        StageId::CrossNetworkNatClassification,
        StageId::CrossNetworkNatMatrix,
        StageId::ChaosClockAttack,
        StageId::ChaosCrashRecovery,
        StageId::ChaosDaemonFault,
        StageId::ChaosDaemonSigstopSigcont,
        StageId::ChaosMembershipAdversarial,
        StageId::ChaosNetworkImpairment,
        StageId::ChaosPrivilegedBoundary,
        StageId::ChaosResourceExhaustion,
        StageId::ChaosSignedStateAdversarial,
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
            StageId::Ipv6LeakValidation => "ipv6_leak_validation",
            StageId::LiveAnchor => "live_anchor",
            StageId::LiveTwoHopValidation => "live_two_hop_validation",
            StageId::LiveManagedDnsValidation => "live_managed_dns_validation",
            StageId::LiveNetworkFlapValidation => "live_network_flap_validation",
            StageId::LiveRebootRecoveryValidation => "live_reboot_recovery_validation",
            StageId::LiveSecretsNotInLogsValidation => "live_secrets_not_in_logs_validation",
            StageId::LiveKeyCustodyValidation => "live_key_custody_validation",
            StageId::LiveEnrollmentRestartValidation => "live_enrollment_restart_validation",
            StageId::LiveLanToggleValidation => "live_lan_toggle_validation",
            StageId::LiveMixedTopologyValidation => "live_mixed_topology_validation",
            StageId::LiveExtendedSoakValidation => "extended_soak",
            StageId::CrossNetworkPreflight => "cross_network_preflight",
            StageId::CrossNetworkDirectRemoteExit => "cross_network_direct_remote_exit",
            StageId::CrossNetworkNodeNetworkSwitch => "cross_network_node_network_switch",
            StageId::CrossNetworkRelayRemoteExit => "cross_network_relay_remote_exit",
            StageId::CrossNetworkFailbackRoaming => "cross_network_failback_roaming",
            StageId::CrossNetworkControllerSwitch => "cross_network_controller_switch",
            StageId::CrossNetworkTraversalAdversarial => "cross_network_traversal_adversarial",
            StageId::CrossNetworkRemoteExitDns => "cross_network_remote_exit_dns",
            StageId::CrossNetworkRemoteExitSoak => "cross_network_remote_exit_soak",
            StageId::CrossNetworkNatClassification => "cross_network_nat_classification",
            StageId::CrossNetworkNatMatrix => "cross_network_nat_matrix",
            StageId::ChaosClockAttack => "chaos_clock_attack",
            StageId::ChaosCrashRecovery => "chaos_crash_recovery",
            StageId::ChaosDaemonFault => "chaos_daemon_fault",
            StageId::ChaosDaemonSigstopSigcont => "chaos_daemon_sigstop_sigcont",
            StageId::ChaosMembershipAdversarial => "chaos_membership_adversarial",
            StageId::ChaosNetworkImpairment => "chaos_network_impairment",
            StageId::ChaosPrivilegedBoundary => "chaos_privileged_boundary",
            StageId::ChaosResourceExhaustion => "chaos_resource_exhaustion",
            StageId::ChaosSignedStateAdversarial => "chaos_signed_state_adversarial",
            StageId::DeployRelayService => "deploy_relay_service",
            StageId::RelayValidation => "relay_validation",
            StageId::TrafficTestMatrix => "traffic_test_matrix",
            StageId::RoleSwitchMatrix => "role_switch_matrix",
            StageId::ExitHandoff => "exit_handoff",
            StageId::ActiveExit => "active_exit",
            StageId::ExitDemotionResidueValidation => "exit_demotion_residue_validation",
            StageId::ExitDnsFailclosedValidation => "exit_dns_failclosed_validation",
            StageId::ExitNatLifecycleValidation => "exit_nat_lifecycle_validation",
            StageId::BlindExitDataplaneValidation => "blind_exit_dataplane_validation",
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
