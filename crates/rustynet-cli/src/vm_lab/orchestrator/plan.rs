#![allow(dead_code)]
//! # Adding a stage to the Rust `--node` plan
//!
//! The stage catalog in `stage/mod.rs` is the single typed authority
//! (RNQ-16): one catalog row carries the `StageId` variant, its canonical
//! pipeline position, its wire name, its suite tag, and its acceptance tier
//! (A1 — `NodeEngineAcceptanceSpec_2026-07-23.md` §3). Plan membership +
//! order derive from it, the registry rust-native predicate and the
//! run-matrix oracle derive from `StageId::try_from`, and the instantiation
//! match below is compiler-enforced exhaustive. Touch, in order:
//!
//! 1. `stage/mod.rs` — ONE catalog row:
//!    `Variant => "wire_name" @ Suite / Tier`, at the stage's true pipeline
//!    position, plus `pub mod <file>;`. The tier token is REQUIRED — a row
//!    without one does not compile (the acceptance spec's totality gate).
//! 2. `stage/<name>.rs` — the `OrchestrationStage` impl (id / dependencies /
//!    applies_to_roles / fanout / execute; override `always_run` for teardown).
//! 3. `plan.rs` (this file) — the compiler now FORCES one `Box::new(<Stage>)`
//!    arm in `build`'s exhaustive match (position no longer matters — order
//!    comes from the catalog). Update `build_returns_N_stages` + the
//!    canonical-order list in `mod tests` (the independent order pin).
//! 4. `vm_lab/mod.rs` — the `rust_native_cli_stage_ids_match_plan_builder`
//!    absolute-count assert (`cli_ids.len() == N`).
//! 5. `live_lab_stage_registry.rs` — the `StageSpec` entry (the extensibility
//!    gate asserts every `StageId::ALL` member is registered — finding 1D).
//!    `rust_native` is DERIVED from `StageId` (no flag to set); add
//!    cross-os/special column fields only if the stage owns such a column
//!    (mirrored by `oracle_cross_os_column`/`oracle_special_column` in
//!    `live_lab_run_matrix.rs` tests).
//! 6. `rustynet-mcp/.../repo_context.rs` — add the row to the
//!    `ORCHESTRATOR_STAGES` doc table and the `EXPECTED` list in
//!    `orchestrator_stages_doc_matches_the_rust_planbuilder` (cross-crate
//!    string gate; keep it equal to `StageId::ALL` order).
use crate::vm_lab::orchestrator::stage::OrchestrationStage;
use crate::vm_lab::orchestrator::stage::active_exit::ActiveExitStage;
use crate::vm_lab::orchestrator::stage::admin_issue::AdminIssueStage;
use crate::vm_lab::orchestrator::stage::anchor_validation::AnchorValidationStage;
use crate::vm_lab::orchestrator::stage::authenticode_validation::AuthenticodeValidationStage;
use crate::vm_lab::orchestrator::stage::blind_exit::BlindExitStage;
use crate::vm_lab::orchestrator::stage::blind_exit_dataplane_validation::BlindExitDataplaneValidationStage;
use crate::vm_lab::orchestrator::stage::chaos::{
    ChaosClockAttackStage, ChaosCrashRecoveryStage, ChaosDaemonFaultStage,
    ChaosDaemonSigstopSigcontStage, ChaosMembershipAdversarialStage, ChaosNetworkImpairmentStage,
    ChaosPrivilegedBoundaryStage, ChaosResourceExhaustionStage, ChaosSignedStateAdversarialStage,
};
use crate::vm_lab::orchestrator::stage::cleanup::CleanupHostsStage;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::CollectPubkeysStage;
use crate::vm_lab::orchestrator::stage::cross_network::{
    CrossNetworkControllerSwitchStage, CrossNetworkDirectRemoteExitStage,
    CrossNetworkFailbackRoamingStage, CrossNetworkNatClassificationStage,
    CrossNetworkNatMatrixStage, CrossNetworkNodeNetworkSwitchStage, CrossNetworkOptions,
    CrossNetworkPreflightStage, CrossNetworkRelayRemoteExitStage, CrossNetworkRemoteExitDnsStage,
    CrossNetworkRemoteExitSoakStage, CrossNetworkTraversalAdversarialStage,
};
use crate::vm_lab::orchestrator::stage::deploy_relay::DeployRelayServiceStage;
use crate::vm_lab::orchestrator::stage::distribute_assignments::DistributeAssignmentsStage;
use crate::vm_lab::orchestrator::stage::distribute_dns_zone::DistributeDnsZoneStage;
use crate::vm_lab::orchestrator::stage::distribute_membership::DistributeMembershipStage;
use crate::vm_lab::orchestrator::stage::distribute_traversal::DistributeTraversalStage;
use crate::vm_lab::orchestrator::stage::dns_failclosed_validation::DnsFailclosedValidationStage;
use crate::vm_lab::orchestrator::stage::enforce_runtime::EnforceBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::exit_demotion_residue_validation::ExitDemotionResidueValidationStage;
use crate::vm_lab::orchestrator::stage::exit_dns_failclosed_validation::ExitDnsFailclosedValidationStage;
use crate::vm_lab::orchestrator::stage::exit_handoff::ExitHandoffStage;
use crate::vm_lab::orchestrator::stage::exit_nat_lifecycle_validation::ExitNatLifecycleValidationStage;
use crate::vm_lab::orchestrator::stage::final_cleanup::FinalCleanupStage;
use crate::vm_lab::orchestrator::stage::install::BootstrapHostsStage;
use crate::vm_lab::orchestrator::stage::ipv6_leak_validation::Ipv6LeakValidationStage;
use crate::vm_lab::orchestrator::stage::key_custody_validation::KeyCustodyValidationStage;
use crate::vm_lab::orchestrator::stage::live_anchor::LiveAnchorStage;
use crate::vm_lab::orchestrator::stage::live_enrollment_restart_validation::LiveEnrollmentRestartValidationStage;
use crate::vm_lab::orchestrator::stage::live_extended_soak_validation::LiveExtendedSoakValidationStage;
use crate::vm_lab::orchestrator::stage::live_hello_limiter_flood_validation::LiveHelloLimiterFloodValidationStage;
use crate::vm_lab::orchestrator::stage::live_key_custody_validation::LiveKeyCustodyValidationStage;
use crate::vm_lab::orchestrator::stage::live_lan_toggle_validation::LiveLanToggleValidationStage;
use crate::vm_lab::orchestrator::stage::live_managed_dns_validation::LiveManagedDnsValidationStage;
use crate::vm_lab::orchestrator::stage::live_mixed_topology_validation::LiveMixedTopologyValidationStage;
use crate::vm_lab::orchestrator::stage::live_network_flap_validation::LiveNetworkFlapValidationStage;
use crate::vm_lab::orchestrator::stage::live_reboot_recovery_validation::LiveRebootRecoveryValidationStage;
use crate::vm_lab::orchestrator::stage::live_secrets_not_in_logs_validation::LiveSecretsNotInLogsValidationStage;
use crate::vm_lab::orchestrator::stage::live_two_hop_validation::LiveTwoHopValidationStage;
use crate::vm_lab::orchestrator::stage::membership_init::MembershipInitStage;
use crate::vm_lab::orchestrator::stage::mesh_status_validation::MeshStatusValidationStage;
use crate::vm_lab::orchestrator::stage::preflight::PreflightStage;
use crate::vm_lab::orchestrator::stage::relay_validation::RelayValidationStage;
use crate::vm_lab::orchestrator::stage::role_switch_matrix::RoleSwitchMatrixStage;
use crate::vm_lab::orchestrator::stage::runtime_acls_validation::RuntimeAclsValidationStage;
use crate::vm_lab::orchestrator::stage::security_audit_validation::SecurityAuditValidationStage;
use crate::vm_lab::orchestrator::stage::service_hardening_validation::ServiceHardeningValidationStage;
use crate::vm_lab::orchestrator::stage::source_archive::{
    ArchiveSourceMode, PrepareSourceArchiveStage,
};
use crate::vm_lab::orchestrator::stage::traffic_test_matrix::TrafficTestMatrixStage;
use crate::vm_lab::orchestrator::stage::validate_runtime::ValidateBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::verify_ssh::VerifySshReachabilityStage;

/// Builds the ordered list of stages for a lab run.
#[derive(Default)]
pub struct PlanBuilder {
    /// `--rebuild-nodes`: when `Some`, only these aliases rebuild in
    /// `bootstrap_hosts`; `None` rebuilds every node (the default).
    rebuild_only: Option<Vec<String>>,
    /// `--source-mode`: which tree the shipped source archive is built from.
    source_mode: ArchiveSourceMode,
    /// `--skip-linux-live-suite`: when true, drop the post-baseline live
    /// validation + role stages ([`Self::live_suite_stages`]) so the plan runs
    /// only setup → baseline → cleanup. The fast inner loop (mesh-health check /
    /// mac-win cell iteration) that the MCP loop tooling already emits.
    skip_live_suite: bool,
    /// `--enable-chaos-suite`: append the opt-in chaos stages. They remain
    /// outside the default plan so a normal live lab does not inject faults.
    enable_chaos_suite: bool,
    /// `--skip-soak`: drop the long-running extended soak composite.
    skip_soak: bool,
    /// `--skip-cross-network`: when false, run the Rust-owned cross-network
    /// suite. Same-subnet/non-substrate cases are stage-level Skipped.
    cross_network: CrossNetworkOptions,
    /// Maximum concurrent per-node adapter operations.
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl PlanBuilder {
    /// The post-baseline live-validation + role stages, dropped when
    /// `--skip-linux-live-suite` is set. Setup (through `validate_baseline_runtime`)
    /// and the always-run `cleanup` are never in this set. Derived from the
    /// stage catalog's suite tags (RNQ-16) — cannot drift from `StageId::ALL`.
    pub fn live_suite_stages() -> Vec<crate::vm_lab::orchestrator::stage::StageId> {
        Self::stages_in_suite(crate::vm_lab::orchestrator::stage::StageSuite::Live)
    }

    pub fn soak_suite_stages() -> Vec<crate::vm_lab::orchestrator::stage::StageId> {
        Self::stages_in_suite(crate::vm_lab::orchestrator::stage::StageSuite::Soak)
    }

    pub fn chaos_suite_stages() -> Vec<crate::vm_lab::orchestrator::stage::StageId> {
        Self::stages_in_suite(crate::vm_lab::orchestrator::stage::StageSuite::Chaos)
    }

    pub fn cross_network_suite_stages() -> Vec<crate::vm_lab::orchestrator::stage::StageId> {
        Self::stages_in_suite(crate::vm_lab::orchestrator::stage::StageSuite::CrossNetwork)
    }

    fn stages_in_suite(
        suite: crate::vm_lab::orchestrator::stage::StageSuite,
    ) -> Vec<crate::vm_lab::orchestrator::stage::StageId> {
        crate::vm_lab::orchestrator::stage::StageId::ALL
            .iter()
            .filter(|id| id.suite() == suite)
            .cloned()
            .collect()
    }

    pub fn new() -> Self {
        PlanBuilder::default()
    }

    /// Limit `bootstrap_hosts` rebuilds to the named aliases (fast single-node
    /// iteration). `None` keeps the default rebuild-all behaviour.
    pub fn with_rebuild_only(mut self, rebuild_only: Option<Vec<String>>) -> Self {
        self.rebuild_only = rebuild_only;
        self
    }

    /// Select the source archive mode (committed `HEAD` vs working tree).
    pub fn with_source_mode(mut self, source_mode: ArchiveSourceMode) -> Self {
        self.source_mode = source_mode;
        self
    }

    /// `--skip-linux-live-suite`: drop the post-baseline live-validation + role
    /// stages, keeping only setup → baseline → cleanup.
    pub fn with_skip_live_suite(mut self, skip_live_suite: bool) -> Self {
        self.skip_live_suite = skip_live_suite;
        self
    }

    /// Append the opt-in chaos stages to the plan.
    pub fn with_enable_chaos_suite(mut self, enable_chaos_suite: bool) -> Self {
        self.enable_chaos_suite = enable_chaos_suite;
        self
    }

    pub fn with_skip_soak(mut self, skip_soak: bool) -> Self {
        self.skip_soak = skip_soak;
        self
    }

    pub fn with_cross_network_options(mut self, cross_network: CrossNetworkOptions) -> Self {
        self.cross_network = cross_network;
        self
    }

    pub fn with_max_parallel_node_workers(mut self, max_workers: usize) -> Self {
        self.max_parallel_node_workers = max_workers.max(1);
        self
    }

    pub fn with_shutdown_flag(
        mut self,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        self.shutdown_flag = shutdown_flag;
        self
    }

    pub fn build(self) -> Vec<Box<dyn OrchestrationStage>> {
        use crate::vm_lab::orchestrator::stage::{StageId, StageSuite};
        let PlanBuilder {
            rebuild_only,
            source_mode,
            skip_live_suite,
            enable_chaos_suite,
            skip_soak,
            cross_network,
            max_parallel_node_workers,
            shutdown_flag,
        } = self;

        // Suite-inclusion authority (RNQ-16): the plan is StageId::ALL in
        // canonical order, filtered by each stage's catalog suite tag.
        // `--skip-linux-live-suite` keeps only setup → baseline → cleanup
        // (cleanup is always-run teardown and is never dropped, so this
        // run's own killswitch / exit-NAT residue is still removed).
        let include = |suite: StageSuite| -> bool {
            match suite {
                StageSuite::Setup | StageSuite::Cleanup => true,
                StageSuite::Live => !skip_live_suite,
                StageSuite::Soak => !skip_live_suite && !skip_soak,
                StageSuite::CrossNetwork => !skip_live_suite && cross_network.enable_suite,
                StageSuite::Chaos => !skip_live_suite && enable_chaos_suite,
            }
        };

        // One instantiation arm per stage, compiler-enforced exhaustive: a
        // new StageId variant fails to compile here until it gets an arm, so
        // plan membership can no longer silently drift from the catalog.
        StageId::ALL
            .iter()
            .filter(|id| include(id.suite()))
            .map(|id| -> Box<dyn OrchestrationStage> {
                match id {
                    StageId::Preflight => Box::new(PreflightStage),
                    StageId::PrepareSourceArchive => {
                        Box::new(PrepareSourceArchiveStage::new(source_mode))
                    }
                    StageId::VerifySshReachability => Box::new(VerifySshReachabilityStage),
                    // cleanup + bootstrap must share the same rebuild set: a
                    // node we refuse to clean must also be refused a rebuild
                    // (and vice versa).
                    StageId::CleanupHosts => Box::new(CleanupHostsStage::new(rebuild_only.clone())),
                    StageId::BootstrapHosts => Box::new(BootstrapHostsStage::new(
                        rebuild_only.clone(),
                        max_parallel_node_workers,
                        std::sync::Arc::clone(&shutdown_flag),
                    )),
                    StageId::CollectPubkeys => Box::new(CollectPubkeysStage),
                    StageId::MembershipInit => Box::new(MembershipInitStage),
                    StageId::DistributeMembership => Box::new(DistributeMembershipStage),
                    // Anchor capability-advertisement proof for any Anchor
                    // node — after the membership snapshot is distributed and
                    // before assignments.
                    StageId::AnchorValidation => Box::new(AnchorValidationStage),
                    StageId::AdminIssue => Box::new(AdminIssueStage),
                    StageId::BlindExit => Box::new(BlindExitStage),
                    StageId::DistributeAssignments => Box::new(DistributeAssignmentsStage::new(
                        max_parallel_node_workers,
                        std::sync::Arc::clone(&shutdown_flag),
                    )),
                    StageId::DistributeTraversal => Box::new(DistributeTraversalStage::new(
                        max_parallel_node_workers,
                        std::sync::Arc::clone(&shutdown_flag),
                    )),
                    StageId::DistributeDnsZone => Box::new(DistributeDnsZoneStage::new(
                        max_parallel_node_workers,
                        std::sync::Arc::clone(&shutdown_flag),
                    )),
                    StageId::EnforceBaselineRuntime => Box::new(EnforceBaselineRuntimeStage::new(
                        max_parallel_node_workers,
                        std::sync::Arc::clone(&shutdown_flag),
                    )),
                    StageId::ValidateBaselineRuntime => {
                        Box::new(ValidateBaselineRuntimeStage::new(
                            max_parallel_node_workers,
                            std::sync::Arc::clone(&shutdown_flag),
                        ))
                    }
                    // Eight Tier-0 adversarial daemon self-audits — after
                    // baseline-runtime validation, before the traffic matrix.
                    StageId::SecurityAuditValidation => Box::new(SecurityAuditValidationStage),
                    StageId::DnsFailclosedValidation => Box::new(DnsFailclosedValidationStage),
                    StageId::RuntimeAclsValidation => Box::new(RuntimeAclsValidationStage),
                    StageId::ServiceHardeningValidation => {
                        Box::new(ServiceHardeningValidationStage)
                    }
                    StageId::KeyCustodyValidation => Box::new(KeyCustodyValidationStage),
                    StageId::MeshStatusValidation => Box::new(MeshStatusValidationStage),
                    StageId::AuthenticodeValidation => Box::new(AuthenticodeValidationStage),
                    StageId::Ipv6LeakValidation => Box::new(Ipv6LeakValidationStage),
                    // Deploy the rustynet-relay sibling service onto every
                    // Relay node so relay_validation has a live relay to prove.
                    StageId::DeployRelayService => Box::new(DeployRelayServiceStage),
                    StageId::RelayValidation => Box::new(RelayValidationStage),
                    StageId::TrafficTestMatrix => Box::new(TrafficTestMatrixStage),
                    StageId::RoleSwitchMatrix => Box::new(RoleSwitchMatrixStage),
                    StageId::ExitHandoff => Box::new(ExitHandoffStage),
                    StageId::ActiveExit => Box::new(ActiveExitStage),
                    StageId::ExitDnsFailclosedValidation => {
                        Box::new(ExitDnsFailclosedValidationStage)
                    }
                    StageId::ExitNatLifecycleValidation => {
                        Box::new(ExitNatLifecycleValidationStage)
                    }
                    StageId::ExitDemotionResidueValidation => {
                        Box::new(ExitDemotionResidueValidationStage)
                    }
                    StageId::BlindExitDataplaneValidation => {
                        Box::new(BlindExitDataplaneValidationStage)
                    }
                    StageId::LiveAnchor => Box::new(LiveAnchorStage),
                    StageId::LiveTwoHopValidation => Box::new(LiveTwoHopValidationStage),
                    StageId::LiveManagedDnsValidation => Box::new(LiveManagedDnsValidationStage),
                    StageId::LiveNetworkFlapValidation => Box::new(LiveNetworkFlapValidationStage),
                    StageId::LiveRebootRecoveryValidation => {
                        Box::new(LiveRebootRecoveryValidationStage)
                    }
                    StageId::LiveSecretsNotInLogsValidation => {
                        Box::new(LiveSecretsNotInLogsValidationStage)
                    }
                    StageId::LiveKeyCustodyValidation => Box::new(LiveKeyCustodyValidationStage),
                    StageId::LiveEnrollmentRestartValidation => {
                        Box::new(LiveEnrollmentRestartValidationStage)
                    }
                    StageId::LiveLanToggleValidation => Box::new(LiveLanToggleValidationStage),
                    StageId::LiveMixedTopologyValidation => {
                        Box::new(LiveMixedTopologyValidationStage)
                    }
                    StageId::LiveHelloLimiterFloodValidation => {
                        Box::new(LiveHelloLimiterFloodValidationStage)
                    }
                    StageId::LiveExtendedSoakValidation => {
                        Box::new(LiveExtendedSoakValidationStage)
                    }
                    StageId::CrossNetworkPreflight => {
                        Box::new(CrossNetworkPreflightStage::new(cross_network.clone()))
                    }
                    StageId::CrossNetworkDirectRemoteExit => Box::new(
                        CrossNetworkDirectRemoteExitStage::new(cross_network.clone()),
                    ),
                    StageId::CrossNetworkNodeNetworkSwitch => Box::new(
                        CrossNetworkNodeNetworkSwitchStage::new(cross_network.clone()),
                    ),
                    StageId::CrossNetworkRelayRemoteExit => {
                        Box::new(CrossNetworkRelayRemoteExitStage::new(cross_network.clone()))
                    }
                    StageId::CrossNetworkFailbackRoaming => {
                        Box::new(CrossNetworkFailbackRoamingStage::new(cross_network.clone()))
                    }
                    StageId::CrossNetworkControllerSwitch => Box::new(
                        CrossNetworkControllerSwitchStage::new(cross_network.clone()),
                    ),
                    StageId::CrossNetworkTraversalAdversarial => Box::new(
                        CrossNetworkTraversalAdversarialStage::new(cross_network.clone()),
                    ),
                    StageId::CrossNetworkRemoteExitDns => {
                        Box::new(CrossNetworkRemoteExitDnsStage::new(cross_network.clone()))
                    }
                    StageId::CrossNetworkRemoteExitSoak => {
                        Box::new(CrossNetworkRemoteExitSoakStage::new(cross_network.clone()))
                    }
                    StageId::CrossNetworkNatClassification => Box::new(
                        CrossNetworkNatClassificationStage::new(cross_network.clone()),
                    ),
                    StageId::CrossNetworkNatMatrix => {
                        Box::new(CrossNetworkNatMatrixStage::new(cross_network.clone()))
                    }
                    StageId::ChaosClockAttack => Box::new(ChaosClockAttackStage),
                    StageId::ChaosCrashRecovery => Box::new(ChaosCrashRecoveryStage),
                    StageId::ChaosDaemonFault => Box::new(ChaosDaemonFaultStage),
                    StageId::ChaosDaemonSigstopSigcont => Box::new(ChaosDaemonSigstopSigcontStage),
                    StageId::ChaosMembershipAdversarial => {
                        Box::new(ChaosMembershipAdversarialStage)
                    }
                    StageId::ChaosNetworkImpairment => Box::new(ChaosNetworkImpairmentStage),
                    StageId::ChaosPrivilegedBoundary => Box::new(ChaosPrivilegedBoundaryStage),
                    StageId::ChaosResourceExhaustion => Box::new(ChaosResourceExhaustionStage),
                    StageId::ChaosSignedStateAdversarial => {
                        Box::new(ChaosSignedStateAdversarialStage)
                    }
                    StageId::Cleanup => Box::new(FinalCleanupStage::new(rebuild_only.clone())),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_returns_58_stages() {
        let stages = PlanBuilder::new().build();
        assert_eq!(stages.len(), 58, "plan must contain exactly 58 stages");
    }

    #[test]
    fn chaos_suite_opt_in_appends_9_fault_stages() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().with_enable_chaos_suite(true).build();
        let ids: Vec<StageId> = stages.iter().map(|stage| stage.id()).collect();
        assert_eq!(ids.len(), 67, "chaos-enabled plan must contain 67 stages");
        for chaos_id in PlanBuilder::chaos_suite_stages() {
            assert!(
                ids.contains(&chaos_id),
                "chaos-enabled plan must include {chaos_id:?}"
            );
        }
        assert!(
            ids.iter().position(|id| id == &StageId::ChaosClockAttack)
                > ids
                    .iter()
                    .position(|id| id == &StageId::LiveMixedTopologyValidation)
        );
        assert_eq!(ids.last(), Some(&StageId::Cleanup));
    }

    #[test]
    fn skip_live_suite_drops_the_post_baseline_suite_but_keeps_setup_and_cleanup() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().with_skip_live_suite(true).build();
        let ids: Vec<StageId> = stages.iter().map(|s| s.id()).collect();
        // 58 total - 29 live-suite stages - 11 cross-network stages - 1 soak stage = 17.
        assert_eq!(
            ids.len(),
            58 - PlanBuilder::live_suite_stages().len()
                - PlanBuilder::cross_network_suite_stages().len()
                - PlanBuilder::soak_suite_stages().len()
        );
        for dropped in PlanBuilder::live_suite_stages() {
            assert!(
                !ids.contains(&dropped),
                "live-suite stage {dropped:?} must be dropped"
            );
        }
        for dropped in PlanBuilder::cross_network_suite_stages() {
            assert!(
                !ids.contains(&dropped),
                "skip-live-suite must drop cross-network stage {dropped:?}"
            );
        }
        for dropped in PlanBuilder::soak_suite_stages() {
            assert!(
                !ids.contains(&dropped),
                "skip-live-suite must drop soak stage {dropped:?}"
            );
        }
        // Setup boundary + the always-run cleanup remain.
        assert!(ids.contains(&StageId::ValidateBaselineRuntime));
        assert!(ids.contains(&StageId::BootstrapHosts));
        assert_eq!(
            ids.last(),
            Some(&StageId::Cleanup),
            "cleanup must still run last so guest residue is torn down"
        );
    }

    #[test]
    fn skip_live_suite_drops_opt_in_chaos_too() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new()
            .with_enable_chaos_suite(true)
            .with_skip_live_suite(true)
            .build();
        let ids: Vec<StageId> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(
            ids.len(),
            58 - PlanBuilder::live_suite_stages().len()
                - PlanBuilder::cross_network_suite_stages().len()
                - PlanBuilder::soak_suite_stages().len()
        );
        for dropped in PlanBuilder::chaos_suite_stages() {
            assert!(
                !ids.contains(&dropped),
                "skip-live-suite must drop opt-in chaos stage {dropped:?}"
            );
        }
        assert_eq!(ids.last(), Some(&StageId::Cleanup));
    }

    #[test]
    fn build_returns_canonical_security_stage_order() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let ids: Vec<_> = stages.iter().map(|stage| stage.id()).collect();

        assert_eq!(
            ids,
            vec![
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
                StageId::DistributeAssignments,
                StageId::DistributeTraversal,
                StageId::DistributeDnsZone,
                StageId::EnforceBaselineRuntime,
                StageId::BlindExit,
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
                StageId::ExitDnsFailclosedValidation,
                StageId::ExitNatLifecycleValidation,
                StageId::ExitDemotionResidueValidation,
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
                StageId::LiveHelloLimiterFloodValidation,
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
                StageId::Cleanup,
            ],
            "orchestrator stage order is security-sensitive"
        );
    }

    #[test]
    fn skip_soak_drops_extended_soak_only() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().with_skip_soak(true).build();
        let ids: Vec<StageId> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(ids.len(), 57);
        assert!(!ids.contains(&StageId::LiveExtendedSoakValidation));
        assert!(ids.contains(&StageId::LiveMixedTopologyValidation));
        assert!(ids.contains(&StageId::CrossNetworkPreflight));
        assert_eq!(ids.last(), Some(&StageId::Cleanup));
    }

    #[test]
    fn disabled_cross_network_options_drop_only_cross_network_suite() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let cross_network = CrossNetworkOptions {
            enable_suite: false,
            ..CrossNetworkOptions::default()
        };
        let stages = PlanBuilder::new()
            .with_cross_network_options(cross_network)
            .build();
        let ids: Vec<StageId> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(
            ids.len(),
            58 - PlanBuilder::cross_network_suite_stages().len()
        );
        for dropped in PlanBuilder::cross_network_suite_stages() {
            assert!(
                !ids.contains(&dropped),
                "disabled cross-network suite must drop {dropped:?}"
            );
        }
        assert!(ids.contains(&StageId::LiveExtendedSoakValidation));
        assert!(ids.contains(&StageId::TrafficTestMatrix));
        assert_eq!(ids.last(), Some(&StageId::Cleanup));
    }

    #[test]
    fn active_exit_runs_after_exit_handoff_and_before_cleanup() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::ActiveExit) > pos(StageId::ExitHandoff));
        assert!(pos(StageId::ActiveExit) < pos(StageId::BlindExitDataplaneValidation));
        assert!(pos(StageId::ActiveExit) < pos(StageId::Cleanup));
    }

    #[test]
    fn anchor_validation_runs_after_distribute_membership_and_before_distribute_assignments() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::AnchorValidation) > pos(StageId::DistributeMembership));
        assert!(pos(StageId::AnchorValidation) < pos(StageId::DistributeAssignments));
    }

    #[test]
    fn relay_validation_runs_after_baseline_runtime_and_before_traffic_matrix() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::RelayValidation) > pos(StageId::ValidateBaselineRuntime));
        assert!(pos(StageId::RelayValidation) < pos(StageId::TrafficTestMatrix));
    }

    #[test]
    fn deploy_relay_service_runs_after_baseline_runtime_and_before_relay_validation() {
        // The relay runtime must be deployed before relay_validation probes it.
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::DeployRelayService) > pos(StageId::ValidateBaselineRuntime));
        assert!(pos(StageId::DeployRelayService) < pos(StageId::RelayValidation));
    }

    #[test]
    fn stage_ids_are_unique() {
        use std::collections::HashSet;
        let stages = PlanBuilder::new().build();
        let ids: HashSet<_> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(ids.len(), stages.len(), "all stage IDs must be unique");
    }

    #[test]
    fn chaos_stage_ids_are_unique_when_enabled() {
        use std::collections::HashSet;
        let stages = PlanBuilder::new().with_enable_chaos_suite(true).build();
        let ids: HashSet<_> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(
            ids.len(),
            stages.len(),
            "all chaos-enabled stage IDs must be unique"
        );
    }
}
