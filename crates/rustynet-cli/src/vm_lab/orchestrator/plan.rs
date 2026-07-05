#![allow(dead_code)]
//! # Adding a stage to the Rust `--node` plan
//!
//! A new stage is a single source-of-truth item (its `StageId`), but it is
//! surfaced in seven places that drift gates + full-suite asserts enforce.
//! Adding a stage without updating all seven fails CI (each at a different
//! test scope — the extensibility/drift gates catch the registry/doc omissions,
//! the full `cargo test` suite catches the count + oracle omissions). Touch, in
//! order:
//!
//! 1. `stage/mod.rs` — add the `StageId` variant, extend `StageId::ALL: [_; N]`
//!    (bump N), add the `as_str` arm, and `pub mod <file>;`.
//! 2. `stage/<name>.rs` — the `OrchestrationStage` impl (id / dependencies /
//!    applies_to_roles / fanout / execute; override `always_run` for teardown).
//! 3. `plan.rs` (this file) — `Box::new(<Stage>)` at the right pipeline
//!    position, and update `build_returns_N_stages` + the canonical-order list
//!    in `mod tests`.
//! 4. `vm_lab/mod.rs` — the `rust_native_cli_stage_ids_match_plan_builder`
//!    absolute-count assert (`cli_ids.len() == N`).
//! 5. `live_lab_stage_registry.rs` — the `StageSpec` entry (the extensibility
//!    gate asserts every `StageId::ALL` member is registered — finding 1D).
//! 6. `live_lab_run_matrix.rs` — if the stage is rust-native, add it to the
//!    `oracle_is_rust_native` historical copy (it also drives the
//!    `registry_matches_historical_platform_resolution` expected-platform
//!    branch); add `oracle_cross_os_column` / `oracle_special_column` arms only
//!    if the stage owns such a column.
//! 7. `rustynet-mcp/.../repo_context.rs` — add the row to the
//!    `ORCHESTRATOR_STAGES` doc table and the `EXPECTED` list in
//!    `orchestrator_stages_doc_matches_the_rust_planbuilder` (the drift gate
//!    asserts the doc == `StageId::ALL`).
use crate::vm_lab::orchestrator::stage::OrchestrationStage;
use crate::vm_lab::orchestrator::stage::active_exit::ActiveExitStage;
use crate::vm_lab::orchestrator::stage::anchor_validation::AnchorValidationStage;
use crate::vm_lab::orchestrator::stage::cleanup::CleanupHostsStage;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::CollectPubkeysStage;
use crate::vm_lab::orchestrator::stage::deploy_relay::DeployRelayServiceStage;
use crate::vm_lab::orchestrator::stage::distribute_assignments::DistributeAssignmentsStage;
use crate::vm_lab::orchestrator::stage::distribute_dns_zone::DistributeDnsZoneStage;
use crate::vm_lab::orchestrator::stage::distribute_membership::DistributeMembershipStage;
use crate::vm_lab::orchestrator::stage::distribute_traversal::DistributeTraversalStage;
use crate::vm_lab::orchestrator::stage::enforce_runtime::EnforceBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::exit_handoff::ExitHandoffStage;
use crate::vm_lab::orchestrator::stage::final_cleanup::FinalCleanupStage;
use crate::vm_lab::orchestrator::stage::install::BootstrapHostsStage;
use crate::vm_lab::orchestrator::stage::membership_init::MembershipInitStage;
use crate::vm_lab::orchestrator::stage::preflight::PreflightStage;
use crate::vm_lab::orchestrator::stage::relay_validation::RelayValidationStage;
use crate::vm_lab::orchestrator::stage::role_switch_matrix::RoleSwitchMatrixStage;
use crate::vm_lab::orchestrator::stage::security_audit_validation::SecurityAuditValidationStage;
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
}

impl PlanBuilder {
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

    pub fn build(self) -> Vec<Box<dyn OrchestrationStage>> {
        let PlanBuilder {
            rebuild_only,
            source_mode,
        } = self;
        vec![
            Box::new(PreflightStage),
            Box::new(PrepareSourceArchiveStage::new(source_mode)),
            Box::new(VerifySshReachabilityStage),
            // cleanup + bootstrap must share the same rebuild set: a node we
            // refuse to clean must also be refused a rebuild (and vice versa).
            Box::new(CleanupHostsStage::new(rebuild_only.clone())),
            Box::new(BootstrapHostsStage::new(rebuild_only)),
            Box::new(CollectPubkeysStage),
            Box::new(MembershipInitStage),
            Box::new(DistributeMembershipStage),
            // Anchor capability-advertisement proof for any Anchor node —
            // folds the capability-advertisement surface of the formerly
            // Linux-only anchor test bin in, cross-OS. Runs after the
            // membership snapshot is distributed (so the daemon can derive
            // the anchor view) and before assignments are distributed.
            Box::new(AnchorValidationStage),
            Box::new(DistributeAssignmentsStage),
            Box::new(DistributeTraversalStage),
            Box::new(DistributeDnsZoneStage),
            Box::new(EnforceBaselineRuntimeStage),
            Box::new(ValidateBaselineRuntimeStage),
            // Eight Tier-0 adversarial daemon self-audits (membership-revoke,
            // revoked-peer-denied, signature-forgery, privileged-helper-allowlist,
            // policy-default-deny, gossip-revoked-readmit, enrollment-replay,
            // hello-limiter-flood) — folds the formerly bash-only Linux security
            // suite into the Rust engine. After baseline-runtime validation (the
            // daemon must be up + baseline-good) and before the traffic matrix.
            Box::new(SecurityAuditValidationStage),
            // Deploy the rustynet-relay sibling service onto every Relay node
            // (verifier key + `ops install-systemd-relay`) so relay_validation
            // has a live relay to prove. Closes the gap where the standard
            // orchestrator advertised relay_host in membership but never
            // installed the relay runtime. Runs after baseline-runtime
            // validation (no network needed) and before relay_validation.
            Box::new(DeployRelayServiceStage),
            // Relay-service-lifecycle proof for any Relay node — folds the
            // formerly Linux-only relay test bin in, cross-OS. Runs after
            // the relay runtime is deployed, before the traffic matrix.
            Box::new(RelayValidationStage),
            Box::new(TrafficTestMatrixStage),
            Box::new(RoleSwitchMatrixStage),
            Box::new(ExitHandoffStage),
            Box::new(ActiveExitStage),
            Box::new(FinalCleanupStage),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_returns_22_stages() {
        let stages = PlanBuilder::new().build();
        assert_eq!(stages.len(), 22, "plan must contain exactly 22 stages");
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
                StageId::DistributeAssignments,
                StageId::DistributeTraversal,
                StageId::DistributeDnsZone,
                StageId::EnforceBaselineRuntime,
                StageId::ValidateBaselineRuntime,
                StageId::SecurityAuditValidation,
                StageId::DeployRelayService,
                StageId::RelayValidation,
                StageId::TrafficTestMatrix,
                StageId::RoleSwitchMatrix,
                StageId::ExitHandoff,
                StageId::ActiveExit,
                StageId::Cleanup,
            ],
            "orchestrator stage order is security-sensitive"
        );
    }

    #[test]
    fn active_exit_runs_after_exit_handoff_and_before_cleanup() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::ActiveExit) > pos(StageId::ExitHandoff));
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
}
