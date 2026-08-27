//! SignedMembership transition signing sub-flow — pure step sequencer.
//!
//! D-4a (`SignedMembershipTransitionSigningSubflowDesign_2026-08-27.md`):
//! encodes the §10.7 side-effect ordering invariants for capability-changing
//! role transitions as an explicit, testable step sequence. The sequencer is
//! PURE — it performs no I/O, no signing, and no IPC. It exists so that any
//! future executor (CLI one-shot, live-lab stage, operator wizard) consumes
//! ONE canonical ordering instead of re-deriving it, and so the ordering is
//! provable by unit test rather than asserted by comment.
//!
//! Ordering decree (CLAUDE.md §10.7, NodeRoleTaxonomy_2026-05-21.md §10,
//! SecurityMinimumBar §6.D control 7):
//!
//! - Adding a capability with a capability-providing sibling service
//!   (`serves_relay` / `serves_nas` / `serves_llm` / `anchor.relay_colocation`):
//!   deploy the service BEFORE the signed bundle advertises the capability.
//! - Removing such a capability: undeploy the service BEFORE the signed
//!   revocation publishes.
//! - `serves_exit` is the documented inversion on the ADD side
//!   (`role_cli.rs` admin→exit arm): the admin-gated
//!   `RouteAdvertise 0.0.0.0/0` IPC IS the atomic exit-serving bring-up and
//!   ownership signal, so it leads; the exit preflight unit follows. On the
//!   REMOVE side the §10.7 teardown rule holds strictly: preflight down,
//!   route retracted, and only then the signed revocation — exit NAT residue
//!   after capability revocation is a release-blocking defect.
//! - All local side-effects precede the signing phase. The signing phase is
//!   deliberately abstract here ([`SubflowStep::CollectApproverSignatures`]):
//!   WHERE the approver key lives and WHO drives the signing session is an
//!   owner-facing custody decision (design doc §4) that this sequencer must
//!   not prejudge. The only thing it encodes is that signing happens after
//!   local effects and before publication.
//!
//! The step vocabulary intentionally mirrors the executable
//! `role_cli::ConcreteAction` order produced by `plan_role_set` so the two
//! cannot silently diverge — the CLI crate's contract tests compare them.

use crate::role_presets::{
    Capability, RolePreset, ServiceKind, TransitionKind, TransitionPlan, transition_plan,
};

/// One step of the SignedMembership sub-flow, in execution order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubflowStep {
    /// Rewrite the local primary-role config (env file / plist /
    /// service config) when the transition also changes the primary
    /// role. Local, reversible, rides along per `TransitionKind`
    /// docs.
    UpdatePrimaryRoleConfig,
    /// Admin-gated `RouteAdvertise 0.0.0.0/0` IPC — the atomic
    /// exit-serving bring-up (leads the exit ADD pair by decree; see
    /// module docs).
    AdvertiseExitRoute,
    /// Install/enable the platform exit preflight unit (host-kernel
    /// forwarding evidence; NOT the NAT owner).
    DeployExitPreflight,
    /// Install, enable, start, and health-verify a capability-providing
    /// sibling service. MUST precede the signed advertisement.
    DeployService(ServiceKind),
    /// Stop, disable, and remove a sibling service. MUST precede the
    /// signed revocation.
    UndeployService(ServiceKind),
    /// Tear down the platform exit preflight. MUST precede the signed
    /// revocation.
    UndeployExitPreflight,
    /// `RouteRetract 0.0.0.0/0` IPC — tears down exit-serving
    /// forwarding/NAT. MUST precede the signed revocation.
    RetractExitRoute,
    /// Build the unsigned `SetNodeCapabilities`
    /// `MembershipUpdateRecord` for the destination capability set
    /// (existing builders only: `membership propose-set-capabilities`
    /// / `anchor advertise` shape; RSA-0009 state-root preview rule
    /// applies).
    EmitUnsignedCapabilityRecord,
    /// External signing session(s) with the membership approver
    /// key(s) — `membership sign-update`. The key never moves; the
    /// step runs wherever the key already legitimately lives. With
    /// quorum > 1 the sub-flow stops after this step if the artifact
    /// is still below threshold (partially-signed is a terminal,
    /// reportable state for automation).
    CollectApproverSignatures,
    /// Verify + apply the quorum-signed update through the verified
    /// membership apply path (`membership apply-update [--daemon]`;
    /// signature → epoch/replay watermark → apply).
    PublishSignedUpdate,
    /// `StateRefresh` IPC on the transitioning node so the daemon
    /// re-reads signed state through
    /// `refresh_signed_state_with_reason` (the ONE verified apply
    /// path).
    RefreshSignedState,
}

/// Why a sub-flow sequence could not be produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubflowError {
    /// The transition is not a SignedMembership transition — the
    /// signing sub-flow does not apply (fail closed rather than
    /// return an empty sequence a caller might execute).
    NotSignedMembership(TransitionKind),
}

impl std::fmt::Display for SubflowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubflowError::NotSignedMembership(kind) => write!(
                f,
                "signing sub-flow only applies to SignedMembership transitions (got {kind:?})"
            ),
        }
    }
}

/// Compute the canonical ordered step sequence for a SignedMembership
/// transition plan. Pure. Errors (fail closed) on any other
/// transition kind.
///
/// Local-side-effect order mirrors `role_cli::plan_role_set`'s
/// generic SignedMembership arm exactly:
/// primary-role config write → exit ADD pair (advertise → preflight)
/// → sibling deploys → sibling undeploys → exit REMOVE pair
/// (preflight down → retract) → emit → sign → publish → refresh.
pub fn signing_subflow_steps(plan: &TransitionPlan) -> Result<Vec<SubflowStep>, SubflowError> {
    if plan.kind != TransitionKind::SignedMembership {
        return Err(SubflowError::NotSignedMembership(plan.kind.clone()));
    }
    let mut steps = Vec::new();
    if plan.primary_change.is_some() {
        steps.push(SubflowStep::UpdatePrimaryRoleConfig);
    }
    if plan.adds_capabilities.contains(&Capability::ServesExit) {
        steps.push(SubflowStep::AdvertiseExitRoute);
        steps.push(SubflowStep::DeployExitPreflight);
    }
    for &kind in plan.service_deploys.iter() {
        steps.push(SubflowStep::DeployService(kind));
    }
    for &kind in plan.service_undeploys.iter() {
        steps.push(SubflowStep::UndeployService(kind));
    }
    if plan.removes_capabilities.contains(&Capability::ServesExit) {
        steps.push(SubflowStep::UndeployExitPreflight);
        steps.push(SubflowStep::RetractExitRoute);
    }
    steps.push(SubflowStep::EmitUnsignedCapabilityRecord);
    steps.push(SubflowStep::CollectApproverSignatures);
    steps.push(SubflowStep::PublishSignedUpdate);
    steps.push(SubflowStep::RefreshSignedState);
    Ok(steps)
}

/// Convenience: sequence for a `from → to` preset pair.
pub fn signing_subflow_for(
    from: RolePreset,
    to: RolePreset,
) -> Result<Vec<SubflowStep>, SubflowError> {
    signing_subflow_steps(&transition_plan(from, to))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idx(steps: &[SubflowStep], step: &SubflowStep) -> usize {
        steps
            .iter()
            .position(|s| s == step)
            .unwrap_or_else(|| panic!("step {step:?} missing from {steps:?}"))
    }

    fn all_signed_membership_pairs() -> Vec<(RolePreset, RolePreset)> {
        let mut pairs = Vec::new();
        for &from in RolePreset::all().iter() {
            for &to in RolePreset::all().iter() {
                if transition_plan(from, to).kind == TransitionKind::SignedMembership {
                    pairs.push((from, to));
                }
            }
        }
        assert!(
            !pairs.is_empty(),
            "preset matrix must contain SignedMembership cells"
        );
        pairs
    }

    /// §10.7 ADD invariant: every service deploy precedes the
    /// unsigned-record emission (deploy → sign → publish).
    #[test]
    fn every_deploy_precedes_record_emission() {
        for (from, to) in all_signed_membership_pairs() {
            let steps = signing_subflow_for(from, to).expect("signed membership");
            let emit = idx(&steps, &SubflowStep::EmitUnsignedCapabilityRecord);
            for (i, step) in steps.iter().enumerate() {
                if matches!(
                    step,
                    SubflowStep::DeployService(_)
                        | SubflowStep::DeployExitPreflight
                        | SubflowStep::AdvertiseExitRoute
                ) {
                    assert!(i < emit, "{from}->{to}: {step:?} must precede emission");
                }
            }
        }
    }

    /// §10.7 REMOVE invariant: every undeploy precedes the revocation
    /// record emission (undeploy → revoke).
    #[test]
    fn every_undeploy_precedes_record_emission() {
        for (from, to) in all_signed_membership_pairs() {
            let steps = signing_subflow_for(from, to).expect("signed membership");
            let emit = idx(&steps, &SubflowStep::EmitUnsignedCapabilityRecord);
            for (i, step) in steps.iter().enumerate() {
                if matches!(
                    step,
                    SubflowStep::UndeployService(_)
                        | SubflowStep::UndeployExitPreflight
                        | SubflowStep::RetractExitRoute
                ) {
                    assert!(i < emit, "{from}->{to}: {step:?} must precede emission");
                }
            }
        }
    }

    /// Signing-phase order is fixed and terminal:
    /// emit → collect signatures → publish → refresh.
    #[test]
    fn signing_phase_order_is_emit_sign_publish_refresh() {
        for (from, to) in all_signed_membership_pairs() {
            let steps = signing_subflow_for(from, to).expect("signed membership");
            let emit = idx(&steps, &SubflowStep::EmitUnsignedCapabilityRecord);
            let sign = idx(&steps, &SubflowStep::CollectApproverSignatures);
            let publish = idx(&steps, &SubflowStep::PublishSignedUpdate);
            let refresh = idx(&steps, &SubflowStep::RefreshSignedState);
            assert!(emit < sign && sign < publish && publish < refresh);
            assert_eq!(refresh, steps.len() - 1, "refresh must be terminal");
        }
    }

    /// Exit ADD pair: advertise (atomic bring-up) leads the preflight
    /// deploy — the documented `role_cli.rs` admin→exit inversion.
    #[test]
    fn exit_add_advertise_leads_preflight() {
        let steps =
            signing_subflow_for(RolePreset::Admin, RolePreset::Exit).expect("signed membership");
        assert!(
            idx(&steps, &SubflowStep::AdvertiseExitRoute)
                < idx(&steps, &SubflowStep::DeployExitPreflight)
        );
    }

    /// Exit REMOVE pair: preflight teardown precedes route retract,
    /// and both precede the revocation emission (§10.7 residue rule).
    #[test]
    fn exit_remove_teardown_precedes_retract_and_revocation() {
        let steps =
            signing_subflow_for(RolePreset::Exit, RolePreset::Admin).expect("signed membership");
        let undeploy = idx(&steps, &SubflowStep::UndeployExitPreflight);
        let retract = idx(&steps, &SubflowStep::RetractExitRoute);
        let emit = idx(&steps, &SubflowStep::EmitUnsignedCapabilityRecord);
        assert!(undeploy < retract && retract < emit);
    }

    /// Sibling deploys precede sibling undeploys (new capability's
    /// service up before the old one goes down — mirrors the
    /// `role_cli` generic arm).
    #[test]
    fn deploys_precede_undeploys() {
        for (from, to) in all_signed_membership_pairs() {
            let steps = signing_subflow_for(from, to).expect("signed membership");
            let first_undeploy = steps
                .iter()
                .position(|s| matches!(s, SubflowStep::UndeployService(_)));
            let last_deploy = steps
                .iter()
                .rposition(|s| matches!(s, SubflowStep::DeployService(_)));
            if let (Some(u), Some(d)) = (first_undeploy, last_deploy) {
                assert!(d < u, "{from}->{to}: deploys must precede undeploys");
            }
        }
    }

    /// Non-SignedMembership transitions fail closed rather than
    /// returning an executable (empty or misleading) sequence.
    #[test]
    fn non_signed_membership_kinds_are_rejected() {
        for (from, to) in [
            (RolePreset::Admin, RolePreset::Admin),      // Identity
            (RolePreset::Admin, RolePreset::Client),     // LocalOnly
            (RolePreset::BlindExit, RolePreset::Client), // Blocked
            (RolePreset::Client, RolePreset::BlindExit), // Irreversible
        ] {
            let err = signing_subflow_for(from, to).expect_err("must reject");
            assert!(matches!(err, SubflowError::NotSignedMembership(_)));
        }
    }

    /// Relay preset transition carries the relay service lifecycle in
    /// the §10.7 direction: client→relay deploys before emission,
    /// relay→client undeploys before emission.
    #[test]
    fn relay_capability_lifecycle_ordering() {
        let up = signing_subflow_for(RolePreset::Client, RolePreset::Relay).expect("relay up");
        assert!(
            idx(&up, &SubflowStep::DeployService(ServiceKind::Relay))
                < idx(&up, &SubflowStep::EmitUnsignedCapabilityRecord)
        );
        let down = signing_subflow_for(RolePreset::Relay, RolePreset::Client).expect("relay down");
        assert!(
            idx(&down, &SubflowStep::UndeployService(ServiceKind::Relay))
                < idx(&down, &SubflowStep::EmitUnsignedCapabilityRecord)
        );
    }

    /// A primary-role change rides along at the front of the local
    /// phase (matches the `role_cli` generic-arm action order).
    #[test]
    fn primary_change_step_is_first_when_present() {
        for (from, to) in all_signed_membership_pairs() {
            let plan = transition_plan(from, to);
            let steps = signing_subflow_steps(&plan).expect("signed membership");
            match plan.primary_change {
                Some(_) => assert_eq!(
                    steps.first(),
                    Some(&SubflowStep::UpdatePrimaryRoleConfig),
                    "{from}->{to}"
                ),
                None => assert!(!steps.contains(&SubflowStep::UpdatePrimaryRoleConfig)),
            }
        }
    }
}
