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

use std::collections::BTreeSet;

use crate::role_presets::{
    Capability, RolePreset, ServiceKind, TransitionKind, TransitionPlan, composition_for,
    required_service_binaries, transition_plan,
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

// ---------------------------------------------------------------------------
// §10.7 ordering validation — the invariants as a checkable property.
//
// The sequencer above PRODUCES a correctly ordered sequence; this half
// VERIFIES any sequence against the invariants, so a hand-built or
// future-produced sequence is provably correct (or provably rejected)
// rather than trusted. The emission step is the invariant boundary: after
// it, the record exists and only external signing intervenes before the
// capability becomes effective at `PublishSignedUpdate`.
// ---------------------------------------------------------------------------

/// A §10.7 ordering invariant that a step sequence violates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrderingViolation {
    /// A sibling service was deployed after the capability record was
    /// emitted — I-1 (advertise-before-running-service).
    DeployAfterEmission {
        kind: ServiceKind,
        deploy_idx: usize,
        emission_idx: usize,
    },
    /// A sibling service was undeployed after the revocation record was
    /// emitted — I-2 (revoked-but-still-running residue).
    UndeployAfterEmission {
        kind: ServiceKind,
        undeploy_idx: usize,
        emission_idx: usize,
    },
    /// A service's teardown was ordered before its bring-up within one
    /// transition — removes the new capability's service before it
    /// ever ran.
    UndeployBeforeDeploy { kind: ServiceKind },
    /// The exit route advertisement did not lead its preflight deploy
    /// (the documented ADD inversion at `role_cli.rs` admin→exit).
    PreflightBeforeAdvertise {
        advertise_idx: usize,
        preflight_idx: usize,
    },
    /// An exit teardown step ran at or after the revocation record
    /// emission — exit NAT/forwarding residue after revocation is a
    /// release-blocking defect.
    ExitTeardownAfterEmission {
        step_idx: usize,
        emission_idx: usize,
    },
    /// The fixed signing phase order (emit → sign → publish → refresh,
    /// refresh terminal) was not respected.
    SigningPhaseOutOfOrder,
}

impl std::fmt::Display for OrderingViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrderingViolation::DeployAfterEmission {
                kind,
                deploy_idx,
                emission_idx,
            } => write!(
                f,
                "§10.7 I-1 violated: {kind} deployed at {deploy_idx} after record emission at {emission_idx}"
            ),
            OrderingViolation::UndeployAfterEmission {
                kind,
                undeploy_idx,
                emission_idx,
            } => write!(
                f,
                "§10.7 I-2 violated: {kind} undeployed at {undeploy_idx} after revocation emission at {emission_idx}"
            ),
            OrderingViolation::UndeployBeforeDeploy { kind } => write!(
                f,
                "§10.7 violated: {kind} undeploy ordered before its deploy"
            ),
            OrderingViolation::PreflightBeforeAdvertise {
                advertise_idx,
                preflight_idx,
            } => write!(
                f,
                "exit ADD inversion violated: preflight at {preflight_idx} precedes advertise at {advertise_idx}"
            ),
            OrderingViolation::ExitTeardownAfterEmission {
                step_idx,
                emission_idx,
            } => write!(
                f,
                "§10.7 exit residue: exit teardown at {step_idx} not before revocation emission at {emission_idx}"
            ),
            OrderingViolation::SigningPhaseOutOfOrder => write!(
                f,
                "signing phase must be emit → sign → publish → refresh (refresh terminal)"
            ),
        }
    }
}

impl std::error::Error for OrderingViolation {}

/// Verify that a step sequence satisfies every §10.7 ordering invariant.
/// Pure. Checks the emission boundary for EVERY service-bearing
/// capability present in the sequence (relay, nas, llm, dns — whatever
/// appears), the exit pair inversions, and the fixed signing phase.
pub fn validate_step_ordering(steps: &[SubflowStep]) -> Result<(), OrderingViolation> {
    let emission = steps
        .iter()
        .position(|s| *s == SubflowStep::EmitUnsignedCapabilityRecord);
    let sign = steps
        .iter()
        .position(|s| *s == SubflowStep::CollectApproverSignatures);
    let publish = steps
        .iter()
        .position(|s| *s == SubflowStep::PublishSignedUpdate);
    let refresh = steps
        .iter()
        .position(|s| *s == SubflowStep::RefreshSignedState);

    // Signing phase: emit < sign < publish < refresh, refresh terminal.
    // A sequence without the signing phase at all is malformed — the
    // sub-flow always terminates in RefreshSignedState.
    match (emission, sign, publish, refresh) {
        (Some(e), Some(s), Some(p), Some(r)) if e < s && s < p && p < r && r == steps.len() - 1 => {
        }
        _ => return Err(OrderingViolation::SigningPhaseOutOfOrder),
    }
    let emission = emission.unwrap_or_else(|| steps.len().saturating_sub(1));

    // Per-service-kind ordering: deploy < undeploy (when both), and
    // each strictly before the emission boundary.
    for &kind in ServiceKind::all() {
        let deploy = steps
            .iter()
            .position(|s| *s == SubflowStep::DeployService(kind));
        let undeploy = steps
            .iter()
            .position(|s| *s == SubflowStep::UndeployService(kind));
        if let (Some(d), Some(u)) = (deploy, undeploy)
            && u < d
        {
            return Err(OrderingViolation::UndeployBeforeDeploy { kind });
        }
        if let Some(d) = deploy
            && d >= emission
        {
            return Err(OrderingViolation::DeployAfterEmission {
                kind,
                deploy_idx: d,
                emission_idx: emission,
            });
        }
        if let Some(u) = undeploy
            && u >= emission
        {
            return Err(OrderingViolation::UndeployAfterEmission {
                kind,
                undeploy_idx: u,
                emission_idx: emission,
            });
        }
    }

    // Exit ordering: advertise leads preflight on ADD; every exit
    // teardown step strictly precedes the revocation emission.
    let advertise = steps
        .iter()
        .position(|s| *s == SubflowStep::AdvertiseExitRoute);
    let deploy_preflight = steps
        .iter()
        .position(|s| *s == SubflowStep::DeployExitPreflight);
    if let (Some(a), Some(p)) = (advertise, deploy_preflight)
        && p < a
    {
        return Err(OrderingViolation::PreflightBeforeAdvertise {
            advertise_idx: a,
            preflight_idx: p,
        });
    }
    for (i, step) in steps.iter().enumerate() {
        if matches!(
            step,
            SubflowStep::UndeployExitPreflight | SubflowStep::RetractExitRoute
        ) && i >= emission
        {
            return Err(OrderingViolation::ExitTeardownAfterEmission {
                step_idx: i,
                emission_idx: emission,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Partial-failure state model (design §4) — a pure replay of what the node
// looks like if the process dies at any step boundary, plus the fail-closed
// check that no boundary state advertises a capability the node cannot
// serve (I-1) or leaves residue behind after a revocation publishes (I-2).
//
// Health verification (design §8.3, owner-gated) is taken as ABSTRACT
// input: a deploy step only marks a service running when the supplied
// health verdict says so. The default model assumes healthy deploys.
// ---------------------------------------------------------------------------

/// What "the node can serve it" means per service at a boundary —
/// abstract input, supplied by the eventual driver (§8.3 owner-gated).
pub type ServiceHealthVerdict<'a> = &'a dyn Fn(ServiceKind) -> bool;

/// Default health model: every deploy completes and verifies healthy.
pub fn always_healthy(_kind: ServiceKind) -> bool {
    true
}

/// The node's transition-relevant local state at a step boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeTransitionState {
    services_running: BTreeSet<ServiceKind>,
    exit_route_advertised: bool,
    exit_preflight_deployed: bool,
    unsigned_record_emitted: bool,
    signatures_collected: bool,
    update_published: bool,
    state_refreshed: bool,
}

impl NodeTransitionState {
    /// The state a node is in BEFORE the sub-flow starts: every service
    /// its source composition requires is running, and the exit
    /// route/preflight are up iff the source advertises `serves_exit`.
    pub fn initial(plan: &TransitionPlan) -> Self {
        let from_caps = composition_for(plan.from).capabilities;
        NodeTransitionState {
            services_running: required_service_binaries(from_caps).into_iter().collect(),
            exit_route_advertised: from_caps.contains(&Capability::ServesExit),
            exit_preflight_deployed: from_caps.contains(&Capability::ServesExit),
            unsigned_record_emitted: false,
            signatures_collected: false,
            update_published: false,
            state_refreshed: false,
        }
    }

    /// Apply one step's effect. All effects are idempotent set/flag
    /// updates, so applying a step twice converges.
    pub fn apply(&mut self, step: &SubflowStep, health: ServiceHealthVerdict<'_>) {
        match step {
            SubflowStep::UpdatePrimaryRoleConfig => {}
            SubflowStep::AdvertiseExitRoute => self.exit_route_advertised = true,
            SubflowStep::DeployExitPreflight => self.exit_preflight_deployed = true,
            SubflowStep::DeployService(kind) => {
                if health(*kind) {
                    self.services_running.insert(*kind);
                }
            }
            SubflowStep::UndeployService(kind) => {
                self.services_running.remove(kind);
            }
            SubflowStep::UndeployExitPreflight => self.exit_preflight_deployed = false,
            SubflowStep::RetractExitRoute => self.exit_route_advertised = false,
            SubflowStep::EmitUnsignedCapabilityRecord => self.unsigned_record_emitted = true,
            SubflowStep::CollectApproverSignatures => self.signatures_collected = true,
            SubflowStep::PublishSignedUpdate => self.update_published = true,
            SubflowStep::RefreshSignedState => self.state_refreshed = true,
        }
    }

    /// Replay the first `completed` steps of `steps` over the plan's
    /// initial state, using the supplied health verdict.
    pub fn replay(
        plan: &TransitionPlan,
        steps: &[SubflowStep],
        completed: usize,
        health: ServiceHealthVerdict<'_>,
    ) -> Self {
        let mut state = Self::initial(plan);
        for step in steps.iter().take(completed) {
            state.apply(step, health);
        }
        state
    }

    /// Convenience: replay with the default (all-healthy) health model.
    pub fn replay_healthy(plan: &TransitionPlan, steps: &[SubflowStep], completed: usize) -> Self {
        Self::replay(plan, steps, completed, &always_healthy)
    }

    pub fn services_running(&self) -> &BTreeSet<ServiceKind> {
        &self.services_running
    }

    pub fn update_published(&self) -> bool {
        self.update_published
    }

    /// §10.7 fail-closed check (I-1/I-2) evaluated AT the publish
    /// boundary. Returns every violation; empty means the published
    /// capability set exactly matches what the node can serve.
    ///
    /// Before publication the record is inert (unsigned or unapplied) —
    /// intermediate states cannot advertise anything, so the check
    /// short-circuits to "no violation" and availability windows are
    /// the caller's concern (design §4), not trust violations.
    pub fn fail_closed_violations(&self, plan: &TransitionPlan) -> Vec<FailClosedViolation> {
        let mut violations = Vec::new();
        if !self.update_published {
            return violations;
        }
        let to_caps = composition_for(plan.to).capabilities;

        // I-1: every service the DESTINATION advertises must be running.
        for kind in required_service_binaries(to_caps) {
            if !self.services_running.contains(&kind) {
                violations.push(FailClosedViolation::AdvertisedWithoutRunningService { kind });
            }
        }
        // I-2: every service the transition undeployed must be down.
        for kind in &plan.service_undeploys {
            if self.services_running.contains(kind) {
                violations.push(FailClosedViolation::RevokedResidue { kind: *kind });
            }
        }
        // Exit pair.
        if plan.adds_capabilities.contains(&Capability::ServesExit)
            && !(self.exit_route_advertised && self.exit_preflight_deployed)
        {
            violations.push(FailClosedViolation::AdvertisedExitWithoutBringUp {
                route_advertised: self.exit_route_advertised,
                preflight_deployed: self.exit_preflight_deployed,
            });
        }
        if plan.removes_capabilities.contains(&Capability::ServesExit)
            && (self.exit_route_advertised || self.exit_preflight_deployed)
        {
            violations.push(FailClosedViolation::RevokedExitResidue {
                route_advertised: self.exit_route_advertised,
                preflight_deployed: self.exit_preflight_deployed,
            });
        }
        violations
    }
}

/// A fail-closed invariant violated by a (published) boundary state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailClosedViolation {
    /// The signed state advertises a capability whose sibling service
    /// is not running — the node cannot serve what it advertises (I-1).
    AdvertisedWithoutRunningService { kind: ServiceKind },
    /// The signed revocation published but the sibling service is
    /// still running — residue (I-2, release-blocking).
    RevokedResidue { kind: ServiceKind },
    /// `serves_exit` advertised without the route advertisement +
    /// preflight bring-up both in place (I-1, exit pair).
    AdvertisedExitWithoutBringUp {
        route_advertised: bool,
        preflight_deployed: bool,
    },
    /// `serves_exit` revoked but the route/preflight is still up —
    /// exit NAT/forwarding residue (I-2, release-blocking).
    RevokedExitResidue {
        route_advertised: bool,
        preflight_deployed: bool,
    },
}

impl std::fmt::Display for FailClosedViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailClosedViolation::AdvertisedWithoutRunningService { kind } => write!(
                f,
                "I-1: {kind} advertised by signed state but its service is not running"
            ),
            FailClosedViolation::RevokedResidue { kind } => write!(
                f,
                "I-2: {kind} revoked by signed state but its service is still running"
            ),
            FailClosedViolation::AdvertisedExitWithoutBringUp {
                route_advertised,
                preflight_deployed,
            } => write!(
                f,
                "I-1: serves_exit advertised without bring-up (route={route_advertised}, preflight={preflight_deployed})"
            ),
            FailClosedViolation::RevokedExitResidue {
                route_advertised,
                preflight_deployed,
            } => write!(
                f,
                "I-2: serves_exit revoked with residue (route={route_advertised}, preflight={preflight_deployed})"
            ),
        }
    }
}

impl std::error::Error for FailClosedViolation {}

// ---------------------------------------------------------------------------
// Recovery directives (design §4/§5) — the idempotent re-run /
// refuse-and-report model as a pure classification of (boundary, outcome).
// ---------------------------------------------------------------------------

/// How a step can go wrong at a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepFailure {
    /// The step attempted and errored (installer failure, IPC error,
    /// audit append failure, verify/apply failure).
    Failed,
    /// `CollectApproverSignatures` completed but the artifact is below
    /// the membership quorum threshold. The threshold policy is an
    /// owner decision (§8.2, parked); the sequencer only models the
    /// below-quorum stop as terminal-for-automation.
    BelowQuorum,
}

/// What an operator/driver should do after a failure at a boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDirective {
    /// Re-run the sub-flow from the start. Every already-executed step
    /// is a convergent no-op (idempotent installers, idempotent route
    /// IPC, record regenerated from current state).
    RerunFromStart,
    /// A fully-signed artifact exists between sign and publish —
    /// resume by publishing it (bounded by record TTL) rather than
    /// redoing local side effects.
    ResumeFromSignedArtifact,
    /// Stop and report. Local state is consistent (nothing published);
    /// the sub-flow must NOT continue past this failure.
    RefuseAndReport,
}

/// Classify the recovery for a run that either died at a boundary
/// (`failure == None`, `completed` steps done) or had a step fail
/// (`Some((failed_idx, how))`).
///
/// Pure. Rules follow design §4 (per-boundary table) and §5
/// (refuse-and-report list): deploy/undeploy/apply failures refuse
/// before anything publishes; a death after signing resumes from the
/// artifact; everything else re-runs from the start.
pub fn recovery_directive(
    steps: &[SubflowStep],
    completed: usize,
    failure: Option<(usize, StepFailure)>,
) -> RecoveryDirective {
    match failure {
        None => {
            // Process death at a boundary: the sign→publish window is
            // the one resumable checkpoint; everything else re-runs.
            match steps.get(completed.wrapping_sub(1)) {
                Some(SubflowStep::CollectApproverSignatures) => {
                    RecoveryDirective::ResumeFromSignedArtifact
                }
                _ => RecoveryDirective::RerunFromStart,
            }
        }
        Some((idx, how)) => {
            let failed = match steps.get(idx) {
                Some(step) => step,
                None => return RecoveryDirective::RefuseAndReport,
            };
            match (failed, how) {
                // Below quorum: partially-signed is a terminal,
                // reportable state for automation (§2, §8.2 parked).
                (SubflowStep::CollectApproverSignatures, StepFailure::BelowQuorum) => {
                    RecoveryDirective::RefuseAndReport
                }
                // A step that errored: refuse-and-report for every
                // side-effecting local step and the apply step (§5).
                // Regenerable/atomic steps (config rewrite, record
                // emission) and the idempotent refresh re-run.
                (
                    SubflowStep::DeployService(_)
                    | SubflowStep::UndeployService(_)
                    | SubflowStep::DeployExitPreflight
                    | SubflowStep::UndeployExitPreflight
                    | SubflowStep::AdvertiseExitRoute
                    | SubflowStep::RetractExitRoute
                    | SubflowStep::CollectApproverSignatures
                    | SubflowStep::PublishSignedUpdate,
                    StepFailure::Failed,
                ) => RecoveryDirective::RefuseAndReport,
                _ => RecoveryDirective::RerunFromStart,
            }
        }
    }
}

/// Whether the boundary state at `completed` steps is consistent-old or
/// already half-transitioned — the refuse-and-report precondition
/// check: a refusal is only safe while nothing has published (the
/// signed state still says what the node actually serves).
pub fn refusal_is_safe(plan: &TransitionPlan, steps: &[SubflowStep], completed: usize) -> bool {
    !NodeTransitionState::replay_healthy(plan, steps, completed).update_published()
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

    // ------------------------------------------------------------------
    // §10.7 ordering VALIDATOR — the invariants as a checkable property.
    // ------------------------------------------------------------------

    /// Every canonical sequence the sequencer produces passes the
    /// independent ordering validator — producer and checker agree.
    #[test]
    fn validator_accepts_every_sequenced_matrix_cell() {
        for (from, to) in all_signed_membership_pairs() {
            let steps = signing_subflow_for(from, to).expect("signed membership");
            assert_eq!(
                validate_step_ordering(&steps),
                Ok(()),
                "{from}->{to}: produced sequence violates §10.7"
            );
        }
    }

    /// I-1 negative: a deploy after the record emission is rejected.
    #[test]
    fn validator_rejects_deploy_after_emission() {
        let steps = vec![
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::DeployService(ServiceKind::Relay),
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::RefreshSignedState,
        ];
        assert_eq!(
            validate_step_ordering(&steps),
            Err(OrderingViolation::DeployAfterEmission {
                kind: ServiceKind::Relay,
                deploy_idx: 1,
                emission_idx: 0,
            })
        );
    }

    /// I-2 negative: an undeploy at or after the revocation emission is
    /// rejected (revoked-but-still-running residue ordering).
    #[test]
    fn validator_rejects_undeploy_after_emission() {
        let steps = vec![
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::UndeployService(ServiceKind::Nas),
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::RefreshSignedState,
        ];
        assert!(matches!(
            validate_step_ordering(&steps),
            Err(OrderingViolation::UndeployAfterEmission { .. })
        ));
    }

    /// A service torn down before it is brought up within one
    /// transition is rejected.
    #[test]
    fn validator_rejects_undeploy_before_deploy() {
        let steps = vec![
            SubflowStep::UndeployService(ServiceKind::Llm),
            SubflowStep::DeployService(ServiceKind::Llm),
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::RefreshSignedState,
        ];
        assert_eq!(
            validate_step_ordering(&steps),
            Err(OrderingViolation::UndeployBeforeDeploy {
                kind: ServiceKind::Llm,
            })
        );
    }

    /// The exit ADD inversion is required: preflight must not lead
    /// advertise.
    #[test]
    fn validator_rejects_preflight_before_advertise() {
        let steps = vec![
            SubflowStep::DeployExitPreflight,
            SubflowStep::AdvertiseExitRoute,
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::RefreshSignedState,
        ];
        assert!(matches!(
            validate_step_ordering(&steps),
            Err(OrderingViolation::PreflightBeforeAdvertise { .. })
        ));
    }

    /// Exit teardown at or after the revocation emission is rejected —
    /// NAT/forwarding residue after revocation is release-blocking.
    #[test]
    fn validator_rejects_exit_teardown_after_emission() {
        let steps = vec![
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::UndeployExitPreflight,
            SubflowStep::RetractExitRoute,
            SubflowStep::RefreshSignedState,
        ];
        assert!(matches!(
            validate_step_ordering(&steps),
            Err(OrderingViolation::ExitTeardownAfterEmission { .. })
        ));
    }

    /// The signing phase order (and its presence, refresh terminal) is
    /// enforced — publish-before-sign and missing-refresh both fail.
    #[test]
    fn validator_rejects_signing_phase_out_of_order() {
        let swapped = vec![
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::PublishSignedUpdate,
            SubflowStep::CollectApproverSignatures,
            SubflowStep::RefreshSignedState,
        ];
        assert_eq!(
            validate_step_ordering(&swapped),
            Err(OrderingViolation::SigningPhaseOutOfOrder)
        );
        let missing_refresh = vec![
            SubflowStep::EmitUnsignedCapabilityRecord,
            SubflowStep::CollectApproverSignatures,
            SubflowStep::PublishSignedUpdate,
        ];
        assert_eq!(
            validate_step_ordering(&missing_refresh),
            Err(OrderingViolation::SigningPhaseOutOfOrder)
        );
    }

    // ------------------------------------------------------------------
    // Partial-failure state model (design §4) — fail-closed at every
    // boundary.
    // ------------------------------------------------------------------

    /// Core fail-closed property: at NO step boundary of ANY
    /// SignedMembership transition does the modelled node state
    /// advertise a capability it cannot serve or leave revocation
    /// residue — including after publish completes. Every boundary is
    /// availability-window-safe by construction.
    #[test]
    fn no_boundary_state_violates_fail_closed_invariants() {
        for (from, to) in all_signed_membership_pairs() {
            let plan = transition_plan(from, to);
            let steps = signing_subflow_steps(&plan).expect("signed membership");
            for completed in 0..=steps.len() {
                let state = NodeTransitionState::replay_healthy(&plan, &steps, completed);
                assert!(
                    state.fail_closed_violations(&plan).is_empty(),
                    "{from}->{to} boundary {completed}: {:?}",
                    state
                );
            }
        }
    }

    /// A deploy whose abstract health verdict is negative must never
    /// end in an advertised-but-unservable capability: the fail-closed
    /// checker detects it at the publish boundary (I-1).
    #[test]
    fn unhealthy_deploy_is_detected_as_advertised_unservable() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Relay);
        let steps = signing_subflow_steps(&plan).expect("signed membership");
        let deny_relay = |kind: ServiceKind| kind != ServiceKind::Relay;
        let state = NodeTransitionState::replay(&plan, &steps, steps.len(), &deny_relay);
        let violations = state.fail_closed_violations(&plan);
        assert_eq!(
            violations,
            vec![FailClosedViolation::AdvertisedWithoutRunningService {
                kind: ServiceKind::Relay,
            }]
        );
    }

    /// A half-transitioned (pre-publish) node advertises nothing: the
    /// fail-closed check short-circuits before publication because the
    /// unsigned/unapplied record is inert (design §4).
    #[test]
    fn pre_publish_boundaries_advertise_nothing() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Relay);
        let steps = signing_subflow_steps(&plan).expect("signed membership");
        let publish_idx = idx(&steps, &SubflowStep::PublishSignedUpdate);
        for completed in 0..publish_idx {
            let state = NodeTransitionState::replay_healthy(&plan, &steps, completed);
            assert!(!state.update_published(), "boundary {completed}");
            assert!(state.fail_closed_violations(&plan).is_empty());
        }
    }

    // ------------------------------------------------------------------
    // Idempotency + resumability (design §5) — re-run from any failure
    // point converges.
    // ------------------------------------------------------------------

    /// Re-running the FULL sequence over ANY boundary state converges
    /// to the same terminal state as a clean run, and running it again
    /// on the terminal state is a no-op — every step effect is an
    /// idempotent set/flag update, so re-run-from-start (the chosen
    /// §5 resumability model) is safe from every failure point.
    #[test]
    fn rerun_from_any_boundary_converges() {
        for (from, to) in all_signed_membership_pairs() {
            let plan = transition_plan(from, to);
            let steps = signing_subflow_steps(&plan).expect("signed membership");
            let terminal = NodeTransitionState::replay_healthy(&plan, &steps, steps.len());
            for completed in 0..steps.len() {
                let mut resumed = NodeTransitionState::replay_healthy(&plan, &steps, completed);
                for step in &steps {
                    resumed.apply(step, &always_healthy);
                }
                assert_eq!(resumed, terminal, "{from}->{to} from boundary {completed}");
                // Idempotent second pass over the terminal state.
                for step in &steps {
                    resumed.apply(step, &always_healthy);
                }
                assert_eq!(resumed, terminal, "{from}->{to} re-run not a no-op");
            }
        }
    }

    // ------------------------------------------------------------------
    // Recovery directives (design §4/§5).
    // ------------------------------------------------------------------

    /// Process death at a boundary: the sign→publish window resumes
    /// from the signed artifact; every other boundary re-runs from the
    /// start (convergent steps).
    #[test]
    fn death_after_sign_resumes_from_artifact_else_reruns() {
        let plan = transition_plan(RolePreset::Client, RolePreset::Relay);
        let steps = signing_subflow_steps(&plan).expect("signed membership");
        let sign_idx = idx(&steps, &SubflowStep::CollectApproverSignatures);
        for completed in 0..=steps.len() {
            let directive = recovery_directive(&steps, completed, None);
            if completed == sign_idx + 1 {
                assert_eq!(directive, RecoveryDirective::ResumeFromSignedArtifact);
            } else {
                assert_eq!(directive, RecoveryDirective::RerunFromStart);
            }
        }
    }

    /// Errored side-effecting steps and the apply step refuse and
    /// report; regenerable/atomic steps and the idempotent refresh
    /// re-run; below-quorum signing is terminal for automation (§8.2
    /// parked — modeled as abstract input only).
    #[test]
    fn failure_directives_follow_refuse_and_report_list() {
        let plan = transition_plan(RolePreset::Exit, RolePreset::Admin);
        let steps = signing_subflow_steps(&plan).expect("signed membership");
        let directive_at = |step: &SubflowStep, how: StepFailure| {
            let i = idx(&steps, step);
            recovery_directive(&steps, i, Some((i, how)))
        };
        for step in [
            SubflowStep::UndeployExitPreflight,
            SubflowStep::RetractExitRoute,
            SubflowStep::PublishSignedUpdate,
        ] {
            assert_eq!(
                directive_at(&step, StepFailure::Failed),
                RecoveryDirective::RefuseAndReport,
                "{step:?}"
            );
        }
        assert_eq!(
            directive_at(
                &SubflowStep::CollectApproverSignatures,
                StepFailure::BelowQuorum
            ),
            RecoveryDirective::RefuseAndReport
        );
        // Regenerable/atomic steps re-run — including the primary
        // rewrite wherever a matrix cell actually carries one.
        assert_eq!(
            directive_at(
                &SubflowStep::EmitUnsignedCapabilityRecord,
                StepFailure::Failed
            ),
            RecoveryDirective::RerunFromStart
        );
        assert_eq!(
            directive_at(&SubflowStep::RefreshSignedState, StepFailure::Failed),
            RecoveryDirective::RerunFromStart
        );
        for (from, to) in all_signed_membership_pairs() {
            let p = transition_plan(from, to);
            if p.primary_change.is_some() {
                let s = signing_subflow_steps(&p).expect("signed membership");
                let i = idx(&s, &SubflowStep::UpdatePrimaryRoleConfig);
                assert_eq!(
                    recovery_directive(&s, i, Some((i, StepFailure::Failed))),
                    RecoveryDirective::RerunFromStart,
                    "{from}->{to}"
                );
            }
        }
        // An index outside the sequence fails closed to refusal.
        assert_eq!(
            recovery_directive(&steps, 0, Some((steps.len() + 1, StepFailure::Failed))),
            RecoveryDirective::RefuseAndReport
        );
    }

    /// A refusal is only safe while nothing has published: after that,
    /// stopping would leave the signed state describing a node that no
    /// longer matches reality — the model exposes that precondition.
    #[test]
    fn refusal_is_safe_only_before_publish_completes() {
        for (from, to) in all_signed_membership_pairs() {
            let plan = transition_plan(from, to);
            let steps = signing_subflow_steps(&plan).expect("signed membership");
            let publish_idx = idx(&steps, &SubflowStep::PublishSignedUpdate);
            for completed in 0..publish_idx {
                assert!(
                    refusal_is_safe(&plan, &steps, completed),
                    "{from}->{to} boundary {completed}"
                );
            }
            assert!(!refusal_is_safe(&plan, &steps, publish_idx + 1));
        }
    }
}
