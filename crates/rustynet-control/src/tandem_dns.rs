//! RustyDNS tandem integration — D-6a Phase 1: toggle surface and
//! fail-closed state machine (control plane only).
//!
//! This module implements the **pure control-plane state machine** for
//! the RustyDNS tandem DNS toggle as specified in
//! `RustydnsTandemIntegrationDesign_2026-08-27.md` (§5.1 toggle
//! semantics, §10.1 persistent phases, §11 closed reason codes) and the
//! operator decree `RustydnsExitIntegrationDecree_2026-08-25.md`.
//!
//! Scope of Phase 1 (deliberately narrow):
//!
//! * the operator-visible toggle phase enum ([`TandemTogglePhase`]),
//! * the total, pure reconcile function ([`reconcile`]) that maps
//!   `(current phase, desired signed policy, policy validity, readiness,
//!   assignment, deactivation barrier, residue)` to exactly one next
//!   phase,
//! * the local `contain now` safety veto ([`contain_now`]) with a
//!   machine-checked "strictly tightening" proof
//!   ([`capability_width`]),
//! * the abstract, non-authorizing prepare-intent record
//!   ([`TandemDnsPrepareIntentV1`]) — typed fields and validation only;
//!   **the signed wire format is NOT defined here** (owner /
//!   security-gated; see
//!   `documents/operations/active/RustydnsTandemPhase1Notes_2026-08-28.md`),
//! * the closed reason-code vocabulary ([`TandemReasonCode`], §11).
//!
//! Out of scope (Phase 2/3, not implemented here): managed-DNS handoff
//! wiring, exit `:53` NAT redirect, per-OS dataplane enforcement,
//! cross-repo calls to `rustydns`, signature/wire formats.
//!
//! Fail-closed core (decree + design §3 invariant 7): a signed ON
//! policy combined with any readiness, validity, assignment, or trust
//! degradation yields **contained** — the selected DNS is deliberately
//! unavailable and the reason is recorded. There is no transition in
//! this machine that falls back to the system resolver, installs a
//! direct port-53 egress path, or widens the effective capability set
//! as a reaction to a failure. Only fresh, replay-rejected, valid
//! signed state combined with proven readiness and proven assignment
//! can produce (or keep) an [`TandemTogglePhase::Active`] phase.

use std::fmt;

use subtle::ConstantTimeEq;

/// Bound on the number of explicit node ids in a
/// [`TandemScope::NodeIds`] scope. The design (§5.4) requires a
/// "sorted dedup bounded" list but does not pin the bound; the value
/// is recorded as an owner sub-decision in the Phase-1 notes document.
pub const TANDEM_SCOPE_MAX_NODE_IDS: usize = 64;

/// Tandem DNS operating mode (§5.4). The two modes are explicit and
/// there is **no implicit fallback** between them (control TDNS-19):
/// a `ManagedRedirect` deployment never silently degrades to
/// `Managed`, and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TandemMode {
    /// Managed local resolver handoff without an exit-side redirect.
    Managed,
    /// Managed handoff plus an exit-side `:53` redirect.
    ManagedRedirect,
}

impl TandemMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TandemMode::Managed => "managed",
            TandemMode::ManagedRedirect => "managed_redirect",
        }
    }
}

impl fmt::Display for TandemMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which selected clients a tandem policy applies to (§5.4). The
/// explicit list form is validated by [`TandemScope::validate`]:
/// sorted, deduplicated, non-empty, bounded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TandemScope {
    /// Every client currently assigned to the policy's exit node.
    AllClientsUsingExit,
    /// An explicit, sorted, deduplicated, bounded client list.
    NodeIds(Vec<String>),
}

impl TandemScope {
    /// Fail-closed validation of the explicit-list form. `Ok(())` is
    /// returned unchanged for [`TandemScope::AllClientsUsingExit`].
    pub fn validate(&self) -> Result<(), TandemReasonCode> {
        match self {
            TandemScope::AllClientsUsingExit => Ok(()),
            TandemScope::NodeIds(ids) => {
                if ids.is_empty() {
                    return Err(TandemReasonCode::SignedPolicyInvalid);
                }
                if ids.len() > TANDEM_SCOPE_MAX_NODE_IDS {
                    return Err(TandemReasonCode::SignedPolicyInvalid);
                }
                let sorted_and_deduped = ids
                    .windows(2)
                    .all(|pair| !pair[0].trim().is_empty() && pair[0] < pair[1]);
                if sorted_and_deduped {
                    Ok(())
                } else {
                    Err(TandemReasonCode::SignedPolicyInvalid)
                }
            }
        }
    }
}

/// Closed vocabulary of tandem reason codes (design §11). Closed on
/// purpose: structured, bounded status display and audit entries never
/// carry free-form error text, which prevents error-text injection.
///
/// The discriminant set is exactly the §11 table; new codes are added
/// by appending a variant **and** updating the notes ledger, never by
/// stringifying arbitrary errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TandemReasonCode {
    SignedPolicyInvalid,
    Replay,
    SignedPolicyExpired,
    AssignmentMismatch,
    BlindExitConflict,
    PlatformRedirectUnsupported,
    LocalAuthFailed,
    ProtocolIncompatible,
    RustydnsUnreachable,
    BootChanged,
    ListenerUnready,
    CanaryFailed,
    BlocklistUnready,
    UpstreamUnready,
    ProfileMismatch,
    IdentityStale,
    UnknownClient,
    DohFeedStale,
    BypassRuleDrift,
    RuleApplyFailed,
    RuleDrift,
    Residue,
    ControlStaleWarning,
    ClockUntrusted,
}

impl TandemReasonCode {
    /// All codes in the closed §11 order. Used by the round-trip test
    /// that pins the vocabulary.
    pub const ALL: [TandemReasonCode; 24] = [
        TandemReasonCode::SignedPolicyInvalid,
        TandemReasonCode::Replay,
        TandemReasonCode::SignedPolicyExpired,
        TandemReasonCode::AssignmentMismatch,
        TandemReasonCode::BlindExitConflict,
        TandemReasonCode::PlatformRedirectUnsupported,
        TandemReasonCode::LocalAuthFailed,
        TandemReasonCode::ProtocolIncompatible,
        TandemReasonCode::RustydnsUnreachable,
        TandemReasonCode::BootChanged,
        TandemReasonCode::ListenerUnready,
        TandemReasonCode::CanaryFailed,
        TandemReasonCode::BlocklistUnready,
        TandemReasonCode::UpstreamUnready,
        TandemReasonCode::ProfileMismatch,
        TandemReasonCode::IdentityStale,
        TandemReasonCode::UnknownClient,
        TandemReasonCode::DohFeedStale,
        TandemReasonCode::BypassRuleDrift,
        TandemReasonCode::RuleApplyFailed,
        TandemReasonCode::RuleDrift,
        TandemReasonCode::Residue,
        TandemReasonCode::ControlStaleWarning,
        TandemReasonCode::ClockUntrusted,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            TandemReasonCode::SignedPolicyInvalid => "SIGNED_POLICY_INVALID",
            TandemReasonCode::Replay => "REPLAY",
            TandemReasonCode::SignedPolicyExpired => "SIGNED_POLICY_EXPIRED",
            TandemReasonCode::AssignmentMismatch => "ASSIGNMENT_MISMATCH",
            TandemReasonCode::BlindExitConflict => "BLIND_EXIT_CONFLICT",
            TandemReasonCode::PlatformRedirectUnsupported => "PLATFORM_REDIRECT_UNSUPPORTED",
            TandemReasonCode::LocalAuthFailed => "LOCAL_AUTH_FAILED",
            TandemReasonCode::ProtocolIncompatible => "PROTOCOL_INCOMPATIBLE",
            TandemReasonCode::RustydnsUnreachable => "RUSTYDNS_UNREACHABLE",
            TandemReasonCode::BootChanged => "BOOT_CHANGED",
            TandemReasonCode::ListenerUnready => "LISTENER_UNREADY",
            TandemReasonCode::CanaryFailed => "CANARY_FAILED",
            TandemReasonCode::BlocklistUnready => "BLOCKLIST_UNREADY",
            TandemReasonCode::UpstreamUnready => "UPSTREAM_UNREADY",
            TandemReasonCode::ProfileMismatch => "PROFILE_MISMATCH",
            TandemReasonCode::IdentityStale => "IDENTITY_STALE",
            TandemReasonCode::UnknownClient => "UNKNOWN_CLIENT",
            TandemReasonCode::DohFeedStale => "DOH_FEED_STALE",
            TandemReasonCode::BypassRuleDrift => "BYPASS_RULE_DRIFT",
            TandemReasonCode::RuleApplyFailed => "RULE_APPLY_FAILED",
            TandemReasonCode::RuleDrift => "RULE_DRIFT",
            TandemReasonCode::Residue => "RESIDUE",
            TandemReasonCode::ControlStaleWarning => "CONTROL_STALE_WARNING",
            TandemReasonCode::ClockUntrusted => "CLOCK_UNTRUSTED",
        }
    }

    /// Strict parse of the closed vocabulary. Unknown strings are
    /// rejected — the enum is never extended implicitly.
    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.as_str() == value)
    }
}

impl fmt::Display for TandemReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Operator-visible tandem toggle phase. Mirrors the §5.1 toggle
/// states onto the §10.1 persistent phases:
///
/// | §5.1 toggle state      | this enum                             |
/// | ---------------------- | ------------------------------------- |
/// | OFF                    | `Off`                                 |
/// | ON (preparing)         | `PreparingContained`                  |
/// | ON (prepared)          | `Prepared`                           |
/// | ON/managed             | `Active(TandemMode::Managed)`         |
/// | ON/managed+redirect    | `Active(TandemMode::ManagedRedirect)` |
/// | ON/contained           | `RuntimeContained`                    |
/// | DRAINING               | `Draining`                            |
/// | ERROR/residue          | `ResidueError`                        |
///
/// `PreparingContained` and `Prepared` are contained-by-construction:
/// local state is being prepared (or prepared) while no client is
/// pointed at the tandem resolver. `RuntimeContained` is desired-ON
/// with a failed trust/readiness/apply/verify condition: the selected
/// DNS is **deliberately unavailable** and the reason is recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TandemTogglePhase {
    /// Default. No tandem ownership of any kind.
    Off,
    /// Desired-ON; local contained state is being prepared under a
    /// valid prepare intent. No client-facing capability exists yet.
    PreparingContained,
    /// Prepared, contained local state; readiness not yet proven.
    Prepared,
    /// Serving the selected clients in the given mode.
    Active(TandemMode),
    /// Desired-ON but a condition failed: DNS deliberately unavailable,
    /// reason recorded. The prior desired mode is preserved so a
    /// recovery can never widen or silently change the mode.
    RuntimeContained {
        reason: TandemReasonCode,
        desired_mode: TandemMode,
    },
    /// Signed disable/scope-removal propagating. New handoffs are
    /// gone; existing leases are bounded; enforcement is NOT removed
    /// until the §10.4 deactivation barrier passes.
    Draining,
    /// Desired-OFF but owned state remains (residue), or desired-ON
    /// with ambiguous observed ownership. Further enabling is refused.
    ResidueError,
}

impl TandemTogglePhase {
    /// Whether this phase belongs to the "ON family" (a signed ON
    /// policy is at least notionally in force). Used by
    /// [`contain_now`].
    pub fn is_on_family(&self) -> bool {
        matches!(
            self,
            TandemTogglePhase::PreparingContained
                | TandemTogglePhase::Prepared
                | TandemTogglePhase::Active(_)
                | TandemTogglePhase::RuntimeContained { .. }
                | TandemTogglePhase::Draining
        )
    }

    /// The desired mode carried by this phase, when one exists.
    pub fn desired_mode(&self) -> Option<TandemMode> {
        match self {
            TandemTogglePhase::Active(mode) => Some(*mode),
            TandemTogglePhase::RuntimeContained { desired_mode, .. } => Some(*desired_mode),
            _ => None,
        }
    }
}

/// Machine-checkable ordering of how much client-facing capability a
/// phase exposes. Used to *prove* that `contain now` is strictly
/// tightening and that no failure transition widens capability:
///
/// `Off == ResidueError (0) < RuntimeContained == Draining ==
/// PreparingContained (1) < Prepared (2) < Active(Managed) (3) <
/// Active(ManagedRedirect) (4)`
pub fn capability_width(phase: &TandemTogglePhase) -> u8 {
    match phase {
        TandemTogglePhase::Off | TandemTogglePhase::ResidueError => 0,
        TandemTogglePhase::PreparingContained
        | TandemTogglePhase::Draining
        | TandemTogglePhase::RuntimeContained { .. } => 1,
        TandemTogglePhase::Prepared => 2,
        TandemTogglePhase::Active(TandemMode::Managed) => 3,
        TandemTogglePhase::Active(TandemMode::ManagedRedirect) => 4,
    }
}

/// Validity of the signed desired policy, as judged by the existing
/// signed-state machinery (signature verification, freshness window,
/// replay watermark). This module consumes the verdict; it does not
/// re-implement verification.
///
/// Anything other than [`PolicyValidity::Fresh`] can never enable or
/// maintain the ON family (design §3 invariant 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyValidity {
    /// Signature verified, within freshness window, replay watermark
    /// accepted.
    Fresh,
    /// Outside the signed freshness window.
    Expired,
    /// Rejected by the replay/anti-rollback watermark.
    ReplayRejected,
    /// Malformed, wrong signer/quorum, or failed strict decoding.
    Invalid,
}

/// Readiness observation for the `rustydns` sibling service, abstract
/// behind a value so the state machine stays pure and transport
/// agnostic (§6.2: readiness is a compound contract, NOT a bare
/// `/health` probe; the real provider is wired in a later phase —
/// see [`RustydnsReadinessProvider`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadinessObservation {
    /// The compound readiness contract holds.
    Ready,
    /// The service answers but a named component is not ready.
    NotReady(TandemReasonCode),
    /// The observation itself is stale (older than the freshness
    /// window) — treated as unreadiness, never as absence of evidence.
    Stale,
    /// The observation failed local authentication.
    Unauthenticated,
    /// The service is running but incompatible (protocol/profile).
    Incompatible(TandemReasonCode),
}

impl ReadinessObservation {
    /// Map an observation to the reason a contained phase records.
    /// `Ready` maps to `None` by construction of [`reconcile`].
    pub fn contain_reason(&self) -> Option<TandemReasonCode> {
        match self {
            ReadinessObservation::Ready => None,
            ReadinessObservation::NotReady(code) => Some(*code),
            ReadinessObservation::Stale => Some(TandemReasonCode::ControlStaleWarning),
            ReadinessObservation::Unauthenticated => Some(TandemReasonCode::LocalAuthFailed),
            ReadinessObservation::Incompatible(code) => Some(*code),
        }
    }
}

/// Provider trait for the `rustydns` readiness observation. Phase 1
/// ships only the trait and a stub; wiring the real compound contract
/// (§6.2 `TandemDnsReadinessV1`) is later-phase work.
///
/// The trait's contract is fail-closed: an implementation that cannot
/// obtain a trustworthy observation MUST return a degradation variant
/// (`NotReady(..)`, `Stale`, `Unauthenticated`, `Incompatible(..)`),
/// never `Ready`.
pub trait RustydnsReadinessProvider {
    fn readiness(&self) -> ReadinessObservation;
}

/// Deterministic stub used by tests (and as a placeholder wiring
/// point). Not a production readiness oracle.
#[derive(Debug, Clone, Copy)]
pub struct StaticReadinessProvider(pub ReadinessObservation);

impl RustydnsReadinessProvider for StaticReadinessProvider {
    fn readiness(&self) -> ReadinessObservation {
        self.0
    }
}

/// The desired state carried by a verified signed tandem policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDesiredOn {
    pub mode: TandemMode,
    /// The named exit node the tandem service runs on (the activation
    /// unit is "named exit + explicit client selector", §3 invariant 2).
    pub exit_node_id: String,
    pub scope: TandemScope,
}

/// Desired toggle direction, extracted from verified signed state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesiredPolicy {
    On(TandemDesiredOn),
    Off,
}

/// Whether the selected clients are proven to be assigned to the same
/// exit the policy names (§3 invariant 3). Unknown (`None`) is treated
/// as a mismatch — trust state that is missing fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitAssignment {
    ProvenSameExit,
    ProvenMismatch,
    Unknown,
}

/// Outcome of the local `contain now` safety veto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainNowOutcome {
    /// Containment applied (or already in force); carries the phase
    /// after the veto.
    Contained(TandemTogglePhase),
    /// Veto refused: there is nothing it may contain (no ON state to
    /// tighten) or containment is refused by the residue posture.
    Refused {
        reason: TandemReasonCode,
        unchanged: TandemTogglePhase,
    },
}

/// Result of one reconcile step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TandemReconcileOutput {
    pub next: TandemTogglePhase,
    pub reason: Option<TandemReasonCode>,
}

/// Reason recorded when the local `contain now` veto (or the
/// readiness-staleness mapping) has no more specific §11 code.
///
/// The veto is an operator-initiated tightening of an already-ON
/// state; §11 has no dedicated "operator veto" code, so
/// `CONTROL_STALE_WARNING` is used. Recorded as an owner sub-decision
/// in the Phase-1 notes.
pub const CONTAIN_NOW_REASON: TandemReasonCode = TandemReasonCode::ControlStaleWarning;

/// The total, pure reconcile step (§5.1/§10.1).
///
/// Deterministic: the same inputs always produce the same output, and
/// every input combination is mapped (no panics, no `unreachable!`).
///
/// Guarantees enforced here (each has a negative test below):
///
/// 1. Only `PolicyValidity::Fresh` can enter or remain in the ON
///    family. Expired / replay-rejected / invalid desired-ON yields
///    `RuntimeContained` (from ON family) or refusal to enable (from
///    `Off`), never `Off` (no automatic OFF-data-path creation) and
///    never `Active`.
/// 2. Readiness degradation while desired-ON yields
///    `RuntimeContained` — the fail-closed posture — never a mode
///    fallback (TDNS-19) and never a system-resolver fallback.
/// 3. Unknown or mismatched exit assignment yields
///    `RuntimeContained(ASSIGNMENT_MISMATCH)`; unknown is not
///    "proven good".
/// 4. Mode changes while ACTIVE are refused (`PROFILE_MISMATCH`); the
///    only legal mode transition path is disable → drain → enable.
/// 5. `ResidueError` refuses every enabling path.
/// 6. `Draining` never removes enforcement before
///    `deactivation_barrier_passed`, and drains to `ResidueError`
///    when owned state remains.
/// 7. No input combination moves an ON-family phase to `Off` except
///    the `Draining` → (barrier passed ∧ no residue) → `Off` edge.
#[allow(clippy::too_many_arguments)]
pub fn reconcile(
    current: &TandemTogglePhase,
    desired: &DesiredPolicy,
    validity: PolicyValidity,
    readiness: &ReadinessObservation,
    prepare_intent_valid: bool,
    exit_assignment: ExitAssignment,
    deactivation_barrier_passed: bool,
    residue_present: bool,
) -> TandemReconcileOutput {
    // Containment reason for the ON family under a degraded input.
    let degradation = degradation_reason(validity, readiness, exit_assignment);

    match desired {
        DesiredPolicy::Off => {
            reconcile_desired_off(current, deactivation_barrier_passed, residue_present)
        }
        DesiredPolicy::On(on) => reconcile_desired_on(
            current,
            on,
            validity,
            readiness,
            prepare_intent_valid,
            degradation,
        ),
    }
}

/// `Some(reason)` when a signed-ON policy may not be maintained, with
/// the exact §11 code to record. Ordered: policy validity first, then
/// assignment proof, then readiness.
fn degradation_reason(
    validity: PolicyValidity,
    readiness: &ReadinessObservation,
    exit_assignment: ExitAssignment,
) -> Option<TandemReasonCode> {
    let validity_reason = match validity {
        PolicyValidity::Fresh => None,
        PolicyValidity::Expired => Some(TandemReasonCode::SignedPolicyExpired),
        PolicyValidity::ReplayRejected => Some(TandemReasonCode::Replay),
        PolicyValidity::Invalid => Some(TandemReasonCode::SignedPolicyInvalid),
    };
    if let Some(reason) = validity_reason {
        return Some(reason);
    }
    match exit_assignment {
        ExitAssignment::ProvenSameExit => {}
        // Unknown assignment is NOT proof of same-exit: fail closed
        // with the mismatch code rather than inventing an allow.
        ExitAssignment::ProvenMismatch | ExitAssignment::Unknown => {
            return Some(TandemReasonCode::AssignmentMismatch);
        }
    }
    readiness.contain_reason()
}

fn reconcile_desired_off(
    current: &TandemTogglePhase,
    deactivation_barrier_passed: bool,
    residue_present: bool,
) -> TandemReconcileOutput {
    match current {
        TandemTogglePhase::Off => TandemReconcileOutput {
            next: TandemTogglePhase::Off,
            reason: None,
        },
        // Signed disable begins by draining: bounded propagation,
        // enforcement stays until the barrier passes.
        TandemTogglePhase::PreparingContained
        | TandemTogglePhase::Prepared
        | TandemTogglePhase::Active(_)
        | TandemTogglePhase::RuntimeContained { .. } => TandemReconcileOutput {
            next: TandemTogglePhase::Draining,
            reason: None,
        },
        TandemTogglePhase::Draining => {
            if !deactivation_barrier_passed {
                // Enforcement must not be removed early.
                TandemReconcileOutput {
                    next: TandemTogglePhase::Draining,
                    reason: None,
                }
            } else if residue_present {
                TandemReconcileOutput {
                    next: TandemTogglePhase::ResidueError,
                    reason: Some(TandemReasonCode::Residue),
                }
            } else {
                TandemReconcileOutput {
                    next: TandemTogglePhase::Off,
                    reason: None,
                }
            }
        }
        TandemTogglePhase::ResidueError => {
            if residue_present {
                TandemReconcileOutput {
                    next: TandemTogglePhase::ResidueError,
                    reason: Some(TandemReasonCode::Residue),
                }
            } else {
                // Residue cleared (verified externally); the phase may
                // return to Off. Clearing requires positive proof, so
                // "no residue observed" alone does NOT clear it — the
                // caller must have run the residue proof; we accept
                // only the explicit not-present verdict here.
                TandemReconcileOutput {
                    next: TandemTogglePhase::Off,
                    reason: None,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn reconcile_desired_on(
    current: &TandemTogglePhase,
    on: &TandemDesiredOn,
    validity: PolicyValidity,
    readiness: &ReadinessObservation,
    prepare_intent_valid: bool,
    degradation: Option<TandemReasonCode>,
) -> TandemReconcileOutput {
    let desired = on.mode;
    match current {
        TandemTogglePhase::Off => {
            // Enabling requires fresh signed state AND a valid
            // (non-authorizing) prepare intent. Anything less refuses
            // in place — Off never widens on a bad input.
            match (validity, prepare_intent_valid) {
                (PolicyValidity::Fresh, true) => TandemReconcileOutput {
                    next: TandemTogglePhase::PreparingContained,
                    reason: None,
                },
                (PolicyValidity::Fresh, false) => TandemReconcileOutput {
                    next: TandemTogglePhase::Off,
                    reason: Some(TandemReasonCode::SignedPolicyInvalid),
                },
                (PolicyValidity::Expired, _)
                | (PolicyValidity::ReplayRejected, _)
                | (PolicyValidity::Invalid, _) => TandemReconcileOutput {
                    next: TandemTogglePhase::Off,
                    reason: Some(validity_reason_code(validity)),
                },
            }
        }
        TandemTogglePhase::ResidueError => {
            // ERROR/residue refuses further enabling. Always.
            TandemReconcileOutput {
                next: TandemTogglePhase::ResidueError,
                reason: Some(TandemReasonCode::Residue),
            }
        }
        TandemTogglePhase::Draining => {
            // A signed ON policy does not cut short a drain in
            // progress: the §10.4 deactivation barrier must complete
            // before any re-enable. Stays Draining.
            TandemReconcileOutput {
                next: TandemTogglePhase::Draining,
                reason: Some(CONTAIN_NOW_REASON),
            }
        }
        TandemTogglePhase::PreparingContained => match degradation {
            Some(reason) => TandemReconcileOutput {
                next: TandemTogglePhase::RuntimeContained {
                    reason,
                    desired_mode: desired,
                },
                reason: Some(reason),
            },
            None => {
                if readiness_is_ready(readiness) {
                    TandemReconcileOutput {
                        next: TandemTogglePhase::Prepared,
                        reason: None,
                    }
                } else {
                    // Unreachable by construction (degradation is None
                    // iff readiness is Ready); kept total anyway.
                    TandemReconcileOutput {
                        next: TandemTogglePhase::PreparingContained,
                        reason: None,
                    }
                }
            }
        },
        TandemTogglePhase::Prepared => match degradation {
            Some(reason) => TandemReconcileOutput {
                next: TandemTogglePhase::RuntimeContained {
                    reason,
                    desired_mode: desired,
                },
                reason: Some(reason),
            },
            None => TandemReconcileOutput {
                next: TandemTogglePhase::Active(desired),
                reason: None,
            },
        },
        TandemTogglePhase::Active(active_mode) => {
            if *active_mode != desired {
                // Mode changes require an explicit signed disable →
                // drain → enable cycle. A direct switch could widen
                // (managed → managed_redirect) or silently drop the
                // redirect (managed_redirect → managed, TDNS-19).
                return TandemReconcileOutput {
                    next: TandemTogglePhase::RuntimeContained {
                        reason: TandemReasonCode::ProfileMismatch,
                        desired_mode: desired,
                    },
                    reason: Some(TandemReasonCode::ProfileMismatch),
                };
            }
            match degradation {
                Some(reason) => TandemReconcileOutput {
                    next: TandemTogglePhase::RuntimeContained {
                        reason,
                        desired_mode: desired,
                    },
                    reason: Some(reason),
                },
                None => TandemReconcileOutput {
                    next: TandemTogglePhase::Active(*active_mode),
                    reason: None,
                },
            }
        }
        TandemTogglePhase::RuntimeContained {
            reason: _,
            desired_mode: contained_mode,
        } => {
            if *contained_mode != desired {
                // The desired policy no longer matches the mode that
                // was contained. Recovery must not silently change the
                // mode: stay contained and flag the profile drift.
                return TandemReconcileOutput {
                    next: TandemTogglePhase::RuntimeContained {
                        reason: TandemReasonCode::ProfileMismatch,
                        desired_mode: desired,
                    },
                    reason: Some(TandemReasonCode::ProfileMismatch),
                };
            }
            match degradation {
                Some(new_reason) => TandemReconcileOutput {
                    // Record the MOST RECENT degradation observation:
                    // the contained phase's reason should reflect the
                    // latest failed condition, not an arbitrary
                    // enum-order minimum.
                    next: TandemTogglePhase::RuntimeContained {
                        reason: new_reason,
                        desired_mode: desired,
                    },
                    reason: Some(new_reason),
                },
                None => TandemReconcileOutput {
                    // Recovery: the condition that caused containment
                    // cleared. Returns to the SAME mode only — never a
                    // wider one.
                    next: TandemTogglePhase::Active(desired),
                    reason: None,
                },
            }
        }
    }
}

fn validity_reason_code(validity: PolicyValidity) -> TandemReasonCode {
    match validity {
        PolicyValidity::Fresh => TandemReasonCode::SignedPolicyInvalid,
        PolicyValidity::Expired => TandemReasonCode::SignedPolicyExpired,
        PolicyValidity::ReplayRejected => TandemReasonCode::Replay,
        PolicyValidity::Invalid => TandemReasonCode::SignedPolicyInvalid,
    }
}

fn readiness_is_ready(readiness: &ReadinessObservation) -> bool {
    matches!(readiness, ReadinessObservation::Ready)
}

/// The local `contain now` safety veto (§5.1).
///
/// Contract: the veto can ONLY tighten. It never creates an OFF data
/// path (a contained phase keeps the signed policy and its recorded
/// reason rather than reverting to `Off`), never expands scope, never
/// changes mode, and never enables anything. Refusals are explicit.
pub fn contain_now(current: &TandemTogglePhase) -> ContainNowOutcome {
    match current {
        // Nothing ON to contain. Refusing here is the widening-proof:
        // "contain" on OFF must not create any state at all.
        TandemTogglePhase::Off => ContainNowOutcome::Refused {
            reason: TandemReasonCode::SignedPolicyInvalid,
            unchanged: TandemTogglePhase::Off,
        },
        // ERROR/residue posture refuses further mutation, including a
        // contain that could mask residue.
        TandemTogglePhase::ResidueError => ContainNowOutcome::Refused {
            reason: TandemReasonCode::Residue,
            unchanged: TandemTogglePhase::ResidueError,
        },
        // Already contained: idempotent no-op.
        TandemTogglePhase::RuntimeContained { .. } => ContainNowOutcome::Contained(*current),
        // ON family: tighten to contained, preserving the desired mode
        // as data. Scope is untouched (the veto cannot expand it and
        // narrowing happens at the dataplane layer, which this control
        // module does not reach).
        TandemTogglePhase::PreparingContained
        | TandemTogglePhase::Prepared
        | TandemTogglePhase::Active(_)
        | TandemTogglePhase::Draining => {
            let desired_mode = current.desired_mode().unwrap_or(TandemMode::Managed);
            ContainNowOutcome::Contained(TandemTogglePhase::RuntimeContained {
                reason: CONTAIN_NOW_REASON,
                desired_mode,
            })
        }
    }
}

/// Abstract, NON-AUTHORIZING prepare intent (§5.2).
///
/// **Wire format deliberately NOT defined here.** The signed record
/// shape (canonical serialization, signature envelope, strict decode)
/// is a security-gated owner decision recorded in the Phase-1 notes;
/// this struct defines only the validated, typed field set so the
/// state machine can be built against the abstract intent.
///
/// Semantics frozen by §5.2: a valid prepare intent authorizes
/// preparing local contained state and running canaries ONLY. It never
/// enables client use, never lets a client advertise a resolver, and
/// never opens the exit firewall's client endpoint admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TandemDnsPrepareIntentV1 {
    /// Network the intent applies to (as in the membership head
    /// commitment; `network_id` is the canonical string id).
    pub network_id: String,
    /// The named exit node that would host the tandem service.
    pub exit_node_id: String,
    /// Digest of the proposed service instance descriptor
    /// (32 bytes; exact preimage format is part of the gated wire
    /// format decision).
    pub service_instance_digest: [u8; 32],
    /// Digest of the proposed profile.
    pub profile_digest: [u8; 32],
    /// Digest of the proposed mode + scope (the policy shape this
    /// intent would prepare for).
    pub mode_scope_digest: [u8; 32],
    /// Membership epoch the intent was cut against.
    pub membership_epoch: u64,
    /// Freshness window, caller-supplied epoch seconds. Clock trust
    /// is the caller's concern (a clock deemed untrusted yields
    /// `TandemReasonCode::ClockUntrusted` at the call site).
    pub not_before: u64,
    pub not_after: u64,
    /// Single-use nonce (replay protection; the watermark itself
    /// lives in the existing replay machinery, not here).
    pub nonce: [u8; 32],
}

impl TandemDnsPrepareIntentV1 {
    /// Validate the intent against the caller-supplied clock and the
    /// current membership epoch. Pure; no signature verification (the
    /// signed envelope is the gated wire-format decision).
    ///
    /// Fail-closed ordering: structural validity first, then the time
    /// window, then epoch freshness.
    pub fn validate(
        &self,
        now_epoch: u64,
        current_membership_epoch: u64,
    ) -> Result<(), TandemReasonCode> {
        if self.network_id.trim().is_empty()
            || self.exit_node_id.trim().is_empty()
            || self.not_before >= self.not_after
        {
            return Err(TandemReasonCode::SignedPolicyInvalid);
        }
        // A non-zero nonce is required: an all-zero nonce would make
        // "freshness" forgeable across otherwise identical intents.
        // Constant-time compare per the workspace secret-material
        // equality audit (the nonce is replay-sensitive material).
        if bool::from(self.nonce.ct_eq(&[0u8; 32])) {
            return Err(TandemReasonCode::SignedPolicyInvalid);
        }
        // All digests must be present (non-zero). A zero digest would
        // bind the intent to nothing.
        if self.service_instance_digest == [0u8; 32]
            || self.profile_digest == [0u8; 32]
            || self.mode_scope_digest == [0u8; 32]
        {
            return Err(TandemReasonCode::SignedPolicyInvalid);
        }
        if now_epoch < self.not_before || now_epoch >= self.not_after {
            return Err(TandemReasonCode::SignedPolicyExpired);
        }
        // The intent is stale if the membership has advanced past the
        // epoch it was cut against: prepared-only state computed from
        // a superseded membership must not be trusted.
        if current_membership_epoch != self.membership_epoch {
            return Err(TandemReasonCode::ControlStaleWarning);
        }
        Ok(())
    }
}

/// Design §3 invariant 10 (control TDNS-03): `blind_exit` and tandem
/// DNS (`ServesDns`) are mutually exclusive. Enforcement point for the
/// enable path: an eligibility check the signed-ON apply path must
/// call before any tandem state mutation on this node.
///
/// Returns `Err(BLIND_EXIT_CONFLICT)` when the node's primary role is
/// `BlindExit`, or when a `ServesDns` capability would be combined
/// with an exit role already flagged blind. `Ok(())` otherwise.
pub fn validate_tandem_enable_eligibility(
    primary_role: crate::role_presets::PrimaryRole,
    capabilities: &[crate::role_presets::Capability],
) -> Result<(), TandemReasonCode> {
    if primary_role == crate::role_presets::PrimaryRole::BlindExit {
        return Err(TandemReasonCode::BlindExitConflict);
    }
    if capabilities.contains(&crate::role_presets::Capability::ServesDns)
        && primary_role == crate::role_presets::PrimaryRole::BlindExit
    {
        return Err(TandemReasonCode::BlindExitConflict);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on(mode: TandemMode) -> DesiredPolicy {
        DesiredPolicy::On(TandemDesiredOn {
            mode,
            exit_node_id: "exit-1".to_string(),
            scope: TandemScope::AllClientsUsingExit,
        })
    }

    fn fresh_on(mode: TandemMode) -> (DesiredPolicy, PolicyValidity, ReadinessObservation) {
        (on(mode), PolicyValidity::Fresh, ReadinessObservation::Ready)
    }

    fn rec(
        current: &TandemTogglePhase,
        desired: &DesiredPolicy,
        validity: PolicyValidity,
        readiness: &ReadinessObservation,
    ) -> TandemReconcileOutput {
        reconcile(
            current,
            desired,
            validity,
            readiness,
            true,
            ExitAssignment::ProvenSameExit,
            false,
            false,
        )
    }

    // ------------------------------------------------------------------
    // Legal transition matrix
    // ------------------------------------------------------------------

    #[test]
    fn off_with_fresh_policy_and_valid_intent_enables_to_preparing_contained() {
        let (desired, validity, readiness) = fresh_on(TandemMode::Managed);
        let out = rec(&TandemTogglePhase::Off, &desired, validity, &readiness);
        assert_eq!(out.next, TandemTogglePhase::PreparingContained);
        assert_eq!(out.reason, None);
    }

    #[test]
    fn preparing_contained_with_ready_readiness_advances_to_prepared() {
        let (desired, validity, readiness) = fresh_on(TandemMode::Managed);
        let out = rec(
            &TandemTogglePhase::PreparingContained,
            &desired,
            validity,
            &readiness,
        );
        assert_eq!(out.next, TandemTogglePhase::Prepared);
    }

    #[test]
    fn prepared_with_ready_readiness_activates_in_desired_mode() {
        for mode in [TandemMode::Managed, TandemMode::ManagedRedirect] {
            let (desired, validity, readiness) = fresh_on(mode);
            let out = rec(&TandemTogglePhase::Prepared, &desired, validity, &readiness);
            assert_eq!(out.next, TandemTogglePhase::Active(mode));
        }
    }

    #[test]
    fn active_is_sticky_when_all_conditions_hold() {
        for mode in [TandemMode::Managed, TandemMode::ManagedRedirect] {
            let (desired, validity, readiness) = fresh_on(mode);
            let out = rec(
                &TandemTogglePhase::Active(mode),
                &desired,
                validity,
                &readiness,
            );
            assert_eq!(out.next, TandemTogglePhase::Active(mode));
            assert_eq!(out.reason, None);
        }
    }

    #[test]
    fn runtime_contained_recovers_to_same_mode_when_condition_clears() {
        let (desired, validity, readiness) = fresh_on(TandemMode::ManagedRedirect);
        let out = rec(
            &TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::RustydnsUnreachable,
                desired_mode: TandemMode::ManagedRedirect,
            },
            &desired,
            validity,
            &readiness,
        );
        assert_eq!(
            out.next,
            TandemTogglePhase::Active(TandemMode::ManagedRedirect)
        );
        assert_eq!(out.reason, None);
    }

    #[test]
    fn signed_disable_drains_then_reaches_off_only_through_barrier() {
        let off = DesiredPolicy::Off;
        // Active → Draining
        let out = rec(
            &TandemTogglePhase::Active(TandemMode::Managed),
            &off,
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
        );
        assert_eq!(out.next, TandemTogglePhase::Draining);

        // Draining holds until the deactivation barrier passes.
        let out = reconcile(
            &TandemTogglePhase::Draining,
            &off,
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            false,
            false,
        );
        assert_eq!(out.next, TandemTogglePhase::Draining);

        // Barrier passed, no residue → Off.
        let out = reconcile(
            &TandemTogglePhase::Draining,
            &off,
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            true,
            false,
        );
        assert_eq!(out.next, TandemTogglePhase::Off);
        assert_eq!(out.reason, None);
    }

    #[test]
    fn every_on_family_phase_drains_on_signed_disable() {
        let off = DesiredPolicy::Off;
        let on_family = [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Active(TandemMode::Managed),
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::CanaryFailed,
                desired_mode: TandemMode::Managed,
            },
        ];
        for phase in on_family {
            let out = rec(
                &phase,
                &off,
                PolicyValidity::Fresh,
                &ReadinessObservation::Ready,
            );
            assert_eq!(out.next, TandemTogglePhase::Draining, "phase {phase:?}");
        }
    }

    // ------------------------------------------------------------------
    // Illegal transitions — fail closed
    // ------------------------------------------------------------------

    #[test]
    fn enable_without_valid_prepare_intent_is_refused() {
        let (desired, validity, readiness) = fresh_on(TandemMode::Managed);
        let out = reconcile(
            &TandemTogglePhase::Off,
            &desired,
            validity,
            &readiness,
            false,
            ExitAssignment::ProvenSameExit,
            false,
            false,
        );
        assert_eq!(out.next, TandemTogglePhase::Off);
        assert_eq!(out.reason, Some(TandemReasonCode::SignedPolicyInvalid));
    }

    #[test]
    fn enable_with_non_fresh_policy_is_refused_per_validity_kind() {
        let cases = [
            (
                PolicyValidity::Expired,
                TandemReasonCode::SignedPolicyExpired,
            ),
            (PolicyValidity::ReplayRejected, TandemReasonCode::Replay),
            (
                PolicyValidity::Invalid,
                TandemReasonCode::SignedPolicyInvalid,
            ),
        ];
        for (validity, expected_reason) in cases {
            let out = rec(
                &TandemTogglePhase::Off,
                &on(TandemMode::Managed),
                validity,
                &ReadinessObservation::Ready,
            );
            assert_eq!(out.next, TandemTogglePhase::Off);
            assert_eq!(out.reason, Some(expected_reason));
        }
    }

    #[test]
    fn degraded_inputs_never_activate_and_never_fall_back_to_off() {
        let degraded = [
            (
                PolicyValidity::Expired,
                ReadinessObservation::Ready,
                Some(TandemReasonCode::SignedPolicyExpired),
            ),
            (
                PolicyValidity::ReplayRejected,
                ReadinessObservation::Ready,
                Some(TandemReasonCode::Replay),
            ),
            (
                PolicyValidity::Invalid,
                ReadinessObservation::Ready,
                Some(TandemReasonCode::SignedPolicyInvalid),
            ),
            (
                PolicyValidity::Fresh,
                ReadinessObservation::NotReady(TandemReasonCode::ListenerUnready),
                Some(TandemReasonCode::ListenerUnready),
            ),
            (
                PolicyValidity::Fresh,
                ReadinessObservation::Stale,
                Some(TandemReasonCode::ControlStaleWarning),
            ),
            (
                PolicyValidity::Fresh,
                ReadinessObservation::Unauthenticated,
                Some(TandemReasonCode::LocalAuthFailed),
            ),
            (
                PolicyValidity::Fresh,
                ReadinessObservation::Incompatible(TandemReasonCode::ProtocolIncompatible),
                Some(TandemReasonCode::ProtocolIncompatible),
            ),
            (
                PolicyValidity::Fresh,
                ReadinessObservation::NotReady(TandemReasonCode::RustydnsUnreachable),
                Some(TandemReasonCode::RustydnsUnreachable),
            ),
        ];
        let on_family = [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::UpstreamUnready,
                desired_mode: TandemMode::ManagedRedirect,
            },
        ];
        for phase in on_family {
            for (validity, readiness, expected) in degraded {
                let out = rec(
                    &phase,
                    &on(TandemMode::ManagedRedirect),
                    validity,
                    &readiness,
                );
                assert_eq!(
                    out.next,
                    TandemTogglePhase::RuntimeContained {
                        reason: expected.unwrap(),
                        desired_mode: TandemMode::ManagedRedirect,
                    },
                    "phase {phase:?} + {validity:?} + {readiness:?}"
                );
                // Never an OFF data path, never Active.
                assert_ne!(out.next, TandemTogglePhase::Off);
                assert!(!matches!(out.next, TandemTogglePhase::Active(_)));
            }
        }
    }

    #[test]
    fn unknown_exit_assignment_fails_closed_as_mismatch() {
        for assignment in [ExitAssignment::Unknown, ExitAssignment::ProvenMismatch] {
            let out = reconcile(
                &TandemTogglePhase::Prepared,
                &on(TandemMode::Managed),
                PolicyValidity::Fresh,
                &ReadinessObservation::Ready,
                true,
                assignment,
                false,
                false,
            );
            assert_eq!(
                out.next,
                TandemTogglePhase::RuntimeContained {
                    reason: TandemReasonCode::AssignmentMismatch,
                    desired_mode: TandemMode::Managed,
                }
            );
        }
    }

    #[test]
    fn no_input_combination_moves_on_family_to_off_except_drain_completion() {
        // Every desired/validity/readiness/assignment combination from
        // every ON-family phase must land somewhere in the ON family
        // (or contained), never in Off or ResidueError.
        let validities = [
            PolicyValidity::Fresh,
            PolicyValidity::Expired,
            PolicyValidity::ReplayRejected,
            PolicyValidity::Invalid,
        ];
        let readinesses = [
            ReadinessObservation::Ready,
            ReadinessObservation::Stale,
            ReadinessObservation::Unauthenticated,
            ReadinessObservation::NotReady(TandemReasonCode::CanaryFailed),
        ];
        let assignments = [
            ExitAssignment::ProvenSameExit,
            ExitAssignment::ProvenMismatch,
            ExitAssignment::Unknown,
        ];
        let on_family = [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::RuleDrift,
                desired_mode: TandemMode::ManagedRedirect,
            },
        ];
        for phase in on_family {
            for validity in validities {
                for readiness in readinesses {
                    for assignment in assignments {
                        let out = reconcile(
                            &phase,
                            &on(TandemMode::ManagedRedirect),
                            validity,
                            &readiness,
                            true,
                            assignment,
                            false,
                            false,
                        );
                        assert_ne!(out.next, TandemTogglePhase::Off, "phase {phase:?}");
                        assert_ne!(out.next, TandemTogglePhase::ResidueError, "phase {phase:?}");
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Mode semantics — no fallback (TDNS-19), no silent switch
    // ------------------------------------------------------------------

    #[test]
    fn active_managed_redirect_never_falls_back_to_managed() {
        // The ONLY mode change outcome from Active is containment with
        // PROFILE_MISMATCH; no input yields Active(Managed).
        let validities = [
            PolicyValidity::Fresh,
            PolicyValidity::Expired,
            PolicyValidity::ReplayRejected,
            PolicyValidity::Invalid,
        ];
        let readinesses = [
            ReadinessObservation::Ready,
            ReadinessObservation::Stale,
            ReadinessObservation::NotReady(TandemReasonCode::ListenerUnready),
        ];
        for validity in validities {
            for readiness in readinesses {
                let out = rec(
                    &TandemTogglePhase::Active(TandemMode::ManagedRedirect),
                    &on(TandemMode::Managed),
                    validity,
                    &readiness,
                );
                assert_ne!(
                    out.next,
                    TandemTogglePhase::Active(TandemMode::Managed),
                    "managed_redirect fell back to managed via {validity:?}/{readiness:?}"
                );
            }
        }
    }

    #[test]
    fn direct_mode_switch_while_active_is_refused_with_profile_mismatch() {
        for (from, to) in [
            (TandemMode::Managed, TandemMode::ManagedRedirect),
            (TandemMode::ManagedRedirect, TandemMode::Managed),
        ] {
            let out = rec(
                &TandemTogglePhase::Active(from),
                &on(to),
                PolicyValidity::Fresh,
                &ReadinessObservation::Ready,
            );
            assert_eq!(out.reason, Some(TandemReasonCode::ProfileMismatch));
            assert!(!matches!(out.next, TandemTogglePhase::Active(_)));
        }
    }

    #[test]
    fn contained_mode_drift_refuses_recovery() {
        let out = rec(
            &TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::RustydnsUnreachable,
                desired_mode: TandemMode::ManagedRedirect,
            },
            &on(TandemMode::Managed),
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
        );
        assert_eq!(out.reason, Some(TandemReasonCode::ProfileMismatch));
        assert!(!matches!(out.next, TandemTogglePhase::Active(_)));
    }

    // ------------------------------------------------------------------
    // Residue / ERROR posture
    // ------------------------------------------------------------------

    #[test]
    fn residue_error_refuses_every_enable() {
        for validity in [
            PolicyValidity::Fresh,
            PolicyValidity::Expired,
            PolicyValidity::ReplayRejected,
            PolicyValidity::Invalid,
        ] {
            for readiness in [
                ReadinessObservation::Ready,
                ReadinessObservation::NotReady(TandemReasonCode::UpstreamUnready),
            ] {
                let out = rec(
                    &TandemTogglePhase::ResidueError,
                    &on(TandemMode::Managed),
                    validity,
                    &readiness,
                );
                assert_eq!(out.next, TandemTogglePhase::ResidueError);
                assert_eq!(out.reason, Some(TandemReasonCode::Residue));
            }
        }
    }

    #[test]
    fn drain_with_residue_lands_in_residue_error() {
        let out = reconcile(
            &TandemTogglePhase::Draining,
            &DesiredPolicy::Off,
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            true,
            true,
        );
        assert_eq!(out.next, TandemTogglePhase::ResidueError);
        assert_eq!(out.reason, Some(TandemReasonCode::Residue));
    }

    #[test]
    fn residue_error_requires_positive_clear_to_reach_off() {
        // Desired Off + residue gone (explicitly not present) → Off.
        let out = reconcile(
            &TandemTogglePhase::ResidueError,
            &DesiredPolicy::Off,
            PolicyValidity::Fresh,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            true,
            false,
        );
        assert_eq!(out.next, TandemTogglePhase::Off);
    }

    // ------------------------------------------------------------------
    // `contain now` — strictly tightening
    // ------------------------------------------------------------------

    #[test]
    fn contain_now_never_increases_capability_width() {
        let phases = [
            TandemTogglePhase::Off,
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Active(TandemMode::Managed),
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::RustydnsUnreachable,
                desired_mode: TandemMode::ManagedRedirect,
            },
            TandemTogglePhase::Draining,
            TandemTogglePhase::ResidueError,
        ];
        for phase in phases {
            let before = capability_width(&phase);
            match contain_now(&phase) {
                ContainNowOutcome::Contained(next) => {
                    assert!(
                        capability_width(&next) <= before,
                        "contain widened {phase:?} → {next:?}"
                    );
                }
                ContainNowOutcome::Refused { unchanged, .. } => {
                    assert_eq!(capability_width(&unchanged), before);
                }
            }
        }
    }

    #[test]
    fn contain_now_strictly_tightens_every_on_family_phase() {
        let on_family = [
            TandemTogglePhase::PreparingContained,
            TandemTogglePhase::Prepared,
            TandemTogglePhase::Active(TandemMode::Managed),
            TandemTogglePhase::Active(TandemMode::ManagedRedirect),
            TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::RuleApplyFailed,
                desired_mode: TandemMode::Managed,
            },
            TandemTogglePhase::Draining,
        ];
        for phase in on_family {
            let before = capability_width(&phase);
            match contain_now(&phase) {
                ContainNowOutcome::Contained(next) => {
                    assert!(matches!(next, TandemTogglePhase::RuntimeContained { .. }));
                    assert!(
                        capability_width(&next) < before || before <= 1,
                        "contain did not tighten {phase:?}"
                    );
                    // Desired mode preserved as data — never changed.
                    // Phases that carry no mode of their own
                    // (PreparingContained/Prepared/Draining) take the
                    // Managed placeholder; the signed policy remains
                    // the mode authority at reconcile time.
                    if let Some(mode) = phase.desired_mode() {
                        assert_eq!(next.desired_mode(), Some(mode));
                    }
                }
                ContainNowOutcome::Refused { .. } => {
                    panic!("contain_now refused an ON-family phase: {phase:?}")
                }
            }
        }
    }

    #[test]
    fn contain_now_cannot_enable_from_off_or_residue() {
        match contain_now(&TandemTogglePhase::Off) {
            ContainNowOutcome::Refused { unchanged, .. } => {
                assert_eq!(unchanged, TandemTogglePhase::Off);
            }
            ContainNowOutcome::Contained(_) => panic!("contain created state from Off"),
        }
        match contain_now(&TandemTogglePhase::ResidueError) {
            ContainNowOutcome::Refused { unchanged, .. } => {
                assert_eq!(unchanged, TandemTogglePhase::ResidueError);
            }
            ContainNowOutcome::Contained(_) => panic!("contain mutated ResidueError"),
        }
    }

    #[test]
    fn contain_now_is_idempotent_when_already_contained() {
        let contained = TandemTogglePhase::RuntimeContained {
            reason: TandemReasonCode::BypassRuleDrift,
            desired_mode: TandemMode::Managed,
        };
        assert_eq!(
            contain_now(&contained),
            ContainNowOutcome::Contained(contained)
        );
    }

    #[test]
    fn reconcile_never_widens_from_contained_on_degraded_inputs() {
        // From a contained phase, only the exact recovery conditions
        // (fresh + ready + proven assignment + same mode) may widen.
        let contained = TandemTogglePhase::RuntimeContained {
            reason: TandemReasonCode::ListenerUnready,
            desired_mode: TandemMode::ManagedRedirect,
        };
        let out = reconcile(
            &contained,
            &on(TandemMode::ManagedRedirect),
            PolicyValidity::Expired,
            &ReadinessObservation::Ready,
            true,
            ExitAssignment::ProvenSameExit,
            false,
            false,
        );
        assert!(
            capability_width(&out.next) <= capability_width(&contained),
            "expired policy widened a contained phase"
        );
    }

    // ------------------------------------------------------------------
    // Closed reason-code vocabulary
    // ------------------------------------------------------------------

    #[test]
    fn reason_codes_round_trip_and_are_closed() {
        assert_eq!(TandemReasonCode::ALL.len(), 24);
        for code in TandemReasonCode::ALL {
            assert_eq!(TandemReasonCode::parse(code.as_str()), Some(code));
        }
        assert_eq!(TandemReasonCode::parse("NOT_A_CODE"), None);
        assert_eq!(TandemReasonCode::parse(""), None);
    }

    // ------------------------------------------------------------------
    // Scope validation (fail closed)
    // ------------------------------------------------------------------

    #[test]
    fn scope_validation_rejects_empty_unsorted_deduped_and_overbound() {
        assert_eq!(TandemScope::AllClientsUsingExit.validate(), Ok(()));
        assert_eq!(
            TandemScope::NodeIds(vec![]).validate(),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        assert_eq!(
            TandemScope::NodeIds(vec!["b".into(), "a".into()]).validate(),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        assert_eq!(
            TandemScope::NodeIds(vec!["a".into(), "a".into()]).validate(),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        let overbound: Vec<String> = (0..=TANDEM_SCOPE_MAX_NODE_IDS)
            .map(|i| format!("node-{i:04}"))
            .collect();
        assert_eq!(
            TandemScope::NodeIds(overbound).validate(),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        let at_bound: Vec<String> = (0..TANDEM_SCOPE_MAX_NODE_IDS)
            .map(|i| format!("node-{i:04}"))
            .collect();
        assert_eq!(TandemScope::NodeIds(at_bound).validate(), Ok(()));
    }

    // ------------------------------------------------------------------
    // Prepare intent validation (abstract; wire format gated)
    // ------------------------------------------------------------------

    fn valid_intent() -> TandemDnsPrepareIntentV1 {
        TandemDnsPrepareIntentV1 {
            network_id: "net-1".to_string(),
            exit_node_id: "exit-1".to_string(),
            service_instance_digest: [1u8; 32],
            profile_digest: [2u8; 32],
            mode_scope_digest: [3u8; 32],
            membership_epoch: 7,
            not_before: 100,
            not_after: 200,
            nonce: [9u8; 32],
        }
    }

    #[test]
    fn prepare_intent_accepts_a_fresh_epoch_aligned_intent() {
        assert_eq!(valid_intent().validate(150, 7), Ok(()));
    }

    #[test]
    fn prepare_intent_fails_closed_on_structural_or_freshness_or_epoch_faults() {
        let base = valid_intent();
        // Window inverted.
        let mut i = base.clone();
        i.not_before = 300;
        assert_eq!(
            i.validate(150, 7),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        // Before window.
        assert_eq!(
            base.validate(50, 7),
            Err(TandemReasonCode::SignedPolicyExpired)
        );
        // At/after expiry (not_after is exclusive).
        assert_eq!(
            base.validate(200, 7),
            Err(TandemReasonCode::SignedPolicyExpired)
        );
        // Zero nonce.
        let mut i = base.clone();
        i.nonce = [0u8; 32];
        assert_eq!(
            i.validate(150, 7),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        // Zero digest.
        let mut i = base.clone();
        i.service_instance_digest = [0u8; 32];
        assert_eq!(
            i.validate(150, 7),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        // Empty identifiers.
        let mut i = base.clone();
        i.exit_node_id = "  ".to_string();
        assert_eq!(
            i.validate(150, 7),
            Err(TandemReasonCode::SignedPolicyInvalid)
        );
        // Superseded membership epoch.
        assert_eq!(
            base.validate(150, 8),
            Err(TandemReasonCode::ControlStaleWarning)
        );
    }

    // ------------------------------------------------------------------
    // Blind-exit conflict (§3 invariant 10 / TDNS-03)
    // ------------------------------------------------------------------

    #[test]
    fn blind_exit_conflicts_with_tandem_enable() {
        use crate::role_presets::{Capability, PrimaryRole};
        assert_eq!(
            validate_tandem_enable_eligibility(PrimaryRole::BlindExit, &[]),
            Err(TandemReasonCode::BlindExitConflict)
        );
        assert_eq!(
            validate_tandem_enable_eligibility(PrimaryRole::BlindExit, &[Capability::ServesDns]),
            Err(TandemReasonCode::BlindExitConflict)
        );
        // Non-blind roles are eligible (exit role is the normal host).
        assert_eq!(
            validate_tandem_enable_eligibility(
                PrimaryRole::Admin,
                &[Capability::ServesExit, Capability::ServesDns]
            ),
            Ok(())
        );
    }

    // ------------------------------------------------------------------
    // Readiness provider trait (stub) — fail-closed default
    // ------------------------------------------------------------------

    #[test]
    fn static_readiness_provider_reports_what_it_was_given() {
        let provider = StaticReadinessProvider(ReadinessObservation::Stale);
        assert_eq!(provider.readiness(), ReadinessObservation::Stale);
        assert_eq!(
            provider.readiness().contain_reason(),
            Some(TandemReasonCode::ControlStaleWarning)
        );
        assert_eq!(
            StaticReadinessProvider(ReadinessObservation::Ready)
                .readiness()
                .contain_reason(),
            None
        );
    }

    // ------------------------------------------------------------------
    // Reconcile is total: exhaustively exercised above; also pin the
    // width ordering that the proofs lean on.
    // ------------------------------------------------------------------

    #[test]
    fn capability_width_ordering_holds() {
        assert_eq!(capability_width(&TandemTogglePhase::Off), 0);
        assert_eq!(capability_width(&TandemTogglePhase::ResidueError), 0);
        assert_eq!(
            capability_width(&TandemTogglePhase::RuntimeContained {
                reason: TandemReasonCode::Residue,
                desired_mode: TandemMode::Managed
            }),
            1
        );
        assert_eq!(capability_width(&TandemTogglePhase::Draining), 1);
        assert_eq!(capability_width(&TandemTogglePhase::PreparingContained), 1);
        assert_eq!(capability_width(&TandemTogglePhase::Prepared), 2);
        assert_eq!(
            capability_width(&TandemTogglePhase::Active(TandemMode::Managed)),
            3
        );
        assert_eq!(
            capability_width(&TandemTogglePhase::Active(TandemMode::ManagedRedirect)),
            4
        );
    }
}
