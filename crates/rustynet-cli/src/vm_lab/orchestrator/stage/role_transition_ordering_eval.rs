#![cfg_attr(not(test), allow(dead_code))]
// Dead-code allowance is deliberate: the live driving path (stage wiring) lands
// with the rename+extend change (design §3.1) once the lab is available; until
// then only the #[cfg(test)] suite executes this module.

//! Offline, pure decision logic for GAP-1 — role-transition side-effect
//! ORDERING validation, per
//! `documents/operations/active/LiveLabTransitionOrderingStageDesign_2026-09-01.md`:
//! §2 (the per-transition-kind assertions, including the A3 state-anchor
//! fallback rule and A4 bounded-window semantics), §2.5 (audit-assertion scope
//! and the pre-registered CLI-only audit-wiring fact), §3.3 (reuse), §3.4
//! (fail-loud), and §4 (the offline tests pinned below). Decree under test:
//! `AGENTS.md` §10.7, mirrored by `documents/SecurityMinimumBar.md` §6.D.
//!
//! This module is an evaluator over *recorded* observations: no I/O in the
//! production paths, no adapter calls, no SSH, no lab. The stage rename
//! (`role_switch_matrix` → `live_role_transition_ordering_validation`) and the
//! wiring of this core into a stage body are explicitly NOT part of this
//! module; they land in a separate later change.

use std::collections::BTreeMap;

use rustynet_control::role_audit::{verify_role_audit_chain, RoleAuditEntry};
use rustynet_control::role_presets::{
    Capability, RolePreset, ServiceKind, TransitionKind, TransitionPlan,
};

use crate::vm_lab::orchestrator::error::StageOutcome;

// ── A. Ordering comparator (design §2 preamble A3, §2.1–§2.3, §4 test 1) ────

/// Admissible A3 fallback anchors. Every fallback ordering acceptance must be
/// anchored to an effect the transition itself performed; an unanchored
/// fallback acceptance is a failure, never a pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateAnchor {
    /// (i) a post-transition deploy/restart acknowledgment with a fresh
    /// process identity (fresh PID / boot-id / start-time relative to a
    /// pre-transition capture).
    FreshProcessIdentity,
    /// (ii) a first-ever observation of the service's state against a
    /// pre-transition snapshot that recorded the opposite state.
    FirstEverObservation,
}

/// One recorded side-effect (or emission) observation with its wall-clock
/// timestamp and, where the timestamp alone is ambiguous, its state anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub at_unix: Option<u64>,
    pub state_anchor: Option<StateAnchor>,
}

/// The four decree kinds (`AGENTS.md` §10.7 / SecurityMinimumBar §6.D).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderingRule {
    /// Adding `serves_relay`: deploy service BEFORE emitting the signed bundle.
    DeployBeforeAdvertise,
    /// Removing `serves_relay`: undeploy service BEFORE the revocation bundle.
    UndeployBeforeRevocation,
    /// Exit NAT: tear down BEFORE removing the capability (residue =
    /// release-blocker).
    TeardownBeforeCapabilityRemoval,
    /// `blind_exit` is irreversible — requires factory reset.
    BlindExitIrreversible,
}

impl OrderingRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeployBeforeAdvertise => "deploy_before_advertise",
            Self::UndeployBeforeRevocation => "undeploy_before_revocation",
            Self::TeardownBeforeCapabilityRemoval => "teardown_before_capability_removal",
            Self::BlindExitIrreversible => "blind_exit_irreversible",
        }
    }
}

/// Compare a side-effect observation against the bundle/revocation emission
/// observation for one decree rule.
///
/// Strict `side_effect.at_unix < bundle.at_unix` is accepted for the three
/// ordering rules. An inversion (side effect observed at or after emission) is
/// rejected, naming the rule. On EQUAL timestamps or a missing timestamp the
/// A3 state-based fallback applies: the side-effect observation must carry a
/// [`StateAnchor`] — an unanchored fallback is a FAILURE, an anchored one is
/// accepted.
pub fn compare_ordering(
    rule: OrderingRule,
    side_effect: &Observation,
    bundle: &Observation,
) -> Result<(), String> {
    match (side_effect.at_unix, bundle.at_unix) {
        (Some(side_effect_ts), Some(bundle_ts)) if side_effect_ts < bundle_ts => Ok(()),
        (Some(side_effect_ts), Some(bundle_ts)) if side_effect_ts > bundle_ts => Err(format!(
            "ordering violation for rule {}: side effect observed at unix {} is not \
             strictly before the emission record at unix {}; the decree requires the \
             side effect first",
            rule.as_str(),
            side_effect_ts,
            bundle_ts
        )),
        // Equal timestamps or any missing timestamp: A3 state-based fallback.
        _ => match side_effect.state_anchor {
            Some(_anchor) => Ok(()),
            None => Err(format!(
                "ordering for rule {} is inconclusive (equal or missing timestamps) and \
                 the side-effect observation carries no state anchor; an unanchored \
                 fallback acceptance is a failure, never a pass (design §2, review A3)",
                rule.as_str()
            )),
        },
    }
}

// ── B. Plan-vs-observed sequencer (design §3.3, §4 test 2) ──────────────────

/// One step a live run can observe during a role transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedStep {
    /// A sibling service binary was deployed (deploy-before-advertise).
    ServiceDeployed(ServiceKind),
    /// The signed membership bundle advertising this capability was distributed.
    CapabilityAdvertised(Capability),
    /// The signed membership bundle was emitted.
    BundleEmitted,
    /// Exit NAT rules were torn down (teardown-before-capability-removal).
    NatTornDown,
    /// A sibling service binary was stopped/undeployed
    /// (undeploy-before-revocation).
    ServiceUndeployed(ServiceKind),
    /// The capability was removed from local state.
    CapabilityRemoved(Capability),
    /// The signed revocation bundle was emitted.
    RevocationEmitted,
    /// A transition attempt was rejected by the matrix before any side effect.
    BlockedAttempt,
    /// An irreversible transition (entering `blind_exit`) was executed.
    IrreversibleEntry,
}

impl ObservedStep {
    pub fn label(&self) -> String {
        match self {
            Self::ServiceDeployed(kind) => format!("service_deployed({})", kind.as_str()),
            Self::CapabilityAdvertised(cap) => {
                format!("capability_advertised({})", cap.as_str())
            }
            Self::BundleEmitted => "bundle_emitted".to_owned(),
            Self::NatTornDown => "nat_torn_down".to_owned(),
            Self::ServiceUndeployed(kind) => format!("service_undeployed({})", kind.as_str()),
            Self::CapabilityRemoved(cap) => format!("capability_removed({})", cap.as_str()),
            Self::RevocationEmitted => "revocation_emitted".to_owned(),
            Self::BlockedAttempt => "blocked_attempt".to_owned(),
            Self::IrreversibleEntry => "irreversible_entry".to_owned(),
        }
    }
}

/// Derive the decree-ordered expected steps from a [`TransitionPlan`]
/// (`rustynet_control::role_presets::transition_plan`), the ordering oracle:
/// deploy before advertise; undeploy before revocation; NAT teardown before
/// exit-capability removal. Blocked and irreversible plans compute no side
/// effects, so they yield the single terminal step.
pub fn expected_sequence(plan: &TransitionPlan) -> Vec<ObservedStep> {
    match &plan.kind {
        TransitionKind::Blocked(_reason) => return vec![ObservedStep::BlockedAttempt],
        TransitionKind::Irreversible(_reason) => return vec![ObservedStep::IrreversibleEntry],
        _ => {}
    }
    let mut sequence = Vec::new();
    // Adding direction: deploy service BEFORE the bundle advertises (§10.7).
    for kind in &plan.service_deploys {
        sequence.push(ObservedStep::ServiceDeployed(*kind));
    }
    for cap in &plan.adds_capabilities {
        sequence.push(ObservedStep::CapabilityAdvertised(*cap));
    }
    if !plan.adds_capabilities.is_empty() {
        sequence.push(ObservedStep::BundleEmitted);
    }
    // Removal direction: NAT teardown BEFORE the exit capability is removed
    // (§10.7 line 3), then undeploy before the revocation drops the
    // capability (§10.7 line 2).
    if plan.removes_capabilities.contains(&Capability::ServesExit) {
        sequence.push(ObservedStep::NatTornDown);
    }
    for kind in &plan.service_undeploys {
        sequence.push(ObservedStep::ServiceUndeployed(*kind));
    }
    for cap in &plan.removes_capabilities {
        sequence.push(ObservedStep::CapabilityRemoved(*cap));
    }
    if !plan.removes_capabilities.is_empty() {
        sequence.push(ObservedStep::RevocationEmitted);
    }
    sequence
}

/// Check the observed step sequence against the expected one. The first
/// out-of-order or missing step is named in the failure string; unexpected
/// extra steps are also a failure.
pub fn check_sequence(expected: &[ObservedStep], observed: &[ObservedStep]) -> Result<(), String> {
    let mut cursor = 0usize;
    for step in expected {
        match observed[cursor..]
            .iter()
            .position(|candidate| candidate == step)
        {
            Some(0) => cursor += 1,
            Some(offset) => {
                return Err(format!(
                    "observed step '{}' is out of order: expected '{}' next (first \
                     out-of-order step)",
                    observed[cursor + offset].label(),
                    step.label()
                ));
            }
            None => {
                return Err(format!("missing observed step: '{}'", step.label()));
            }
        }
    }
    if observed.len() > cursor {
        return Err(format!(
            "unexpected extra observed step: '{}'",
            observed[cursor].label()
        ));
    }
    Ok(())
}

// ── C. Outcome aggregation (design §3.4, §4 test 5) ─────────────────────────

/// Aggregate per-node failures and reported skips into the stage outcome,
/// with the same semantics as `exit_nat_lifecycle_validation::outcome_for`.
/// That function is file-private in its owning module, so the semantics are
/// mirrored here (design §3.3 reuse note) rather than imported: any failure →
/// `Failed`; skips only → `Skipped` naming the count and that nothing
/// executed; clean → `Passed`.
pub fn aggregate_outcome(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped(format!(
            "no node executed this validation; {} node(s) reported a runtime skip",
            reported_skips.len()
        ))
    } else {
        StageOutcome::Passed
    }
}

// ── D. Blind-exit blocked assertion (design §2.4(a), §4 test 6) ─────────────

/// Outcome of a CLI-driven attempt to transition away from `blind_exit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReversalAttempt {
    /// The transition matrix / CLI rejected the attempt.
    Rejected,
    /// The attempt was accepted and executed — irreversibility violated.
    Accepted,
}

/// Assess a `blind_exit` reversal attempt against the decree
/// (`blind_exit` is irreversible). Accepted attempt → failure. Rejected
/// attempt with unchanged node state → ok. Rejected attempt with mutated
/// state → failure: the block happened AFTER a side effect, which is
/// precisely the hazard this assertion exists to catch.
pub fn assess_blind_exit_reversal(
    attempt: ReversalAttempt,
    state_before: &str,
    state_after: &str,
) -> Result<(), String> {
    match attempt {
        ReversalAttempt::Accepted => Err(
            "blind_exit reversal attempt was accepted; blind_exit is irreversible \
             (AGENTS.md §10.7 / SecurityMinimumBar §6.D) and requires a factory reset"
                .to_owned(),
        ),
        ReversalAttempt::Rejected if state_before == state_after => Ok(()),
        ReversalAttempt::Rejected => Err(format!(
            "blind_exit reversal was rejected but node state changed ({state_before} -> \
             {state_after}); the block happened AFTER a side effect"
        )),
    }
}

// ── E. Audit growth verifier (design §2.1(c)–§2.5, §4 test 3) ───────────────

/// One expected preset-transition audit event: a CLI-driven transition from
/// `from` to `to` must have appended exactly this kind of entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedAuditEvent {
    pub from: RolePreset,
    pub to: RolePreset,
}

/// Verify the recorded audit entries: first the tamper-evident chain
/// (`verify_role_audit_chain`; any chain error maps to a stage failure
/// string), then one matching entry per expected transition event, naming any
/// missing kind.
pub fn verify_audit_growth(
    entries: &[RoleAuditEntry],
    expected: &[ExpectedAuditEvent],
) -> Result<(), String> {
    verify_role_audit_chain(entries)
        .map_err(|e| format!("role audit chain verification failed: {e}"))?;
    for want in expected {
        let matched = entries.iter().any(|entry| {
            decode_event_payload(entry).is_some_and(|payload| {
                payload.get("event_kind").map(String::as_str) == Some("preset_transition")
                    && payload.get("from").map(String::as_str) == Some(want.from.as_str())
                    && payload.get("to").map(String::as_str) == Some(want.to.as_str())
            })
        });
        if !matched {
            return Err(format!(
                "audit log is missing an entry for preset transition {} -> {}; expected \
                 one append-only entry per CLI-driven transition (design §2.5)",
                want.from.as_str(),
                want.to.as_str()
            ));
        }
    }
    Ok(())
}

/// Hex-decode an entry's `event_hex` and parse its canonical `key=value`
/// payload lines into a field map. `None` on any decode/parse failure — the
/// chain verifier is the authority on malformed payloads.
fn decode_event_payload(entry: &RoleAuditEntry) -> Option<BTreeMap<String, String>> {
    let bytes = hex_decode(&entry.event_hex)?;
    let payload = String::from_utf8(bytes).ok()?;
    let mut fields = BTreeMap::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=')?;
        fields.insert(key.to_owned(), value.to_owned());
    }
    Some(fields)
}

/// Lowercase hex decode of an even-length hex string.
fn hex_decode(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    (0..input.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&input[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustynet_control::role_audit::{
        append_role_audit_entry, read_role_audit_log, RoleTransitionEvent, RoleTransitionOutcome,
    };
    use rustynet_control::role_presets::transition_plan;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::time::{SystemTime, UNIX_EPOCH};

    // ── A. Ordering comparator table ──

    fn observation(at_unix: Option<u64>, state_anchor: Option<StateAnchor>) -> Observation {
        Observation {
            at_unix,
            state_anchor,
        }
    }

    #[test]
    fn ordering_comparator_accepts_strict_side_effect_before_emission_for_every_rule() {
        for rule in [
            OrderingRule::DeployBeforeAdvertise,
            OrderingRule::UndeployBeforeRevocation,
            OrderingRule::TeardownBeforeCapabilityRemoval,
            OrderingRule::BlindExitIrreversible,
        ] {
            assert!(compare_ordering(
                rule,
                &observation(Some(100), None),
                &observation(Some(200), None)
            )
            .is_ok());
        }
    }

    #[test]
    fn ordering_comparator_rejects_inversion_naming_the_rule() {
        for rule in [
            OrderingRule::DeployBeforeAdvertise,
            OrderingRule::UndeployBeforeRevocation,
            OrderingRule::TeardownBeforeCapabilityRemoval,
            OrderingRule::BlindExitIrreversible,
        ] {
            let err = compare_ordering(
                rule,
                &observation(Some(200), None),
                &observation(Some(100), None),
            )
            .unwrap_err();
            assert!(err.contains(rule.as_str()), "{err}");
            assert!(err.contains("not strictly before"), "{err}");
        }
    }

    #[test]
    fn ordering_comparator_equal_timestamps_require_a_state_anchor() {
        for rule in [
            OrderingRule::DeployBeforeAdvertise,
            OrderingRule::UndeployBeforeRevocation,
            OrderingRule::TeardownBeforeCapabilityRemoval,
            OrderingRule::BlindExitIrreversible,
        ] {
            for anchor in [
                StateAnchor::FreshProcessIdentity,
                StateAnchor::FirstEverObservation,
            ] {
                assert!(compare_ordering(
                    rule,
                    &observation(Some(150), Some(anchor)),
                    &observation(Some(150), None)
                )
                .is_ok());
                let err = compare_ordering(
                    rule,
                    &observation(Some(150), None),
                    &observation(Some(150), None),
                )
                .unwrap_err();
                assert!(err.contains("no state anchor"), "{err}");
            }
        }
    }

    #[test]
    fn ordering_comparator_missing_timestamp_requires_a_state_anchor() {
        for rule in [
            OrderingRule::DeployBeforeAdvertise,
            OrderingRule::UndeployBeforeRevocation,
            OrderingRule::TeardownBeforeCapabilityRemoval,
            OrderingRule::BlindExitIrreversible,
        ] {
            for anchor in [
                StateAnchor::FreshProcessIdentity,
                StateAnchor::FirstEverObservation,
            ] {
                assert!(compare_ordering(
                    rule,
                    &observation(None, Some(anchor)),
                    &observation(Some(200), None)
                )
                .is_ok());
                assert!(compare_ordering(
                    rule,
                    &observation(None, None),
                    &observation(Some(200), None)
                )
                .is_err());
            }
            assert!(compare_ordering(
                rule,
                &observation(Some(100), Some(StateAnchor::FirstEverObservation)),
                &observation(None, None)
            )
            .is_ok());
            assert!(compare_ordering(
                rule,
                &observation(Some(100), None),
                &observation(None, None)
            )
            .is_err());
        }
    }

    // ── B. Plan-vs-observed sequencer ──

    #[test]
    fn sequencer_accepts_decree_ordered_sequences_for_all_four_transition_kinds() {
        // client → relay: deploy service BEFORE the bundle advertises.
        let plan = transition_plan(RolePreset::Client, RolePreset::Relay);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        let expected = expected_sequence(&plan);
        let observed = vec![
            ObservedStep::ServiceDeployed(ServiceKind::Relay),
            ObservedStep::CapabilityAdvertised(Capability::ServesRelay),
            ObservedStep::BundleEmitted,
        ];
        assert_eq!(expected, observed);
        assert!(check_sequence(&expected, &observed).is_ok());

        // relay → client: undeploy service BEFORE the revocation bundle.
        let plan = transition_plan(RolePreset::Relay, RolePreset::Client);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        let expected = expected_sequence(&plan);
        let observed = vec![
            ObservedStep::ServiceUndeployed(ServiceKind::Relay),
            ObservedStep::CapabilityRemoved(Capability::ServesRelay),
            ObservedStep::RevocationEmitted,
        ];
        assert_eq!(expected, observed);
        assert!(check_sequence(&expected, &observed).is_ok());

        // exit → client: NAT teardown BEFORE the exit capability is removed.
        let plan = transition_plan(RolePreset::Exit, RolePreset::Client);
        assert_eq!(plan.kind, TransitionKind::SignedMembership);
        let expected = expected_sequence(&plan);
        let observed = vec![
            ObservedStep::NatTornDown,
            ObservedStep::CapabilityRemoved(Capability::ServesExit),
            ObservedStep::RevocationEmitted,
        ];
        assert_eq!(expected, observed);
        assert!(check_sequence(&expected, &observed).is_ok());

        // client → blind_exit: irreversible, no ordered side effects.
        let plan = transition_plan(RolePreset::Client, RolePreset::BlindExit);
        assert!(matches!(plan.kind, TransitionKind::Irreversible(_)));
        let expected = expected_sequence(&plan);
        let observed = vec![ObservedStep::IrreversibleEntry];
        assert_eq!(expected, observed);
        assert!(check_sequence(&expected, &observed).is_ok());
    }

    #[test]
    fn sequencer_rejects_inverted_sequences_naming_the_step() {
        // Relay black hole: bundle advertised before the service was deployed.
        let plan = transition_plan(RolePreset::Client, RolePreset::Relay);
        let inverted = vec![
            ObservedStep::CapabilityAdvertised(Capability::ServesRelay),
            ObservedStep::ServiceDeployed(ServiceKind::Relay),
            ObservedStep::BundleEmitted,
        ];
        let err = check_sequence(&expected_sequence(&plan), &inverted).unwrap_err();
        assert!(err.contains("out of order"), "{err}");
        assert!(err.contains("service_deployed(relay)"), "{err}");

        // Revocation emitted before the relay service was undeployed.
        let plan = transition_plan(RolePreset::Relay, RolePreset::Client);
        let inverted = vec![
            ObservedStep::RevocationEmitted,
            ObservedStep::ServiceUndeployed(ServiceKind::Relay),
            ObservedStep::CapabilityRemoved(Capability::ServesRelay),
        ];
        let err = check_sequence(&expected_sequence(&plan), &inverted).unwrap_err();
        assert!(err.contains("out of order"), "{err}");
        assert!(err.contains("service_undeployed(relay)"), "{err}");

        // Exit residue: capability removed before NAT teardown.
        let plan = transition_plan(RolePreset::Exit, RolePreset::Client);
        let inverted = vec![
            ObservedStep::CapabilityRemoved(Capability::ServesExit),
            ObservedStep::NatTornDown,
            ObservedStep::RevocationEmitted,
        ];
        let err = check_sequence(&expected_sequence(&plan), &inverted).unwrap_err();
        assert!(err.contains("nat_torn_down"), "{err}");

        // Wrong step for the irreversible kind: missing step is named.
        let plan = transition_plan(RolePreset::Client, RolePreset::BlindExit);
        let inverted = vec![ObservedStep::ServiceDeployed(ServiceKind::Relay)];
        let err = check_sequence(&expected_sequence(&plan), &inverted).unwrap_err();
        assert!(err.contains("missing observed step"), "{err}");
        assert!(err.contains("irreversible_entry"), "{err}");
    }

    #[test]
    fn blocked_blind_exit_exit_plan_yields_blocked_attempt_step() {
        let plan = transition_plan(RolePreset::BlindExit, RolePreset::Client);
        assert!(matches!(plan.kind, TransitionKind::Blocked(_)));
        let expected = expected_sequence(&plan);
        assert_eq!(expected, vec![ObservedStep::BlockedAttempt]);
        assert!(check_sequence(&expected, &[ObservedStep::BlockedAttempt]).is_ok());
    }

    // ── C. Outcome aggregation ──

    #[test]
    fn outcome_clean_is_passed() {
        assert_eq!(aggregate_outcome(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_skips_only_is_skipped_naming_the_count() {
        let outcome = aggregate_outcome(
            &[],
            &[
                ("win-1".to_owned(), "Windows".to_owned()),
                ("mac-1".to_owned(), "Macos".to_owned()),
            ],
        );
        match outcome {
            StageOutcome::Skipped(message) => {
                assert!(message.contains("2 node(s)"), "{message}");
                assert!(
                    message.contains("no node executed this validation"),
                    "{message}"
                );
            }
            other => panic!("expected Skipped, got {other:?}"),
        }
    }

    #[test]
    fn outcome_any_failure_is_failed_even_with_skips() {
        let outcome = aggregate_outcome(
            &["deb-1: ordering violation".to_owned()],
            &[("mac-1".to_owned(), "Macos".to_owned())],
        );
        assert!(matches!(outcome, StageOutcome::Failed(_)));
    }

    // ── D. Blind-exit blocked assertion ──

    #[test]
    fn blind_exit_rejected_with_identical_state_is_accepted() {
        assert!(
            assess_blind_exit_reversal(ReversalAttempt::Rejected, "digest-aaa", "digest-aaa")
                .is_ok()
        );
    }

    #[test]
    fn blind_exit_rejected_with_mutated_state_is_the_post_side_effect_hazard() {
        let err = assess_blind_exit_reversal(ReversalAttempt::Rejected, "digest-aaa", "digest-bbb")
            .unwrap_err();
        assert!(err.contains("AFTER a side effect"), "{err}");
    }

    #[test]
    fn blind_exit_accepted_attempt_violates_irreversibility() {
        let err = assess_blind_exit_reversal(ReversalAttempt::Accepted, "d", "d").unwrap_err();
        assert!(err.contains("irreversible"), "{err}");
    }

    // ── E. Audit growth verifier ──

    fn temp_audit_log_path(tag: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = NEXT.fetch_add(1, AtomicOrdering::SeqCst);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "role_transition_ordering_eval_{}_{}_{tag}_{nanos}.log",
            std::process::id(),
            unique,
        ))
    }

    fn write_three_chained_entries(path: &Path) {
        let events = [
            RoleTransitionEvent::PresetTransition {
                from: RolePreset::Client,
                to: RolePreset::Relay,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
            RoleTransitionEvent::PresetTransition {
                from: RolePreset::Relay,
                to: RolePreset::Client,
                outcome: RoleTransitionOutcome::Succeeded,
                error_category: None,
            },
            RoleTransitionEvent::PresetTransition {
                from: RolePreset::BlindExit,
                to: RolePreset::Client,
                outcome: RoleTransitionOutcome::Blocked,
                error_category: Some("blind_exit_immutable"),
            },
        ];
        for (offset, event) in events.iter().enumerate() {
            append_role_audit_entry(path, 1_700_000_000 + offset as u64, event).unwrap();
        }
    }

    #[test]
    fn audit_growth_accepts_three_chained_cli_transitions() {
        let path = temp_audit_log_path("accept");
        write_three_chained_entries(&path);
        let entries = read_role_audit_log(&path).unwrap();
        let expected = [
            ExpectedAuditEvent {
                from: RolePreset::Client,
                to: RolePreset::Relay,
            },
            ExpectedAuditEvent {
                from: RolePreset::Relay,
                to: RolePreset::Client,
            },
            ExpectedAuditEvent {
                from: RolePreset::BlindExit,
                to: RolePreset::Client,
            },
        ];
        assert!(verify_audit_growth(&entries, &expected).is_ok());
    }

    #[test]
    fn audit_growth_failure_names_the_missing_transition_kind() {
        let path = temp_audit_log_path("missing");
        write_three_chained_entries(&path);
        let entries = read_role_audit_log(&path).unwrap();
        let expected = [
            ExpectedAuditEvent {
                from: RolePreset::Client,
                to: RolePreset::Relay,
            },
            ExpectedAuditEvent {
                from: RolePreset::Client,
                to: RolePreset::Exit,
            },
        ];
        let err = verify_audit_growth(&entries, &expected).unwrap_err();
        assert!(err.contains("missing an entry"), "{err}");
        assert!(err.contains("client -> exit"), "{err}");
    }

    #[test]
    fn audit_growth_maps_a_broken_chain_to_a_stage_failure() {
        let path = temp_audit_log_path("tamper");
        write_three_chained_entries(&path);
        let mut entries = read_role_audit_log(&path).unwrap();
        let tampered = entries[1].event_hex.clone();
        let flipped: String = tampered
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i == 0 {
                    if c == '0' {
                        '1'
                    } else {
                        '0'
                    }
                } else {
                    c
                }
            })
            .collect();
        entries[1].event_hex = flipped;
        let err = verify_audit_growth(
            &entries,
            &[ExpectedAuditEvent {
                from: RolePreset::Client,
                to: RolePreset::Relay,
            }],
        )
        .unwrap_err();
        assert!(
            err.contains("role audit chain verification failed"),
            "{err}"
        );
    }

    // ── F. Audit-wiring source scan (design §2.5, review A2, §4 test 7) ──

    fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap();
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn audit_wiring_is_cli_side_only_per_design_2_5() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let daemon_src = manifest_dir.join("../rustynetd/src");
        let mut files = Vec::new();
        collect_rs_files(&daemon_src, &mut files);
        assert!(
            !files.is_empty(),
            "no rustynetd sources found under {daemon_src:?}"
        );

        let mut daemon_call_sites = Vec::new();
        for path in &files {
            let body = std::fs::read_to_string(path).unwrap();
            for (line_no, line) in body.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                if trimmed.contains("append_role_audit_entry(") {
                    daemon_call_sites.push(format!("{}:{}", path.display(), line_no + 1));
                }
            }
        }
        assert!(
            daemon_call_sites.is_empty(),
            "daemon-side append_role_audit_entry call site(s) appeared; design §2.5's \
             CLI-only wiring model must be flipped deliberately in the stage, never \
             silently: {daemon_call_sites:?}"
        );

        let cli_main = std::fs::read_to_string(manifest_dir.join("src/main.rs")).unwrap();
        assert!(
            cli_main.contains("fn execute_role_plan"),
            "sole production executor execute_role_plan vanished from rustynet-cli/src/main.rs"
        );
        assert!(
            cli_main.lines().any(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && trimmed.contains("append_role_audit_entry(")
            }),
            "no append_role_audit_entry call site found in rustynet-cli/src/main.rs"
        );
    }
}
