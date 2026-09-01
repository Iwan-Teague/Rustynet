//! Offline, pure-decision-logic core of GAP-3 (ACL deny re-probe across
//! failover/failback), per
//! `documents/operations/active/LiveLabAclDenyAcrossFailoverStageDesign_2026-09-01.md`
//! §2.1 (window semantics) and §2.4 (the ten offline validator tests).
//!
//! This module is an evaluator over *recorded* probe samples: no I/O, no
//! adapter calls, no lab. The live `failback_roaming` wiring (the CHECKS-list
//! arms, the fourth `client-2` node, and the in-scenario pair probes) is
//! §2.2 work that is owner-gated pending lab availability; until then this
//! module's only execution is the `#[cfg(test)]` suite below.

/// Outcome of the denied-pair probe (design §2.1 amendment A5): a
/// three-state result shape carried with its attribution, not inferred later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairProbeResult {
    /// Probe traffic to the denied peer failed while the control pair on the
    /// same node is known-reachable in the same window.
    Blocked,
    /// Probe traffic *reached* the denied peer: the exclusion lapsed.
    Reachable,
    /// The probe command itself failed to run (adapter absent, host error).
    Error,
}

/// Outcome of the allowed control-pair probe in the same window. The control
/// is what makes a `Blocked` denied pair distinguishable from a dead data
/// path (§2.1 item 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlProbeResult {
    Reachable,
    Unreachable,
    Error,
}

/// One sampling window: the denied-pair probe outcome and the allowed
/// control-pair outcome observed at the same moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowSample {
    pub denied: PairProbeResult,
    pub control: ControlProbeResult,
}

/// Whether the window is mid-transition (reconvergence in flight) or settled
/// (the post-`POST_ADVERTISE_SETTLE` round or the post-failback settled
/// point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowKind {
    MidTransition,
    Settled,
}

/// Per-sample attribution verdict (§2.1 attribution rule, amended per A2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleVerdict {
    /// `Blocked` denied result with a `Reachable` control in the same window:
    /// a positively attributed pass.
    AttributedPass,
    /// A `Blocked`/`Error` result without a reachable control: recorded, and
    /// the window-level rules decide whether it fails.
    AttributedInconclusive,
    /// Probe traffic reached the denied peer: the exclusion lapsed.
    Violated,
}

/// Classify one window sample exactly per §2.1:
///
/// - `denied == Reachable` is `Violated` **unconditionally** — no control
///   precondition softens a lapse (§2.1 item 2 / A2).
/// - `denied == Error` is a probe failure: recorded as inconclusive, and the
///   window evaluator fails on it per the FAIL-LOUD contract (§2.3).
/// - `denied == Blocked` with `control == Reachable` is `AttributedPass`.
/// - `denied == Blocked` with a non-reachable control (including a control
///   `Error`, per the A5 mapping) is `AttributedInconclusive`.
pub fn classify_sample(sample: WindowSample) -> SampleVerdict {
    match sample.denied {
        PairProbeResult::Reachable => SampleVerdict::Violated,
        PairProbeResult::Error => SampleVerdict::AttributedInconclusive,
        PairProbeResult::Blocked => match sample.control {
            ControlProbeResult::Reachable => SampleVerdict::AttributedPass,
            ControlProbeResult::Unreachable | ControlProbeResult::Error => {
                SampleVerdict::AttributedInconclusive
            }
        },
    }
}

/// Evaluate one sampling window per §2.1 items 1/3/4 and the §2.3 FAIL-LOUD
/// contract.
///
/// - An empty sample set is a failure naming the missing evidence — a
///   transition with no probe samples is never a vacuous pass (§2.1 item 4).
/// - Any `denied == Reachable` sample is a `VIOLATED` failure naming the
///   condition, unconditionally (§2.1 item 2).
/// - Any `denied == Error` sample fails: a probe error is inconclusive and
///   inconclusive is a failure, never a soft pass (§2.3).
/// - A settled window must contain at least one attributed pass (§2.1
///   item 3): a settle point with only inconclusive samples is a deny that
///   could not be positively attributed, and fails.
/// - A mid-transition window records inconclusive samples without failing
///   them (§2.1 item 1); it still fails on violated/error samples above.
pub fn evaluate_window(kind: WindowKind, samples: &[WindowSample]) -> Result<(), String> {
    if samples.is_empty() {
        return Err(match kind {
            WindowKind::Settled => {
                "missing window evidence: no denied-pair probe samples recorded for the \
                 post-transition settled window (fail-closed: missing evidence is never a \
                 vacuous pass)"
            }
            WindowKind::MidTransition => {
                "missing window evidence: no denied-pair probe samples recorded for the \
                 mid-transition window (fail-closed: missing evidence is never a vacuous pass)"
            }
        }
        .to_owned());
    }

    for sample in samples {
        match sample.denied {
            PairProbeResult::Reachable => {
                return Err(format!(
                    "acl denied pair VIOLATED: probe traffic reached the denied peer \
                     (control={:?}); the policy exclusion lapsed across the transition — \
                     no control precondition applies",
                    sample.control
                ));
            }
            PairProbeResult::Error => {
                return Err(format!(
                    "acl denied pair probe ERROR: the probe command itself failed to run \
                     (control={:?}); inconclusive evidence fails the window per FAIL-LOUD",
                    sample.control
                ));
            }
            PairProbeResult::Blocked => {}
        }
    }

    if kind == WindowKind::Settled {
        let has_attributed_pass = samples
            .iter()
            .any(|s| classify_sample(*s) == SampleVerdict::AttributedPass);
        if !has_attributed_pass {
            return Err(
                "settled window without an attributed pass: no `Blocked` denied result \
                 carried a `Reachable` control in this window, so the deny is not \
                 positively attributed after the transition settled"
                    .to_owned(),
            );
        }
    }

    Ok(())
}

/// Check-name constants for the three scenario checks GAP-3 adds. The live
/// `CHECKS`-list wiring is §2.2 (deferred pending lab availability); these
/// constants pin the names now so a rename cannot silently diverge between
/// this evaluator and the future wiring.
pub const ACL_DENIED_PAIR_BLOCKED_AFTER_FAILOVER: &str = "acl_denied_pair_blocked_after_failover";
pub const ACL_DENIED_PAIR_BLOCKED_AFTER_FAILBACK: &str = "acl_denied_pair_blocked_after_failback";
pub const ACL_ALLOWED_PAIR_CONTROL_REACHABLE: &str = "acl_allowed_pair_control_reachable";

/// Accumulation helper proving "every transition sampled, not just the first"
/// (§2.4 test 6). Mirrors the shape of the `underlay_leak_samples` counter in
/// `failback_roaming`: every recorded window and every sample increments the
/// counters, so a later transition being sampled cannot be masked by an
/// earlier one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProbeSampleCounters {
    /// How many windows were recorded across all transitions/iterations.
    pub windows_sampled: usize,
    /// Total samples recorded across all windows.
    pub samples_recorded: usize,
    /// Total attributed passes across all windows.
    pub attributed_passes: usize,
    /// Total attributed-inconclusive samples across all windows.
    pub attributed_inconclusives: usize,
    /// Settled windows that ended with only inconclusive samples.
    pub settled_windows_without_pass: usize,
    /// Windows that violated or errored (fail-loud, recorded not swallowed).
    pub violated_or_error_windows: usize,
}

impl ProbeSampleCounters {
    /// Record one window's samples, accumulating every counter. The window's
    /// own evaluation rules are unchanged — this only accumulates the
    /// transcript-level evidence so a re-verifier can reconstruct every
    /// window's outcome (§2.3 artifact completeness).
    pub fn record_window(&mut self, kind: WindowKind, samples: &[WindowSample]) {
        self.windows_sampled += 1;
        self.samples_recorded += samples.len();
        let mut attributed_pass = false;
        for sample in samples {
            match classify_sample(*sample) {
                SampleVerdict::AttributedPass => {
                    self.attributed_passes += 1;
                    attributed_pass = true;
                }
                SampleVerdict::AttributedInconclusive => {
                    self.attributed_inconclusives += 1;
                }
                SampleVerdict::Violated => {}
            }
        }
        match evaluate_window(kind, samples) {
            Ok(()) => {}
            Err(_) => {
                // A settled window whose samples are all inconclusive, or a
                // violated/error window, is still *recorded* — fail-loud
                // naming, not silent dropping.
                if kind == WindowKind::Settled && !attributed_pass {
                    self.settled_windows_without_pass += 1;
                } else {
                    self.violated_or_error_windows += 1;
                }
            }
        }
    }

    /// True when every expected transition was sampled and no window ended in
    /// a state the stage rules treat as failure. Empty evidence (no windows
    /// recorded at all) is incomplete by definition.
    pub fn evidence_complete(&self) -> bool {
        self.windows_sampled > 0
            && self.settled_windows_without_pass == 0
            && self.violated_or_error_windows == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blocked_with_control(control: ControlProbeResult) -> WindowSample {
        WindowSample {
            denied: PairProbeResult::Blocked,
            control,
        }
    }

    /// §2.4 test 1: `Blocked` + control `Reachable` → pass.
    #[test]
    fn denied_blocked_with_reachable_control_passes() {
        let sample = WindowSample {
            denied: PairProbeResult::Blocked,
            control: ControlProbeResult::Reachable,
        };
        assert_eq!(classify_sample(sample), SampleVerdict::AttributedPass);
        assert!(evaluate_window(WindowKind::Settled, &[sample]).is_ok());
        assert!(evaluate_window(WindowKind::MidTransition, &[sample]).is_ok());
    }

    /// §2.4 test 2: `Blocked` with no reachable control is inconclusive — it
    /// FAILS a settled window (the vacuous-deny guard) and is RECORDED
    /// without failing a mid-transition window. Both sides asserted.
    #[test]
    fn denied_blocked_without_control_is_inconclusive_and_fails() {
        let sample = blocked_with_control(ControlProbeResult::Unreachable);
        assert_eq!(
            classify_sample(sample),
            SampleVerdict::AttributedInconclusive
        );

        let settled = evaluate_window(WindowKind::Settled, &[sample]);
        assert!(
            settled
                .err()
                .unwrap()
                .contains("settled window without an attributed pass"),
            "settled window must fail the vacuous-deny guard"
        );

        assert!(evaluate_window(WindowKind::MidTransition, &[sample]).is_ok());
    }

    /// §2.4 test 3: `Reachable` on the denied pair → `VIOLATED`, with no
    /// control attached at all — the verdict is unconditional (§2.1 item 2).
    #[test]
    fn denied_reachable_fails_loudly() {
        let sample = WindowSample {
            denied: PairProbeResult::Reachable,
            // Control state is irrelevant to the verdict; use the strongest
            // "control fine" reading to prove it cannot soften the lapse.
            control: ControlProbeResult::Reachable,
        };
        assert_eq!(classify_sample(sample), SampleVerdict::Violated);

        let err = evaluate_window(WindowKind::MidTransition, &[sample]).unwrap_err();
        assert!(err.contains("acl denied pair VIOLATED"), "{err}");

        let settled = evaluate_window(WindowKind::Settled, &[sample]);
        assert!(settled.err().unwrap().contains("acl denied pair VIOLATED"));
    }

    /// §2.4 test 4: any error variant → failure. A denied-probe `Error` is
    /// inconclusive evidence and inconclusive fails per FAIL-LOUD (§2.3).
    #[test]
    fn probe_error_is_inconclusive_and_fails() {
        let sample = WindowSample {
            denied: PairProbeResult::Error,
            control: ControlProbeResult::Reachable,
        };
        assert_eq!(
            classify_sample(sample),
            SampleVerdict::AttributedInconclusive
        );

        let err = evaluate_window(WindowKind::Settled, &[sample]).unwrap_err();
        assert!(
            err.contains("acl denied pair probe ERROR"),
            "the error must name the failing condition: {err}"
        );

        // A control `Error` alone cannot fail the classification either, but
        // a *probe* error fails in both window kinds.
        let mid = evaluate_window(WindowKind::MidTransition, &[sample]);
        assert!(mid.err().unwrap().contains("acl denied pair probe ERROR"));
    }

    /// §2.4 test 5: a transition with no probe samples recorded → failure.
    /// Missing evidence is never a vacuous pass (§2.1 item 4).
    #[test]
    fn missing_window_fails() {
        let settled = evaluate_window(WindowKind::Settled, &[]);
        let err = settled.unwrap_err();
        assert!(err.contains("missing window evidence"), "{err}");

        let mid = evaluate_window(WindowKind::MidTransition, &[]);
        assert!(mid.err().unwrap().contains("missing window evidence"));

        // And the accumulator reports the same incompleteness.
        let counters = ProbeSampleCounters::default();
        assert!(
            !counters.evidence_complete(),
            "zero recorded windows is missing evidence, not a pass"
        );
    }

    /// §2.4 test 6: counters accumulate across all samples/iterations — not
    /// just the first. Mirrors
    /// `every_leaking_sample_is_counted_not_just_the_first`
    /// (`failback_roaming.rs:856-867`).
    #[test]
    fn every_transition_sampled_not_just_the_first() {
        let mut counters = ProbeSampleCounters::default();

        // Failover #1: settled pass.
        counters.record_window(
            WindowKind::Settled,
            &[blocked_with_control(ControlProbeResult::Reachable)],
        );
        // Transition #2: mid-flight inconclusive.
        counters.record_window(
            WindowKind::MidTransition,
            &[blocked_with_control(ControlProbeResult::Unreachable)],
        );
        // Failback #3: settled pass again — the second pass must also count.
        counters.record_window(
            WindowKind::Settled,
            &[blocked_with_control(ControlProbeResult::Reachable)],
        );
        // Transition #4: another mid-flight inconclusive.
        counters.record_window(
            WindowKind::MidTransition,
            &[blocked_with_control(ControlProbeResult::Unreachable)],
        );

        assert_eq!(counters.windows_sampled, 4, "every transition is sampled");
        assert_eq!(counters.samples_recorded, 4);
        assert_eq!(
            counters.attributed_passes, 2,
            "the second attributed pass is counted, not masked by the first"
        );
        assert_eq!(counters.attributed_inconclusives, 2);
        assert!(counters.evidence_complete());
    }

    /// §2.4 test 7: the three check names exist as constants in this module
    /// and are distinct. The live CHECKS-list declaration/aggregate/verdict-arm
    /// wiring is §2.2 (deferred); this pins the names so the future wiring
    /// cannot silently diverge.
    #[test]
    fn checker_names_declared_and_aggregated() {
        let names = [
            ACL_DENIED_PAIR_BLOCKED_AFTER_FAILOVER,
            ACL_DENIED_PAIR_BLOCKED_AFTER_FAILBACK,
            ACL_ALLOWED_PAIR_CONTROL_REACHABLE,
        ];
        for name in names {
            assert!(
                name.starts_with("acl_"),
                "check name must carry its family prefix: {name}"
            );
        }
        assert_ne!(names[0], names[1]);
        assert_ne!(names[0], names[2]);
        assert_ne!(names[1], names[2]);
        // The names match the design doc §2.1 items 1-3 verbatim.
        assert_eq!(
            ACL_DENIED_PAIR_BLOCKED_AFTER_FAILOVER,
            "acl_denied_pair_blocked_after_failover"
        );
        assert_eq!(
            ACL_DENIED_PAIR_BLOCKED_AFTER_FAILBACK,
            "acl_denied_pair_blocked_after_failback"
        );
        assert_eq!(
            ACL_ALLOWED_PAIR_CONTROL_REACHABLE,
            "acl_allowed_pair_control_reachable"
        );
    }

    /// §2.4 test 8 (A2 item 3): a settled window containing only
    /// attributed-inconclusive samples fails; the same window with one
    /// `Blocked`+`Reachable`-control pass passes.
    #[test]
    fn settled_window_without_attributed_pass_fails() {
        let inconclusive = [
            blocked_with_control(ControlProbeResult::Unreachable),
            blocked_with_control(ControlProbeResult::Error),
        ];
        let err = evaluate_window(WindowKind::Settled, &inconclusive).unwrap_err();
        assert!(
            err.contains("settled window without an attributed pass"),
            "{err}"
        );

        // One attributed pass anywhere in the window satisfies item 3.
        let with_pass = [
            blocked_with_control(ControlProbeResult::Unreachable),
            blocked_with_control(ControlProbeResult::Reachable),
        ];
        assert!(evaluate_window(WindowKind::Settled, &with_pass).is_ok());

        // And the accumulator counts the failing settled window.
        let mut counters = ProbeSampleCounters::default();
        counters.record_window(WindowKind::Settled, &inconclusive);
        assert!(!counters.evidence_complete());
        assert_eq!(counters.settled_windows_without_pass, 1);
    }

    /// §2.4 test 9 (A2 item 1): mid-transition inconclusive samples are
    /// recorded and visible, not failing.
    #[test]
    fn mid_transition_inconclusive_recorded_not_failing() {
        let samples = [
            blocked_with_control(ControlProbeResult::Unreachable),
            blocked_with_control(ControlProbeResult::Error),
        ];
        assert!(evaluate_window(WindowKind::MidTransition, &samples).is_ok());

        let mut counters = ProbeSampleCounters::default();
        counters.record_window(WindowKind::MidTransition, &samples);
        assert_eq!(counters.attributed_inconclusives, 2);
        assert!(counters.evidence_complete());
    }

    /// §2.4 test 10 (A5 mapping): a control `Error` downgrades the same
    /// window's denied result to attributed-inconclusive; the settled-window
    /// rule (test 8) then decides pass/fail.
    #[test]
    fn control_error_downgrades_window_to_inconclusive() {
        let sample = blocked_with_control(ControlProbeResult::Error);
        assert_eq!(
            classify_sample(sample),
            SampleVerdict::AttributedInconclusive
        );

        // Mid-transition: recorded, not failing.
        assert!(evaluate_window(WindowKind::MidTransition, &[sample]).is_ok());
        // Settled: the inconclusive downgrade means no attributed pass, so
        // the settled-window rule fails it (per test 8).
        let err = evaluate_window(WindowKind::Settled, &[sample]).unwrap_err();
        assert!(
            err.contains("settled window without an attributed pass"),
            "{err}"
        );
    }
}
