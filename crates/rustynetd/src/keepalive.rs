//! Per-mapping censored-gap keepalive-interval estimator (FIS-0015).
//!
//! A NAT mapping's binding timeout T is never directly observable — only
//! censored binary evidence exists: a gap of G seconds followed by inbound
//! evidence proves T > G (survival); a gap of G followed by attributable
//! loss proves T ≤ G. The estimator is therefore a bounded probe-search
//! with a confirmed-safe watermark (RFC 4821 PLPMTUD's shape), NOT a
//! mean+variance EWMA — censored binaries carry no variance to smooth.
//!
//! Safety asymmetry, structural: under-sending costs one 5-32-byte packet;
//! over-stretching costs a lost mapping. So decreases are immediate and
//! unconditional; raises are additive (+5s), single-step, evidence-gated
//! (8 consecutive survivals), never within one step of a recorded failure,
//! capped at an unconditional 50s ceiling, and NAT-class-gated: enabled
//! only where mapping expiry is self-healing (relay sessions with the
//! proven re-establish-once safety net; endpoint-independent
//! port-preserving NATs where the next outbound packet transparently
//! re-creates the mapping). Symmetric/unknown NATs stay pinned at their
//! prior and only ever learn DOWNWARD.
//!
//! Pure module: no clocks, no I/O, no daemon types.

#![forbid(unsafe_code)]

/// Below 10s is radio-wakeup abuse with no NAT that needs it; the relay
/// default test already pins the production default ≥ 10s.
pub const KEEPALIVE_FLOOR_SECS: u16 = 10;
/// Unconditional. 2× the WireGuard-convention 25s and 2.4× under
/// RFC 4787 REQ-5's 120s compliant minimum — a spec-compliant router is
/// never at risk even at ceiling.
pub const KEEPALIVE_CEILING_SECS: u16 = 50;
pub const KEEPALIVE_RAISE_STEP_SECS: u16 = 5;
pub const KEEPALIVE_RAISE_AFTER_SURVIVALS: u8 = 8;

/// Cold-start prior for a peer's estimator. Cold start degrades to exactly
/// the already-proven static values: 25s is today's production relay
/// interval; 15/25 are the NAT-conditioned values from the (dead)
/// `TraversalSession::recommended_keepalive_secs`, the only unit-tested
/// NAT-conditioned timing values in the tree. Unknown NAT ⇒ hard prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeepalivePrior {
    RelaySession,
    DirectEasyNat,
    DirectHardOrUnknownNat,
}

impl KeepalivePrior {
    pub const fn prior_interval_secs(self) -> u16 {
        match self {
            KeepalivePrior::RelaySession | KeepalivePrior::DirectEasyNat => 25,
            KeepalivePrior::DirectHardOrUnknownNat => 15,
        }
    }

    /// The class gate: raising is enabled exactly where a mapping expiry is
    /// self-healing. On a symmetric/non-preserving NAT a rebirth lands on a
    /// NEW public port and the peer's signed view of our endpoint breaks —
    /// so hard/unknown NATs never probe upward.
    const fn raise_enabled(self) -> bool {
        !matches!(self, KeepalivePrior::DirectHardOrUnknownNat)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeepaliveEstimator {
    /// The interval actually used between keepalives.
    operating_secs: u16,
    /// Longest gap with positive survival evidence.
    confirmed_safe_secs: u16,
    /// Shortest gap with attributed loss (0 = none recorded).
    failed_low_secs: u16,
    /// Consecutive survivals since the last operating-interval change.
    survivals_at_operating: u8,
    /// NAT-class gate (see [`KeepalivePrior::raise_enabled`]).
    raise_enabled: bool,
}

impl KeepaliveEstimator {
    pub fn new(prior: KeepalivePrior) -> Self {
        Self {
            operating_secs: prior.prior_interval_secs(),
            confirmed_safe_secs: 0,
            failed_low_secs: 0,
            survivals_at_operating: 0,
            raise_enabled: prior.raise_enabled(),
        }
    }

    pub fn operating_secs(&self) -> u16 {
        self.operating_secs
    }

    /// The gap to use for the next keepalive cycle. Returns the operating
    /// interval, or `operating + STEP` as a single probe cycle when every
    /// raise condition holds. Pure — the raise commits only when the probe's
    /// outcome is reported via [`Self::on_survival`] / [`Self::on_binding_loss`].
    pub fn next_gap(&self) -> u16 {
        if self.raise_allowed() {
            self.operating_secs
                .saturating_add(KEEPALIVE_RAISE_STEP_SECS)
                .min(KEEPALIVE_CEILING_SECS)
        } else {
            self.operating_secs
        }
    }

    /// A gap of `gap_secs` was followed by inbound evidence: the mapping
    /// survived at least that long.
    pub fn on_survival(&mut self, gap_secs: u16) {
        self.confirmed_safe_secs = self.confirmed_safe_secs.max(gap_secs);
        self.survivals_at_operating = self.survivals_at_operating.saturating_add(1);
        // A survived probe cycle (evidence at or beyond the next step, with
        // every raise condition still holding) commits the raise.
        if self.raise_allowed()
            && gap_secs
                >= self
                    .operating_secs
                    .saturating_add(KEEPALIVE_RAISE_STEP_SECS)
        {
            self.operating_secs = self
                .operating_secs
                .saturating_add(KEEPALIVE_RAISE_STEP_SECS)
                .min(KEEPALIVE_CEILING_SECS);
            self.survivals_at_operating = 0;
        }
    }

    /// A gap of `gap_secs` was followed by attributable loss (keepalive
    /// failure / re-establish / handshake staleness on the same endpoint).
    /// Decreases are immediate and unconditional; mis-attributed losses
    /// (peer offline, relay restart) only ever tighten — the cheap
    /// direction — and self-correct as survivals re-accumulate.
    pub fn on_binding_loss(&mut self, gap_secs: u16) {
        self.failed_low_secs = if self.failed_low_secs == 0 {
            gap_secs
        } else {
            self.failed_low_secs.min(gap_secs)
        };
        let base_interval_failed = gap_secs <= self.operating_secs;
        // Retreat to the confirmed-safe watermark (floor-clamped).
        self.operating_secs = self
            .operating_secs
            .min(self.confirmed_safe_secs)
            .max(KEEPALIVE_FLOOR_SECS);
        if base_interval_failed {
            // The base interval itself failed, not a probe: step down.
            self.operating_secs = self
                .operating_secs
                .saturating_sub(KEEPALIVE_RAISE_STEP_SECS)
                .max(KEEPALIVE_FLOOR_SECS);
        }
        self.survivals_at_operating = 0;
    }

    fn raise_allowed(&self) -> bool {
        self.raise_enabled
            && self.survivals_at_operating >= KEEPALIVE_RAISE_AFTER_SURVIVALS
            && self
                .operating_secs
                .saturating_add(KEEPALIVE_RAISE_STEP_SECS)
                <= KEEPALIVE_CEILING_SECS
            && (self.failed_low_secs == 0
                || self
                    .operating_secs
                    .saturating_add(2 * KEEPALIVE_RAISE_STEP_SECS)
                    <= self.failed_low_secs)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        KEEPALIVE_CEILING_SECS, KEEPALIVE_FLOOR_SECS, KEEPALIVE_RAISE_AFTER_SURVIVALS,
        KEEPALIVE_RAISE_STEP_SECS, KeepaliveEstimator, KeepalivePrior,
    };

    /// Run `count` survival cycles at the estimator's own next_gap.
    fn survive_cycles(estimator: &mut KeepaliveEstimator, count: u32) {
        for _ in 0..count {
            let gap = estimator.next_gap();
            estimator.on_survival(gap);
        }
    }

    #[test]
    fn keepalive_estimator_cold_start_matches_static_priors() {
        assert_eq!(
            KeepaliveEstimator::new(KeepalivePrior::RelaySession).next_gap(),
            25
        );
        assert_eq!(
            KeepaliveEstimator::new(KeepalivePrior::DirectEasyNat).next_gap(),
            25
        );
        assert_eq!(
            KeepaliveEstimator::new(KeepalivePrior::DirectHardOrUnknownNat).next_gap(),
            15
        );
    }

    #[test]
    fn keepalive_estimator_tightens_immediately_on_loss() {
        let mut estimator = KeepaliveEstimator::new(KeepalivePrior::RelaySession);
        // Some survivals at 25 establish confirmed_safe = 25.
        survive_cycles(&mut estimator, 3);
        assert_eq!(estimator.operating_secs(), 25);
        // A loss at the base interval retreats to confirmed_safe then steps
        // down: min(25, 25) - 5 = 20.
        estimator.on_binding_loss(25);
        assert_eq!(estimator.operating_secs(), 20);
        // A loss with NO survival evidence drops straight to the floor.
        let mut cold = KeepaliveEstimator::new(KeepalivePrior::RelaySession);
        cold.on_binding_loss(25);
        assert_eq!(cold.operating_secs(), KEEPALIVE_FLOOR_SECS);
    }

    #[test]
    fn keepalive_estimator_raise_gated_on_nat_class_and_survival_count() {
        // Hard/unknown NAT never raises no matter how much evidence.
        let mut hard = KeepaliveEstimator::new(KeepalivePrior::DirectHardOrUnknownNat);
        survive_cycles(&mut hard, 100);
        assert_eq!(hard.operating_secs(), 15);
        assert_eq!(hard.next_gap(), 15);

        // Easy NAT: no probe until RAISE_AFTER consecutive survivals.
        let mut easy = KeepaliveEstimator::new(KeepalivePrior::DirectEasyNat);
        for _ in 0..(KEEPALIVE_RAISE_AFTER_SURVIVALS - 1) {
            assert_eq!(easy.next_gap(), 25);
            easy.on_survival(25);
        }
        assert_eq!(easy.next_gap(), 25); // 7 survivals: still no probe
        easy.on_survival(25); // 8th survival
        assert_eq!(easy.next_gap(), 25 + KEEPALIVE_RAISE_STEP_SECS); // probe
        // The probe's survival commits the raise.
        easy.on_survival(30);
        assert_eq!(easy.operating_secs(), 30);
        // Counter reset: the next cycle is back to the (new) base interval.
        assert_eq!(easy.next_gap(), 30);
    }

    #[test]
    fn keepalive_estimator_never_raises_within_step_of_recorded_failure() {
        let mut estimator = KeepaliveEstimator::new(KeepalivePrior::DirectEasyNat);
        survive_cycles(&mut estimator, 8);
        // Probe to 30 fails: failed_low = 30, retreat to confirmed_safe 25.
        estimator.on_binding_loss(30);
        assert_eq!(estimator.operating_secs(), 25);
        // Raising to 30 again would need 25 + 2*5 = 35 <= failed_low (30):
        // false — the estimator must never probe within one step of the
        // recorded failure, no matter how many survivals accumulate.
        survive_cycles(&mut estimator, 50);
        assert_eq!(estimator.operating_secs(), 25);
        assert_eq!(estimator.next_gap(), 25);
    }

    #[test]
    fn keepalive_estimator_never_exceeds_ceiling_regardless_of_history() {
        // Property-style with a deterministic LCG — arbitrary observation
        // sequences must never push next_gap outside [FLOOR, CEILING].
        for prior in [
            KeepalivePrior::RelaySession,
            KeepalivePrior::DirectEasyNat,
            KeepalivePrior::DirectHardOrUnknownNat,
        ] {
            let mut estimator = KeepaliveEstimator::new(prior);
            let mut lcg: u64 = 0x2545_f491_4f6c_dd1d;
            for _ in 0..10_000 {
                lcg = lcg.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let gap = (lcg >> 33) as u16 % 200;
                if lcg & 1 == 0 {
                    estimator.on_survival(gap);
                } else {
                    estimator.on_binding_loss(gap);
                }
                let next = estimator.next_gap();
                assert!(
                    (KEEPALIVE_FLOOR_SECS..=KEEPALIVE_CEILING_SECS).contains(&next),
                    "prior {prior:?}: next_gap {next} escaped [{KEEPALIVE_FLOOR_SECS}, {KEEPALIVE_CEILING_SECS}]"
                );
                assert!(estimator.operating_secs() >= KEEPALIVE_FLOOR_SECS);
                assert!(estimator.operating_secs() <= KEEPALIVE_CEILING_SECS);
            }
        }
        // And the pure-survival extreme parks exactly at the ceiling.
        let mut greedy = KeepaliveEstimator::new(KeepalivePrior::DirectEasyNat);
        survive_cycles(&mut greedy, 200);
        assert_eq!(greedy.operating_secs(), KEEPALIVE_CEILING_SECS);
        assert_eq!(greedy.next_gap(), KEEPALIVE_CEILING_SECS);
    }

    #[test]
    fn keepalive_estimator_two_peers_converge_independently() {
        // Peer A behind a 12s-timeout router: every 15s+ gap dies.
        let mut peer_a = KeepaliveEstimator::new(KeepalivePrior::RelaySession);
        for _ in 0..10 {
            let gap = peer_a.next_gap();
            if gap > 12 {
                peer_a.on_binding_loss(gap);
            } else {
                peer_a.on_survival(gap);
            }
        }
        assert_eq!(peer_a.operating_secs(), KEEPALIVE_FLOOR_SECS);

        // Peer B behind a generous 90s router: raises toward the ceiling.
        let mut peer_b = KeepaliveEstimator::new(KeepalivePrior::RelaySession);
        survive_cycles(&mut peer_b, 200);
        assert_eq!(peer_b.operating_secs(), KEEPALIVE_CEILING_SECS);

        // Independence: peer A's floor never leaked into peer B's ceiling.
        assert_ne!(peer_a.operating_secs(), peer_b.operating_secs());
    }
}
