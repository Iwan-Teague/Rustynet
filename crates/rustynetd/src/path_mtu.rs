//! FIS-0027 Phase 1: pure RFC 8899 Datagram Packetization-Layer Path-MTU
//! Discovery (DPLPMTUD) state machine for the tunnel.
//!
//! This module is deliberately free of I/O and clocks. It models the per-peer
//! search for the largest inner packet size that round-trips on a path, and it
//! is driven entirely by the caller reporting externally observed events:
//!
//! - [`PathMtuDiscovery::on_probe_acked`] — a probe of a given size was
//!   acknowledged in-band (the probe round-tripped inside the tunnel).
//! - [`PathMtuDiscovery::on_probe_lost`] — a probe (or confirmed-size traffic)
//!   of a given size was deemed lost by the caller's own timeout/loss logic.
//! - [`PathMtuDiscovery::on_ptb`] — an inbound ICMP "Packet Too Big" /
//!   "fragmentation needed" report arrived. Advisory only; see the security
//!   invariants below.
//! - [`PathMtuDiscovery::on_reprobe_interval_elapsed`] — the caller's periodic
//!   raise timer fired (RFC 8899 §5.3 PLPMTU raise), allowing an idle,
//!   converged machine to search upward again after a path improvement.
//!
//! The caller reads [`PathMtuDiscovery::next_probe_size`] to learn what padded
//! probe (if any) the machine wants outstanding, and
//! [`PathMtuDiscovery::effective_plpmtu`] for the value the daemon would apply
//! to the interface once Phase 4 wires dynamic application in. Probe carriage
//! (Phase 3, keepalive channel) and MTU application (Phase 4, reconcile loop)
//! are intentionally not part of this module.
//!
//! # State machine
//!
//! ```text
//! Base ──(base probe acked)──▶ Searching ──(search window closed)──▶ SearchComplete
//!   ▲                                                                    │
//!   └────────────(repeated loss of a previously-confirmed size)──────────┘
//!                              (blackhole detected)
//! ```
//!
//! `SearchComplete` may also return to `Searching` via the caller-driven
//! re-probe (raise) interval, keeping the confirmed value as the floor so a
//! re-probe can never degrade a working MTU.
//!
//! # Security invariants (RFC 8899 robustness rules)
//!
//! ICMP PTB messages are attacker-writable on many paths, so they are treated
//! as unauthenticated advisories:
//!
//! 1. A PTB can never raise the effective PLPMTU, the confirmed value, or the
//!    search ceiling.
//! 2. A PTB can lower only the *unconfirmed* search ceiling, and never below
//!    the confirmed floor or `base_plpmtu`.
//! 3. A PTB reporting a size below a confirmed value never overrides that
//!    confirmed value. It only schedules a single in-band verification
//!    re-probe of the confirmed size; demotion happens exclusively through the
//!    in-band loss path (blackhole detection). The worst a forged PTB flood
//!    can do is cost one verification probe.
//! 4. An acknowledgement is accepted only for the exact outstanding probe size
//!    (or the already-confirmed size, which merely clears the blackhole loss
//!    counter), so a forged or stale ack can never raise the confirmed value
//!    either.
//! 5. Fail closed: while nothing is confirmed the effective PLPMTU is
//!    `base_plpmtu` (1280, the IPv6-guaranteed floor), and a detected
//!    blackhole demotes straight back to it.
//!
//! Every invariant above is pinned by a unit test in this file.

/// RFC 8899 `BASE_PLPMTU` default: the IPv6 minimum link MTU. A path that
/// cannot carry this size is treated as unable to support the tunnel at all,
/// so the machine never searches below it.
pub const DEFAULT_BASE_PLPMTU: u16 = 1280;

/// Default search ceiling. Matches the widely used WireGuard convention of a
/// 1420-byte tunnel MTU on a clean 1500-byte Ethernet underlay (1500 minus 80
/// bytes of worst-case IPv6+UDP+WireGuard encapsulation overhead), and the
/// FIS-0027 Phase 2 bring-up MTU the per-OS backend adapters now set. A
/// deployment with a jumbo-frame underlay may pass a larger ceiling derived
/// from the local interface.
pub const DEFAULT_MAX_PLPMTU: u16 = 1420;

/// Default number of consecutive losses of one probe size before that size is
/// declared unsupported by the path (RFC 8899 `MAX_PROBES`).
pub const DEFAULT_MAX_PROBES: u8 = 3;

/// Default number of consecutive losses at a previously-confirmed size before
/// the machine declares a path blackhole and demotes to `Base`. Kept separate
/// from `max_probes` so transient loss on a healthy path does not masquerade
/// as an MTU event (the designer-disclosed weak point in FIS-0027).
pub const DEFAULT_BLACKHOLE_CONFIRM_THRESHOLD: u8 = 3;

/// Absolute lowest `base_plpmtu` this module accepts. IPv4's minimum
/// reassembly buffer; anything below it is a configuration error, not a path
/// property worth searching for.
pub const MIN_SUPPORTED_BASE_PLPMTU: u16 = 576;

/// Validated configuration knobs for one [`PathMtuDiscovery`] instance.
///
/// Construct via [`PathMtuConfig::new`] (or use [`PathMtuConfig::default`],
/// which is always valid); invalid combinations are rejected at construction
/// so a machine can never exist in an unsafe configuration (fail closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathMtuConfig {
    base_plpmtu: u16,
    max_plpmtu: u16,
    max_probes: u8,
    blackhole_confirm_threshold: u8,
}

impl Default for PathMtuConfig {
    fn default() -> Self {
        Self {
            base_plpmtu: DEFAULT_BASE_PLPMTU,
            max_plpmtu: DEFAULT_MAX_PLPMTU,
            max_probes: DEFAULT_MAX_PROBES,
            blackhole_confirm_threshold: DEFAULT_BLACKHOLE_CONFIRM_THRESHOLD,
        }
    }
}

impl PathMtuConfig {
    /// Builds a validated configuration.
    ///
    /// Errors when `base_plpmtu` is below [`MIN_SUPPORTED_BASE_PLPMTU`], when
    /// `max_plpmtu` is below `base_plpmtu`, or when either retry threshold is
    /// zero (a zero threshold would declare loss/blackhole on no evidence).
    pub fn new(
        base_plpmtu: u16,
        max_plpmtu: u16,
        max_probes: u8,
        blackhole_confirm_threshold: u8,
    ) -> Result<Self, PathMtuConfigError> {
        if base_plpmtu < MIN_SUPPORTED_BASE_PLPMTU {
            return Err(PathMtuConfigError::BaseBelowMinimum {
                base_plpmtu,
                minimum: MIN_SUPPORTED_BASE_PLPMTU,
            });
        }
        if max_plpmtu < base_plpmtu {
            return Err(PathMtuConfigError::CeilingBelowBase {
                base_plpmtu,
                max_plpmtu,
            });
        }
        if max_probes == 0 {
            return Err(PathMtuConfigError::ZeroMaxProbes);
        }
        if blackhole_confirm_threshold == 0 {
            return Err(PathMtuConfigError::ZeroBlackholeThreshold);
        }
        Ok(Self {
            base_plpmtu,
            max_plpmtu,
            max_probes,
            blackhole_confirm_threshold,
        })
    }

    /// The always-safe floor the machine assumes while nothing is confirmed.
    pub fn base_plpmtu(&self) -> u16 {
        self.base_plpmtu
    }

    /// The upper search bound, derived by the caller from the local interface.
    pub fn max_plpmtu(&self) -> u16 {
        self.max_plpmtu
    }

    /// Consecutive losses before one candidate size is declared unsupported.
    pub fn max_probes(&self) -> u8 {
        self.max_probes
    }

    /// Consecutive confirmed-size losses before a blackhole is declared.
    pub fn blackhole_confirm_threshold(&self) -> u8 {
        self.blackhole_confirm_threshold
    }
}

/// Rejection reasons for an invalid [`PathMtuConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuConfigError {
    /// `base_plpmtu` is below the absolute supported floor.
    BaseBelowMinimum { base_plpmtu: u16, minimum: u16 },
    /// `max_plpmtu` is below `base_plpmtu`, leaving no valid search range.
    CeilingBelowBase { base_plpmtu: u16, max_plpmtu: u16 },
    /// `max_probes` of zero would fail candidates with no loss evidence.
    ZeroMaxProbes,
    /// A zero blackhole threshold would demote on no loss evidence.
    ZeroBlackholeThreshold,
}

impl std::fmt::Display for PathMtuConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BaseBelowMinimum {
                base_plpmtu,
                minimum,
            } => write!(
                f,
                "base_plpmtu {base_plpmtu} is below the supported minimum {minimum}"
            ),
            Self::CeilingBelowBase {
                base_plpmtu,
                max_plpmtu,
            } => write!(
                f,
                "max_plpmtu {max_plpmtu} is below base_plpmtu {base_plpmtu}"
            ),
            Self::ZeroMaxProbes => write!(f, "max_probes must be at least 1"),
            Self::ZeroBlackholeThreshold => {
                write!(f, "blackhole_confirm_threshold must be at least 1")
            }
        }
    }
}

impl std::error::Error for PathMtuConfigError {}

/// Externally observable state of the search (FIS-0027 / RFC 8899 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuState {
    /// Confirming that the always-safe `base_plpmtu` round-trips on this path.
    /// The effective PLPMTU is `base_plpmtu` (fail closed).
    Base,
    /// Binary search between the confirmed floor and the unconfirmed ceiling.
    Searching,
    /// The search converged; probing is quiescent apart from PTB-triggered
    /// verification re-probes and the caller-driven raise interval.
    SearchComplete,
}

/// What one input event did to the machine. Returned by every event handler
/// so callers (and tests) can observe transitions without diffing state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMtuOutcome {
    /// The event was ignored: stale size, forged/invalid signal, or a state
    /// in which the event has no meaning. The machine is unchanged.
    Ignored,
    /// The event advanced the machine (new probe candidate, retry counted,
    /// blackhole counter cleared) without completing the search.
    Progressed,
    /// The search window closed; the machine is now `SearchComplete` and the
    /// effective PLPMTU equals the highest in-band-confirmed size.
    SearchConverged,
    /// Repeated loss of a previously-confirmed size: the machine demoted to
    /// `Base` and the effective PLPMTU fell back to `base_plpmtu`.
    BlackholeDetected,
    /// A PTB lowered the unconfirmed search ceiling (never the floor, never a
    /// confirmed value).
    CeilingLowered,
    /// A PTB reporting below a confirmed size scheduled a single in-band
    /// verification re-probe of that confirmed size. Nothing was lowered.
    ReprobeScheduled,
}

/// Monotonic observability counters (saturating; never affect behavior).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PathMtuCounters {
    /// Blackhole demotions to `Base`.
    pub blackhole_events: u32,
    /// PTB reports ignored as invalid, stale, or raise attempts.
    pub ptb_ignored: u32,
    /// PTB reports that lowered the unconfirmed search ceiling.
    pub ptb_ceiling_lowered: u32,
    /// PTB reports that scheduled a confirmed-size verification re-probe.
    pub ptb_reprobes_triggered: u32,
    /// Acks ignored because they matched no outstanding probe or confirmed
    /// size (forged or stale).
    pub acks_ignored: u32,
    /// Full retry budgets exhausted while confirming `base_plpmtu` (the path
    /// cannot currently carry even the floor; the machine keeps re-probing
    /// base and the effective PLPMTU stays at the fail-closed floor).
    pub base_confirm_failures: u32,
}

/// Pure per-path DPLPMTUD search machine. See the module docs for the driving
/// contract and security invariants.
#[derive(Debug, Clone)]
pub struct PathMtuDiscovery {
    config: PathMtuConfig,
    state: PathMtuState,
    /// Highest size confirmed by an in-band ack. `None` until the base probe
    /// is acknowledged and after a blackhole demotion (fail closed to base).
    confirmed: Option<u16>,
    /// Inclusive lower search bound. Always a size proven to work (equals
    /// `confirmed`) except while `Base` re-confirms the floor.
    search_low: u16,
    /// Inclusive upper search bound; unconfirmed until probed.
    search_high: u16,
    /// The probe size the machine wants outstanding, if any.
    current_probe: Option<u16>,
    /// Consecutive losses of `current_probe`.
    probe_losses: u8,
    /// Consecutive losses at the confirmed size (blackhole watch).
    confirmed_losses: u8,
    counters: PathMtuCounters,
}

impl PathMtuDiscovery {
    /// Creates a machine in `Base` state, requesting a base-size probe, with
    /// the fail-closed effective PLPMTU of `base_plpmtu`.
    pub fn new(config: PathMtuConfig) -> Self {
        Self {
            config,
            state: PathMtuState::Base,
            confirmed: None,
            search_low: config.base_plpmtu,
            search_high: config.max_plpmtu,
            current_probe: Some(config.base_plpmtu),
            probe_losses: 0,
            confirmed_losses: 0,
            counters: PathMtuCounters::default(),
        }
    }

    /// The configuration this machine was built with.
    pub fn config(&self) -> &PathMtuConfig {
        &self.config
    }

    /// Current search state.
    pub fn state(&self) -> PathMtuState {
        self.state
    }

    /// The PLPMTU the daemon should treat as usable right now: the highest
    /// in-band-confirmed size, or `base_plpmtu` while nothing is confirmed
    /// (fail closed).
    pub fn effective_plpmtu(&self) -> u16 {
        self.confirmed.unwrap_or(self.config.base_plpmtu)
    }

    /// The probe size the machine wants the caller to send (padded to exactly
    /// this many bytes), or `None` when probing is quiescent.
    pub fn next_probe_size(&self) -> Option<u16> {
        self.current_probe
    }

    /// The current (unconfirmed) upper search bound.
    pub fn search_ceiling(&self) -> u16 {
        self.search_high
    }

    /// Observability counters.
    pub fn counters(&self) -> &PathMtuCounters {
        &self.counters
    }

    /// Reports that a probe of exactly `size` bytes round-tripped in-band.
    ///
    /// Only the outstanding probe size is accepted as new evidence; an ack of
    /// the already-confirmed size clears the blackhole loss counter; anything
    /// else is ignored (forged/stale ack hardening — invariant 4).
    pub fn on_probe_acked(&mut self, size: u16) -> PathMtuOutcome {
        if self.current_probe == Some(size) {
            return self.accept_current_probe_ack(size);
        }
        if self.confirmed == Some(size) {
            // Confirmed-size traffic (e.g. a padded keepalive) round-tripped:
            // the path still carries the confirmed size, so the blackhole
            // watch resets. Not new evidence of anything larger.
            self.confirmed_losses = 0;
            return PathMtuOutcome::Progressed;
        }
        self.counters.acks_ignored = self.counters.acks_ignored.saturating_add(1);
        PathMtuOutcome::Ignored
    }

    /// Reports that a probe (or confirmed-size traffic) of exactly `size`
    /// bytes was deemed lost by the caller.
    ///
    /// Losses of the outstanding probe consume the per-candidate retry budget;
    /// losses at the confirmed size feed the blackhole watch. Other sizes are
    /// ignored as stale.
    pub fn on_probe_lost(&mut self, size: u16) -> PathMtuOutcome {
        if self.current_probe == Some(size) && self.confirmed != Some(size) {
            return self.count_current_probe_loss();
        }
        if self.confirmed == Some(size) {
            return self.count_confirmed_size_loss();
        }
        PathMtuOutcome::Ignored
    }

    /// Reports an inbound ICMP PTB advisory claiming the path MTU is
    /// `reported_mtu` (expressed at the same packetization layer as the probe
    /// sizes). Enforces invariants 1-3: never raises, lowers only the
    /// unconfirmed ceiling, never overrides a confirmed value (at most it
    /// schedules one in-band verification re-probe of it).
    pub fn on_ptb(&mut self, reported_mtu: u16) -> PathMtuOutcome {
        if reported_mtu < self.config.base_plpmtu {
            // RFC 8899 §4.6.2: a PTB below BASE_PLPMTU is invalid; the floor
            // is non-negotiable.
            self.counters.ptb_ignored = self.counters.ptb_ignored.saturating_add(1);
            return PathMtuOutcome::Ignored;
        }
        if let Some(confirmed) = self.confirmed
            && reported_mtu < confirmed
        {
            // Invariant 3: never override a confirmed value. Schedule (at
            // most) one in-band verification re-probe of the confirmed size;
            // only repeated in-band loss of that size can demote it.
            self.counters.ptb_reprobes_triggered =
                self.counters.ptb_reprobes_triggered.saturating_add(1);
            if self.current_probe != Some(confirmed) {
                self.current_probe = Some(confirmed);
                self.probe_losses = 0;
            }
            return PathMtuOutcome::ReprobeScheduled;
        }
        // At or above every confirmed size: the report can only be useful as
        // a lowered *unconfirmed* ceiling during an active search window.
        if reported_mtu < self.search_high
            && matches!(self.state, PathMtuState::Base | PathMtuState::Searching)
        {
            self.search_high = reported_mtu.max(self.search_low);
            self.counters.ptb_ceiling_lowered = self.counters.ptb_ceiling_lowered.saturating_add(1);
            if self.state == PathMtuState::Searching {
                if self.search_low >= self.search_high {
                    self.complete_search();
                    return PathMtuOutcome::CeilingLowered;
                }
                self.set_probe(Self::next_candidate(self.search_low, self.search_high));
            }
            return PathMtuOutcome::CeilingLowered;
        }
        // A raise attempt, or a no-op at the current ceiling: ignore.
        self.counters.ptb_ignored = self.counters.ptb_ignored.saturating_add(1);
        PathMtuOutcome::Ignored
    }

    /// Caller-driven raise interval (RFC 8899 §5.3): from `SearchComplete`,
    /// reopen the search window up to the configured ceiling to discover a
    /// path improvement. The confirmed value stays the floor, so re-probing
    /// can never degrade a working MTU. A no-op in any other state or when
    /// already converged at the ceiling.
    pub fn on_reprobe_interval_elapsed(&mut self) -> PathMtuOutcome {
        if self.state != PathMtuState::SearchComplete {
            return PathMtuOutcome::Ignored;
        }
        let Some(confirmed) = self.confirmed else {
            return PathMtuOutcome::Ignored;
        };
        if confirmed >= self.config.max_plpmtu {
            return PathMtuOutcome::Ignored;
        }
        self.state = PathMtuState::Searching;
        self.search_low = confirmed;
        self.search_high = self.config.max_plpmtu;
        self.set_probe(Self::next_candidate(self.search_low, self.search_high));
        PathMtuOutcome::Progressed
    }

    fn accept_current_probe_ack(&mut self, size: u16) -> PathMtuOutcome {
        self.probe_losses = 0;
        self.confirmed_losses = 0;
        match self.state {
            PathMtuState::Base => {
                // The floor is proven; open the search window above it.
                self.confirmed = Some(size);
                self.search_low = size;
                if self.search_low >= self.search_high {
                    self.complete_search();
                    return PathMtuOutcome::SearchConverged;
                }
                self.state = PathMtuState::Searching;
                self.set_probe(Self::next_candidate(self.search_low, self.search_high));
                PathMtuOutcome::Progressed
            }
            PathMtuState::Searching => {
                self.confirmed = Some(size.max(self.confirmed.unwrap_or(size)));
                self.search_low = self.search_low.max(size);
                if self.search_low >= self.search_high {
                    self.complete_search();
                    return PathMtuOutcome::SearchConverged;
                }
                self.set_probe(Self::next_candidate(self.search_low, self.search_high));
                PathMtuOutcome::Progressed
            }
            PathMtuState::SearchComplete => {
                // A PTB-triggered verification probe of the confirmed size
                // round-tripped: the forged (or stale) PTB cost exactly this
                // one probe and nothing changed.
                self.current_probe = None;
                PathMtuOutcome::Progressed
            }
        }
    }

    fn count_current_probe_loss(&mut self) -> PathMtuOutcome {
        self.probe_losses = self.probe_losses.saturating_add(1);
        if self.probe_losses < self.config.max_probes {
            return PathMtuOutcome::Progressed;
        }
        self.probe_losses = 0;
        match self.state {
            PathMtuState::Base => {
                // The path cannot currently carry even the floor. There is
                // nothing lower to fall back to: stay at the fail-closed
                // floor and keep re-probing it.
                self.counters.base_confirm_failures =
                    self.counters.base_confirm_failures.saturating_add(1);
                self.set_probe(self.config.base_plpmtu);
                PathMtuOutcome::Progressed
            }
            PathMtuState::Searching => {
                let Some(candidate) = self.current_probe else {
                    return PathMtuOutcome::Ignored;
                };
                // The candidate is too big for the path; the window shrinks
                // from above. `candidate > search_low` always holds because
                // candidates are strictly above the confirmed floor.
                self.search_high = candidate.saturating_sub(1).max(self.search_low);
                if self.search_low >= self.search_high {
                    self.complete_search();
                    return PathMtuOutcome::SearchConverged;
                }
                self.set_probe(Self::next_candidate(self.search_low, self.search_high));
                PathMtuOutcome::Progressed
            }
            PathMtuState::SearchComplete => {
                // A confirmed-size verification probe is handled by the
                // confirmed-size loss path, so an outstanding probe here can
                // only be stale bookkeeping; clear it.
                self.current_probe = None;
                PathMtuOutcome::Ignored
            }
        }
    }

    fn count_confirmed_size_loss(&mut self) -> PathMtuOutcome {
        self.confirmed_losses = self.confirmed_losses.saturating_add(1);
        if self.confirmed_losses < self.config.blackhole_confirm_threshold {
            return PathMtuOutcome::Progressed;
        }
        // Blackhole: a size this path previously carried is now repeatedly
        // lost. Fail closed all the way back to the floor and start over.
        self.counters.blackhole_events = self.counters.blackhole_events.saturating_add(1);
        self.state = PathMtuState::Base;
        self.confirmed = None;
        self.search_low = self.config.base_plpmtu;
        self.search_high = self.config.max_plpmtu;
        self.set_probe(self.config.base_plpmtu);
        self.confirmed_losses = 0;
        PathMtuOutcome::BlackholeDetected
    }

    fn complete_search(&mut self) {
        self.state = PathMtuState::SearchComplete;
        self.current_probe = None;
        self.probe_losses = 0;
    }

    fn set_probe(&mut self, size: u16) {
        self.current_probe = Some(size);
        self.probe_losses = 0;
    }

    /// Binary-search candidate strictly above `low` and at most `high`.
    /// Requires `low < high`; cannot overflow because the midpoint is
    /// computed from the (non-negative) window width.
    fn next_candidate(low: u16, high: u16) -> u16 {
        low + (high - low).div_ceil(2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(base: u16, max: u16) -> PathMtuConfig {
        PathMtuConfig::new(base, max, 3, 3).expect("test config must be valid")
    }

    /// Drives the machine against a simulated path with true inner MTU
    /// `path_mtu`: every requested probe is acked iff it fits the path. Panics
    /// if the machine keeps probing forever. Returns the number of probes
    /// spent.
    fn drive_to_quiescence(machine: &mut PathMtuDiscovery, path_mtu: u16) -> u32 {
        let mut probes = 0u32;
        while let Some(size) = machine.next_probe_size() {
            probes += 1;
            assert!(
                probes < 10_000,
                "search failed to converge; state {:?}, probe {size}",
                machine.state()
            );
            if size <= path_mtu {
                machine.on_probe_acked(size);
            } else {
                machine.on_probe_lost(size);
            }
            check_invariants(machine, path_mtu);
        }
        probes
    }

    /// Structural invariants that must hold after every event, plus the
    /// end-to-end security property: the effective PLPMTU never exceeds what
    /// the simulated path genuinely acknowledged.
    fn check_invariants(machine: &PathMtuDiscovery, path_mtu: u16) {
        let base = machine.config().base_plpmtu();
        let max = machine.config().max_plpmtu();
        assert!(machine.effective_plpmtu() >= base);
        assert!(machine.effective_plpmtu() <= max);
        assert!(machine.search_ceiling() <= max);
        assert!(machine.search_ceiling() >= base);
        if let Some(probe) = machine.next_probe_size() {
            assert!(probe >= base, "probe {probe} below base {base}");
            assert!(probe <= max, "probe {probe} above ceiling {max}");
        }
        if path_mtu >= base {
            assert!(
                machine.effective_plpmtu() <= path_mtu.max(base),
                "effective {} exceeds genuinely-acked path MTU {path_mtu}",
                machine.effective_plpmtu()
            );
        }
    }

    #[test]
    fn new_machine_starts_at_base_fail_closed() {
        let machine = PathMtuDiscovery::new(config(1280, 1420));
        assert_eq!(machine.state(), PathMtuState::Base);
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.next_probe_size(), Some(1280));
    }

    #[test]
    fn config_rejects_invalid_combinations() {
        assert_eq!(
            PathMtuConfig::new(100, 1420, 3, 3),
            Err(PathMtuConfigError::BaseBelowMinimum {
                base_plpmtu: 100,
                minimum: MIN_SUPPORTED_BASE_PLPMTU,
            })
        );
        assert_eq!(
            PathMtuConfig::new(1400, 1300, 3, 3),
            Err(PathMtuConfigError::CeilingBelowBase {
                base_plpmtu: 1400,
                max_plpmtu: 1300,
            })
        );
        assert_eq!(
            PathMtuConfig::new(1280, 1420, 0, 3),
            Err(PathMtuConfigError::ZeroMaxProbes)
        );
        assert_eq!(
            PathMtuConfig::new(1280, 1420, 3, 0),
            Err(PathMtuConfigError::ZeroBlackholeThreshold)
        );
        assert!(PathMtuConfig::new(1280, 1280, 1, 1).is_ok());
    }

    #[test]
    fn default_config_is_valid_and_matches_documented_constants() {
        let config = PathMtuConfig::default();
        assert_eq!(config.base_plpmtu(), DEFAULT_BASE_PLPMTU);
        assert_eq!(config.max_plpmtu(), DEFAULT_MAX_PLPMTU);
        assert_eq!(
            PathMtuConfig::new(
                config.base_plpmtu(),
                config.max_plpmtu(),
                config.max_probes(),
                config.blackhole_confirm_threshold(),
            ),
            Ok(config)
        );
    }

    #[test]
    fn converges_to_exact_path_mtu_for_every_path_in_default_range() {
        for path_mtu in 1280..=1420u16 {
            let mut machine = PathMtuDiscovery::new(config(1280, 1420));
            let probes = drive_to_quiescence(&mut machine, path_mtu);
            assert_eq!(machine.state(), PathMtuState::SearchComplete);
            assert_eq!(
                machine.effective_plpmtu(),
                path_mtu,
                "path MTU {path_mtu} must be discovered exactly"
            );
            // Binary search over a 141-value window plus the base probe: the
            // probe budget stays small and bounded (retries included).
            assert!(
                probes <= 32,
                "path MTU {path_mtu} took {probes} probes to converge"
            );
        }
    }

    #[test]
    fn converges_on_jumbo_ceiling() {
        let mut machine = PathMtuDiscovery::new(config(1280, 8920));
        drive_to_quiescence(&mut machine, 8000);
        assert_eq!(machine.effective_plpmtu(), 8000);
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
    }

    #[test]
    fn degenerate_base_equals_ceiling_converges_on_first_ack() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1280));
        assert_eq!(machine.next_probe_size(), Some(1280));
        assert_eq!(
            machine.on_probe_acked(1280),
            PathMtuOutcome::SearchConverged
        );
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.next_probe_size(), None);
    }

    #[test]
    fn path_below_base_stays_at_fail_closed_floor() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        // The path drops everything: the machine must stay in Base at the
        // floor, keep re-probing base, and count the confirm failures.
        for _ in 0..12 {
            let size = machine.next_probe_size().expect("base probe must persist");
            assert_eq!(size, 1280);
            machine.on_probe_lost(size);
            assert_eq!(machine.state(), PathMtuState::Base);
            assert_eq!(machine.effective_plpmtu(), 1280);
        }
        assert_eq!(machine.counters().base_confirm_failures, 4);
    }

    #[test]
    fn transient_probe_loss_within_retry_budget_still_converges() {
        let path_mtu = 1400u16;
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        let mut lose_next_good_probe = true;
        let mut steps = 0;
        while let Some(size) = machine.next_probe_size() {
            steps += 1;
            assert!(steps < 1000, "must converge despite transient loss");
            if size <= path_mtu {
                if lose_next_good_probe {
                    // One transient loss of a size the path supports: consumes
                    // one retry, must not shrink the window.
                    lose_next_good_probe = false;
                    let ceiling_before = machine.search_ceiling();
                    machine.on_probe_lost(size);
                    assert_eq!(machine.search_ceiling(), ceiling_before);
                } else {
                    lose_next_good_probe = true;
                    machine.on_probe_acked(size);
                }
            } else {
                machine.on_probe_lost(size);
            }
        }
        assert_eq!(machine.effective_plpmtu(), path_mtu);
    }

    #[test]
    fn blackhole_after_convergence_demotes_to_base_and_recovers_on_new_path() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1420);

        // The path shrinks mid-session: confirmed-size traffic stops
        // round-tripping. Below the threshold nothing demotes...
        assert_eq!(machine.on_probe_lost(1420), PathMtuOutcome::Progressed);
        assert_eq!(machine.on_probe_lost(1420), PathMtuOutcome::Progressed);
        assert_eq!(machine.effective_plpmtu(), 1420);
        // ...and at the threshold the machine fails closed to the floor.
        assert_eq!(
            machine.on_probe_lost(1420),
            PathMtuOutcome::BlackholeDetected
        );
        assert_eq!(machine.state(), PathMtuState::Base);
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.counters().blackhole_events, 1);

        // Recovery: the shrunken path (1340) is re-discovered exactly.
        drive_to_quiescence(&mut machine, 1340);
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
        assert_eq!(machine.effective_plpmtu(), 1340);
    }

    #[test]
    fn confirmed_size_ack_resets_blackhole_counter() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1420);

        machine.on_probe_lost(1420);
        machine.on_probe_lost(1420);
        // Confirmed-size traffic round-trips again: the loss streak is over.
        assert_eq!(machine.on_probe_acked(1420), PathMtuOutcome::Progressed);
        // A fresh streak must need the full threshold again.
        machine.on_probe_lost(1420);
        machine.on_probe_lost(1420);
        assert_eq!(machine.effective_plpmtu(), 1420);
        assert_eq!(machine.counters().blackhole_events, 0);
        assert_eq!(
            machine.on_probe_lost(1420),
            PathMtuOutcome::BlackholeDetected
        );
    }

    #[test]
    fn ptb_cannot_raise_effective_value_or_ceiling() {
        // Converged machine: a PTB claiming a larger path must change nothing.
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1300);
        assert_eq!(machine.effective_plpmtu(), 1300);
        assert_eq!(machine.on_ptb(1400), PathMtuOutcome::Ignored);
        assert_eq!(machine.effective_plpmtu(), 1300);
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
        assert_eq!(machine.next_probe_size(), None, "no probe may be spent");

        // Searching machine: a PTB at or above the ceiling must not move it.
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        machine.on_probe_acked(1280);
        assert_eq!(machine.state(), PathMtuState::Searching);
        let ceiling = machine.search_ceiling();
        assert_eq!(machine.on_ptb(ceiling), PathMtuOutcome::Ignored);
        assert_eq!(machine.on_ptb(u16::MAX), PathMtuOutcome::Ignored);
        assert_eq!(machine.search_ceiling(), ceiling);
        assert_eq!(machine.counters().ptb_ignored, 2);
    }

    #[test]
    fn ptb_lowers_only_the_unconfirmed_ceiling_during_search() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        machine.on_probe_acked(1280);
        assert_eq!(machine.state(), PathMtuState::Searching);

        assert_eq!(machine.on_ptb(1350), PathMtuOutcome::CeilingLowered);
        assert_eq!(machine.search_ceiling(), 1350);
        // The floor and effective value are untouched...
        assert_eq!(machine.effective_plpmtu(), 1280);
        // ...the next candidate respects the new ceiling...
        assert!(machine.next_probe_size().expect("probe") <= 1350);
        // ...and a later, larger PTB cannot raise the ceiling back.
        assert_eq!(machine.on_ptb(1400), PathMtuOutcome::Ignored);
        assert_eq!(machine.search_ceiling(), 1350);

        // The search then converges to min(path, ptb-lowered ceiling).
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1350);
    }

    #[test]
    fn ptb_below_confirmed_value_never_overrides_it() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1420);

        // A forged PTB claiming the path shrank must not lower anything; it
        // may only schedule one in-band verification probe of the confirmed
        // size.
        assert_eq!(machine.on_ptb(1300), PathMtuOutcome::ReprobeScheduled);
        assert_eq!(machine.effective_plpmtu(), 1420, "confirmed value held");
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
        assert_eq!(machine.next_probe_size(), Some(1420));

        // The verification probe round-trips: the forged PTB cost exactly one
        // probe and changed nothing.
        assert_eq!(machine.on_probe_acked(1420), PathMtuOutcome::Progressed);
        assert_eq!(machine.next_probe_size(), None);
        assert_eq!(machine.effective_plpmtu(), 1420);
    }

    #[test]
    fn genuine_path_shrink_after_ptb_demotes_via_in_band_loss_only() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1420);

        // This time the PTB is genuine: the verification probes are lost, and
        // the demotion happens through the in-band blackhole path, never
        // through the PTB itself.
        assert_eq!(machine.on_ptb(1300), PathMtuOutcome::ReprobeScheduled);
        assert_eq!(machine.on_probe_lost(1420), PathMtuOutcome::Progressed);
        assert_eq!(machine.effective_plpmtu(), 1420, "not demoted yet");
        assert_eq!(machine.on_probe_lost(1420), PathMtuOutcome::Progressed);
        assert_eq!(
            machine.on_probe_lost(1420),
            PathMtuOutcome::BlackholeDetected
        );
        assert_eq!(machine.effective_plpmtu(), 1280);

        // Recovery converges on the true shrunken path.
        drive_to_quiescence(&mut machine, 1300);
        assert_eq!(machine.effective_plpmtu(), 1300);
    }

    #[test]
    fn forged_ptb_flood_costs_at_most_one_outstanding_probe() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1420);

        for i in 0..100u16 {
            machine.on_ptb(1280 + (i % 140));
            assert_eq!(machine.effective_plpmtu(), 1420, "flood must not lower");
            assert_eq!(machine.state(), PathMtuState::SearchComplete);
            // At most one verification probe is ever outstanding, and it is
            // always of the confirmed size.
            match machine.next_probe_size() {
                None => {}
                Some(size) => assert_eq!(size, 1420),
            }
        }
        // The path still works: one ack clears the single outstanding probe.
        machine.on_probe_acked(1420);
        assert_eq!(machine.next_probe_size(), None);
        assert_eq!(machine.effective_plpmtu(), 1420);
    }

    #[test]
    fn ptb_below_base_is_invalid_and_ignored() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        assert_eq!(machine.on_ptb(1279), PathMtuOutcome::Ignored);
        assert_eq!(machine.on_ptb(576), PathMtuOutcome::Ignored);
        assert_eq!(machine.on_ptb(0), PathMtuOutcome::Ignored);
        assert_eq!(machine.search_ceiling(), 1420);
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.counters().ptb_ignored, 3);

        // Same once converged: a sub-base PTB cannot even trigger a re-probe.
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.on_ptb(1279), PathMtuOutcome::Ignored);
        assert_eq!(machine.next_probe_size(), None);
    }

    #[test]
    fn ptb_during_base_state_lowers_future_search_ceiling_only() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        assert_eq!(machine.state(), PathMtuState::Base);
        assert_eq!(machine.on_ptb(1320), PathMtuOutcome::CeilingLowered);
        // The floor and the outstanding base probe are untouched.
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.next_probe_size(), Some(1280));
        assert_eq!(machine.search_ceiling(), 1320);

        // The search that follows honors the lowered ceiling.
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1320);
    }

    #[test]
    fn forged_ack_of_unprobed_size_cannot_raise_confirmed_value() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        machine.on_probe_acked(1280);
        let outstanding = machine.next_probe_size().expect("search probe");

        // Acks for sizes that were never the outstanding probe are forged or
        // stale and must be inert — especially larger ones.
        assert_eq!(machine.on_probe_acked(1420), PathMtuOutcome::Ignored);
        assert_eq!(
            machine.on_probe_acked(outstanding + 1),
            PathMtuOutcome::Ignored
        );
        assert_eq!(machine.effective_plpmtu(), 1280);
        assert_eq!(machine.next_probe_size(), Some(outstanding));
        assert_eq!(machine.counters().acks_ignored, 2);

        // Same once converged: an oversized forged ack must not raise.
        drive_to_quiescence(&mut machine, 1350);
        assert_eq!(machine.effective_plpmtu(), 1350);
        assert_eq!(machine.on_probe_acked(1420), PathMtuOutcome::Ignored);
        assert_eq!(machine.effective_plpmtu(), 1350);
    }

    #[test]
    fn reprobe_interval_discovers_path_improvement_without_degrading() {
        // Converge low because the path was constrained...
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        drive_to_quiescence(&mut machine, 1310);
        assert_eq!(machine.effective_plpmtu(), 1310);

        // ...then the path improves and the raise interval fires.
        assert_eq!(
            machine.on_reprobe_interval_elapsed(),
            PathMtuOutcome::Progressed
        );
        assert_eq!(machine.state(), PathMtuState::Searching);
        // The confirmed value stays effective throughout the re-search.
        assert_eq!(machine.effective_plpmtu(), 1310);
        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1420);
    }

    #[test]
    fn reprobe_interval_is_noop_when_not_converged_or_already_at_ceiling() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        assert_eq!(
            machine.on_reprobe_interval_elapsed(),
            PathMtuOutcome::Ignored
        );
        machine.on_probe_acked(1280);
        assert_eq!(machine.state(), PathMtuState::Searching);
        assert_eq!(
            machine.on_reprobe_interval_elapsed(),
            PathMtuOutcome::Ignored
        );

        drive_to_quiescence(&mut machine, 1420);
        assert_eq!(machine.effective_plpmtu(), 1420);
        // Already at the ceiling: nothing to raise toward.
        assert_eq!(
            machine.on_reprobe_interval_elapsed(),
            PathMtuOutcome::Ignored
        );
        assert_eq!(machine.state(), PathMtuState::SearchComplete);
        assert_eq!(machine.next_probe_size(), None);
    }

    #[test]
    fn stale_loss_reports_are_ignored() {
        let mut machine = PathMtuDiscovery::new(config(1280, 1420));
        machine.on_probe_acked(1280);
        let outstanding = machine.next_probe_size().expect("search probe");

        // Losses of sizes that are neither the outstanding probe nor the
        // confirmed size are stale and inert.
        assert_eq!(machine.on_probe_lost(1419), PathMtuOutcome::Ignored);
        assert_eq!(
            machine.on_probe_lost(outstanding + 1),
            PathMtuOutcome::Ignored
        );
        assert_eq!(machine.next_probe_size(), Some(outstanding));
        assert_eq!(machine.search_ceiling(), 1420);
    }

    #[test]
    fn invariants_hold_under_deterministic_event_monkey() {
        // Deterministic LCG so the sequence is reproducible with no
        // dependencies. Mixes genuine path behavior with forged PTBs and
        // forged acks; after every event the structural invariants must hold
        // and the effective PLPMTU must never exceed what the path genuinely
        // carries.
        let mut seed = 0x2545_F491_4F6C_DD1Du64;
        let mut next = move || {
            seed = seed
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (seed >> 33) as u32
        };

        for path_mtu in [1280u16, 1333, 1399, 1420] {
            let mut machine = PathMtuDiscovery::new(config(1280, 1420));
            for _ in 0..5_000 {
                match next() % 6 {
                    // Genuine path response to the outstanding probe.
                    0 | 1 => {
                        if let Some(size) = machine.next_probe_size() {
                            if size <= path_mtu {
                                machine.on_probe_acked(size);
                            } else {
                                machine.on_probe_lost(size);
                            }
                        }
                    }
                    // Forged PTB at an arbitrary size.
                    2 => {
                        machine.on_ptb((next() % 2000) as u16);
                    }
                    // Forged ack at an arbitrary size — only genuine when it
                    // happens to name the outstanding probe AND fits the path.
                    3 => {
                        let size = 1200 + (next() % 400) as u16;
                        let genuine = machine.next_probe_size() == Some(size)
                            || machine.effective_plpmtu() == size;
                        if !genuine || size <= path_mtu {
                            machine.on_probe_acked(size);
                        }
                    }
                    // Confirmed-size traffic outcome (keepalive watch).
                    4 => {
                        let confirmed = machine.effective_plpmtu();
                        if confirmed <= path_mtu {
                            machine.on_probe_acked(confirmed);
                        } else {
                            machine.on_probe_lost(confirmed);
                        }
                    }
                    // Raise interval.
                    _ => {
                        machine.on_reprobe_interval_elapsed();
                    }
                }
                check_invariants(&machine, path_mtu);
            }
        }
    }
}
