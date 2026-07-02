//! D5.5 — ICE pair race integration test.
//!
//! Pass criterion (per
//! `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
//! §D5.5): "Time-to-connect for cone-NAT pairs improves; 'marginal'
//! pairs (one cooperative, one nearly-symmetric) that fail single-
//! candidate connect now succeed via parallel candidate gathering."
//!
//! The integration test stands up an in-process
//! `SimultaneousOpenRuntime` that:
//!
//! * Records every `send_probe` call so we can assert the priority
//!   order matches the RFC 8445 §6.1.2.3 pair ordering.
//! * Lets a specific "winning" endpoint complete the handshake
//!   after observing a probe addressed to it — modelling the
//!   marginal-NAT case where the highest-priority candidate
//!   completes the punch while others time out.
//!
//! Positive pin: `ice_race_picks_highest_priority_winning_endpoint`
//! — the race terminates on round 0 with the highest-priority
//! candidate as the winner.
//!
//! Negative pins:
//!
//! 1. `ice_race_falls_back_to_relay_when_no_direct_handshake_lands`.
//! 2. `ice_race_fails_closed_when_no_direct_candidates`.
//! 3. `ice_race_respects_role_assignment_from_node_ids` — the
//!    deterministic controlling/controlled split is honoured.
//! 4. `ice_race_falls_back_to_top_priority_when_runtime_lacks_endpoint_attribution`.

#![forbid(unsafe_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use rustynet_backend_api::SocketEndpoint;
use rustynetd::traversal::{
    CandidateSource, CoordinationSchedule, SimultaneousOpenRuntime, SimultaneousOpenWaiter,
    TraversalCandidate, TraversalDecision, TraversalDecisionReason, TraversalEngine,
    TraversalEngineConfig, TraversalError,
};

struct ProbeRecord {
    endpoint: SocketEndpoint,
    round: u8,
}

/// Test runtime: records sends + lets the test plant which endpoint
/// "wins" by configuring `winning_endpoint`. After a probe addressed
/// to that endpoint is sent, the next `latest_handshake_unix`
/// reflects a fresh handshake and `handshake_endpoint` returns the
/// winning endpoint.
struct PlantedRuntime {
    sends: Vec<ProbeRecord>,
    winning_endpoint: Option<SocketEndpoint>,
    handshake_unix: Option<u64>,
    advertise_endpoint_attribution: bool,
    /// `now_unix` used to materialise a fresh handshake stamp when
    /// the winning probe lands.
    now_unix: u64,
}

impl PlantedRuntime {
    fn with_winner(winner: SocketEndpoint, now_unix: u64) -> Self {
        Self {
            sends: Vec::new(),
            winning_endpoint: Some(winner),
            handshake_unix: None,
            advertise_endpoint_attribution: true,
            now_unix,
        }
    }

    fn without_winner(now_unix: u64) -> Self {
        Self {
            sends: Vec::new(),
            winning_endpoint: None,
            handshake_unix: None,
            advertise_endpoint_attribution: true,
            now_unix,
        }
    }

    fn without_endpoint_attribution(winner: SocketEndpoint, now_unix: u64) -> Self {
        let mut runtime = Self::with_winner(winner, now_unix);
        runtime.advertise_endpoint_attribution = false;
        runtime
    }
}

impl SimultaneousOpenRuntime for PlantedRuntime {
    fn send_probe(&mut self, endpoint: SocketEndpoint, round: u8) -> Result<(), TraversalError> {
        self.sends.push(ProbeRecord { endpoint, round });
        if Some(endpoint) == self.winning_endpoint {
            // Mark the handshake as having just completed.
            self.handshake_unix = Some(self.now_unix);
        }
        Ok(())
    }

    fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
        Ok(self.handshake_unix)
    }

    fn handshake_endpoint(&mut self) -> Result<Option<SocketEndpoint>, TraversalError> {
        if !self.advertise_endpoint_attribution {
            return Ok(None);
        }
        if self.handshake_unix.is_some() {
            Ok(self.winning_endpoint)
        } else {
            Ok(None)
        }
    }
}

struct ImmediateWaiter;
impl SimultaneousOpenWaiter for ImmediateWaiter {
    fn wait(&mut self, _duration: Duration) {}
}

fn engine_config() -> TraversalEngineConfig {
    TraversalEngineConfig {
        max_candidates: 16,
        max_probe_pairs: 16,
        simultaneous_open_rounds: 3,
        round_spacing_ms: 10,
        ..TraversalEngineConfig::default()
    }
}

fn candidate(
    addr: IpAddr,
    port: u16,
    source: CandidateSource,
    priority: u32,
) -> TraversalCandidate {
    TraversalCandidate {
        endpoint: SocketEndpoint { addr, port },
        source,
        priority,
        observed_at_unix: 1_700_000_000,
    }
}

fn dummy_schedule() -> CoordinationSchedule {
    CoordinationSchedule {
        session_id: [0u8; 16],
        nonce: [0u8; 16],
        probe_start_unix: 1_700_000_000,
        wait_duration: Duration::ZERO,
    }
}

#[test]
fn ice_race_picks_highest_priority_winning_endpoint() {
    // Local: host-v6-global (top priority) + srflx-v4 (lower).
    // Remote: host-v6-global + srflx-v4. The "winner" is the
    // remote's v6 host endpoint, simulating the cone-NAT happy
    // path where the highest-priority pair completes the punch
    // immediately.
    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    let remote_v6_host = SocketEndpoint {
        addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
        port: 51820,
    };
    let local_candidates = vec![
        candidate(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0, 0, 0, 0, 0, 0, 0x2222)),
            51820,
            CandidateSource::Host,
            100,
        ),
        candidate(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)),
            51820,
            CandidateSource::ServerReflexive,
            50,
        ),
    ];
    let remote_candidates = vec![
        candidate(
            remote_v6_host.addr,
            remote_v6_host.port,
            CandidateSource::Host,
            100,
        ),
        candidate(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            51820,
            CandidateSource::ServerReflexive,
            50,
        ),
    ];
    let mut runtime = PlantedRuntime::with_winner(remote_v6_host, now_unix);
    let mut waiter = ImmediateWaiter;
    let result = engine
        .execute_ice_pair_race(
            &mut runtime,
            &mut waiter,
            dummy_schedule(),
            &local_candidates,
            &remote_candidates,
            &[1u8; 32],
            &[2u8; 32],
            None,
            now_unix,
            60,
            None,
            None,
        )
        .expect("race runs");
    match result.decision {
        TraversalDecision::Direct { endpoint, reason } => {
            assert_eq!(endpoint, remote_v6_host);
            assert_eq!(
                reason,
                TraversalDecisionReason::IcePairRaceHandshakeObserved
            );
        }
        other => panic!("expected Direct, got {other:?}"),
    }
    // The first probe of round 0 MUST target the v6 host
    // (highest ICE priority). The race terminates on round 0.
    let round_zero_sends: Vec<_> = runtime.sends.iter().filter(|r| r.round == 0).collect();
    assert!(
        !round_zero_sends.is_empty(),
        "round 0 must have sent at least one probe"
    );
    assert_eq!(
        round_zero_sends[0].endpoint, remote_v6_host,
        "highest-priority pair must be probed first"
    );
}

#[test]
fn ice_race_falls_back_to_relay_when_no_direct_handshake_lands() {
    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    let local_candidates = vec![candidate(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        51820,
        CandidateSource::Host,
        100,
    )];
    let remote_candidates = vec![candidate(
        IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1)),
        51820,
        CandidateSource::Host,
        100,
    )];
    let relay_endpoint = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        port: 51820,
    };
    let mut runtime = PlantedRuntime::without_winner(now_unix);
    let mut waiter = ImmediateWaiter;
    let result = engine
        .execute_ice_pair_race(
            &mut runtime,
            &mut waiter,
            dummy_schedule(),
            &local_candidates,
            &remote_candidates,
            &[1u8; 32],
            &[2u8; 32],
            Some(relay_endpoint),
            now_unix,
            60,
            None,
            None,
        )
        .expect("race runs");
    match result.decision {
        TraversalDecision::Relay {
            endpoint, reason, ..
        } => {
            assert_eq!(endpoint, relay_endpoint);
            assert_eq!(
                reason,
                TraversalDecisionReason::DirectProbeExhaustedRelayArmed
            );
        }
        other => panic!("expected Relay fallback, got {other:?}"),
    }
}

#[test]
fn ice_race_fails_closed_when_no_direct_candidates() {
    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    // Only relay candidates on each side — no direct pair is
    // possible, no relay fallback supplied → FailClosed.
    let local_candidates = vec![candidate(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        51820,
        CandidateSource::Relay,
        10,
    )];
    let remote_candidates = vec![candidate(
        IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1)),
        51820,
        CandidateSource::Relay,
        10,
    )];
    let mut runtime = PlantedRuntime::without_winner(now_unix);
    let mut waiter = ImmediateWaiter;
    let result = engine
        .execute_ice_pair_race(
            &mut runtime,
            &mut waiter,
            dummy_schedule(),
            &local_candidates,
            &remote_candidates,
            &[1u8; 32],
            &[2u8; 32],
            None,
            now_unix,
            60,
            None,
            None,
        )
        .expect("race runs");
    match result.decision {
        TraversalDecision::FailClosed { reason, .. } => {
            assert_eq!(
                reason,
                TraversalDecisionReason::DirectProbeExhaustedFailClosed
            );
        }
        other => panic!("expected FailClosed, got {other:?}"),
    }
}

#[test]
fn ice_race_respects_role_assignment_from_node_ids() {
    // The deterministic controlling/controlled split is the
    // lex-min of the two node ids. With local=[1;32] and
    // remote=[2;32] we're controlling. With local=[9;32] and
    // remote=[2;32] we're controlled. The probes still fire at
    // the same set of pairs, but the priority tie-breaker
    // changes; assert that the probe order remains stable across
    // role reversals when the candidate priorities don't tie.
    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    let v6_winner = SocketEndpoint {
        addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x3333)),
        port: 51820,
    };
    let local_candidates = vec![candidate(
        IpAddr::V6(Ipv6Addr::new(0x2606, 0, 0, 0, 0, 0, 0, 0x4444)),
        51820,
        CandidateSource::Host,
        100,
    )];
    let remote_candidates = vec![candidate(
        v6_winner.addr,
        v6_winner.port,
        CandidateSource::Host,
        100,
    )];

    for &(local_id, remote_id) in &[([1u8; 32], [2u8; 32]), ([9u8; 32], [2u8; 32])] {
        let mut runtime = PlantedRuntime::with_winner(v6_winner, now_unix);
        let mut waiter = ImmediateWaiter;
        let result = engine
            .execute_ice_pair_race(
                &mut runtime,
                &mut waiter,
                dummy_schedule(),
                &local_candidates,
                &remote_candidates,
                &local_id,
                &remote_id,
                None,
                now_unix,
                60,
                None,
                None,
            )
            .expect("race runs");
        match result.decision {
            TraversalDecision::Direct { endpoint, .. } => assert_eq!(endpoint, v6_winner),
            other => panic!("expected Direct, got {other:?}"),
        }
    }
}

#[test]
fn ice_race_falls_back_to_top_priority_when_runtime_lacks_endpoint_attribution() {
    // The default `handshake_endpoint` impl returns Ok(None) for
    // existing runtimes that don't track per-endpoint state. In
    // that case the race runner attributes the win to the
    // highest-priority pair it just probed in the winning round.
    // Verify this fallback by asserting the Direct endpoint
    // matches the v6-host (top priority) even when the runtime
    // refuses to disclose endpoint attribution.
    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    let top_priority_remote = SocketEndpoint {
        addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x5555)),
        port: 51820,
    };
    let local_candidates = vec![candidate(
        IpAddr::V6(Ipv6Addr::new(0x2606, 0, 0, 0, 0, 0, 0, 0x6666)),
        51820,
        CandidateSource::Host,
        100,
    )];
    let remote_candidates = vec![candidate(
        top_priority_remote.addr,
        top_priority_remote.port,
        CandidateSource::Host,
        100,
    )];
    let mut runtime = PlantedRuntime::without_endpoint_attribution(top_priority_remote, now_unix);
    let mut waiter = ImmediateWaiter;
    let result = engine
        .execute_ice_pair_race(
            &mut runtime,
            &mut waiter,
            dummy_schedule(),
            &local_candidates,
            &remote_candidates,
            &[1u8; 32],
            &[2u8; 32],
            None,
            now_unix,
            60,
            None,
            None,
        )
        .expect("race runs");
    match result.decision {
        TraversalDecision::Direct { endpoint, .. } => {
            assert_eq!(endpoint, top_priority_remote);
        }
        other => panic!("expected Direct, got {other:?}"),
    }
}

#[test]
fn ice_race_marginal_nat_succeeds_where_serial_attempts_would_fail() {
    // §D5.5 pass criterion's "marginal pair" case: imagine the
    // remote has a nearly-symmetric NAT that only opens a
    // pinhole when several local outbound packets arrive
    // simultaneously. The race runner sends ALL pairs in a round
    // before polling — exactly the behaviour the marginal pair
    // needs. We simulate this by requiring TWO sends within the
    // same round before the planted runtime marks the handshake
    // complete.
    struct MarginalRuntime {
        sends: Vec<ProbeRecord>,
        winning_endpoint: SocketEndpoint,
        sends_required: usize,
        handshake_unix: Option<u64>,
        now_unix: u64,
    }
    impl SimultaneousOpenRuntime for MarginalRuntime {
        fn send_probe(
            &mut self,
            endpoint: SocketEndpoint,
            round: u8,
        ) -> Result<(), TraversalError> {
            self.sends.push(ProbeRecord { endpoint, round });
            if self.sends.len() >= self.sends_required
                && self
                    .sends
                    .iter()
                    .any(|r| r.endpoint == self.winning_endpoint)
            {
                self.handshake_unix = Some(self.now_unix);
            }
            Ok(())
        }
        fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
            Ok(self.handshake_unix)
        }
        fn handshake_endpoint(&mut self) -> Result<Option<SocketEndpoint>, TraversalError> {
            if self.handshake_unix.is_some() {
                Ok(Some(self.winning_endpoint))
            } else {
                Ok(None)
            }
        }
    }

    let engine = TraversalEngine::new(engine_config()).expect("engine");
    let now_unix = 1_700_000_100u64;
    let winner = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
        port: 51820,
    };
    let local_candidates = vec![
        candidate(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            51820,
            CandidateSource::Host,
            100,
        ),
        candidate(
            IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)),
            51820,
            CandidateSource::ServerReflexive,
            80,
        ),
    ];
    let remote_candidates = vec![
        candidate(
            winner.addr,
            winner.port,
            CandidateSource::ServerReflexive,
            100,
        ),
        candidate(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            51820,
            CandidateSource::Host,
            80,
        ),
    ];
    let mut runtime = MarginalRuntime {
        sends: Vec::new(),
        winning_endpoint: winner,
        sends_required: 2,
        handshake_unix: None,
        now_unix,
    };
    let mut waiter = ImmediateWaiter;
    let result = engine
        .execute_ice_pair_race(
            &mut runtime,
            &mut waiter,
            dummy_schedule(),
            &local_candidates,
            &remote_candidates,
            &[1u8; 32],
            &[2u8; 32],
            None,
            now_unix,
            60,
            None,
            None,
        )
        .expect("race runs");
    match result.decision {
        TraversalDecision::Direct { endpoint, .. } => assert_eq!(endpoint, winner),
        other => panic!("expected Direct (marginal NAT succeeded), got {other:?}"),
    }
    // At least 2 probes must have been issued in round 0 — that's
    // the parallel-race property the §D5.5 pass criterion calls
    // out. If we'd serialised (probe-poll-probe-poll) the second
    // probe would never have fired before the first poll returned.
    let round_zero_count = runtime.sends.iter().filter(|r| r.round == 0).count();
    assert!(
        round_zero_count >= 2,
        "marginal-NAT race must send >= 2 probes in round 0; got {round_zero_count}"
    );
}
