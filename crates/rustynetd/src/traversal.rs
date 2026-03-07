#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;
use std::net::IpAddr;

use rustynet_backend_api::{NodeId, SocketEndpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateSource {
    Host,
    ServerReflexive,
    Relay,
}

impl CandidateSource {
    fn direct_eligible(self) -> bool {
        !matches!(self, CandidateSource::Relay)
    }

    fn preference_score(self) -> u64 {
        match self {
            CandidateSource::Host => 300,
            CandidateSource::ServerReflexive => 200,
            CandidateSource::Relay => 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalCandidate {
    pub endpoint: SocketEndpoint,
    pub source: CandidateSource,
    pub priority: u32,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalEngineConfig {
    pub max_candidates: usize,
    pub max_probe_pairs: usize,
    pub simultaneous_open_rounds: u8,
    pub round_spacing_ms: u64,
    pub relay_switch_after_failures: u8,
}

impl Default for TraversalEngineConfig {
    fn default() -> Self {
        Self {
            max_candidates: 8,
            max_probe_pairs: 24,
            simultaneous_open_rounds: 3,
            round_spacing_ms: 80,
            relay_switch_after_failures: 3,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalError {
    CandidateCountExceeded {
        side: &'static str,
        count: usize,
        max: usize,
    },
    DuplicateCandidate {
        side: &'static str,
        addr: IpAddr,
        port: u16,
        source: CandidateSource,
    },
    InvalidCandidatePort {
        side: &'static str,
    },
    NoDirectCandidates,
    InvalidConfig(&'static str),
}

impl fmt::Display for TraversalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraversalError::CandidateCountExceeded { side, count, max } => {
                write!(
                    f,
                    "candidate count exceeded on {side}: count={count} max={max}"
                )
            }
            TraversalError::DuplicateCandidate {
                side,
                addr,
                port,
                source,
            } => write!(
                f,
                "duplicate candidate on {side}: addr={addr} port={port} source={source:?}"
            ),
            TraversalError::InvalidCandidatePort { side } => {
                write!(f, "invalid candidate port on {side}: port must be non-zero")
            }
            TraversalError::NoDirectCandidates => {
                f.write_str("no direct-eligible candidates available")
            }
            TraversalError::InvalidConfig(message) => {
                write!(f, "invalid traversal config: {message}")
            }
        }
    }
}

impl std::error::Error for TraversalError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFilteringBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatProfile {
    pub mapping: NatMappingBehavior,
    pub filtering: NatFilteringBehavior,
    pub preserves_port: bool,
}

impl NatProfile {
    pub fn is_symmetric(self) -> bool {
        matches!(self.mapping, NatMappingBehavior::AddressAndPortDependent)
    }

    fn is_hard_nat(self) -> bool {
        matches!(
            self.filtering,
            NatFilteringBehavior::AddressAndPortDependent
        ) || self.is_symmetric()
    }
}

pub fn direct_udp_viable(local: NatProfile, remote: NatProfile) -> bool {
    if local.is_symmetric() && remote.is_symmetric() {
        return false;
    }
    if local.is_hard_nat() && remote.is_hard_nat() {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePair {
    pub local: TraversalCandidate,
    pub remote: TraversalCandidate,
    pub round: u8,
    pub delay_ms: u64,
    pub score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePlan {
    pub pairs: Vec<ProbePair>,
}

impl ProbePlan {
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    SessionBoot,
    DirectProbeSuccess,
    DirectProbeTimeout,
    EndpointRoamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionEvent {
    pub from: PathMode,
    pub to: PathMode,
    pub reason: TransitionReason,
    pub at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalSession {
    pub peer_node_id: NodeId,
    pub path: PathMode,
    pub active_endpoint: Option<SocketEndpoint>,
    pub consecutive_direct_failures: u8,
    pub last_transition: TransitionEvent,
    pub last_keepalive_unix: Option<u64>,
}

impl TraversalSession {
    pub fn new(peer_node_id: NodeId, now_unix: u64) -> Self {
        Self {
            peer_node_id,
            path: PathMode::Relay,
            active_endpoint: None,
            consecutive_direct_failures: 0,
            last_transition: TransitionEvent {
                from: PathMode::Relay,
                to: PathMode::Relay,
                reason: TransitionReason::SessionBoot,
                at_unix: now_unix,
            },
            last_keepalive_unix: None,
        }
    }

    pub fn on_direct_probe_success(
        &mut self,
        endpoint: SocketEndpoint,
        now_unix: u64,
    ) -> TransitionEvent {
        let previous = self.path;
        self.path = PathMode::Direct;
        self.active_endpoint = Some(endpoint);
        self.consecutive_direct_failures = 0;
        let event = TransitionEvent {
            from: previous,
            to: PathMode::Direct,
            reason: TransitionReason::DirectProbeSuccess,
            at_unix: now_unix,
        };
        self.last_transition = event;
        event
    }

    pub fn on_direct_probe_timeout(
        &mut self,
        now_unix: u64,
        config: TraversalEngineConfig,
    ) -> Option<TransitionEvent> {
        self.consecutive_direct_failures = self.consecutive_direct_failures.saturating_add(1);
        if self.consecutive_direct_failures < config.relay_switch_after_failures {
            return None;
        }
        let previous = self.path;
        self.path = PathMode::Relay;
        let event = TransitionEvent {
            from: previous,
            to: PathMode::Relay,
            reason: TransitionReason::DirectProbeTimeout,
            at_unix: now_unix,
        };
        self.last_transition = event;
        Some(event)
    }

    pub fn on_endpoint_roamed(
        &mut self,
        new_endpoint: SocketEndpoint,
        now_unix: u64,
    ) -> Option<TransitionEvent> {
        let existing = self.active_endpoint;
        self.active_endpoint = Some(new_endpoint);
        if self.path != PathMode::Direct || existing == Some(new_endpoint) {
            return None;
        }
        let event = TransitionEvent {
            from: PathMode::Direct,
            to: PathMode::Direct,
            reason: TransitionReason::EndpointRoamed,
            at_unix: now_unix,
        };
        self.last_transition = event;
        Some(event)
    }

    pub fn recommended_keepalive_secs(nat_profile: NatProfile) -> u64 {
        if nat_profile.is_hard_nat() || !nat_profile.preserves_port {
            15
        } else {
            25
        }
    }

    pub fn should_send_keepalive(&self, now_unix: u64, nat_profile: NatProfile) -> bool {
        let interval = Self::recommended_keepalive_secs(nat_profile);
        let Some(last) = self.last_keepalive_unix else {
            return true;
        };
        now_unix.saturating_sub(last) >= interval
    }

    pub fn mark_keepalive_sent(&mut self, now_unix: u64) {
        self.last_keepalive_unix = Some(now_unix);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalEngine {
    pub config: TraversalEngineConfig,
}

impl TraversalEngine {
    pub fn new(config: TraversalEngineConfig) -> Result<Self, TraversalError> {
        if config.max_candidates == 0 {
            return Err(TraversalError::InvalidConfig(
                "max_candidates must be greater than zero",
            ));
        }
        if config.max_probe_pairs == 0 {
            return Err(TraversalError::InvalidConfig(
                "max_probe_pairs must be greater than zero",
            ));
        }
        if config.simultaneous_open_rounds == 0 {
            return Err(TraversalError::InvalidConfig(
                "simultaneous_open_rounds must be greater than zero",
            ));
        }
        if config.relay_switch_after_failures == 0 {
            return Err(TraversalError::InvalidConfig(
                "relay_switch_after_failures must be greater than zero",
            ));
        }
        Ok(Self { config })
    }

    pub fn plan_direct_probes(
        &self,
        local_candidates: &[TraversalCandidate],
        remote_candidates: &[TraversalCandidate],
    ) -> Result<ProbePlan, TraversalError> {
        validate_candidates("local", local_candidates, self.config)?;
        validate_candidates("remote", remote_candidates, self.config)?;

        let local_direct = local_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect::<Vec<_>>();
        let remote_direct = remote_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect::<Vec<_>>();

        if local_direct.is_empty() || remote_direct.is_empty() {
            return Err(TraversalError::NoDirectCandidates);
        }

        let mut base_pairs = Vec::new();
        for local in &local_direct {
            for remote in &remote_direct {
                let score = score_pair(*local, *remote);
                base_pairs.push((*local, *remote, score));
            }
        }
        base_pairs.sort_by(|left, right| right.2.cmp(&left.2));
        base_pairs.truncate(self.config.max_probe_pairs);

        let mut plan_pairs = Vec::new();
        for round in 0..self.config.simultaneous_open_rounds {
            let delay_ms = self
                .config
                .round_spacing_ms
                .saturating_mul(u64::from(round));
            for (local, remote, score) in &base_pairs {
                plan_pairs.push(ProbePair {
                    local: *local,
                    remote: *remote,
                    round,
                    delay_ms,
                    score: *score,
                });
            }
        }

        Ok(ProbePlan { pairs: plan_pairs })
    }
}

fn validate_candidates(
    side: &'static str,
    candidates: &[TraversalCandidate],
    config: TraversalEngineConfig,
) -> Result<(), TraversalError> {
    if candidates.len() > config.max_candidates {
        return Err(TraversalError::CandidateCountExceeded {
            side,
            count: candidates.len(),
            max: config.max_candidates,
        });
    }

    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if candidate.endpoint.port == 0 {
            return Err(TraversalError::InvalidCandidatePort { side });
        }
        let key = (
            candidate.endpoint.addr,
            candidate.endpoint.port,
            candidate.source,
        );
        if !seen.insert(key) {
            return Err(TraversalError::DuplicateCandidate {
                side,
                addr: candidate.endpoint.addr,
                port: candidate.endpoint.port,
                source: candidate.source,
            });
        }
    }

    Ok(())
}

fn score_pair(local: TraversalCandidate, remote: TraversalCandidate) -> u64 {
    u64::from(local.priority)
        .saturating_add(u64::from(remote.priority))
        .saturating_add(local.source.preference_score())
        .saturating_add(remote.source.preference_score())
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateSource, NatFilteringBehavior, NatMappingBehavior, NatProfile, PathMode,
        TraversalCandidate, TraversalEngine, TraversalEngineConfig, TraversalError,
        TraversalSession, direct_udp_viable,
    };
    use rustynet_backend_api::{NodeId, SocketEndpoint};
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(octets: [u8; 4], port: u16) -> SocketEndpoint {
        SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::from(octets)),
            port,
        }
    }

    fn candidate(
        octets: [u8; 4],
        port: u16,
        source: CandidateSource,
        priority: u32,
    ) -> TraversalCandidate {
        TraversalCandidate {
            endpoint: endpoint(octets, port),
            source,
            priority,
            observed_at_unix: 1_717_171_717,
        }
    }

    #[test]
    fn direct_plan_builds_simultaneous_rounds() {
        let engine = TraversalEngine::new(TraversalEngineConfig {
            max_candidates: 8,
            max_probe_pairs: 4,
            simultaneous_open_rounds: 3,
            round_spacing_ms: 100,
            relay_switch_after_failures: 3,
        })
        .expect("engine config should be valid");

        let local = vec![
            candidate([10, 0, 0, 10], 51820, CandidateSource::Host, 900),
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                700,
            ),
        ];
        let remote = vec![
            candidate([10, 0, 0, 20], 51820, CandidateSource::Host, 950),
            candidate(
                [203, 0, 113, 20],
                63000,
                CandidateSource::ServerReflexive,
                650,
            ),
        ];

        let plan = engine
            .plan_direct_probes(local.as_slice(), remote.as_slice())
            .expect("probe plan should be generated");
        assert_eq!(plan.pairs.len(), 12);
        assert_eq!(plan.pairs[0].round, 0);
        assert_eq!(plan.pairs[0].delay_ms, 0);
        assert_eq!(plan.pairs[4].round, 1);
        assert_eq!(plan.pairs[4].delay_ms, 100);
        assert_eq!(plan.pairs[8].round, 2);
        assert_eq!(plan.pairs[8].delay_ms, 200);
    }

    #[test]
    fn direct_viability_rejects_double_symmetric_nat() {
        let symmetric = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        assert!(!direct_udp_viable(symmetric, symmetric));

        let easier = NatProfile {
            mapping: NatMappingBehavior::EndpointIndependent,
            filtering: NatFilteringBehavior::AddressDependent,
            preserves_port: true,
        };
        assert!(direct_udp_viable(symmetric, easier));
    }

    #[test]
    fn direct_session_survives_endpoint_roam() {
        let peer = NodeId::new("peer-1").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let first_endpoint = endpoint([198, 51, 100, 5], 55123);
        let second_endpoint = endpoint([198, 51, 100, 6], 55124);

        let event = session.on_direct_probe_success(first_endpoint, 120);
        assert_eq!(event.to, PathMode::Direct);
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(first_endpoint));

        let roam = session
            .on_endpoint_roamed(second_endpoint, 150)
            .expect("roam transition should be recorded");
        assert_eq!(roam.from, PathMode::Direct);
        assert_eq!(roam.to, PathMode::Direct);
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(second_endpoint));
    }

    #[test]
    fn keepalive_interval_is_tighter_for_hard_nat() {
        let hard_nat = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        let easy_nat = NatProfile {
            mapping: NatMappingBehavior::EndpointIndependent,
            filtering: NatFilteringBehavior::EndpointIndependent,
            preserves_port: true,
        };

        assert_eq!(TraversalSession::recommended_keepalive_secs(hard_nat), 15);
        assert_eq!(TraversalSession::recommended_keepalive_secs(easy_nat), 25);
    }

    #[test]
    fn candidate_validation_rejects_duplicates() {
        let engine =
            TraversalEngine::new(TraversalEngineConfig::default()).expect("config should be valid");
        let local = vec![
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                900,
            ),
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                800,
            ),
        ];
        let remote = vec![candidate(
            [203, 0, 113, 20],
            63000,
            CandidateSource::ServerReflexive,
            900,
        )];

        let err = engine
            .plan_direct_probes(local.as_slice(), remote.as_slice())
            .expect_err("duplicate candidate should fail validation");
        assert!(err.to_string().contains("duplicate candidate"));
    }

    #[test]
    fn adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback() {
        let engine =
            TraversalEngine::new(TraversalEngineConfig::default()).expect("config should be valid");
        let relay_only_local = vec![candidate(
            [198, 51, 100, 10],
            62000,
            CandidateSource::Relay,
            900,
        )];
        let relay_only_remote = vec![candidate(
            [203, 0, 113, 20],
            63000,
            CandidateSource::Relay,
            900,
        )];
        let no_direct = engine
            .plan_direct_probes(relay_only_local.as_slice(), relay_only_remote.as_slice())
            .expect_err("relay-only candidate sets must never authorize direct path planning");
        assert!(matches!(no_direct, TraversalError::NoDirectCandidates));

        let hard_nat = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        assert!(
            !direct_udp_viable(hard_nat, hard_nat),
            "hard NAT mismatch must deny direct viability and require relay fallback"
        );

        let peer = NodeId::new("peer-nat-hard").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let fallback_config = TraversalEngineConfig {
            relay_switch_after_failures: 2,
            ..TraversalEngineConfig::default()
        };
        assert_eq!(session.path, PathMode::Relay);
        assert!(
            session
                .on_direct_probe_timeout(101, fallback_config)
                .is_none()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert!(
            session
                .on_direct_probe_timeout(102, fallback_config)
                .is_some()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert_eq!(session.active_endpoint, None);

        let direct_endpoint = endpoint([203, 0, 113, 21], 51820);
        session.on_direct_probe_success(direct_endpoint, 103);
        assert_eq!(session.path, PathMode::Direct);
        session.on_direct_probe_timeout(104, fallback_config);
        let failback = session
            .on_direct_probe_timeout(105, fallback_config)
            .expect("relay failback should trigger after configured direct probe failures");
        assert_eq!(failback.to, PathMode::Relay);
        assert_eq!(session.path, PathMode::Relay);
    }
}
