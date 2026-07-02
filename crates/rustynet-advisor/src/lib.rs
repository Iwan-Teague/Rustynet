//! FIS-0005: decision-support scoring engine for role placement.
//!
//! Pure multi-criteria decision analysis (weighted-sum MCDA) over
//! per-candidate observations, recommending which node should host a
//! role (anchor / relay / exit). Domain-layer discipline: this crate
//! depends only on `rustynet-control` abstract types, never on a backend
//! or transport; collectors (SSH fan-out, status-line parsing) live in
//! the CLI layer and hand observations in.
//!
//! Honesty rules baked into the API: a candidate with no live evidence
//! scores through explicit `Unknown`/`InsufficientData` normalizations
//! (never a fabricated healthy value), and a recommendation computed
//! from any data-starved candidate carries `insufficient_data = true` so
//! operators see advisory output, not fake confidence. Empty candidate
//! sets recommend nobody — the deny-by-empty analog.

#![forbid(unsafe_code)]

/// Role a recommendation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoleType {
    Anchor,
    Relay,
    Exit,
}

impl RoleType {
    pub const fn as_str(self) -> &'static str {
        match self {
            RoleType::Anchor => "anchor",
            RoleType::Relay => "relay",
            RoleType::Exit => "exit",
        }
    }
}

/// NAT classification of a candidate (mirrors the preflight
/// `NatClassHeuristic` vocabulary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClassCode {
    ConeNatLikely,
    PortRestrictedLikely,
    SymmetricLikely,
    InsufficientData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BandwidthHeadroom {
    Unknown,
    Low,
    Medium,
    High,
}

/// One candidate's observed placement signals. Fixed-point ratios are
/// 0..=1000 (permille) so observations stay `Eq`-comparable and
/// serialization-friendly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateObservation {
    pub node_id: String,
    /// EWMA uptime ratio, permille. `None` = no evidence.
    pub uptime_ratio_ewma: Option<u16>,
    pub nat_class: NatClassCode,
    /// EWMA handshake success ratio, permille. `None` = no evidence.
    pub handshake_success_ewma: Option<u16>,
    pub bandwidth_headroom: BandwidthHeadroom,
    /// Betweenness-centrality permille within the mesh graph. `None`
    /// until the (phase 3) Brandes collector lands.
    pub centrality: Option<u16>,
    pub observed_at_unix: u64,
}

/// Per-criterion normalized contributions (each already weighted).
#[derive(Debug, Clone, PartialEq)]
pub struct ScoreBreakdown {
    pub uptime: f64,
    pub reachability_stability: f64,
    pub nat_class: f64,
    pub bandwidth_headroom: f64,
    pub centrality: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ScoredCandidate {
    pub node_id: String,
    pub score: f64,
    pub breakdown: ScoreBreakdown,
    /// True when any criterion scored from a missing/insufficient input.
    pub data_starved: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RoleRecommendation {
    pub role: RoleType,
    /// Ranked best-first; ties broken by node id for determinism.
    pub candidates: Vec<ScoredCandidate>,
    /// True when ANY ranked candidate is data-starved — the whole
    /// recommendation is then advisory, not evidence-backed.
    pub insufficient_data: bool,
}

/// Criterion weights: uptime 0.30, reachability stability 0.25, NAT class
/// 0.20, bandwidth headroom 0.15, centrality 0.10.
const WEIGHTS: [f64; 5] = [0.30, 0.25, 0.20, 0.15, 0.10];

fn permille_normalized(value: Option<u16>) -> (f64, bool) {
    match value {
        Some(permille) => ((f64::from(permille.min(1000))) / 1000.0, false),
        // No evidence scores zero AND marks the candidate data-starved —
        // never a fabricated midpoint.
        None => (0.0, true),
    }
}

fn nat_class_normalized(nat: NatClassCode, role: RoleType) -> (f64, bool) {
    // Anchors/relays want inbound reachability: cone best, symmetric worst.
    // Exit placement is less NAT-sensitive (clients dial OUT through it),
    // so the spread is compressed.
    let (cone, port_restricted, symmetric) = match role {
        RoleType::Anchor | RoleType::Relay => (1.0, 0.6, 0.1),
        RoleType::Exit => (1.0, 0.8, 0.5),
    };
    match nat {
        NatClassCode::ConeNatLikely => (cone, false),
        NatClassCode::PortRestrictedLikely => (port_restricted, false),
        NatClassCode::SymmetricLikely => (symmetric, false),
        NatClassCode::InsufficientData => (0.0, true),
    }
}

fn bandwidth_normalized(headroom: BandwidthHeadroom) -> (f64, bool) {
    match headroom {
        BandwidthHeadroom::High => (1.0, false),
        BandwidthHeadroom::Medium => (0.6, false),
        BandwidthHeadroom::Low => (0.2, false),
        BandwidthHeadroom::Unknown => (0.0, true),
    }
}

/// Weighted-sum MCDA score for one candidate. Deterministic and pure.
/// (Deliberately NOT named `score_candidate` — that name belongs to the
/// ICE pair scorer in rustynetd.)
pub fn compute_role_score(
    observation: &CandidateObservation,
    role: RoleType,
) -> (f64, ScoreBreakdown, bool) {
    let (uptime, uptime_starved) = permille_normalized(observation.uptime_ratio_ewma);
    let (stability, stability_starved) = permille_normalized(observation.handshake_success_ewma);
    let (nat, nat_starved) = nat_class_normalized(observation.nat_class, role);
    let (bandwidth, bandwidth_starved) = bandwidth_normalized(observation.bandwidth_headroom);
    let (centrality, centrality_starved) = permille_normalized(observation.centrality);

    let breakdown = ScoreBreakdown {
        uptime: uptime * WEIGHTS[0],
        reachability_stability: stability * WEIGHTS[1],
        nat_class: nat * WEIGHTS[2],
        bandwidth_headroom: bandwidth * WEIGHTS[3],
        centrality: centrality * WEIGHTS[4],
    };
    let score = breakdown.uptime
        + breakdown.reachability_stability
        + breakdown.nat_class
        + breakdown.bandwidth_headroom
        + breakdown.centrality;
    let data_starved = uptime_starved
        || stability_starved
        || nat_starved
        || bandwidth_starved
        || centrality_starved;
    (score, breakdown, data_starved)
}

/// Rank candidates for a role. Empty input recommends nobody.
pub fn recommend_role_placement(
    role: RoleType,
    observations: &[CandidateObservation],
) -> RoleRecommendation {
    let mut candidates: Vec<ScoredCandidate> = observations
        .iter()
        .map(|observation| {
            let (score, breakdown, data_starved) = compute_role_score(observation, role);
            ScoredCandidate {
                node_id: observation.node_id.clone(),
                score,
                breakdown,
                data_starved,
            }
        })
        .collect();
    // Best-first; deterministic node-id tiebreak (scores are finite by
    // construction: weighted sums of values in [0, 1]).
    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.node_id.cmp(&b.node_id))
    });
    let insufficient_data =
        candidates.is_empty() || candidates.iter().any(|candidate| candidate.data_starved);
    RoleRecommendation {
        role,
        candidates,
        insufficient_data,
    }
}

/// Render a recommendation for operator consumption.
pub fn render_recommendation(recommendation: &RoleRecommendation) -> String {
    let mut out = format!(
        "role placement recommendation: role={}{}\n",
        recommendation.role.as_str(),
        if recommendation.insufficient_data {
            " (ADVISORY: insufficient live evidence for at least one candidate)"
        } else {
            ""
        }
    );
    if recommendation.candidates.is_empty() {
        out.push_str("  no eligible candidates — nothing recommended\n");
        return out;
    }
    for (rank, candidate) in recommendation.candidates.iter().enumerate() {
        out.push_str(&format!(
            "  #{rank_display} {node} score={score:.3} (uptime {uptime:.3} + stability {stability:.3} + nat {nat:.3} + bandwidth {bandwidth:.3} + centrality {centrality:.3}){starved}\n",
            rank_display = rank + 1,
            node = candidate.node_id,
            score = candidate.score,
            uptime = candidate.breakdown.uptime,
            stability = candidate.breakdown.reachability_stability,
            nat = candidate.breakdown.nat_class,
            bandwidth = candidate.breakdown.bandwidth_headroom,
            centrality = candidate.breakdown.centrality,
            starved = if candidate.data_starved {
                " [data-starved]"
            } else {
                ""
            },
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{
        BandwidthHeadroom, CandidateObservation, NatClassCode, RoleType, compute_role_score,
        recommend_role_placement,
    };

    fn full_observation(node_id: &str) -> CandidateObservation {
        CandidateObservation {
            node_id: node_id.to_owned(),
            uptime_ratio_ewma: Some(990),
            nat_class: NatClassCode::ConeNatLikely,
            handshake_success_ewma: Some(950),
            bandwidth_headroom: BandwidthHeadroom::High,
            centrality: Some(500),
            observed_at_unix: 1_000,
        }
    }

    #[test]
    fn deterministic_score_for_known_topology() {
        let observation = full_observation("anchor-1");
        let (score, breakdown, starved) = compute_role_score(&observation, RoleType::Anchor);
        // 0.99*0.30 + 0.95*0.25 + 1.0*0.20 + 1.0*0.15 + 0.5*0.10 = 0.9345
        assert!((score - 0.9345).abs() < 1e-9, "score: {score}");
        assert!((breakdown.uptime - 0.297).abs() < 1e-9);
        assert!(!starved);
        // Determinism: identical input, identical output.
        let (score_again, _, _) = compute_role_score(&observation, RoleType::Anchor);
        assert_eq!(score, score_again);
    }

    #[test]
    fn missing_evidence_scores_zero_and_marks_starved() {
        let observation = CandidateObservation {
            node_id: "mystery".to_owned(),
            uptime_ratio_ewma: None,
            nat_class: NatClassCode::InsufficientData,
            handshake_success_ewma: None,
            bandwidth_headroom: BandwidthHeadroom::Unknown,
            centrality: None,
            observed_at_unix: 1_000,
        };
        let (score, _, starved) = compute_role_score(&observation, RoleType::Relay);
        assert_eq!(score, 0.0, "no evidence never fabricates a score");
        assert!(starved);
    }

    #[test]
    fn symmetric_nat_penalized_for_anchor_but_tolerated_for_exit() {
        let mut observation = full_observation("node-s");
        observation.nat_class = NatClassCode::SymmetricLikely;
        let (anchor_score, _, _) = compute_role_score(&observation, RoleType::Anchor);
        let (exit_score, _, _) = compute_role_score(&observation, RoleType::Exit);
        assert!(
            exit_score > anchor_score,
            "exit placement is less NAT-sensitive: {exit_score} vs {anchor_score}"
        );
    }

    #[test]
    fn recommendation_ranks_best_first_and_denies_on_empty() {
        let strong = full_observation("node-strong");
        let mut weak = full_observation("node-weak");
        weak.uptime_ratio_ewma = Some(400);
        weak.bandwidth_headroom = BandwidthHeadroom::Low;

        let recommendation =
            recommend_role_placement(RoleType::Relay, &[weak.clone(), strong.clone()]);
        assert_eq!(recommendation.candidates[0].node_id, "node-strong");
        assert_eq!(recommendation.candidates[1].node_id, "node-weak");
        assert!(!recommendation.insufficient_data);

        // Deny-by-empty: no candidates, nothing recommended, flagged.
        let empty = recommend_role_placement(RoleType::Relay, &[]);
        assert!(empty.candidates.is_empty());
        assert!(empty.insufficient_data);

        // One starved candidate poisons the recommendation's confidence.
        let mut starved = full_observation("node-x");
        starved.centrality = None;
        let mixed = recommend_role_placement(RoleType::Relay, &[strong, starved]);
        assert!(mixed.insufficient_data);
    }

    #[test]
    fn tie_breaks_deterministically_by_node_id() {
        let first = full_observation("node-b");
        let second = full_observation("node-a");
        let recommendation = recommend_role_placement(RoleType::Anchor, &[first, second]);
        assert_eq!(recommendation.candidates[0].node_id, "node-a");
        assert_eq!(recommendation.candidates[1].node_id, "node-b");
    }
}
