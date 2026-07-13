//! Property-style invariant pins for the FIS-0005 MCDA scorer, driven
//! exclusively through the public API (exactly what `rustynet-cli`'s
//! `role recommend` consumes).
//!
//! The workspace has no `proptest`/`quickcheck`, so these are
//! dependency-free property tests: exhaustive sweeps over a value
//! lattice covering every enum variant and the permille boundary values
//! (`None`, 0, 1, 999, 1000, the >1000 clamp region, `u16::MAX`), plus a
//! seeded SplitMix64 generator for randomized set-level cases. Every
//! case is deterministic and reproducible.
//!
//! Invariants pinned here:
//! 1. Deny-by-empty: an empty candidate set recommends nobody and is
//!    flagged insufficient.
//! 2. Bounds / no NaN-inf leakage: every score and breakdown component
//!    is finite and in [0, 1]; a perfect candidate scores exactly 1.0
//!    (the weight vector sums to exactly 1.0 in f64 — no silent
//!    renormalization), and no candidate can exceed it.
//! 3. The total score equals the sum of its (already weighted)
//!    breakdown components.
//! 4. Honesty flags: `data_starved` iff at least one criterion had
//!    missing/insufficient evidence; `insufficient_data` iff the set is
//!    empty or any ranked candidate is data-starved.
//! 5. Per-criterion monotonicity: improving one criterion, all else
//!    equal, never lowers the score; permille inputs above 1000 clamp
//!    to exactly the 1000 score; enum criteria are strictly ordered
//!    within every role.
//! 6. Rank monotonicity: improving one criterion of one candidate never
//!    worsens that candidate's rank and never reorders the others
//!    relative to each other.
//! 7. Tie-breaks: ranking follows the total order (score descending,
//!    `node_id` ascending); output is deterministic and, for unique
//!    node ids, permutation-invariant.
//! 8. `recommend_role_placement` is exactly map + sort: no candidate is
//!    dropped, invented, or scored differently from
//!    `compute_role_score`.
//! 9. Rendering never panics, marks ADVISORY exactly when the
//!    recommendation is insufficient-data, and tags exactly the
//!    data-starved candidates.

use rustynet_advisor::{
    BandwidthHeadroom, CandidateObservation, NatClassCode, RoleRecommendation, RoleType,
    compute_role_score, recommend_role_placement, render_recommendation,
};

/// Worst-to-best score order along a permille criterion. `None` and
/// `Some(0)` both normalize to 0.0 (only the starved flag differs);
/// everything >= 1000 clamps to 1.0.
const PERMILLE_LATTICE: [Option<u16>; 9] = [
    None,
    Some(0),
    Some(1),
    Some(250),
    Some(500),
    Some(999),
    Some(1000),
    Some(1001),
    Some(u16::MAX),
];

/// Worst-to-best NAT classes (the quality order holds for every role).
const NAT_LATTICE: [NatClassCode; 4] = [
    NatClassCode::InsufficientData,
    NatClassCode::SymmetricLikely,
    NatClassCode::PortRestrictedLikely,
    NatClassCode::ConeNatLikely,
];

/// Worst-to-best bandwidth headroom.
const BANDWIDTH_LATTICE: [BandwidthHeadroom; 4] = [
    BandwidthHeadroom::Unknown,
    BandwidthHeadroom::Low,
    BandwidthHeadroom::Medium,
    BandwidthHeadroom::High,
];

const ROLES: [RoleType; 3] = [RoleType::Anchor, RoleType::Relay, RoleType::Exit];

const AXIS_COUNT: usize = 5;

/// Lattice coordinates for one candidate: indices into the axis arrays
/// above (uptime, handshake, centrality index `PERMILLE_LATTICE`; nat
/// indexes `NAT_LATTICE`; bandwidth indexes `BANDWIDTH_LATTICE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Point {
    uptime: usize,
    handshake: usize,
    nat: usize,
    bandwidth: usize,
    centrality: usize,
}

impl Point {
    fn perfect() -> Self {
        Point {
            uptime: PERMILLE_LATTICE.len() - 1,
            handshake: PERMILLE_LATTICE.len() - 1,
            nat: NAT_LATTICE.len() - 1,
            bandwidth: BANDWIDTH_LATTICE.len() - 1,
            centrality: PERMILLE_LATTICE.len() - 1,
        }
    }

    fn axis_len(axis: usize) -> usize {
        match axis {
            0 | 1 | 4 => PERMILLE_LATTICE.len(),
            2 => NAT_LATTICE.len(),
            3 => BANDWIDTH_LATTICE.len(),
            _ => unreachable!("axis out of range"),
        }
    }

    fn axis_index(self, axis: usize) -> usize {
        match axis {
            0 => self.uptime,
            1 => self.handshake,
            2 => self.nat,
            3 => self.bandwidth,
            4 => self.centrality,
            _ => unreachable!("axis out of range"),
        }
    }

    fn with_axis_index(mut self, axis: usize, index: usize) -> Self {
        match axis {
            0 => self.uptime = index,
            1 => self.handshake = index,
            2 => self.nat = index,
            3 => self.bandwidth = index,
            4 => self.centrality = index,
            _ => unreachable!("axis out of range"),
        }
        self
    }

    fn observation(self, node_id: &str) -> CandidateObservation {
        CandidateObservation {
            node_id: node_id.to_owned(),
            uptime_ratio_ewma: PERMILLE_LATTICE[self.uptime],
            nat_class: NAT_LATTICE[self.nat],
            handshake_success_ewma: PERMILLE_LATTICE[self.handshake],
            bandwidth_headroom: BANDWIDTH_LATTICE[self.bandwidth],
            centrality: PERMILLE_LATTICE[self.centrality],
            observed_at_unix: 1_000,
        }
    }

    fn is_starved(self) -> bool {
        PERMILLE_LATTICE[self.uptime].is_none()
            || PERMILLE_LATTICE[self.handshake].is_none()
            || NAT_LATTICE[self.nat] == NatClassCode::InsufficientData
            || BANDWIDTH_LATTICE[self.bandwidth] == BandwidthHeadroom::Unknown
            || PERMILLE_LATTICE[self.centrality].is_none()
    }
}

/// Every lattice point: 9 x 9 x 4 x 4 x 9 = 34,992 candidates.
fn all_points() -> Vec<Point> {
    let mut points = Vec::new();
    for uptime in 0..PERMILLE_LATTICE.len() {
        for handshake in 0..PERMILLE_LATTICE.len() {
            for nat in 0..NAT_LATTICE.len() {
                for bandwidth in 0..BANDWIDTH_LATTICE.len() {
                    for centrality in 0..PERMILLE_LATTICE.len() {
                        points.push(Point {
                            uptime,
                            handshake,
                            nat,
                            bandwidth,
                            centrality,
                        });
                    }
                }
            }
        }
    }
    points
}

/// Deterministic SplitMix64: dependency-free randomized-case generator.
/// Seeds are fixed constants so every failure reproduces exactly.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Index in `0..bound` (`bound` > 0; modulo bias is irrelevant for
    /// test-case generation at these bounds).
    fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % (bound as u64)) as usize
    }
}

fn random_point(rng: &mut SplitMix64) -> Point {
    Point {
        uptime: rng.below(PERMILLE_LATTICE.len()),
        handshake: rng.below(PERMILLE_LATTICE.len()),
        nat: rng.below(NAT_LATTICE.len()),
        bandwidth: rng.below(BANDWIDTH_LATTICE.len()),
        centrality: rng.below(PERMILLE_LATTICE.len()),
    }
}

// ── 1. deny-by-empty first, per repo convention ──────────────────────────

#[test]
fn empty_candidate_set_recommends_nobody_and_is_flagged() {
    for role in ROLES {
        let recommendation = recommend_role_placement(role, &[]);
        assert!(recommendation.candidates.is_empty());
        assert!(recommendation.insufficient_data, "deny-by-empty must hold");
    }
}

// ── 2+3+4. exhaustive bounds, breakdown-sum, flag honesty ────────────────

#[test]
fn exhaustive_lattice_scores_are_bounded_finite_and_honest() {
    for role in ROLES {
        let (perfect_score, _, perfect_starved) =
            compute_role_score(&Point::perfect().observation("perfect"), role);
        assert!(!perfect_starved);
        assert_eq!(
            perfect_score, 1.0,
            "weights sum to exactly 1.0 in f64, so a perfect candidate scores exactly 1.0 (role {role:?})"
        );
        for point in all_points() {
            let observation = point.observation("node");
            let (score, breakdown, starved) = compute_role_score(&observation, role);
            assert!(
                score.is_finite(),
                "NaN/inf leaked at {point:?} (role {role:?})"
            );
            assert!(score >= 0.0, "negative score at {point:?} (role {role:?})");
            assert!(
                score <= perfect_score,
                "score {score} exceeds the perfect candidate at {point:?} (role {role:?})"
            );
            let components = [
                breakdown.uptime,
                breakdown.reachability_stability,
                breakdown.nat_class,
                breakdown.bandwidth_headroom,
                breakdown.centrality,
            ];
            for component in components {
                assert!(
                    component.is_finite() && (0.0..=1.0).contains(&component),
                    "breakdown component {component} out of range at {point:?} (role {role:?})"
                );
            }
            let recomputed: f64 = components.iter().sum();
            assert!(
                (score - recomputed).abs() <= 1e-12,
                "score must equal the sum of its breakdown: {score} vs {recomputed} at {point:?}"
            );
            assert_eq!(
                starved,
                point.is_starved(),
                "data_starved must be set iff any criterion lacked evidence at {point:?}"
            );
            // Determinism: recomputation is bitwise-identical.
            let (score_again, breakdown_again, starved_again) =
                compute_role_score(&observation, role);
            assert_eq!(score.to_bits(), score_again.to_bits());
            assert_eq!(breakdown, breakdown_again);
            assert_eq!(starved, starved_again);
        }
    }
}

/// A perfect candidate's breakdown components ARE the weights (each
/// criterion normalizes to exactly 1.0), so the documented weight vector
/// is recoverable — and pinned — through the public API alone.
#[test]
fn documented_weights_are_recoverable_and_sum_to_exactly_one() {
    let perfect = Point::perfect().observation("perfect");
    for role in ROLES {
        let (score, breakdown, starved) = compute_role_score(&perfect, role);
        assert!(!starved);
        assert_eq!(breakdown.uptime, 0.30);
        assert_eq!(breakdown.reachability_stability, 0.25);
        assert_eq!(breakdown.nat_class, 0.20);
        assert_eq!(breakdown.bandwidth_headroom, 0.15);
        assert_eq!(breakdown.centrality, 0.10);
        assert_eq!(
            score, 1.0,
            "weight vector must sum to exactly 1.0 — no silent renormalization (role {role:?})"
        );
    }
}

// ── 5. per-criterion monotonicity + clamp + strict enum orderings ────────

#[test]
fn improving_any_single_criterion_never_lowers_the_score() {
    for role in ROLES {
        for point in all_points() {
            let (base_score, _, _) = compute_role_score(&point.observation("node"), role);
            for axis in 0..AXIS_COUNT {
                let index = point.axis_index(axis);
                if index + 1 >= Point::axis_len(axis) {
                    continue;
                }
                let stepped = point.with_axis_index(axis, index + 1);
                let (stepped_score, _, _) = compute_role_score(&stepped.observation("node"), role);
                assert!(
                    stepped_score >= base_score,
                    "improving axis {axis} lowered the score: {base_score} -> {stepped_score} at {point:?} (role {role:?})"
                );
            }
        }
    }
}

#[test]
fn permille_criterion_is_monotone_and_clamps_above_1000_for_every_u16() {
    let base = |value: Option<u16>| CandidateObservation {
        node_id: "node".to_owned(),
        uptime_ratio_ewma: value,
        nat_class: NatClassCode::PortRestrictedLikely,
        handshake_success_ewma: Some(500),
        bandwidth_headroom: BandwidthHeadroom::Medium,
        centrality: Some(500),
        observed_at_unix: 1_000,
    };
    let (score_at_1000, _, _) = compute_role_score(&base(Some(1000)), RoleType::Anchor);
    let mut previous = compute_role_score(&base(None), RoleType::Anchor).0;
    for raw in 0..=u16::MAX {
        let (score, _, starved) = compute_role_score(&base(Some(raw)), RoleType::Anchor);
        assert!(score.is_finite());
        assert!(!starved, "a present observation is never starved ({raw})");
        assert!(
            score >= previous,
            "score must be nondecreasing in permille input at {raw}"
        );
        if raw >= 1000 {
            assert_eq!(
                score.to_bits(),
                score_at_1000.to_bits(),
                "out-of-range permille {raw} must clamp to exactly the 1000 score"
            );
        }
        previous = score;
    }
    // `None` and `Some(0)` score identically; only the honesty flag differs.
    let (none_score, _, none_starved) = compute_role_score(&base(None), RoleType::Anchor);
    let (zero_score, _, zero_starved) = compute_role_score(&base(Some(0)), RoleType::Anchor);
    assert_eq!(none_score.to_bits(), zero_score.to_bits());
    assert!(none_starved);
    assert!(!zero_starved);
}

#[test]
fn enum_criteria_are_strictly_ordered_within_every_role() {
    for role in ROLES {
        let with_nat = |nat: NatClassCode| CandidateObservation {
            node_id: "node".to_owned(),
            uptime_ratio_ewma: Some(700),
            nat_class: nat,
            handshake_success_ewma: Some(700),
            bandwidth_headroom: BandwidthHeadroom::Medium,
            centrality: Some(700),
            observed_at_unix: 1_000,
        };
        let nat_scores: Vec<f64> = NAT_LATTICE
            .iter()
            .map(|nat| compute_role_score(&with_nat(*nat), role).0)
            .collect();
        for pair in nat_scores.windows(2) {
            assert!(
                pair[0] < pair[1],
                "NAT classes must be strictly ordered worst-to-best for role {role:?}: {nat_scores:?}"
            );
        }

        let with_bandwidth = |headroom: BandwidthHeadroom| CandidateObservation {
            node_id: "node".to_owned(),
            uptime_ratio_ewma: Some(700),
            nat_class: NatClassCode::PortRestrictedLikely,
            handshake_success_ewma: Some(700),
            bandwidth_headroom: headroom,
            centrality: Some(700),
            observed_at_unix: 1_000,
        };
        let bandwidth_scores: Vec<f64> = BANDWIDTH_LATTICE
            .iter()
            .map(|headroom| compute_role_score(&with_bandwidth(*headroom), role).0)
            .collect();
        for pair in bandwidth_scores.windows(2) {
            assert!(
                pair[0] < pair[1],
                "bandwidth headroom must be strictly ordered worst-to-best for role {role:?}: {bandwidth_scores:?}"
            );
        }
    }
}

// ── 6. rank monotonicity under a single-candidate improvement ────────────

#[test]
fn improving_one_candidate_never_worsens_its_rank_nor_reorders_the_rest() {
    let mut rng = SplitMix64(0x5EED_0003);
    let mut improvements_exercised = 0_u32;
    for _ in 0..2_000 {
        let role = ROLES[rng.below(ROLES.len())];
        let count = 1 + rng.below(8);
        let points: Vec<Point> = (0..count).map(|_| random_point(&mut rng)).collect();
        let observations: Vec<CandidateObservation> = points
            .iter()
            .enumerate()
            .map(|(index, point)| point.observation(&format!("node-{index:02}")))
            .collect();
        let before = recommend_role_placement(role, &observations);

        let target = rng.below(count);
        let axis = rng.below(AXIS_COUNT);
        let index = points[target].axis_index(axis);
        if index + 1 >= Point::axis_len(axis) {
            continue;
        }
        improvements_exercised += 1;
        let improved_point = points[target].with_axis_index(axis, index + 1);
        let mut improved = observations.clone();
        improved[target] = improved_point.observation(&format!("node-{target:02}"));
        let after = recommend_role_placement(role, &improved);

        let id = format!("node-{target:02}");
        let position = |recommendation: &RoleRecommendation| {
            recommendation
                .candidates
                .iter()
                .position(|candidate| candidate.node_id == id)
                .expect("the improved candidate must stay in the ranking")
        };
        let (before_position, after_position) = (position(&before), position(&after));
        assert!(
            after_position <= before_position,
            "improving a candidate worsened its rank: {before_position} -> {after_position} (axis {axis}, role {role:?})"
        );
        assert!(
            after.candidates[after_position].score >= before.candidates[before_position].score,
            "improving a candidate lowered its score (axis {axis}, role {role:?})"
        );
        let others = |recommendation: &RoleRecommendation| {
            recommendation
                .candidates
                .iter()
                .filter(|candidate| candidate.node_id != id)
                .map(|candidate| candidate.node_id.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            others(&before),
            others(&after),
            "an improvement to one candidate must never reorder the others"
        );
    }
    assert!(
        improvements_exercised > 1_000,
        "generator must actually exercise improvements: {improvements_exercised}"
    );
}

// ── 7+8. ranking is a sorted relabeling; tie-breaks; permutation-invariance ──

#[test]
fn recommendation_is_exactly_a_sorted_relabeling_of_the_scored_input() {
    let mut rng = SplitMix64(0x5EED_0001);
    for _ in 0..500 {
        let role = ROLES[rng.below(ROLES.len())];
        let count = rng.below(9); // 0..=8 — exercises the empty set too
        let observations: Vec<CandidateObservation> = (0..count)
            .map(|index| random_point(&mut rng).observation(&format!("node-{index:02}")))
            .collect();
        let recommendation = recommend_role_placement(role, &observations);
        assert_eq!(recommendation.role, role);
        assert_eq!(
            recommendation.candidates.len(),
            observations.len(),
            "no candidate may be dropped or invented"
        );
        for candidate in &recommendation.candidates {
            let source = observations
                .iter()
                .find(|observation| observation.node_id == candidate.node_id)
                .expect("every ranked candidate must come from the input set");
            let (score, breakdown, starved) = compute_role_score(source, role);
            assert_eq!(candidate.score.to_bits(), score.to_bits());
            assert_eq!(candidate.breakdown, breakdown);
            assert_eq!(candidate.data_starved, starved);
        }
        for pair in recommendation.candidates.windows(2) {
            let ordered = pair[0].score > pair[1].score
                || (pair[0].score == pair[1].score && pair[0].node_id < pair[1].node_id);
            assert!(
                ordered,
                "ranking must follow (score desc, node_id asc): {:?} then {:?}",
                pair[0], pair[1]
            );
        }
        let expected_flag = recommendation.candidates.is_empty()
            || recommendation
                .candidates
                .iter()
                .any(|candidate| candidate.data_starved);
        assert_eq!(recommendation.insufficient_data, expected_flag);
        // Determinism on identical input.
        assert_eq!(
            recommendation,
            recommend_role_placement(role, &observations)
        );
    }
}

#[test]
fn ranking_is_permutation_invariant_for_unique_node_ids() {
    let mut rng = SplitMix64(0x5EED_0002);
    for _ in 0..300 {
        let role = ROLES[rng.below(ROLES.len())];
        let count = 1 + rng.below(8);
        let observations: Vec<CandidateObservation> = (0..count)
            .map(|index| random_point(&mut rng).observation(&format!("node-{index:02}")))
            .collect();
        let baseline = recommend_role_placement(role, &observations);
        let mut shuffled = observations.clone();
        for i in (1..shuffled.len()).rev() {
            let j = rng.below(i + 1);
            shuffled.swap(i, j);
        }
        assert_eq!(
            baseline,
            recommend_role_placement(role, &shuffled),
            "input order must never influence the ranking of unique node ids"
        );
    }
}

#[test]
fn all_equal_candidates_rank_purely_by_node_id() {
    let point = Point {
        uptime: 6,
        handshake: 6,
        nat: 3,
        bandwidth: 2,
        centrality: 4,
    };
    let ids = ["node-e", "node-a", "node-d", "node-b", "node-c", "node-f"];
    let observations: Vec<CandidateObservation> =
        ids.iter().map(|id| point.observation(id)).collect();
    let recommendation = recommend_role_placement(RoleType::Relay, &observations);
    let ranked: Vec<&str> = recommendation
        .candidates
        .iter()
        .map(|candidate| candidate.node_id.as_str())
        .collect();
    assert_eq!(
        ranked,
        ["node-a", "node-b", "node-c", "node-d", "node-e", "node-f"]
    );
    assert!(!recommendation.insufficient_data);
}

#[test]
fn single_candidate_is_ranked_and_flagged_only_by_its_own_evidence() {
    let full = Point::perfect();
    let alone = recommend_role_placement(RoleType::Anchor, &[full.observation("only")]);
    assert_eq!(alone.candidates.len(), 1);
    assert_eq!(alone.candidates[0].node_id, "only");
    assert!(
        !alone.insufficient_data,
        "a lone fully-observed candidate is a defined, evidence-backed ranking of one"
    );

    let starved_point = full.with_axis_index(4, 0); // centrality -> None
    let starved = recommend_role_placement(RoleType::Anchor, &[starved_point.observation("only")]);
    assert!(starved.insufficient_data);
}

// ── 9. rendering ─────────────────────────────────────────────────────────

#[test]
fn rendering_marks_advisory_exactly_when_insufficient_and_never_panics() {
    let empty = recommend_role_placement(RoleType::Exit, &[]);
    let empty_text = render_recommendation(&empty);
    assert!(empty_text.contains("ADVISORY"));
    assert!(empty_text.contains("no eligible candidates"));

    let mut rng = SplitMix64(0x5EED_0004);
    for _ in 0..200 {
        let role = ROLES[rng.below(ROLES.len())];
        let count = rng.below(6);
        let observations: Vec<CandidateObservation> = (0..count)
            .map(|index| random_point(&mut rng).observation(&format!("node-{index:02}")))
            .collect();
        let recommendation = recommend_role_placement(role, &observations);
        let text = render_recommendation(&recommendation);
        assert_eq!(
            text.contains("ADVISORY"),
            recommendation.insufficient_data,
            "ADVISORY marker must appear exactly when the recommendation is insufficient-data"
        );
        assert_eq!(
            text.lines().count(),
            1 + recommendation.candidates.len().max(1),
            "one header line plus one line per candidate (or the explicit nobody line)"
        );
        for candidate in &recommendation.candidates {
            assert!(text.contains(candidate.node_id.as_str()));
        }
        assert_eq!(
            text.matches("[data-starved]").count(),
            recommendation
                .candidates
                .iter()
                .filter(|candidate| candidate.data_starved)
                .count(),
            "exactly the data-starved candidates must be tagged"
        );
    }
}
