#![forbid(unsafe_code)]

//! D5.5 — ICE-style candidate prioritisation (RFC 8445).
//!
//! Given a local [`CandidateSet`] (from [`crate::dataplane_candidates`])
//! and a remote peer's gossiped [`CandidateSet`] (from
//! [`crate::peer_gossip`]), produce an ordered list of candidate
//! pairs that the connect path will try in priority order. The
//! ordering mirrors RFC 8445 §5.1.2.1 and §6.1.2.3:
//!
//! * Per-candidate priority:
//!   `priority = 2^24 * type_pref + 2^8 * local_pref + (256 - component_id)`
//! * Type preferences (RFC 8445 §5.1.2.2):
//!   * Host candidates: 126
//!   * Server-reflexive (srflx) candidates: 100
//!   * Relay candidates: 0
//! * Local preferences are used to break ties between same-type
//!   candidates of different address families. Per the v6-preferred
//!   guidance (RFC 8445 §5.1.2.2 + RFC 8421), IPv6 candidates get
//!   a higher local preference than IPv4.
//! * Pair priority (RFC 8445 §6.1.2.3):
//!   `pair = MIN(G, D)<<32 | MAX(G, D)<<1 | (G > D ? 1 : 0)`
//!   where G = controlling-agent priority, D = controlled-agent
//!   priority. The controlling-agent role is decided
//!   deterministically by lex-ordering the two peers' node IDs (the
//!   smaller ID is the controlling agent). This matches RFC 8445
//!   §6.1.1 in spirit while removing the need for an
//!   ICE-CONTROLLING/ICE-CONTROLLED negotiation handshake.
//!
//! We use only the UDP component (component-id = 1) since WireGuard
//! is a single-UDP-flow protocol.
//!
//! Security framing:
//!
//! * Priority is informational. A peer can claim any priority for its
//!   own candidates, but the actual reachability check (the
//!   subsequent WireGuard handshake) is authenticated, so a malicious
//!   peer that lies about priority only succeeds in changing the
//!   order in which OUR connect path tries pairs — it cannot
//!   intercept traffic.
//! * Foundation strings carry no secret data; they're used to dedupe
//!   pairs that share the same NAT mapping behaviour and would
//!   produce identical observable wire traffic.

use std::cmp::Ordering;
use std::net::{IpAddr, SocketAddr};

use rustynet_backend_api::SocketEndpoint;

use crate::dataplane_candidates::{AddressScope, CandidateSet, classify_ip};
use crate::traversal::{CandidateSource, TraversalCandidate};

/// Single-component-id assumption: WireGuard is one UDP flow.
const COMPONENT_ID: u32 = 1;

/// Type preference for host candidates (RFC 8445 §5.1.2.2).
const TYPE_PREF_HOST: u32 = 126;
/// Type preference for server-reflexive candidates.
const TYPE_PREF_SRFLX: u32 = 100;
/// Type preference for relay candidates.
const TYPE_PREF_RELAY: u32 = 0;

/// Local preference for IPv6 candidates. RFC 8421 / RFC 8445 §5.1.2.2
/// recommend giving IPv6 a higher local preference than IPv4. We use
/// the maximum 16-bit value for IPv6 and a lower value for IPv4.
const LOCAL_PREF_V6: u32 = 65_535;
const LOCAL_PREF_V4: u32 = 32_767;

/// Family-and-scope-aware local preference modifier. Globally-routable
/// candidates rank slightly higher than private ones within the same
/// family; this keeps the ICE priority stable but lets the connect
/// path try the more-likely-to-succeed candidate first.
fn local_preference(addr: IpAddr) -> u32 {
    let scope = classify_ip(addr);
    let base = match addr {
        IpAddr::V4(_) => LOCAL_PREF_V4,
        IpAddr::V6(_) => LOCAL_PREF_V6,
    };
    match scope {
        AddressScope::Global => base,
        AddressScope::Private => base / 2,
        // Loopback / link-local / multicast / broadcast / unspecified
        // shouldn't ever reach the prioritiser; this branch is
        // defensive. Use a very low value so they sort to the end
        // even if some upstream code lets them through.
        _ => 1,
    }
}

/// ICE candidate kind. We do not have peer-reflexive (prflx) yet
/// because that arises only after a STUN binding-request via the
/// connect path; the bootstrap candidate set is host + srflx + relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    Relay,
}

impl CandidateKind {
    pub const fn label(self) -> &'static str {
        match self {
            CandidateKind::Host => "host",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::Relay => "relay",
        }
    }

    fn type_preference(self) -> u32 {
        match self {
            CandidateKind::Host => TYPE_PREF_HOST,
            CandidateKind::ServerReflexive => TYPE_PREF_SRFLX,
            CandidateKind::Relay => TYPE_PREF_RELAY,
        }
    }
}

/// One prioritised candidate. `priority` is the RFC 8445 §5.1.2.1
/// value; higher is preferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrioritizedCandidate {
    pub addr: SocketAddr,
    pub kind: CandidateKind,
    pub priority: u32,
    /// ICE foundation string. Per RFC 8445 §5.1.1.3, two candidates
    /// share a foundation when they have the same type, the same base
    /// IP (the local interface IP that generated them), and the same
    /// STUN/TURN server. We use a simpler discriminator: type ||
    /// family || (host: interface-tag, srflx: server-fingerprint).
    /// The exact form is opaque to the connect path; equality is
    /// what matters.
    pub foundation: String,
}

/// Compute the RFC 8445 §5.1.2.1 priority for a candidate.
pub fn ice_priority(kind: CandidateKind, addr: IpAddr) -> u32 {
    let type_pref = kind.type_preference();
    let local_pref = local_preference(addr);
    // priority = 2^24 * type_pref + 2^8 * local_pref + (256 - component_id)
    type_pref
        .saturating_mul(1 << 24)
        .saturating_add(local_pref.saturating_mul(1 << 8))
        .saturating_add(256u32.saturating_sub(COMPONENT_ID))
}

/// Compute the RFC 8445 §6.1.2.3 pair priority. `controlling` is the
/// priority of the controlling-agent's candidate; `controlled` is the
/// other side's. The pair-priority is a u64.
pub fn pair_priority(controlling: u32, controlled: u32) -> u64 {
    let (g, d) = (u64::from(controlling), u64::from(controlled));
    let min = g.min(d);
    let max = g.max(d);
    let breaker = if g > d { 1u64 } else { 0 };
    (min << 32) | (max << 1) | breaker
}

/// Determines which peer holds the ICE controlling role for a given
/// (local_node_id, remote_node_id) pair. Deterministic: the
/// lexicographically smaller ID is controlling. Both peers agree
/// without any handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

/// Decide our role given our and the peer's 32-byte node IDs.
pub fn decide_role(local_node_id: &[u8; 32], remote_node_id: &[u8; 32]) -> IceRole {
    match local_node_id.cmp(remote_node_id) {
        Ordering::Less => IceRole::Controlling,
        Ordering::Equal => IceRole::Controlling, // shouldn't happen; tie-break to controlling
        Ordering::Greater => IceRole::Controlled,
    }
}

/// Build the prioritised candidate list from a [`CandidateSet`].
///
/// `wg_listen_port` is paired with host candidates because the
/// gossip bundle doesn't carry per-host ports (host candidates are
/// the host's interface addresses, paired with the WG listen port
/// at connect time).
pub fn prioritize_candidate_set(
    set: &CandidateSet,
    wg_listen_port: u16,
) -> Vec<PrioritizedCandidate> {
    let mut out = Vec::new();
    for ip in &set.v4_host {
        out.push(make_candidate(
            SocketAddr::new(*ip, wg_listen_port),
            CandidateKind::Host,
            "host-v4",
        ));
    }
    for ip in &set.v6_host {
        out.push(make_candidate(
            SocketAddr::new(*ip, wg_listen_port),
            CandidateKind::Host,
            "host-v6",
        ));
    }
    for sa in &set.v4_srflx {
        out.push(make_candidate(
            *sa,
            CandidateKind::ServerReflexive,
            "srflx-v4",
        ));
    }
    for sa in &set.v6_srflx {
        out.push(make_candidate(
            *sa,
            CandidateKind::ServerReflexive,
            "srflx-v6",
        ));
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    out
}

fn make_candidate(addr: SocketAddr, kind: CandidateKind, foundation: &str) -> PrioritizedCandidate {
    PrioritizedCandidate {
        addr,
        kind,
        priority: ice_priority(kind, addr.ip()),
        foundation: foundation.to_owned(),
    }
}

/// Map a `traversal::CandidateSource` to the corresponding ICE
/// candidate kind. The two enums carry the same set of values
/// (Host / ServerReflexive / Relay) but live in different crates
/// for historical reasons; this conversion is the single place
/// where the mapping is asserted so a future addition can't drift.
pub fn candidate_kind_from_traversal_source(source: CandidateSource) -> CandidateKind {
    match source {
        CandidateSource::Host => CandidateKind::Host,
        CandidateSource::ServerReflexive => CandidateKind::ServerReflexive,
        CandidateSource::Relay => CandidateKind::Relay,
    }
}

/// Convert a `SocketEndpoint` (from `rustynet-backend-api`) into a
/// `std::net::SocketAddr`. Both representations share the same
/// (ip, port) shape; the conversion is mechanical and is reused
/// by `prioritize_traversal_candidates` below.
fn socket_endpoint_to_socket_addr(endpoint: SocketEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr, endpoint.port)
}

/// Convert `SocketAddr` back into `SocketEndpoint`. Used by the
/// ICE-pair runner so the surviving pair can be reported in the
/// existing `TraversalDecision::Direct` shape without changing
/// downstream consumers.
pub fn socket_addr_to_socket_endpoint(addr: SocketAddr) -> SocketEndpoint {
    SocketEndpoint {
        addr: addr.ip(),
        port: addr.port(),
    }
}

/// Build a prioritised candidate list from a slice of
/// `TraversalCandidate` (the on-the-wire shape carried by the
/// signed traversal-bundle and the gossip bundle). The
/// `default_foundation_prefix` is mixed into each candidate's
/// foundation so a local-vs-remote pair can be deduplicated by
/// foundation correctly: two candidates from the same side that
/// share a (kind, family) lane collapse to one foundation entry,
/// per RFC 8445 §5.1.1.3 / §6.1.2.4.
pub fn prioritize_traversal_candidates(
    candidates: &[TraversalCandidate],
    default_foundation_prefix: &str,
) -> Vec<PrioritizedCandidate> {
    let mut out = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let kind = candidate_kind_from_traversal_source(candidate.source);
        let addr = socket_endpoint_to_socket_addr(candidate.endpoint);
        let family = match addr.ip() {
            IpAddr::V4(_) => "v4",
            IpAddr::V6(_) => "v6",
        };
        let foundation = format!("{default_foundation_prefix}-{}-{family}", kind.label());
        out.push(PrioritizedCandidate {
            addr,
            kind,
            priority: ice_priority(kind, addr.ip()),
            foundation,
        });
    }
    out.sort_by(|a, b| b.priority.cmp(&a.priority));
    out
}

/// One candidate pair with its computed pair-priority. Used by the
/// connect path to choose which (local-addr, remote-addr) to try
/// next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: PrioritizedCandidate,
    pub remote: PrioritizedCandidate,
    pub pair_priority: u64,
}

/// Cap on the number of pairs we'll generate. RFC 8445 recommends
/// pruning the candidate-pair list aggressively; we hard-cap at 32
/// to bound work in pathological multi-homed dual-stack scenarios.
pub const MAX_CANDIDATE_PAIRS: usize = 32;

/// Generate the ordered candidate-pair list. Pairs are formed by
/// taking the cartesian product of `local` and `remote`, filtered to
/// same-family pairs (we don't try v4↔v6 — different IP versions
/// can't connect directly), then deduplicated by foundation, sorted
/// by descending pair-priority, and capped at
/// [`MAX_CANDIDATE_PAIRS`].
pub fn generate_candidate_pairs(
    local: &[PrioritizedCandidate],
    remote: &[PrioritizedCandidate],
    role: IceRole,
) -> Vec<CandidatePair> {
    let mut out = Vec::new();
    let mut seen_foundations: Vec<(String, String)> = Vec::new();
    for l in local {
        for r in remote {
            // Family must match — v4 cannot reach v6 and vice versa.
            let same_family = matches!(
                (l.addr.ip(), r.addr.ip()),
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_))
            );
            if !same_family {
                continue;
            }
            // Per RFC 8445 §6.1.2.4, dedupe pairs that share the same
            // (local_foundation, remote_foundation). The first one
            // we see for a foundation pair wins because we'll have
            // already sorted local + remote by priority.
            let key = (l.foundation.clone(), r.foundation.clone());
            if seen_foundations.contains(&key) {
                continue;
            }
            seen_foundations.push(key);
            let (controlling, controlled) = match role {
                IceRole::Controlling => (l.priority, r.priority),
                IceRole::Controlled => (r.priority, l.priority),
            };
            let pair_priority = pair_priority(controlling, controlled);
            out.push(CandidatePair {
                local: l.clone(),
                remote: r.clone(),
                pair_priority,
            });
        }
    }
    out.sort_by(|a, b| b.pair_priority.cmp(&a.pair_priority));
    out.truncate(MAX_CANDIDATE_PAIRS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ice_priority_for_host_v6_global_exceeds_host_v4_global() {
        let v6_global = IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1));
        let v4_global = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let p6 = ice_priority(CandidateKind::Host, v6_global);
        let p4 = ice_priority(CandidateKind::Host, v4_global);
        assert!(
            p6 > p4,
            "IPv6-global host must outrank IPv4-global host (got {p6} vs {p4})"
        );
    }

    #[test]
    fn ice_priority_for_host_exceeds_srflx_and_srflx_exceeds_relay() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let host = ice_priority(CandidateKind::Host, v4);
        let srflx = ice_priority(CandidateKind::ServerReflexive, v4);
        let relay = ice_priority(CandidateKind::Relay, v4);
        assert!(host > srflx, "host > srflx (got {host} vs {srflx})");
        assert!(srflx > relay, "srflx > relay (got {srflx} vs {relay})");
    }

    #[test]
    fn ice_priority_global_outranks_private_within_same_family_and_type() {
        let global = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let private = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let p_global = ice_priority(CandidateKind::Host, global);
        let p_private = ice_priority(CandidateKind::Host, private);
        assert!(p_global > p_private);
    }

    #[test]
    fn pair_priority_matches_rfc_8445_formula() {
        // From RFC 8445 §6.1.2.3 worked example:
        // G = 100, D = 50 → MIN<<32 | MAX<<1 | (G>D)
        // MIN=50, MAX=100, breaker=1.
        let p = pair_priority(100, 50);
        let expected: u64 = (50u64 << 32) | (100u64 << 1) | 1u64;
        assert_eq!(p, expected);

        let p_reverse = pair_priority(50, 100);
        let expected_reverse: u64 = (50u64 << 32) | (100u64 << 1);
        assert_eq!(p_reverse, expected_reverse);
        // The G<D case yields a 1-less priority than G>D for the same
        // pair of values; the controlling agent therefore gets the
        // tie-breaker advantage.
        assert!(p > p_reverse);
    }

    #[test]
    fn decide_role_uses_lex_min_as_controlling() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(decide_role(&a, &b), IceRole::Controlling);
        assert_eq!(decide_role(&b, &a), IceRole::Controlled);
    }

    fn sample_candidate_set() -> CandidateSet {
        CandidateSet {
            v4_host: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            v6_host: vec![IpAddr::V6(Ipv6Addr::new(0x2606, 0, 0, 0, 0, 0, 0, 1))],
            v4_srflx: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                51820,
            )],
            v6_srflx: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                51820,
            )],
        }
    }

    #[test]
    fn prioritize_candidate_set_orders_v6_host_first() {
        let prioritised = prioritize_candidate_set(&sample_candidate_set(), 51820);
        assert_eq!(prioritised.len(), 4);
        assert_eq!(prioritised[0].kind, CandidateKind::Host);
        assert!(matches!(prioritised[0].addr.ip(), IpAddr::V6(_)));
    }

    #[test]
    fn prioritize_candidate_set_paths_for_host_use_wg_listen_port() {
        let prioritised = prioritize_candidate_set(&sample_candidate_set(), 51820);
        for c in &prioritised {
            if c.kind == CandidateKind::Host {
                assert_eq!(
                    c.port_or_panic(),
                    51820,
                    "host candidate must carry WG port"
                );
            }
        }
    }

    // helper for the test above
    impl PrioritizedCandidate {
        fn port_or_panic(&self) -> u16 {
            self.addr.port()
        }
    }

    #[test]
    fn generate_candidate_pairs_filters_cross_family_pairs() {
        let local = prioritize_candidate_set(&sample_candidate_set(), 51820);
        let remote = prioritize_candidate_set(&sample_candidate_set(), 51820);
        let pairs = generate_candidate_pairs(&local, &remote, IceRole::Controlling);
        // 4 local x 4 remote = 16, but cross-family filtered out.
        // Same family pairs: (v4_host, v4_host), (v4_host, v4_srflx),
        // (v4_srflx, v4_host), (v4_srflx, v4_srflx) for v4 and same
        // for v6 — 8 pairs total. But dedupe-by-foundation reduces
        // each combo to one entry. Since we used 4 distinct
        // foundations on each side, dedupe doesn't actually fire
        // here — we should have 8 pairs.
        assert_eq!(
            pairs.len(),
            8,
            "expected 8 same-family pairs from 4x4 with no foundation collisions"
        );
        // No cross-family pairs.
        for p in &pairs {
            let lf = matches!(p.local.addr.ip(), IpAddr::V4(_));
            let rf = matches!(p.remote.addr.ip(), IpAddr::V4(_));
            assert_eq!(lf, rf, "pair must be same-family");
        }
    }

    #[test]
    fn generate_candidate_pairs_orders_v6_host_pair_first() {
        let local = prioritize_candidate_set(&sample_candidate_set(), 51820);
        let remote = prioritize_candidate_set(&sample_candidate_set(), 51820);
        let pairs = generate_candidate_pairs(&local, &remote, IceRole::Controlling);
        let first = &pairs[0];
        assert_eq!(first.local.kind, CandidateKind::Host);
        assert_eq!(first.remote.kind, CandidateKind::Host);
        assert!(matches!(first.local.addr.ip(), IpAddr::V6(_)));
        assert!(matches!(first.remote.addr.ip(), IpAddr::V6(_)));
    }

    #[test]
    fn generate_candidate_pairs_dedupes_same_foundation_pair() {
        // If two locals share a foundation string and two remotes
        // share a foundation, only one pair per (lf, rf) pair
        // survives — RFC 8445 §6.1.2.4 redundancy elimination.
        let local = vec![
            PrioritizedCandidate {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820),
                kind: CandidateKind::Host,
                priority: 1000,
                foundation: "host-v4".to_owned(),
            },
            PrioritizedCandidate {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 51820),
                kind: CandidateKind::Host,
                priority: 999,
                foundation: "host-v4".to_owned(), // intentional dupe
            },
        ];
        let remote = vec![PrioritizedCandidate {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1)), 51820),
            kind: CandidateKind::Host,
            priority: 500,
            foundation: "host-v4".to_owned(),
        }];
        let pairs = generate_candidate_pairs(&local, &remote, IceRole::Controlling);
        assert_eq!(
            pairs.len(),
            1,
            "duplicate foundations must collapse to one pair"
        );
    }

    #[test]
    fn generate_candidate_pairs_caps_at_max_candidate_pairs() {
        // Stuff a synthetic candidate set with many distinct
        // foundations to defeat dedupe, then assert the cap holds.
        let mut local = Vec::new();
        let mut remote = Vec::new();
        for i in 0..40u32 {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(i + 1)), 51820);
            local.push(PrioritizedCandidate {
                addr,
                kind: CandidateKind::Host,
                priority: 1000 - i,
                foundation: format!("l-{i}"),
            });
            remote.push(PrioritizedCandidate {
                addr,
                kind: CandidateKind::Host,
                priority: 500 - i,
                foundation: format!("r-{i}"),
            });
        }
        let pairs = generate_candidate_pairs(&local, &remote, IceRole::Controlling);
        assert!(
            pairs.len() <= MAX_CANDIDATE_PAIRS,
            "pair list must respect MAX_CANDIDATE_PAIRS cap; got {}",
            pairs.len()
        );
    }

    #[test]
    fn generate_candidate_pairs_role_changes_tie_breaker_only() {
        let local = vec![PrioritizedCandidate {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 51820),
            kind: CandidateKind::Host,
            priority: 100,
            foundation: "l".to_owned(),
        }];
        let remote = vec![PrioritizedCandidate {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(20, 0, 0, 1)), 51820),
            kind: CandidateKind::Host,
            priority: 50,
            foundation: "r".to_owned(),
        }];
        let controlling = generate_candidate_pairs(&local, &remote, IceRole::Controlling);
        let controlled = generate_candidate_pairs(&local, &remote, IceRole::Controlled);
        // Same MIN<<32 + MAX<<1 component; differ in the breaker LSB.
        assert_eq!(
            controlling[0].pair_priority & !1u64,
            controlled[0].pair_priority & !1u64
        );
        assert_eq!(
            controlling[0].pair_priority - controlled[0].pair_priority,
            1
        );
    }

    #[test]
    fn candidate_kind_labels_are_stable_snake_case() {
        // Pinned so downstream log-grep doesn't silently drift.
        assert_eq!(CandidateKind::Host.label(), "host");
        assert_eq!(CandidateKind::ServerReflexive.label(), "srflx");
        assert_eq!(CandidateKind::Relay.label(), "relay");
    }
}
