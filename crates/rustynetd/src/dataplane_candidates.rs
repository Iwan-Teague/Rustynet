#![forbid(unsafe_code)]

//! D2.4 — IPv6 candidate gathering and ICE-style candidate enumeration.
//!
//! Per the dataplane execution plan §D2.4 (and §D5.5 ICE), each peer's
//! gossiped endpoint list should carry both IPv4 and IPv6 candidates so
//! the connect path can prefer IPv6 when both ends are dual-stack.
//!
//! This module is the producer side of that endpoint list. It surfaces:
//!
//! * [`enumerate_local_host_candidates`] — walks `getifaddrs(2)` on
//!   Linux/macOS and returns EVERY interface address with its
//!   classified scope. This includes loopback, link-local, multicast
//!   etc.  Callers that want only the routable subset must filter
//!   via `LocalHostCandidate::is_gossip_worthy()` or use
//!   [`gather_gossip_worthy_host_candidates`] which does the filter
//!   and ICE-priority sort in one call. Windows is stubbed (empty
//!   list); a follow-up slice can wire `GetAdaptersAddresses` via a
//!   dedicated crate.
//!
//! * [`gather_srflx_candidates`] — given a [`StunClient`], a list of
//!   IPv4 STUN server URLs, and a list of IPv6 STUN server URLs,
//!   binds a UDP socket per family, queries each STUN server, and
//!   returns the observed mapped endpoints (v4 srflx + v6 srflx).
//!
//! * [`CandidateSet`] — typed grouping of all candidate kinds:
//!   `v4_host`, `v6_host`, `v4_srflx`, `v6_srflx`. The ICE
//!   prioritisation slice (D5.5) consumes this to assign foundation
//!   priorities and ICE candidate types.
//!
//! Security framing:
//!
//! * Host candidates include the host's *local* addresses; gossiping
//!   them is fine because they're already visible to the LAN, and a
//!   peer on a different LAN can ignore them. We do NOT include
//!   loopback or link-local because those are useless to a remote
//!   peer and could leak interface naming.
//! * Srflx candidates come from STUN responses. The STUN servers are
//!   not trusted — they cannot inject our private address into the
//!   reply (the XOR-MAPPED-ADDRESS attribute is computed by the
//!   gateway, not the STUN server). We do trust them to report our
//!   public-facing endpoint accurately; if a malicious STUN server
//!   reports a wrong endpoint, the peer would attempt a handshake
//!   that fails. The WG-handshake authenticity check catches any
//!   downstream consequence.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use crate::stun_client::{StunClient, StunResult};

/// Family + scope classification of a local interface address. Used by
/// `enumerate_local_host_candidates` to filter the list down to what
/// is useful to gossip as a peer candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressScope {
    /// `0.0.0.0` / `::` — never useful as a peer candidate.
    Unspecified,
    /// `127.0.0.0/8` / `::1` — never useful as a peer candidate.
    Loopback,
    /// IPv4 `169.254.0.0/16` or IPv6 `fe80::/10` — useful only on a
    /// shared link, not from a remote peer.
    LinkLocal,
    /// IPv4 multicast / IPv6 multicast — not a peer endpoint.
    Multicast,
    /// IPv4 `255.255.255.255` — never useful as a peer candidate.
    Broadcast,
    /// IPv4 `10/8`, `172.16/12`, `192.168/16`, `100.64/10` (CGNAT),
    /// or IPv6 ULA `fc00::/7`. Useful only on the same admin domain.
    /// We surface these as "host candidates" because they ARE useful
    /// for same-LAN peer reachability; a peer on a different LAN can
    /// ignore them.
    Private,
    /// Globally routable IPv4 (anything not in the above) or IPv6
    /// (`2000::/3` global unicast). The highest-value host candidate
    /// — these reach remote peers directly without NAT traversal when
    /// both ends have one.
    Global,
}

/// One enumerated local interface address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHostCandidate {
    pub interface: String,
    pub addr: IpAddr,
    pub scope: AddressScope,
}

impl LocalHostCandidate {
    /// True for candidates we would surface to a peer over the gossip
    /// channel — globally-routable v4/v6 plus private ranges.
    /// Loopback, link-local, multicast, broadcast, and unspecified
    /// are filtered out.
    pub fn is_gossip_worthy(&self) -> bool {
        matches!(self.scope, AddressScope::Global | AddressScope::Private)
    }

    /// True for IPv6 globally-routable. Used by the ICE selector to
    /// prefer v6 when both peers have one.
    pub fn is_v6_global(&self) -> bool {
        matches!(self.addr, IpAddr::V6(_)) && self.scope == AddressScope::Global
    }
}

/// Classify an IPv4 address by scope using the `std::net::Ipv4Addr`
/// classification helpers + extra rules for CGNAT (RFC 6598).
pub fn classify_ipv4(addr: Ipv4Addr) -> AddressScope {
    if addr.is_unspecified() {
        return AddressScope::Unspecified;
    }
    if addr.is_loopback() {
        return AddressScope::Loopback;
    }
    if addr.is_broadcast() {
        return AddressScope::Broadcast;
    }
    if addr.is_link_local() {
        return AddressScope::LinkLocal;
    }
    if addr.is_multicast() {
        return AddressScope::Multicast;
    }
    if addr.is_private() {
        return AddressScope::Private;
    }
    // RFC 6598 Shared Address Space (CGNAT): 100.64.0.0/10.
    // `Ipv4Addr::is_private` doesn't include CGNAT; treat it as
    // Private because peers behind the same carrier-grade NAT can
    // reach each other directly.
    let oct = addr.octets();
    if oct[0] == 100 && (64..=127).contains(&oct[1]) {
        return AddressScope::Private;
    }
    AddressScope::Global
}

/// Classify an IPv6 address by scope using the `std::net::Ipv6Addr`
/// classification helpers + extra rules.
pub fn classify_ipv6(addr: Ipv6Addr) -> AddressScope {
    if addr.is_unspecified() {
        return AddressScope::Unspecified;
    }
    if addr.is_loopback() {
        return AddressScope::Loopback;
    }
    if addr.is_multicast() {
        return AddressScope::Multicast;
    }
    if addr.is_unicast_link_local() {
        return AddressScope::LinkLocal;
    }
    // RFC 4193 Unique Local Addresses: fc00::/7.
    let seg0 = addr.segments()[0];
    if (seg0 & 0xfe00) == 0xfc00 {
        return AddressScope::Private;
    }
    // RFC 6052 IPv4-mapped (::ffff:X.X.X.X) — surface as v4 scope
    // mapped to its embedded v4 address's classification.
    if let Some(v4) = addr.to_ipv4_mapped() {
        return classify_ipv4(v4);
    }
    // IPv6 documentation prefix (2001:db8::/32 RFC 3849) — never
    // useful as a real candidate.
    if addr.segments()[0] == 0x2001 && addr.segments()[1] == 0x0db8 {
        return AddressScope::Unspecified;
    }
    AddressScope::Global
}

/// Combined IPv4 + IPv6 classifier; dispatches on family.
pub fn classify_ip(addr: IpAddr) -> AddressScope {
    match addr {
        IpAddr::V4(v4) => classify_ipv4(v4),
        IpAddr::V6(v6) => classify_ipv6(v6),
    }
}

/// Per-platform interface enumeration. On Linux/macOS uses
/// `nix::ifaddrs::getifaddrs`. On Windows returns an empty list — the
/// follow-up slice will wire GetAdaptersAddresses.
///
/// Returns the FULL list of classified addresses including
/// non-routable scopes (loopback, link-local, multicast). Callers
/// that want only the gossip-worthy subset should use
/// [`gather_gossip_worthy_host_candidates`], which filters and
/// sorts in one call.
pub fn enumerate_local_host_candidates() -> Vec<LocalHostCandidate> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        enumerate_via_getifaddrs()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        // Windows / other — a follow-up slice will wire
        // GetAdaptersAddresses via the windows crate. For now the
        // empty list means the host has no host candidates and must
        // rely on srflx (STUN) discovery.
        Vec::new()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn enumerate_via_getifaddrs() -> Vec<LocalHostCandidate> {
    use nix::ifaddrs;
    let mut out = Vec::new();
    let Ok(iter) = ifaddrs::getifaddrs() else {
        return out;
    };
    for ifaddr in iter {
        let Some(addr) = ifaddr.address else {
            continue;
        };
        let ip: IpAddr = if let Some(inet) = addr.as_sockaddr_in() {
            IpAddr::V4(inet.ip())
        } else if let Some(inet6) = addr.as_sockaddr_in6() {
            IpAddr::V6(inet6.ip())
        } else {
            continue;
        };
        let scope = classify_ip(ip);
        out.push(LocalHostCandidate {
            interface: ifaddr.interface_name,
            addr: ip,
            scope,
        });
    }
    out
}

/// Just the gossip-worthy host candidates, sorted with global IPv6
/// first, then global IPv4, then private. The ordering reflects ICE
/// preference (RFC 8445 §5.1.2.2): higher-priority candidates should
/// appear earlier in the list when serialised.
pub fn gather_gossip_worthy_host_candidates() -> Vec<LocalHostCandidate> {
    let mut all = enumerate_local_host_candidates();
    all.retain(LocalHostCandidate::is_gossip_worthy);
    all.sort_by_key(host_candidate_sort_key);
    all
}

fn host_candidate_sort_key(c: &LocalHostCandidate) -> u8 {
    // Lower numbers sort first.
    match (c.scope, c.addr) {
        (AddressScope::Global, IpAddr::V6(_)) => 0,
        (AddressScope::Global, IpAddr::V4(_)) => 1,
        (AddressScope::Private, IpAddr::V6(_)) => 2,
        (AddressScope::Private, IpAddr::V4(_)) => 3,
        _ => 4,
    }
}

/// Combined set of host + srflx candidates for both address families.
/// Consumed by the gossip layer (D2.5) and ICE prioritisation (D5.5).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CandidateSet {
    pub v4_host: Vec<IpAddr>,
    pub v6_host: Vec<IpAddr>,
    pub v4_srflx: Vec<SocketAddr>,
    pub v6_srflx: Vec<SocketAddr>,
}

impl CandidateSet {
    /// True when the host has at least one globally-routable IPv6
    /// host or srflx candidate. Used by the connect path to decide
    /// whether to advertise v6 preference.
    pub fn has_global_v6(&self) -> bool {
        self.v6_host
            .iter()
            .any(|ip| classify_ip(*ip) == AddressScope::Global)
            || self
                .v6_srflx
                .iter()
                .any(|sa| classify_ip(sa.ip()) == AddressScope::Global)
    }

    /// Total candidate count across all kinds.
    pub fn len(&self) -> usize {
        self.v4_host.len() + self.v6_host.len() + self.v4_srflx.len() + self.v6_srflx.len()
    }

    /// True when no candidates were gathered. Useful for unit-test
    /// assertions on empty-host paths.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Bind a UDP socket of the requested family and query each STUN
/// server in `stun_servers`. Returns the per-server StunResult vector.
///
/// `family` selects IPv4 (binds `0.0.0.0:0`) or IPv6 (binds `[::]:0`).
/// Servers that don't resolve in the requested family are skipped.
/// The function returns the empty list rather than an error so an
/// IPv6-unreachable host degrades cleanly to "no v6 srflx".
pub fn gather_srflx_for_family(
    family: AddressFamily,
    stun_servers: &[String],
    timeout: Duration,
) -> Vec<StunResult> {
    let bind = match family {
        AddressFamily::V4 => "0.0.0.0:0",
        AddressFamily::V6 => "[::]:0",
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return Vec::new();
    };
    // Filter the supplied STUN servers to ones that resolve in the
    // requested family so we don't waste socket round-trips on
    // unreachable targets.
    let filtered: Vec<String> = stun_servers
        .iter()
        .filter(|url| stun_server_resolves_in_family(url, family))
        .cloned()
        .collect();
    if filtered.is_empty() {
        return Vec::new();
    }
    let client = StunClient::new(filtered, timeout);
    client.gather_mapped_endpoints(Some(&socket))
}

/// Address family selector for [`gather_srflx_for_family`] and other
/// family-aware operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    V4,
    V6,
}

fn stun_server_resolves_in_family(url: &str, family: AddressFamily) -> bool {
    use std::net::ToSocketAddrs;
    let Ok(addrs) = url.to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        let matches = matches!(
            (family, addr),
            (AddressFamily::V4, SocketAddr::V4(_)) | (AddressFamily::V6, SocketAddr::V6(_))
        );
        if matches {
            return true;
        }
    }
    false
}

/// Gather a complete [`CandidateSet`] — local host candidates from
/// `getifaddrs(2)` + srflx candidates from both v4 and v6 STUN
/// servers.
pub fn gather_candidate_set(
    v4_stun_servers: &[String],
    v6_stun_servers: &[String],
    stun_timeout: Duration,
) -> CandidateSet {
    let hosts = gather_gossip_worthy_host_candidates();
    let mut set = CandidateSet::default();
    for h in &hosts {
        match h.addr {
            IpAddr::V4(_) => set.v4_host.push(h.addr),
            IpAddr::V6(_) => set.v6_host.push(h.addr),
        }
    }
    for r in gather_srflx_for_family(AddressFamily::V4, v4_stun_servers, stun_timeout) {
        set.v4_srflx.push(r.mapped_endpoint);
    }
    for r in gather_srflx_for_family(AddressFamily::V6, v6_stun_servers, stun_timeout) {
        set.v6_srflx.push(r.mapped_endpoint);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_ipv4_named_ranges() {
        assert_eq!(
            classify_ipv4(Ipv4Addr::UNSPECIFIED),
            AddressScope::Unspecified
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            AddressScope::Loopback
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(255, 255, 255, 255)),
            AddressScope::Broadcast
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(169, 254, 0, 1)),
            AddressScope::LinkLocal
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(224, 0, 0, 1)),
            AddressScope::Multicast
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            AddressScope::Private
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(172, 16, 0, 1)),
            AddressScope::Private
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(192, 168, 1, 1)),
            AddressScope::Private
        );
        // CGNAT — RFC 6598 100.64.0.0/10
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(100, 64, 0, 1)),
            AddressScope::Private
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(100, 127, 255, 254)),
            AddressScope::Private
        );
        // 100.128.0.1 is OUTSIDE CGNAT, so it should classify as Global
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(100, 128, 0, 1)),
            AddressScope::Global
        );
        assert_eq!(
            classify_ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            AddressScope::Global
        );
    }

    #[test]
    fn classify_ipv6_named_ranges() {
        assert_eq!(
            classify_ipv6(Ipv6Addr::UNSPECIFIED),
            AddressScope::Unspecified
        );
        assert_eq!(classify_ipv6(Ipv6Addr::LOCALHOST), AddressScope::Loopback);
        // Link-local: fe80::/10
        assert_eq!(
            classify_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            AddressScope::LinkLocal
        );
        // Multicast: ff00::/8
        assert_eq!(
            classify_ipv6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            AddressScope::Multicast
        );
        // ULA: fc00::/7
        assert_eq!(
            classify_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            AddressScope::Private
        );
        // Global unicast: 2000::/3
        assert_eq!(
            classify_ipv6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
            AddressScope::Global
        );
        // Documentation prefix 2001:db8::/32 — never a real endpoint
        assert_eq!(
            classify_ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            AddressScope::Unspecified
        );
    }

    #[test]
    fn local_host_candidate_is_gossip_worthy_filters_out_link_local_and_loopback() {
        let global = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            scope: AddressScope::Global,
        };
        assert!(global.is_gossip_worthy());

        let private = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            scope: AddressScope::Private,
        };
        assert!(private.is_gossip_worthy());

        let link_local = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            scope: AddressScope::LinkLocal,
        };
        assert!(!link_local.is_gossip_worthy());

        let loopback = LocalHostCandidate {
            interface: "lo".into(),
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            scope: AddressScope::Loopback,
        };
        assert!(!loopback.is_gossip_worthy());
    }

    #[test]
    fn local_host_candidate_is_v6_global() {
        let v6_global = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
            scope: AddressScope::Global,
        };
        assert!(v6_global.is_v6_global());

        let v6_private = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            scope: AddressScope::Private,
        };
        assert!(!v6_private.is_v6_global());

        let v4_global = LocalHostCandidate {
            interface: "wg0".into(),
            addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            scope: AddressScope::Global,
        };
        assert!(!v4_global.is_v6_global());
    }

    #[test]
    fn enumerate_local_host_candidates_returns_at_least_loopback_classified_correctly_on_linux_macos()
     {
        // Every host we test on has 127.0.0.1 + ::1 visible via
        // getifaddrs. The classifier should mark them Loopback. We
        // also verify the routable subset never contains them.
        let all = enumerate_local_host_candidates();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            assert!(
                all.iter()
                    .any(|c| matches!(c.scope, AddressScope::Loopback)),
                "expected at least one Loopback-scope candidate on Linux/macOS"
            );
            let gossip = gather_gossip_worthy_host_candidates();
            assert!(
                gossip
                    .iter()
                    .all(|c| !matches!(c.scope, AddressScope::Loopback))
            );
            assert!(
                gossip
                    .iter()
                    .all(|c| !matches!(c.scope, AddressScope::LinkLocal))
            );
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            // Stub path on Windows / other — must return empty.
            assert!(all.is_empty());
        }
    }

    #[test]
    fn gather_gossip_worthy_host_candidates_sorts_v6_global_before_v4_global() {
        // Pure-sort test using synthesised candidates. Real
        // enumeration is exercised by the test above.
        let mut input = [
            LocalHostCandidate {
                interface: "a".into(),
                addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                scope: AddressScope::Global,
            },
            LocalHostCandidate {
                interface: "b".into(),
                addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                scope: AddressScope::Global,
            },
            LocalHostCandidate {
                interface: "c".into(),
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                scope: AddressScope::Private,
            },
            LocalHostCandidate {
                interface: "d".into(),
                addr: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                scope: AddressScope::Private,
            },
        ];
        input.sort_by_key(host_candidate_sort_key);
        // Expected order: v6-global, v4-global, v6-private, v4-private
        assert_eq!(input[0].interface, "b");
        assert_eq!(input[1].interface, "a");
        assert_eq!(input[2].interface, "d");
        assert_eq!(input[3].interface, "c");
    }

    #[test]
    fn candidate_set_has_global_v6_picks_up_global_hosts() {
        let set = CandidateSet {
            v4_host: vec![],
            v6_host: vec![IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))],
            v4_srflx: vec![],
            v6_srflx: vec![],
        };
        assert!(set.has_global_v6());

        let only_v6_private = CandidateSet {
            v6_host: vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))],
            ..Default::default()
        };
        assert!(!only_v6_private.has_global_v6());

        let only_v4 = CandidateSet {
            v4_host: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
            ..Default::default()
        };
        assert!(!only_v4.has_global_v6());
    }

    #[test]
    fn candidate_set_has_global_v6_picks_up_global_srflx() {
        let set = CandidateSet {
            v6_srflx: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                51820,
            )],
            ..Default::default()
        };
        assert!(set.has_global_v6());
    }

    #[test]
    fn candidate_set_len_and_is_empty() {
        let set = CandidateSet::default();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);

        let set = CandidateSet {
            v4_host: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
            v6_host: vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
            v4_srflx: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                51820,
            )],
            v6_srflx: vec![],
        };
        assert!(!set.is_empty());
        assert_eq!(set.len(), 3);
    }

    /// Spawn an in-process STUN echo server bound to `bind_addr` and
    /// return its socket address. Mirrors the helper in stun_client
    /// tests: replies with a STUN binding response containing a
    /// XOR-MAPPED-ADDRESS that echoes the requester's source.
    fn spawn_local_stun_echo(bind_addr: &str) -> SocketAddr {
        use std::thread;
        let listener = UdpSocket::bind(bind_addr).expect("bind stun echo");
        let addr = listener.local_addr().expect("local_addr");
        thread::spawn(move || {
            listener.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut buf = [0u8; 1024];
            let Ok((len, src)) = listener.recv_from(&mut buf) else {
                return;
            };
            // STUN binding request: 20-byte header followed by no
            // attributes (length=0). Mirror the transaction ID.
            if len < 20 {
                return;
            }
            let mut tx_id = [0u8; 12];
            tx_id.copy_from_slice(&buf[8..20]);
            // Build a binding response with one XOR-MAPPED-ADDRESS
            // attribute pointing at `src`.
            let response = build_xor_mapped_binding_response(&tx_id, src);
            let _ = listener.send_to(&response, src);
        });
        addr
    }

    /// Helper: build a STUN binding response carrying one
    /// XOR-MAPPED-ADDRESS attribute. Mirrors the helper in
    /// stun_client::tests but lives here so this module is
    /// self-contained for testing.
    fn build_xor_mapped_binding_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;
        const STUN_BINDING_RESPONSE: u16 = 0x0101;
        const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
        let (family_byte, addr_len, xor_addr_bytes) = match mapped {
            SocketAddr::V4(v4) => {
                let raw = v4.ip().octets();
                let xor = [raw[0] ^ 0x21, raw[1] ^ 0x12, raw[2] ^ 0xa4, raw[3] ^ 0x42];
                (0x01u8, 4u16, xor.to_vec())
            }
            SocketAddr::V6(v6) => {
                let raw = v6.ip().octets();
                // XOR the address with magic cookie + tx_id (RFC 5389 §15.2).
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                mask[4..16].copy_from_slice(tx_id);
                let mut xor = [0u8; 16];
                for i in 0..16 {
                    xor[i] = raw[i] ^ mask[i];
                }
                (0x02u8, 16u16, xor.to_vec())
            }
        };
        let xor_port = mapped.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let attr_len = 4 + addr_len; // family + reserved + port + addr
        let total_len = 4 + attr_len;
        let mut packet = Vec::with_capacity(20 + total_len as usize);
        packet.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        packet.extend_from_slice(&total_len.to_be_bytes());
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(tx_id);
        packet.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        packet.extend_from_slice(&attr_len.to_be_bytes());
        packet.push(0); // reserved
        packet.push(family_byte);
        packet.extend_from_slice(&xor_port.to_be_bytes());
        packet.extend_from_slice(&xor_addr_bytes);
        packet
    }

    #[test]
    fn gather_srflx_for_family_v4_against_local_echo_server() {
        let stun_addr = spawn_local_stun_echo("127.0.0.1:0");
        let servers = vec![stun_addr.to_string()];
        let results = gather_srflx_for_family(AddressFamily::V4, &servers, Duration::from_secs(2));
        assert_eq!(results.len(), 1, "one STUN response expected");
        assert!(matches!(results[0].mapped_endpoint, SocketAddr::V4(_)));
    }

    #[test]
    fn gather_srflx_for_family_v6_against_local_echo_server() {
        // [::1]:0 — IPv6 loopback, always available on Linux/macOS test boxes.
        let stun_addr = spawn_local_stun_echo("[::1]:0");
        let servers = vec![stun_addr.to_string()];
        let results = gather_srflx_for_family(AddressFamily::V6, &servers, Duration::from_secs(2));
        assert_eq!(results.len(), 1, "one v6 STUN response expected");
        assert!(matches!(results[0].mapped_endpoint, SocketAddr::V6(_)));
    }

    #[test]
    fn gather_srflx_for_family_skips_servers_in_wrong_family() {
        // A v4-only STUN server URL passed to the v6 gather path
        // should produce zero results — without burning the timeout
        // — because the resolver filter rejects it first.
        let stun_addr = spawn_local_stun_echo("127.0.0.1:0");
        let servers = vec![stun_addr.to_string()];
        let results = gather_srflx_for_family(AddressFamily::V6, &servers, Duration::from_secs(1));
        assert!(
            results.is_empty(),
            "v4-only server must be skipped on v6 gather"
        );
    }

    #[test]
    fn gather_candidate_set_combines_host_and_srflx_for_both_families() {
        let v4_stun = spawn_local_stun_echo("127.0.0.1:0");
        let v6_stun = spawn_local_stun_echo("[::1]:0");
        let set = gather_candidate_set(
            &[v4_stun.to_string()],
            &[v6_stun.to_string()],
            Duration::from_secs(2),
        );
        assert_eq!(set.v4_srflx.len(), 1);
        assert_eq!(set.v6_srflx.len(), 1);
        assert!(matches!(set.v4_srflx[0], SocketAddr::V4(_)));
        assert!(matches!(set.v6_srflx[0], SocketAddr::V6(_)));
        // Host candidates depend on the test box's network — we can't
        // assert their count, but we can assert they're all
        // gossip-worthy (no loopback, no link-local).
        for ip in set.v4_host.iter().chain(set.v6_host.iter()) {
            let scope = classify_ip(*ip);
            assert!(
                matches!(scope, AddressScope::Global | AddressScope::Private),
                "host candidate {ip:?} should be gossip-worthy but scope is {scope:?}"
            );
        }
    }
}
