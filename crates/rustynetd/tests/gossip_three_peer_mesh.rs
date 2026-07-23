//! D2.5 — Three-peer mesh end-to-end test.
//!
//! Topology: A only direct-talks to B; B direct-talks to A and C; C
//! only direct-talks to B. There is no A↔C edge. We assert that
//! when A signs a fresh bundle, B applies it within 3 seconds, then
//! re-broadcasts so C applies it within 6 seconds total — exactly
//! the pass criterion in
//! `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
//! §D2.5.
//!
//! The test drives `GossipNode` + `GossipTransport` directly: those
//! are the same building blocks that `DaemonRuntime` owns in
//! production, so the test exercises the actual mint + accept +
//! epidemic re-push code paths with a real UDP loopback transport
//! (no stubbed channels, no mocks) and real Ed25519 signing.
//!
//! Negative pins included alongside the positive propagation pin:
//!
//! 1. Bad signature → drop (tamper a candidate after signing).
//! 2. Replay of last-seen sequence → drop.
//! 3. Loopback candidate → drop.
//! 4. Bundle whose claimed source is unknown to the receiver → drop.

#![forbid(unsafe_code)]
// This crate drives `GossipNode` + `GossipTransport` directly; the transport
// binds a real UDP socket and is unix-only in this slice (the Windows gossip
// path is queued behind Track Beta — `GossipTransport::bind` returns
// Unsupported on non-unix). Gate the entire integration-test crate off Windows
// so every test plus the `Peer` harness and `loopback`/`unix_now`/`drain_until`
// helpers compile only where the transport exists (no unused-code `-D warnings`
// on the Windows CI build).
#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;

use rustynetd::dataplane_candidates::CandidateSet;
use rustynetd::gossip_runtime::GossipNode;
use rustynetd::gossip_transport::GossipTransport;
use rustynetd::peer_gossip::{
    GossipError, MAX_GOSSIP_DATAGRAM_BYTES, mint_bundle_with_timestamp, serialise_bundle,
};

/// Membership epoch shared by every peer in these mesh tests (I2 —
/// bundles carry the minter's verified epoch and receivers enforce a
/// skew window around their own; a uniform value keeps the mesh
/// propagation pins orthogonal to the epoch-window pins, which live in
/// `peer_gossip`'s unit tests).
const TEST_EPOCH: u64 = 7;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after UNIX_EPOCH")
        .as_secs()
}

struct Peer {
    node: GossipNode,
    transport: GossipTransport,
    local_addr: SocketAddr,
    /// Stable label used by the test for diagnostic messages.
    label: &'static str,
}

impl Peer {
    fn new(label: &'static str, key_byte: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let mut node = GossipNode::new(signing_key, None).expect("node ctor");
        node.set_local_membership_epoch(TEST_EPOCH);
        let transport = GossipTransport::bind(loopback()).expect("transport bind");
        let local_addr = transport.local_addr().expect("local_addr");
        Self {
            node,
            transport,
            local_addr,
            label,
        }
    }
}

/// Drain the transport into the node for as many bundles as
/// arrive within `deadline`. Returns the count of bundles
/// accepted (errors are silently dropped — the test asserts
/// against applied_endpoints, which is the post-accept state).
///
/// `stop_when` is consulted after every recv attempt; if it
/// returns true the function exits early. This is how the
/// positive-propagation test measures *actual* time-to-apply
/// rather than the deadline window itself.
fn drain_until<F>(peer: &mut Peer, deadline: Instant, mut stop_when: F) -> usize
where
    F: FnMut(&Peer) -> bool,
{
    let mut accepted = 0usize;
    while Instant::now() < deadline {
        let slice = std::cmp::min(
            Duration::from_millis(50),
            deadline.saturating_duration_since(Instant::now()),
        );
        match peer.transport.recv_bundle(slice) {
            Ok(Some((sender, bundle))) => {
                let now_unix = unix_now();
                if peer
                    .node
                    .ingest_inbound_bundle(Some(sender), bundle, &peer.transport, now_unix)
                    .is_ok()
                {
                    accepted += 1;
                }
            }
            Ok(None) => {}
            Err(err) => {
                eprintln!("{} recv error: {err}", peer.label);
            }
        }
        if stop_when(peer) {
            break;
        }
    }
    accepted
}

/// Convenience: drain ignoring the early-exit hint. Used by the
/// negative-case tests where the goal is "no accept ever happens"
/// — we want to exhaust the window.
fn drain_until_deadline(peer: &mut Peer, deadline: Instant) -> usize {
    drain_until(peer, deadline, |_| false)
}

#[test]
fn bundle_propagates_a_to_b_within_3s_and_a_to_c_via_b_within_6s() {
    // Build three peers with distinct signing keys.
    let mut a = Peer::new("A", 0xa1);
    let mut b = Peer::new("B", 0xb2);
    let mut c = Peer::new("C", 0xc3);
    let a_id = a.node.local_node_id;
    let b_id = b.node.local_node_id;
    let c_id = c.node.local_node_id;

    // Capture verifying keys before we mutate the nodes by
    // calling register_peer (a borrow-checker convenience).
    let a_vk = SigningKey::from_bytes(&[0xa1u8; 32]).verifying_key();
    let b_vk = SigningKey::from_bytes(&[0xb2u8; 32]).verifying_key();
    let c_vk = SigningKey::from_bytes(&[0xc3u8; 32]).verifying_key();

    // Topology: A↔B, B↔C, NO A↔C.
    a.node.register_peer(b_id, b_vk, b.local_addr);
    b.node.register_peer(a_id, a_vk, a.local_addr);
    b.node.register_peer(c_id, c_vk, c.local_addr);
    c.node.register_peer(b_id, b_vk, b.local_addr);
    // Cross-load verifying keys so each peer can verify any
    // bundle that originated from any other peer (even one that
    // arrives via a re-push from a non-originator).
    a.node.register_peer(c_id, c_vk, c.local_addr);
    c.node.register_peer(a_id, a_vk, a.local_addr);
    // ... but with a deliberate flip: remove A↔C from the push
    // address book. A peer that knows another's verifying key
    // can still verify their bundle when it arrives via the
    // re-push path; the lack of a push entry just means A would
    // not send DIRECTLY to C and vice versa. Achieved by
    // re-registering with a sentinel push address that nobody
    // is bound to — but a cleaner expression is to NOT have
    // them registered as push targets at all. The test re-
    // expresses topology by overriding push_addr to a deliberate
    // dead address; ingest_inbound_bundle skips push errors so
    // an unreachable push target is silently dropped. Use a
    // closed-port loopback address.
    let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1);
    a.node.register_peer(c_id, c_vk, dead);
    c.node.register_peer(a_id, a_vk, dead);

    // A's distinctive candidate set.
    let mut candidates = CandidateSet::default();
    candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 99, 77, 1)));
    candidates.v4_srflx.push(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
        51820,
    ));

    // A mints and broadcasts.
    let started = Instant::now();
    let bundle = a
        .node
        .maybe_mint_and_broadcast(started, unix_now(), candidates.clone(), &a.transport)
        .expect("A mint ok")
        .expect("first mint must emit a bundle");
    assert_eq!(bundle.sequence, 1);
    assert_eq!(bundle.candidates, candidates);

    // Within 3 s, B must have ingested and applied the bundle.
    let b_deadline = started + Duration::from_secs(3);
    drain_until(&mut b, b_deadline, |peer| {
        peer.node.applied_endpoints.contains_key(&a_id)
    });
    let b_endpoints = b
        .node
        .applied_endpoints
        .get(&a_id)
        .cloned()
        .unwrap_or_default();
    assert!(
        !b_endpoints.is_empty(),
        "B must have applied A's endpoints within 3 s; applied_endpoints had {:?}",
        b.node.applied_endpoints.keys().collect::<Vec<_>>()
    );
    let b_elapsed = started.elapsed();
    assert!(
        b_elapsed <= Duration::from_secs(3),
        "B applied A's bundle but took {b_elapsed:?}, exceeds 3 s budget"
    );

    // C must receive via B's re-push. Within 6 s total.
    let c_deadline = started + Duration::from_secs(6);
    drain_until(&mut c, c_deadline, |peer| {
        peer.node.applied_endpoints.contains_key(&a_id)
    });
    let c_endpoints = c
        .node
        .applied_endpoints
        .get(&a_id)
        .cloned()
        .unwrap_or_default();
    assert!(
        !c_endpoints.is_empty(),
        "C must have applied A's endpoints within 6 s (via B's re-push); applied had {:?}",
        c.node.applied_endpoints.keys().collect::<Vec<_>>()
    );
    let c_elapsed = started.elapsed();
    assert!(
        c_elapsed <= Duration::from_secs(6),
        "C applied A's bundle but took {c_elapsed:?}, exceeds 6 s budget"
    );

    // Defensive: the bundle reaching C must carry A's original
    // candidates — the re-push preserves the signed payload
    // byte-for-byte (the signature is over the same pre-image).
    // Inspecting the in-memory `applied_endpoints` is sufficient
    // because the value was derived from the verified bundle.
    let expected_endpoints = rustynetd::peer_gossip::flatten_endpoints(&bundle);
    assert_eq!(
        c_endpoints, expected_endpoints,
        "C's applied endpoints must equal A's signed candidates"
    );
}

#[test]
fn replay_of_last_seen_sequence_is_dropped() {
    let mut a = Peer::new("A", 0x11);
    let mut b = Peer::new("B", 0x22);
    let a_id = a.node.local_node_id;
    let b_id = b.node.local_node_id;
    let a_vk = SigningKey::from_bytes(&[0x11u8; 32]).verifying_key();
    let b_vk = SigningKey::from_bytes(&[0x22u8; 32]).verifying_key();
    a.node.register_peer(b_id, b_vk, b.local_addr);
    b.node.register_peer(a_id, a_vk, a.local_addr);

    let mut candidates = CandidateSet::default();
    candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13)));
    a.node
        .maybe_mint_and_broadcast(Instant::now(), unix_now(), candidates.clone(), &a.transport)
        .expect("mint 1")
        .expect("emit 1");
    // B accepts the first bundle.
    drain_until_deadline(&mut b, Instant::now() + Duration::from_secs(2));
    assert!(b.node.applied_endpoints.contains_key(&a_id));
    let first_accepted = b.node.accepted_count;
    assert_eq!(first_accepted, 1);

    // Send the same bundle again via the transport directly.
    let bundle = a
        .node
        .last_minted_bundle
        .clone()
        .expect("A has a last-minted bundle");
    a.transport
        .push_bundle(b.local_addr, &bundle)
        .expect("push replay");
    drain_until_deadline(&mut b, Instant::now() + Duration::from_secs(2));
    // accepted_count must NOT increase — the replay was dropped.
    assert_eq!(
        b.node.accepted_count, first_accepted,
        "replay of last-seen sequence must be dropped"
    );
    assert_eq!(
        b.node
            .rejected_counts
            .get("sequence_not_monotonic")
            .copied()
            .unwrap_or(0),
        1,
        "replay must increment the sequence_not_monotonic counter exactly once"
    );
}

#[test]
fn tampered_signature_is_dropped() {
    let mut a = Peer::new("A", 0x44);
    let mut b = Peer::new("B", 0x55);
    let a_id = a.node.local_node_id;
    let b_id = b.node.local_node_id;
    let a_vk = SigningKey::from_bytes(&[0x44u8; 32]).verifying_key();
    let b_vk = SigningKey::from_bytes(&[0x55u8; 32]).verifying_key();
    a.node.register_peer(b_id, b_vk, b.local_addr);
    b.node.register_peer(a_id, a_vk, a.local_addr);

    // Mint a bundle directly with A's key.
    let mut candidates = CandidateSet::default();
    candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)));
    let signing_key = SigningKey::from_bytes(&[0x44u8; 32]);
    let mut bundle =
        mint_bundle_with_timestamp(&signing_key, 1, unix_now(), TEST_EPOCH, candidates)
            .expect("mint");
    // Tamper the candidate AFTER signing.
    bundle
        .candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let wire = serialise_bundle(&bundle);
    assert!(wire.len() <= MAX_GOSSIP_DATAGRAM_BYTES);
    a.transport
        .push_bundle(b.local_addr, &bundle)
        .expect("push tampered");
    drain_until_deadline(&mut b, Instant::now() + Duration::from_secs(2));
    assert_eq!(
        b.node.accepted_count, 0,
        "tampered bundle must not be accepted"
    );
    assert!(
        b.node.rejected_counts.contains_key("signature_invalid"),
        "tampered bundle must trip the signature_invalid counter; counters: {:?}",
        b.node.rejected_counts
    );
}

#[test]
fn loopback_candidate_is_dropped() {
    let mut a = Peer::new("A", 0x66);
    let mut b = Peer::new("B", 0x77);
    let a_id = a.node.local_node_id;
    let b_id = b.node.local_node_id;
    let a_vk = SigningKey::from_bytes(&[0x66u8; 32]).verifying_key();
    let b_vk = SigningKey::from_bytes(&[0x77u8; 32]).verifying_key();
    a.node.register_peer(b_id, b_vk, b.local_addr);
    b.node.register_peer(a_id, a_vk, a.local_addr);

    let mut candidates = CandidateSet::default();
    // 127.0.0.1 — loopback srflx is the canonical attack: a
    // malicious or hijacked peer could redirect our connect-back
    // traffic to localhost services. Must fail closed.
    candidates.v4_srflx.push(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        51820,
    ));
    let signing_key = SigningKey::from_bytes(&[0x66u8; 32]);
    let bundle = mint_bundle_with_timestamp(&signing_key, 1, unix_now(), TEST_EPOCH, candidates)
        .expect("mint");
    a.transport
        .push_bundle(b.local_addr, &bundle)
        .expect("push loopback");
    drain_until_deadline(&mut b, Instant::now() + Duration::from_secs(2));
    assert_eq!(
        b.node.accepted_count, 0,
        "loopback candidate must not be accepted"
    );
    assert!(
        b.node.rejected_counts.contains_key("unreachable_candidate"),
        "loopback must trip the unreachable_candidate counter; counters: {:?}",
        b.node.rejected_counts
    );
}

#[test]
fn unknown_source_is_dropped() {
    // A peer that B has never heard of mints a bundle and pushes
    // it directly. Even if the signature is structurally valid,
    // accept_bundle must reject it because the source isn't in
    // B's known-peer map. This is the "compromised intermediate
    // peer cannot forge new sources" pin.
    let mut intruder = Peer::new("X", 0x99);
    let mut b = Peer::new("B", 0x33);
    // B does NOT register the intruder. B only knows about a
    // legitimate counterparty Y.
    let y_vk = SigningKey::from_bytes(&[0xeeu8; 32]).verifying_key();
    let y_id = y_vk.to_bytes();
    b.node.register_peer(y_id, y_vk, loopback());
    // Intruder registers B so its push succeeds.
    let b_id = b.node.local_node_id;
    let b_vk = SigningKey::from_bytes(&[0x33u8; 32]).verifying_key();
    intruder.node.register_peer(b_id, b_vk, b.local_addr);

    let mut candidates = CandidateSet::default();
    candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)));
    intruder
        .node
        .maybe_mint_and_broadcast(Instant::now(), unix_now(), candidates, &intruder.transport)
        .expect("intruder mint ok")
        .expect("intruder mint emits");
    drain_until_deadline(&mut b, Instant::now() + Duration::from_secs(2));
    assert_eq!(b.node.accepted_count, 0);
    assert!(
        b.node.rejected_counts.contains_key("unknown_source"),
        "unknown-source bundle must trip the unknown_source counter; counters: {:?}",
        b.node.rejected_counts
    );
}

#[test]
fn malformed_wire_does_not_corrupt_state() {
    // Defense-in-depth: a malformed wire from a (potentially
    // hostile) peer must not leak past the deserialise step. We
    // push raw bytes from a UdpSocket bypassing serialise_bundle.
    let b = Peer::new("B", 0xddu8);
    let raw = std::net::UdpSocket::bind(loopback()).expect("raw send sock");
    // 8 bytes — way short of the fixed header (65 bytes).
    raw.send_to(&[0, 0, 0, 0, 0, 0, 0, 0], b.local_addr)
        .expect("send malformed");
    // Use the transport's recv path (not the node's drain) so we
    // can observe the typed error.
    let res = b.transport.recv_bundle(Duration::from_secs(2));
    match res {
        Err(rustynetd::gossip_transport::TransportError::InvalidBundle(
            GossipError::WireTruncated { .. },
        )) => {}
        other => panic!("expected WireTruncated, got {other:?}"),
    }
    // State must remain pristine.
    assert!(b.node.applied_endpoints.is_empty());
    assert_eq!(b.node.accepted_count, 0);
}
