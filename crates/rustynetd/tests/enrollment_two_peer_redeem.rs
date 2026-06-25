//! D2.7 — Two-peer enrollment integration test.
//!
//! Pass criterion (from
//! `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
//! §D2.7): an existing peer mints a token; a new device (separate
//! process, simulating a fresh install) given the token + the
//! existing-peer endpoint joins the mesh, receives the signed
//! bundle, and participates in further gossip.
//!
//! In-process realisation: we stand up two `GossipNode` instances
//! on loopback (the existing peer A, and the new device N) with
//! independent signing keys and independent state. A pre-shared
//! enrollment secret is the only out-of-band material; the test
//! does the mint → operator-paste → consume round trip and then
//! verifies that A's next gossip bundle reaches N AND that N's
//! reply bundle reaches A (N is now a participating peer).
//!
//! Negative pins:
//!
//! 1. The token cannot be redeemed twice (replay → AlreadyConsumed).
//! 2. A token from a different secret is rejected (TagMismatch).
//! 3. An expired token is rejected (Expired).
//! 4. A loopback push address from the enrollee is rejected when the
//!    daemon is in Strict policy mode (the production setting).

#![forbid(unsafe_code)]
// The whole harness binds a real `GossipTransport` UDP socket, which is
// unix-only in this slice (the Windows gossip path is queued behind Track
// Beta — `GossipTransport::bind` returns Unsupported on non-unix). Gate the
// entire integration-test crate off Windows so the tests, the `Peer` harness,
// and the `loopback`/`drain_until` helpers compile only where the transport
// exists (avoids unused-code `-D warnings` on the Windows CI build).
#![cfg(unix)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;

use rustynetd::dataplane_candidates::CandidateSet;
use rustynetd::enrollment_consume::{
    ConsumeError, PushAddressPolicy, consume_and_register_peer_with_now,
};
use rustynetd::enrollment_token::{
    ConsumedTokenLedger, ENROLLMENT_SECRET_LEN, EnrollmentTokenError, mint_token_with_clock,
};
use rustynetd::gossip_runtime::GossipNode;
use rustynetd::gossip_transport::GossipTransport;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

struct Peer {
    node: GossipNode,
    transport: GossipTransport,
    local_addr: SocketAddr,
}

impl Peer {
    fn new(key_byte: u8) -> Self {
        let signing_key = SigningKey::from_bytes(&[key_byte; 32]);
        let node = GossipNode::new(signing_key, None).expect("ctor");
        let transport = GossipTransport::bind(loopback()).expect("transport bind");
        let local_addr = transport.local_addr().expect("local_addr");
        Self {
            node,
            transport,
            local_addr,
        }
    }
}

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
                if peer
                    .node
                    .ingest_inbound_bundle(Some(sender), bundle, &peer.transport, 1_700_000_100)
                    .is_ok()
                {
                    accepted += 1;
                }
            }
            Ok(None) => {}
            Err(_) => {}
        }
        if stop_when(peer) {
            break;
        }
    }
    accepted
}

#[test]
fn enrollee_joins_mesh_via_token_consume_and_participates_in_gossip() {
    // Shared HMAC secret — in production this would be persisted at
    // a 0o600 path under /var/lib/rustynet/keys/. The test plants
    // it inline.
    let secret = [0xa5u8; ENROLLMENT_SECRET_LEN];
    let now_unix = 1_700_000_100u64;
    // Pre-existing peer A.
    let mut existing = Peer::new(0xa1);
    let existing_id = existing.node.local_node_id;
    let existing_pubkey = SigningKey::from_bytes(&[0xa1u8; 32]).verifying_key();
    // New device N (simulating a fresh install with a fresh keypair).
    let mut enrollee = Peer::new(0xc3);
    let enrollee_pubkey = SigningKey::from_bytes(&[0xc3u8; 32]).verifying_key();
    // Out-of-band trust bootstrap: the operator hands N a copy of
    // A's verifying key + endpoint so N can verify any bundle that
    // arrives from A.
    enrollee
        .node
        .register_peer(existing_id, existing_pubkey, existing.local_addr);

    // A's operator mints a token. The token is then handed to N
    // via a side channel (QR / file / paste).
    let (_, encoded_token) = mint_token_with_clock(&secret, 600, now_unix).expect("mint succeeds");

    // N (the enrollee) generates its keypair and gives A's operator
    // its pubkey + push address. A's operator runs the consume
    // verb. The orchestrator atomically: verifies the token, marks
    // it consumed, and registers N in A's gossip peer table.
    let mut ledger = ConsumedTokenLedger::new();
    let outcome = consume_and_register_peer_with_now(
        &encoded_token,
        &secret,
        &mut ledger,
        None,
        enrollee_pubkey,
        enrollee.local_addr,
        &mut existing.node,
        PushAddressPolicy::AllowLoopback,
        now_unix,
    )
    .expect("consume succeeds");
    assert_eq!(outcome.enrollee_node_id, enrollee_pubkey.to_bytes());
    assert_eq!(outcome.enrollee_push_addr, enrollee.local_addr);
    assert!(ledger.was_consumed(&outcome.token_id));
    assert!(existing.node.peers.contains_key(&outcome.enrollee_node_id));

    // A mints a bundle. Because N is now in A.peers, A pushes to N.
    let mut a_candidates = CandidateSet::default();
    a_candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)));
    existing
        .node
        .maybe_mint_and_broadcast(
            Instant::now(),
            now_unix,
            a_candidates.clone(),
            &existing.transport,
        )
        .expect("A mint")
        .expect("A emits");

    // Within 3 s, N must have applied A's bundle.
    let n_deadline = Instant::now() + Duration::from_secs(3);
    drain_until(&mut enrollee, n_deadline, |peer| {
        peer.node.applied_endpoints.contains_key(&existing_id)
    });
    assert!(
        enrollee.node.applied_endpoints.contains_key(&existing_id),
        "enrollee must have applied A's endpoints after consume; applied: {:?}",
        enrollee.node.applied_endpoints.keys().collect::<Vec<_>>()
    );

    // Now N mints a bundle of its own — proving N "participates in
    // further gossip" as the pass criterion requires.
    let mut n_candidates = CandidateSet::default();
    n_candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 43)));
    enrollee
        .node
        .maybe_mint_and_broadcast(Instant::now(), now_unix, n_candidates, &enrollee.transport)
        .expect("N mint")
        .expect("N emits");

    // A must apply N's bundle within 3 s.
    let a_deadline = Instant::now() + Duration::from_secs(3);
    let enrollee_id = enrollee.node.local_node_id;
    drain_until(&mut existing, a_deadline, |peer| {
        peer.node.applied_endpoints.contains_key(&enrollee_id)
    });
    assert!(
        existing.node.applied_endpoints.contains_key(&enrollee_id),
        "existing peer must have applied N's endpoints; applied: {:?}",
        existing.node.applied_endpoints.keys().collect::<Vec<_>>()
    );
}

#[test]
fn token_cannot_be_redeemed_twice() {
    let secret = [0xa6u8; ENROLLMENT_SECRET_LEN];
    let now_unix = 1_700_000_100u64;
    let (_, encoded) = mint_token_with_clock(&secret, 600, now_unix).expect("mint");
    let mut existing = Peer::new(0xa2);
    let enrollee_pubkey = SigningKey::from_bytes(&[0xc4u8; 32]).verifying_key();
    let enrollee_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)), 51821);
    let mut ledger = ConsumedTokenLedger::new();
    consume_and_register_peer_with_now(
        &encoded,
        &secret,
        &mut ledger,
        None,
        enrollee_pubkey,
        enrollee_addr,
        &mut existing.node,
        PushAddressPolicy::Strict,
        now_unix,
    )
    .expect("first consume succeeds");
    let err = consume_and_register_peer_with_now(
        &encoded,
        &secret,
        &mut ledger,
        None,
        enrollee_pubkey,
        enrollee_addr,
        &mut existing.node,
        PushAddressPolicy::Strict,
        now_unix,
    )
    .expect_err("replay must reject");
    match err {
        ConsumeError::Token(EnrollmentTokenError::AlreadyConsumed) => {}
        other => panic!("expected AlreadyConsumed, got {other:?}"),
    }
}

#[test]
fn token_signed_under_a_different_secret_is_rejected() {
    let issuer = [0xa7u8; ENROLLMENT_SECRET_LEN];
    let attacker = [0xa8u8; ENROLLMENT_SECRET_LEN];
    let now_unix = 1_700_000_100u64;
    let (_, encoded) = mint_token_with_clock(&issuer, 600, now_unix).expect("mint");
    let mut existing = Peer::new(0xa3);
    let enrollee_pubkey = SigningKey::from_bytes(&[0xc5u8; 32]).verifying_key();
    let enrollee_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 101)), 51821);
    let mut ledger = ConsumedTokenLedger::new();
    let err = consume_and_register_peer_with_now(
        &encoded,
        &attacker,
        &mut ledger,
        None,
        enrollee_pubkey,
        enrollee_addr,
        &mut existing.node,
        PushAddressPolicy::Strict,
        now_unix,
    )
    .expect_err("wrong secret must reject");
    assert!(matches!(
        err,
        ConsumeError::Token(EnrollmentTokenError::TagMismatch)
    ));
    assert!(
        existing.node.peers.is_empty(),
        "tampered token must NOT register any peer"
    );
}

#[test]
fn expired_token_is_rejected() {
    let secret = [0xa9u8; ENROLLMENT_SECRET_LEN];
    let issued_at = 1_700_000_000u64;
    let (_, encoded) = mint_token_with_clock(&secret, 60, issued_at).expect("mint");
    let mut existing = Peer::new(0xa4);
    let enrollee_pubkey = SigningKey::from_bytes(&[0xc6u8; 32]).verifying_key();
    let enrollee_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 102)), 51821);
    let mut ledger = ConsumedTokenLedger::new();
    // Now is 3600 seconds AFTER issued_at; TTL was 60 s.
    let err = consume_and_register_peer_with_now(
        &encoded,
        &secret,
        &mut ledger,
        None,
        enrollee_pubkey,
        enrollee_addr,
        &mut existing.node,
        PushAddressPolicy::Strict,
        issued_at + 3600,
    )
    .expect_err("expired token must reject");
    assert!(matches!(
        err,
        ConsumeError::Token(EnrollmentTokenError::Expired { .. })
    ));
}

#[test]
fn strict_policy_refuses_loopback_push_address_under_production_setting() {
    // The IPC handler hard-codes `Strict`. Pin that the loopback
    // address an operator might paste in a hostile context is
    // refused before the token is even consumed.
    let secret = [0xaau8; ENROLLMENT_SECRET_LEN];
    let now_unix = 1_700_000_100u64;
    let (_, encoded) = mint_token_with_clock(&secret, 600, now_unix).expect("mint");
    let mut existing = Peer::new(0xa5);
    let enrollee_pubkey = SigningKey::from_bytes(&[0xc7u8; 32]).verifying_key();
    let loopback_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51821);
    let mut ledger = ConsumedTokenLedger::new();
    let err = consume_and_register_peer_with_now(
        &encoded,
        &secret,
        &mut ledger,
        None,
        enrollee_pubkey,
        loopback_addr,
        &mut existing.node,
        PushAddressPolicy::Strict,
        now_unix,
    )
    .expect_err("loopback push addr under Strict must reject");
    assert!(matches!(err, ConsumeError::UnreachablePushAddress(_)));
    assert_eq!(
        ledger.consumed_count(),
        0,
        "rejected push-address must leave the token intact"
    );
}
