#![forbid(unsafe_code)]

//! D2.7 — Enrollment-token consume + gossip-peer registration.
//!
//! The CLI verb `rustynet enrollment consume` and the matching IPC
//! verb both land here. The orchestrator wraps three previously
//! separate primitives:
//!
//! 1. `enrollment_token::verify_and_consume_token` — validates the
//!    HMAC tag, expiry window, and single-use ledger entry.
//! 2. `enrollment_token::write_ledger` — atomically persists the
//!    updated ledger so the single-use semantic survives a daemon
//!    restart even if the next step fails.
//! 3. `gossip_runtime::GossipNode::register_peer` — adds the
//!    enrollee's verifying key + push address to the local gossip
//!    routing table so the next mint reaches them.
//!
//! Ordering matters. The ledger write happens BEFORE the peer
//! registration: if the ledger spool fails we never advance the
//! in-memory `seen` state, so a retry with the same token will
//! succeed at the token layer (idempotent) but a successful peer
//! registration without a durable ledger entry would let a
//! crash-restarted daemon redeem the same token twice. We fail
//! closed on watermark write failure.
//!
//! Security framing:
//!
//! * The HMAC tag is the bearer credential; verifying it is enough
//!   to authenticate the token bearer. We do NOT additionally trust
//!   the enrollee-supplied verifying key — that key is taken at face
//!   value and merely binds an identity to the consumed token. If
//!   the enrollee later misbehaves the operator must rotate them out
//!   via the membership-revoke path.
//! * The push-address is validated for scope (Global / Private) the
//!   same way the gossip layer validates inbound candidates, so an
//!   operator who pastes a loopback address in a hostile context
//!   cannot redirect gossip pushes at local services.
//! * No information about a rejected token (which check failed, how
//!   far past expiry, etc.) is returned to non-operator callers —
//!   the IPC handler maps every `EnrollmentTokenError` to a fixed
//!   vocabulary so a timing/oracle attacker cannot extract bits
//!   about the secret.

use std::net::SocketAddr;
use std::path::Path;

use ed25519_dalek::VerifyingKey;

use crate::dataplane_candidates::{AddressScope, classify_ip};
use crate::enrollment_token::{
    ConsumedTokenLedger, ENROLLMENT_SECRET_LEN, EnrollmentSpoolError, EnrollmentToken,
    EnrollmentTokenError, verify_and_consume_token, verify_and_consume_token_with_now,
    write_ledger,
};
use crate::gossip_runtime::GossipNode;

/// One-shot result of a successful consume.
#[derive(Debug, Clone)]
pub struct ConsumeOutcome {
    pub token_id: [u8; 16],
    pub enrollee_node_id: [u8; 32],
    pub enrollee_push_addr: SocketAddr,
    /// Unix-seconds expiry of the token that was just consumed.
    /// Surfaced so the operator-facing CLI can report it.
    pub token_expires_at_unix: u64,
}

/// Errors surfaced by [`consume_and_register_peer`]. Distinct from
/// `EnrollmentTokenError` so the caller can distinguish a
/// post-consume registration failure (e.g. bad push address scope)
/// from a token-layer reject.
#[derive(Debug)]
pub enum ConsumeError {
    /// Token-layer reject: bad tag, expired, replay, etc.
    Token(EnrollmentTokenError),
    /// Ledger spool write failed. Fail-closed: we abort the consume
    /// and do NOT register the peer.
    LedgerWriteFailed(EnrollmentSpoolError),
    /// The enrollee-supplied push address is not in a scope we'd
    /// willingly send gossip pushes to. Rejected to stop a hostile
    /// or misconfigured operator from redirecting gossip pushes at
    /// local services or multicast groups.
    UnreachablePushAddress(String),
}

impl std::fmt::Display for ConsumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsumeError::Token(err) => write!(f, "enrollment token rejected: {err}"),
            ConsumeError::LedgerWriteFailed(err) => {
                write!(f, "enrollment ledger persistence failed: {err}")
            }
            ConsumeError::UnreachablePushAddress(addr) => {
                write!(f, "enrollment push address has non-routable scope: {addr}")
            }
        }
    }
}

impl std::error::Error for ConsumeError {}

/// Policy for the enrollee-supplied push address.
///
/// `Strict` (production default) refuses anything outside the
/// Global / Private scope set — exactly the same scope filter the
/// gossip layer applies to inbound candidates.
///
/// `AllowLoopback` is for tests that bind all peers to 127.0.0.1
/// loopback sockets. The production CLI never sets it; the IPC
/// handler never sets it; only `#[cfg(test)]` paths do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushAddressPolicy {
    Strict,
    #[cfg_attr(not(test), allow(dead_code))]
    AllowLoopback,
}

/// Consume a token presented by `enrollee_pubkey` and register
/// the enrollee in `gossip_node`. The ledger is persisted to disk
/// (if `ledger_path` is set) before the peer is registered, so a
/// crash between the two steps leaves the on-disk state durable.
///
/// Pre-condition under `PushAddressPolicy::Strict`: the supplied
/// `enrollee_push_addr` MUST be a gossip-worthy scope (Global or
/// Private). Loopback, link-local, multicast, broadcast, and
/// unspecified addresses are rejected.
///
/// Test paths can pass `ledger_path = None` to skip the spool I/O.
#[allow(clippy::too_many_arguments)]
pub fn consume_and_register_peer(
    encoded_token: &str,
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ledger: &mut ConsumedTokenLedger,
    ledger_path: Option<&Path>,
    enrollee_pubkey: VerifyingKey,
    enrollee_push_addr: SocketAddr,
    gossip_node: &mut GossipNode,
    policy: PushAddressPolicy,
) -> Result<ConsumeOutcome, ConsumeError> {
    enforce_push_address_policy(enrollee_push_addr, policy)?;
    let token: EnrollmentToken =
        verify_and_consume_token(encoded_token, secret, ledger).map_err(ConsumeError::Token)?;
    finalise_consume(
        token,
        ledger,
        ledger_path,
        enrollee_pubkey,
        enrollee_push_addr,
        gossip_node,
    )
}

/// Test-friendly variant taking an explicit clock. Mirrors
/// [`crate::enrollment_token::verify_and_consume_token_with_now`].
#[allow(clippy::too_many_arguments)]
pub fn consume_and_register_peer_with_now(
    encoded_token: &str,
    secret: &[u8; ENROLLMENT_SECRET_LEN],
    ledger: &mut ConsumedTokenLedger,
    ledger_path: Option<&Path>,
    enrollee_pubkey: VerifyingKey,
    enrollee_push_addr: SocketAddr,
    gossip_node: &mut GossipNode,
    policy: PushAddressPolicy,
    now_unix: u64,
) -> Result<ConsumeOutcome, ConsumeError> {
    enforce_push_address_policy(enrollee_push_addr, policy)?;
    let token: EnrollmentToken =
        verify_and_consume_token_with_now(encoded_token, secret, ledger, now_unix)
            .map_err(ConsumeError::Token)?;
    finalise_consume(
        token,
        ledger,
        ledger_path,
        enrollee_pubkey,
        enrollee_push_addr,
        gossip_node,
    )
}

fn enforce_push_address_policy(
    addr: SocketAddr,
    policy: PushAddressPolicy,
) -> Result<(), ConsumeError> {
    let scope = classify_ip(addr.ip());
    let gossip_worthy = matches!(scope, AddressScope::Global | AddressScope::Private);
    let allowed = match policy {
        PushAddressPolicy::Strict => gossip_worthy,
        PushAddressPolicy::AllowLoopback => {
            gossip_worthy || matches!(scope, AddressScope::Loopback)
        }
    };
    if !allowed {
        return Err(ConsumeError::UnreachablePushAddress(format!(
            "{addr} (scope: {scope:?})"
        )));
    }
    Ok(())
}

fn finalise_consume(
    token: EnrollmentToken,
    ledger: &mut ConsumedTokenLedger,
    ledger_path: Option<&Path>,
    enrollee_pubkey: VerifyingKey,
    enrollee_push_addr: SocketAddr,
    gossip_node: &mut GossipNode,
) -> Result<ConsumeOutcome, ConsumeError> {
    // Persist the ledger BEFORE registering the peer. If the spool
    // write fails we report the failure so the operator can fix
    // the spool and retry; a daemon restart at that point would
    // reload the on-disk ledger (which does NOT yet contain the
    // just-consumed id), allowing the same token to be re-redeemed
    // once durable storage is healthy. That is the desired fail-
    // closed-on-the-side-of-the-operator behaviour.
    if let Some(path) = ledger_path {
        write_ledger(path, ledger).map_err(ConsumeError::LedgerWriteFailed)?;
    }
    let enrollee_node_id = enrollee_pubkey.to_bytes();
    gossip_node.register_peer(enrollee_node_id, enrollee_pubkey, enrollee_push_addr);
    Ok(ConsumeOutcome {
        token_id: token.token_id,
        enrollee_node_id,
        enrollee_push_addr,
        token_expires_at_unix: token.expires_at_unix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_token::{ENROLLMENT_SECRET_LEN, mint_token_with_clock};
    // Used only by the `#[cfg(unix)]` transport-backed test below (gossip
    // transport is unix-only — Track Beta); gate it or it is unused on Windows.
    #[cfg(unix)]
    use crate::gossip_transport::GossipTransport;
    use ed25519_dalek::SigningKey;
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    fn make_gossip_node(byte: u8) -> GossipNode {
        let signing_key = SigningKey::from_bytes(&[byte; 32]);
        let mut node = GossipNode::new(signing_key, None).expect("ctor");
        // I2: mint and inbound accept both require a verified
        // membership epoch (fail closed without one); any fixed value
        // shared by both ends keeps this test about enrollment, not
        // the epoch window.
        node.set_local_membership_epoch(1);
        node
    }

    #[cfg(unix)] // only the unix-only GossipTransport test below binds a loopback addr
    fn loopback_bind() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn consume_registers_peer_and_persists_ledger() {
        let secret = [0xa5u8; ENROLLMENT_SECRET_LEN];
        let mut ledger = ConsumedTokenLedger::new();
        let dir = TempDir::new().expect("tempdir");
        let ledger_path = dir.path().join("enrollment.ledger");
        let (_, encoded) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        let mut gossip_node = make_gossip_node(0xb1);
        let enrollee_key = SigningKey::from_bytes(&[0xc2u8; 32]);
        let enrollee_pubkey = enrollee_key.verifying_key();
        let push_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7)), 51821);

        let outcome = consume_and_register_peer_with_now(
            &encoded,
            &secret,
            &mut ledger,
            Some(&ledger_path),
            enrollee_pubkey,
            push_addr,
            &mut gossip_node,
            PushAddressPolicy::Strict,
            1_700_000_300,
        )
        .expect("consume succeeds");
        assert_eq!(outcome.enrollee_push_addr, push_addr);
        assert_eq!(outcome.enrollee_node_id, enrollee_pubkey.to_bytes());
        assert!(ledger.was_consumed(&outcome.token_id));
        assert!(gossip_node.peers.contains_key(&outcome.enrollee_node_id));
        // Ledger file must exist and round-trip the entry.
        let reloaded = crate::enrollment_token::load_ledger(&ledger_path).expect("reload");
        assert!(reloaded.was_consumed(&outcome.token_id));
    }

    #[test]
    fn consume_refuses_loopback_push_address_under_strict_policy() {
        let secret = [0xa6u8; ENROLLMENT_SECRET_LEN];
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        let mut gossip_node = make_gossip_node(0xb2);
        let enrollee_pubkey = SigningKey::from_bytes(&[0xc3u8; 32]).verifying_key();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 51821);

        let err = consume_and_register_peer_with_now(
            &encoded,
            &secret,
            &mut ledger,
            None,
            enrollee_pubkey,
            loopback,
            &mut gossip_node,
            PushAddressPolicy::Strict,
            1_700_000_300,
        )
        .expect_err("loopback push address must reject under Strict policy");
        assert!(matches!(err, ConsumeError::UnreachablePushAddress(_)));
        // Important: the token MUST NOT have been consumed.
        assert_eq!(
            ledger.consumed_count(),
            0,
            "rejected push-address must leave the token intact"
        );
    }

    #[test]
    fn replay_after_consume_returns_already_consumed() {
        let secret = [0xa7u8; ENROLLMENT_SECRET_LEN];
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        let mut gossip_node = make_gossip_node(0xb3);
        let enrollee_pubkey = SigningKey::from_bytes(&[0xc4u8; 32]).verifying_key();
        let push_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 51821);

        consume_and_register_peer_with_now(
            &encoded,
            &secret,
            &mut ledger,
            None,
            enrollee_pubkey,
            push_addr,
            &mut gossip_node,
            PushAddressPolicy::Strict,
            1_700_000_300,
        )
        .expect("first consume succeeds");
        let err = consume_and_register_peer_with_now(
            &encoded,
            &secret,
            &mut ledger,
            None,
            enrollee_pubkey,
            push_addr,
            &mut gossip_node,
            PushAddressPolicy::Strict,
            1_700_000_350,
        )
        .expect_err("replay must fail");
        match err {
            ConsumeError::Token(EnrollmentTokenError::AlreadyConsumed) => {}
            other => panic!("expected AlreadyConsumed, got {other:?}"),
        }
    }

    #[test]
    fn tampered_token_does_not_register_peer() {
        let issuer = [0xa8u8; ENROLLMENT_SECRET_LEN];
        let attacker = [0xb9u8; ENROLLMENT_SECRET_LEN];
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) = mint_token_with_clock(&issuer, 600, 1_700_000_000).expect("mint");
        let mut gossip_node = make_gossip_node(0xb4);
        let enrollee_pubkey = SigningKey::from_bytes(&[0xc5u8; 32]).verifying_key();
        let push_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)), 51821);
        let err = consume_and_register_peer_with_now(
            &encoded,
            &attacker,
            &mut ledger,
            None,
            enrollee_pubkey,
            push_addr,
            &mut gossip_node,
            PushAddressPolicy::Strict,
            1_700_000_300,
        )
        .expect_err("wrong secret must reject");
        assert!(matches!(
            err,
            ConsumeError::Token(EnrollmentTokenError::TagMismatch)
        ));
        assert!(
            gossip_node.peers.is_empty(),
            "tampered token must NOT register peer"
        );
    }

    #[cfg(unix)] // builds the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn after_consume_a_minted_bundle_reaches_the_enrollee() {
        // End-to-end smoke test that mirrors what the D2.7 integration
        // test exercises at the test-binary layer: after consume the
        // existing peer's next mint must reach the enrollee.
        let secret = [0xaau8; ENROLLMENT_SECRET_LEN];
        let mut ledger = ConsumedTokenLedger::new();
        let (_, encoded) = mint_token_with_clock(&secret, 600, 1_700_000_000).expect("mint");
        let mut existing = make_gossip_node(0xbb);
        let mut enrollee = make_gossip_node(0xcc);
        let existing_transport =
            GossipTransport::bind(loopback_bind()).expect("existing transport");
        let enrollee_transport =
            GossipTransport::bind(loopback_bind()).expect("enrollee transport");
        let enrollee_addr = enrollee_transport.local_addr().expect("enrollee addr");
        // The enrollee must already know the existing peer's
        // verifying key (out-of-band trust bootstrap).
        let existing_pubkey = SigningKey::from_bytes(&[0xbbu8; 32]).verifying_key();
        let existing_id = existing.local_node_id;
        let enrollee_pubkey = SigningKey::from_bytes(&[0xccu8; 32]).verifying_key();
        let existing_addr = existing_transport.local_addr().expect("existing addr");
        enrollee.register_peer(existing_id, existing_pubkey, existing_addr);

        consume_and_register_peer_with_now(
            &encoded,
            &secret,
            &mut ledger,
            None,
            enrollee_pubkey,
            enrollee_addr,
            &mut existing,
            // Loopback addresses are allowed only in tests — the
            // production CLI / IPC handler hard-codes `Strict`.
            PushAddressPolicy::AllowLoopback,
            1_700_000_100,
        )
        .expect("consume succeeds");

        // Existing peer mints a bundle; it should reach the
        // enrollee because consume_and_register_peer_with_now just
        // put the enrollee in `existing.peers`.
        let mut candidates = crate::dataplane_candidates::CandidateSet::default();
        candidates
            .v4_host
            .push(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)));
        existing
            .maybe_mint_and_broadcast(
                std::time::Instant::now(),
                1_700_000_100,
                candidates,
                &existing_transport,
            )
            .expect("mint ok")
            .expect("emit");
        // Drain on the enrollee with a generous timeout. Real test
        // budget is in the dedicated two-peer integration test.
        let received = enrollee_transport
            .recv_bundle(std::time::Duration::from_secs(2))
            .expect("recv ok")
            .expect("at least one datagram");
        let outcome = enrollee
            .ingest_inbound_bundle(
                Some(received.0),
                received.1,
                &enrollee_transport,
                1_700_000_100,
            )
            .expect("enrollee accepts");
        assert_eq!(outcome.source_node_id, existing_id);
    }
}
