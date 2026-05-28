//! Membership-level role capability enforcement tests.
//!
//! `validate_membership_node_capabilities` (called by `MembershipState::validate`)
//! enforces hard security invariants about which capability combinations are
//! legal. These tests pin those rules from outside the crate so a future
//! refactor cannot silently remove enforcement without breaking the test suite.
//!
//! Rules verified here:
//! - `BlindExit` requires `ExitServer`
//! - `EntryRelay` requires `Client`
//! - `AnchorRelayColocation` requires `RelayHost`
//! - `BlindExit` and `Anchor` (or any anchor sub-capability) cannot coexist
//! - Valid combinations accepted without error

#![forbid(unsafe_code)]

use rustynet_control::membership::{
    MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipError,
    MembershipNode, MembershipNodeStatus, MembershipState,
};
use rustynet_control::roles::RoleCapability;

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build a minimal valid state containing a single node with the given
/// capabilities. Panics if the state fails validation for reasons other
/// than capability rules (i.e. structural invariants are always satisfied).
fn state_with_node_caps(
    node_id: &str,
    capabilities: Vec<RoleCapability>,
) -> Result<(), MembershipError> {
    use ed25519_dalek::SigningKey;
    let owner_pk = SigningKey::from_bytes(&[0x50u8; 32])
        .verifying_key()
        .to_bytes();
    let node_pk = SigningKey::from_bytes(&[0x51u8; 32])
        .verifying_key()
        .to_bytes();
    let state = MembershipState {
        schema_version: 1,
        network_id: "cap-enforcement-net".to_owned(),
        epoch: 1,
        nodes: vec![MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex_lower(&node_pk),
            owner: "alice".to_owned(),
            status: MembershipNodeStatus::Active,
            capabilities,
            roles: vec!["admin".to_owned()],
            joined_at_unix: 1_700_000_000,
            updated_at_unix: 1_700_000_000,
        }],
        approver_set: vec![MembershipApprover {
            approver_id: "owner-1".to_owned(),
            approver_pubkey_hex: hex_lower(&owner_pk),
            role: MembershipApproverRole::Owner,
            status: MembershipApproverStatus::Active,
            created_at_unix: 1_700_000_000,
        }],
        quorum_threshold: 1,
        metadata_hash: None,
    };
    state.validate()
}

// ── Valid combinations ──────────────────────────────────────────────────────

#[test]
fn anchor_with_relay_host_and_sub_caps_is_valid() {
    state_with_node_caps(
        "anchor-node",
        vec![
            RoleCapability::Anchor,
            RoleCapability::RelayHost,
            RoleCapability::AnchorGossipSeed,
            RoleCapability::AnchorBundlePull,
            RoleCapability::AnchorEnrollmentEndpoint,
            RoleCapability::AnchorRelayColocation,
            RoleCapability::AnchorPortMappingAuthoritative,
        ],
    )
    .expect("full anchor capability set must be valid");
}

#[test]
fn exit_server_with_blind_exit_is_valid() {
    state_with_node_caps(
        "blind-exit-node",
        vec![RoleCapability::ExitServer, RoleCapability::BlindExit],
    )
    .expect("ExitServer + BlindExit must be valid");
}

#[test]
fn client_with_entry_relay_is_valid() {
    state_with_node_caps(
        "entry-relay-node",
        vec![RoleCapability::Client, RoleCapability::EntryRelay],
    )
    .expect("Client + EntryRelay must be valid");
}

// ── Invalid combinations ────────────────────────────────────────────────────

#[test]
fn blind_exit_without_exit_server_is_rejected() {
    let err = state_with_node_caps("bad-node", vec![RoleCapability::BlindExit])
        .expect_err("BlindExit without ExitServer must fail validate");
    match err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("blind_exit"),
                "error must mention blind_exit: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

#[test]
fn entry_relay_without_client_is_rejected() {
    let err = state_with_node_caps("bad-node", vec![RoleCapability::EntryRelay])
        .expect_err("EntryRelay without Client must fail validate");
    match err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("entry_relay"),
                "error must mention entry_relay: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

#[test]
fn anchor_relay_colocation_without_relay_host_is_rejected() {
    let err = state_with_node_caps(
        "bad-node",
        vec![
            RoleCapability::Anchor,
            RoleCapability::AnchorRelayColocation,
        ],
    )
    .expect_err("AnchorRelayColocation without RelayHost must fail validate");
    match err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("relay_colocation") || msg.contains("relay_host"),
                "error must mention colocation or relay_host: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

#[test]
fn blind_exit_cannot_coexist_with_anchor() {
    let err = state_with_node_caps(
        "bad-node",
        vec![
            RoleCapability::ExitServer,
            RoleCapability::BlindExit,
            RoleCapability::Anchor,
        ],
    )
    .expect_err("BlindExit + Anchor must fail validate");
    match err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("anchor") || msg.contains("blind_exit"),
                "error must mention anchor or blind_exit: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

#[test]
fn blind_exit_cannot_coexist_with_anchor_sub_capability() {
    // Even without the top-level Anchor capability, having an anchor
    // sub-capability alongside BlindExit is forbidden.
    let err = state_with_node_caps(
        "bad-node",
        vec![
            RoleCapability::ExitServer,
            RoleCapability::BlindExit,
            RoleCapability::AnchorGossipSeed, // anchor sub-cap, no Anchor root
        ],
    )
    .expect_err("BlindExit + anchor sub-cap must fail validate");
    match err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("anchor") || msg.contains("blind_exit"),
                "error must mention anchor or blind_exit: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}
