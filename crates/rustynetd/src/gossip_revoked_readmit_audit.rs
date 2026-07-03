#![allow(clippy::result_large_err)]

//! Adversarial self-audit proving GM-1's fix actually works: `GossipNode`
//! must refuse to (re-)admit a peer that is currently Revoked/Quarantined in
//! signed membership, even when that peer's bundle passes signature,
//! freshness, and sequence checks.
//!
//! Companion of the orchestrator-side `evaluate_gossip_revoked_readmit_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd gossip-revoked-readmit-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §6.B/§6.C.1 — membership revocation must be
//! enforced before trust-sensitive gossip. `GossipNode::ingest_inbound_bundle`
//! (RSA-0034) used to check only `self.peers` (routing/verification state),
//! never signed membership status — a revoked node could re-advertise itself
//! and be re-admitted via gossip alone, even after the dataplane ACL fix
//! (DD-03/RSA-0007) closed the main access channel. The fix adds
//! `GossipNode::revoked_peer_ids` (populated from verified membership via
//! `set_revoked_peer_ids`/`revoked_peer_ids_from_membership`) and checks it
//! on every inbound bundle, after signature verification and before any
//! state mutation.
//!
//! This audit drives the REAL shipped `GossipNode`, in-process, with
//! synthetic Ed25519 keys and no production key, socket, or state:
//!   - a bundle from a peer marked Revoked in membership MUST be rejected
//!     with `GossipError::RevokedSource`, and its endpoints must never be
//!     admitted;
//!   - the SAME scenario with an Active (non-revoked) peer MUST be
//!     accepted — proving this audit isn't vacuously "always reject".
//!
//! It FAILs LOUD (non-zero exit) if a revoked peer's bundle is ever admitted
//! or the active-peer baseline is wrongly denied.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::dataplane_candidates::CandidateSet;
use crate::gossip_runtime::{GossipNode, GossipNodeError};
use crate::peer_gossip::{GossipError, mint_bundle_with_timestamp};

const GOSSIP_REVOKED_READMIT_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_NOW_UNIX: u64 = 1_700_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipRevokedReadmitAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the 1 "must reject" case that was correctly REJECTED.
    pub revoked_denied: u32,
    /// Count of the 1 "must accept" baseline case that was correctly
    /// ACCEPTED.
    pub active_accepted: u32,
    pub violations: Vec<GossipRevokedReadmitCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GossipRevokedReadmitCaseResult {
    pub id: String,
    pub expectation: String,
    pub outcome: String,
    pub reason: String,
    pub passed: bool,
}

fn loopback_bind() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn build_failed_result(
    id: &str,
    expect_denied: bool,
    reason: String,
) -> GossipRevokedReadmitCaseResult {
    GossipRevokedReadmitCaseResult {
        id: id.to_owned(),
        expectation: if expect_denied { "reject" } else { "accept" }.to_owned(),
        outcome: "build_failed".to_owned(),
        reason,
        passed: false,
    }
}

/// Constructs a receiver `GossipNode`, registers a sender peer as a known
/// (routable, verified) peer, mints a validly-signed bundle from that
/// sender, and ingests it — optionally after marking the sender revoked.
fn run_case(
    id: &str,
    receiver_key_byte: u8,
    sender_key_byte: u8,
    revoke_sender: bool,
) -> GossipRevokedReadmitCaseResult {
    let receiver_key = SigningKey::from_bytes(&[receiver_key_byte; 32]);
    let mut receiver = match GossipNode::new(receiver_key, None) {
        Ok(node) => node,
        Err(err) => return build_failed_result(id, revoke_sender, format!("{err:?}")),
    };
    let sender_key = SigningKey::from_bytes(&[sender_key_byte; 32]);
    let sender_id = sender_key.verifying_key().to_bytes();
    receiver.register_peer(sender_id, sender_key.verifying_key(), loopback_bind());
    if revoke_sender {
        receiver.set_revoked_peer_ids([sender_id]);
    }
    let mut candidates = CandidateSet::default();
    candidates
        .v4_host
        .push(IpAddr::V4(Ipv4Addr::new(10, 0, 0, sender_key_byte)));
    let bundle = match mint_bundle_with_timestamp(&sender_key, 1, AUDIT_NOW_UNIX, candidates) {
        Ok(bundle) => bundle,
        Err(err) => {
            return build_failed_result(id, revoke_sender, format!("mint failed: {err}"));
        }
    };
    let expectation = if revoke_sender { "reject" } else { "accept" };
    match receiver.ingest_inbound_bundle_without_rebroadcast_for_local_audit(
        None,
        bundle,
        AUDIT_NOW_UNIX,
    ) {
        Ok(summary) => {
            let endpoints_applied = !summary.applied_endpoints.is_empty()
                && receiver.applied_endpoints.contains_key(&sender_id);
            GossipRevokedReadmitCaseResult {
                id: id.to_owned(),
                expectation: expectation.to_owned(),
                outcome: if endpoints_applied {
                    "accepted".to_owned()
                } else {
                    "accepted_without_endpoints".to_owned()
                },
                reason: "ACCEPTED: bundle admitted, endpoints applied".to_owned(),
                passed: !revoke_sender && endpoints_applied,
            }
        }
        Err(GossipNodeError::Bundle(err)) => {
            let is_revoked_rejection = matches!(err, GossipError::RevokedSource);
            GossipRevokedReadmitCaseResult {
                id: id.to_owned(),
                expectation: expectation.to_owned(),
                outcome: "rejected".to_owned(),
                reason: err.to_string(),
                passed: revoke_sender && is_revoked_rejection,
            }
        }
        Err(other) => GossipRevokedReadmitCaseResult {
            id: id.to_owned(),
            expectation: expectation.to_owned(),
            outcome: "rejected_other".to_owned(),
            reason: format!("{other:?}"),
            passed: false,
        },
    }
}

pub fn run_gossip_revoked_readmit_audit() -> Result<GossipRevokedReadmitAuditReport, String> {
    let results = [
        run_case("revoked_peer_bundle_denied", 1, 7, true),
        run_case("active_peer_bundle_accepted", 2, 8, false),
    ];

    let revoked_denied = results
        .iter()
        .filter(|r| r.expectation == "reject" && r.passed)
        .count() as u32;
    let active_accepted = results
        .iter()
        .filter(|r| r.expectation == "accept" && r.passed)
        .count() as u32;
    let violations: Vec<GossipRevokedReadmitCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(GossipRevokedReadmitAuditReport {
        schema_version: GOSSIP_REVOKED_READMIT_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        revoked_denied,
        active_accepted,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_fixed_gossip_node() {
        let report = run_gossip_revoked_readmit_audit().expect("audit runs");
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 2);
        assert_eq!(report.revoked_denied, 1);
        assert_eq!(report.active_accepted, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn revoked_case_is_individually_denied() {
        let result = run_case("case", 3, 9, true);
        assert!(
            result.passed,
            "revoked peer bundle must be denied: {result:?}"
        );
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn active_case_is_accepted_not_vacuously_denied() {
        let result = run_case("case", 4, 10, false);
        assert!(
            result.passed,
            "active peer bundle must be accepted: {result:?}"
        );
        assert_eq!(result.outcome, "accepted");
    }
}
