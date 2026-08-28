#![forbid(unsafe_code)]

//! D2.7 — Enrollment-to-membership bridge.
//!
//! After the operator on an existing peer consumes a fresh
//! enrollment token presented by a new device, the new device must
//! be folded into the signed membership snapshot so the rest of the
//! mesh learns about its identity. Without that step the new device
//! is reachable from the existing peer (via the gossip-routing
//! registration in `enrollment_consume`) but invisible to every
//! other peer, which is the trust-propagation gap the user wants
//! closed.
//!
//! This module is the bridge: given the current snapshot and the
//! enrollee's identity, [`build_add_node_record_for_enrollee`]
//! produces an unsigned [`MembershipUpdateRecord`] for an `AddNode`
//! operation. The operator then runs the existing
//! `sign-update` → `apply-update` membership flow (or the new
//! one-shot `rustynet enrollment admit` CLI verb which does both at
//! once when quorum is achievable in a single signature).
//!
//! Security framing:
//!
//! * The membership update produced here carries no signatures.
//!   It MUST be signed by enough approvers to meet
//!   `state.quorum_threshold` before it can be applied. The existing
//!   apply-update path enforces this; we do not relax it.
//! * The enrollee's verifying key is taken at face value — that is
//!   the same trust model as every other AddNode update, which is
//!   sanctioned by the approvers signing the membership update.
//!   We do NOT pretend the token consumes provides additional
//!   approver-grade trust; the approver(s) doing the signing are
//!   the trust authority.
//! * The reducer-preview is the existing public `preview_next_state`
//!   helper — we never bypass the reducer or shortcut the state-
//!   root computation. A misconfigured reason code or owner would
//!   still produce a record that round-trips through
//!   `apply_signed_update`.

use crate::membership::{
    MembershipError, MembershipNode, MembershipNodeStatus, MembershipOperation, MembershipState,
    MembershipUpdateRecord, preview_next_state, validate_membership_payload_field,
};
use crate::roles::{RoleCapability, canonicalize_role_capabilities};

/// Default time-to-live for a freshly-built AddNode update. Mirrors
/// the membership Propose CLI's default TTL — long enough to walk
/// an operator through co-signing if quorum > 1, short enough that
/// a stale update doesn't sit around indefinitely.
pub const DEFAULT_ADMIT_UPDATE_TTL_SECS: u64 = 60 * 60;

/// Construction-time inputs for [`build_add_node_record_for_enrollee`].
/// Distinct struct (rather than a long argument list) so the call
/// site is readable and a future field addition stays additive at
/// the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolleeAdmitContext {
    /// Logical node id the enrollee will carry in the membership
    /// snapshot (e.g. "minipc-2"). Must not collide with an existing
    /// node id; the reducer rejects duplicates with
    /// `InvalidTransition`.
    pub node_id: String,
    /// Enrollee's 32-byte Ed25519 verifying key, hex-encoded
    /// lowercase. The reducer rejects non-32-byte values.
    pub node_pubkey_hex: String,
    /// Free-form owner identifier — typically the operator's
    /// principal name, but the membership schema doesn't constrain
    /// it. Surfaced in the canonical update payload.
    pub owner: String,
    /// Roles the enrollee will carry. Empty vec is a legitimate
    /// "client peer with no special privileges" entry.
    pub roles: Vec<String>,
    /// Unique update id (e.g. UUID-style). The replay cache refuses
    /// a second update with the same id under the same epoch.
    pub update_id: String,
    /// Reason code for the audit log (e.g.
    /// `enrollment.token_consume.v1`). Free-form but stable so
    /// downstream audit tooling can group identical-shape updates.
    pub reason_code: String,
    /// Optional policy context — currently passed through verbatim
    /// into the canonical payload.
    pub policy_context: Option<String>,
    /// Wall-clock now in unix seconds, used for `created_at_unix`
    /// and to compute `expires_at_unix`.
    pub now_unix: u64,
    /// TTL window for the produced update. The membership Propose
    /// default is one hour; admit defaults to the same.
    pub ttl_secs: u64,
}

/// Errors specific to the enrollment-to-membership bridge. Most
/// failures funnel into the underlying `MembershipError` variants;
/// this enum adds a single new variant for the "ttl_secs is zero"
/// case so the call site can produce a typed reject without
/// reaching for `InvalidFormat`.
#[derive(Debug)]
pub enum EnrollmentMembershipError {
    /// Caller passed `ttl_secs = 0` — the resulting update would
    /// have `expires_at_unix <= created_at_unix` which the
    /// canonical-payload validator already rejects, but failing
    /// earlier with a clearer diagnostic is friendlier.
    TtlMustBePositive,
    /// Caller passed a `--roles` token the canonical
    /// [`RoleCapability::parse`] does not recognise. Previously such a
    /// token was silently discarded, which is the ENR-05 defect: the
    /// admit reported success while granting something other than what
    /// was asked for.
    UnknownRole(String),
    /// Underlying membership reducer / validation error.
    Membership(MembershipError),
}

impl std::fmt::Display for EnrollmentMembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentMembershipError::TtlMustBePositive => {
                write!(f, "admit update ttl_secs must be > 0")
            }
            EnrollmentMembershipError::UnknownRole(role) => {
                write!(
                    f,
                    "unrecognised role {role:?}; admit accepts only the canonical role-capability tokens"
                )
            }
            EnrollmentMembershipError::Membership(err) => {
                write!(f, "membership bridge failed: {err}")
            }
        }
    }
}

impl std::error::Error for EnrollmentMembershipError {}

impl From<MembershipError> for EnrollmentMembershipError {
    fn from(err: MembershipError) -> Self {
        EnrollmentMembershipError::Membership(err)
    }
}

/// Build an unsigned `AddNode` [`MembershipUpdateRecord`] that adds
/// `ctx.node_id` (with `ctx.node_pubkey_hex` and `ctx.owner`) to the
/// snapshot. The record's `prev_state_root` and `new_state_root` are
/// computed from `state` using the same reducer the apply path uses,
/// so a signature gathered against this record will validate when
/// `apply_signed_update` runs.
///
/// The caller's responsibility:
///
/// 1. Sign the returned record with one or more approver keys (the
///    existing `sign_update_record` helper).
/// 2. Verify quorum: count signatures against `state.quorum_threshold`.
/// 3. Run the existing `apply_signed_update` → `append_membership_log_entry`
///    → `persist_membership_snapshot` flow when quorum is met.
pub fn build_add_node_record_for_enrollee(
    state: &MembershipState,
    ctx: EnrolleeAdmitContext,
) -> Result<MembershipUpdateRecord, EnrollmentMembershipError> {
    if ctx.ttl_secs == 0 {
        return Err(EnrollmentMembershipError::TtlMustBePositive);
    }
    // ENR-01/ENR-03: the operator-supplied identifiers are interpolated into
    // the line-oriented canonical payload this record's state roots are
    // computed over. `MembershipState::validate` is the real chokepoint and
    // would refuse these below, inside `preview_next_state`, but only after a
    // `MembershipError` has been wrapped several layers deep. Checking them
    // here turns "membership bridge failed: invalid format …" into a reject
    // naming the offending input, for the one caller — the admit CLI — whose
    // user typed it.
    validate_membership_payload_field("node id", &ctx.node_id)?;
    validate_membership_payload_field("node owner", &ctx.owner)?;
    let now_unix = ctx.now_unix;
    let expires_at_unix = now_unix.saturating_add(ctx.ttl_secs);
    let candidate_node = MembershipNode {
        node_id: ctx.node_id.clone(),
        node_pubkey_hex: ctx.node_pubkey_hex.clone(),
        owner: ctx.owner.clone(),
        status: MembershipNodeStatus::Active,
        capabilities: enrollee_capabilities_from_roles(&ctx.roles)?,
        roles: ctx.roles,
        joined_at_unix: now_unix,
        updated_at_unix: now_unix,
    };
    let operation = MembershipOperation::AddNode(candidate_node);
    let prev_state_root = state
        .state_root_hex()
        .map_err(EnrollmentMembershipError::from)?;
    // RSA-0009: feed the record's created_at_unix so the root reproduces at apply.
    let next =
        preview_next_state(state, &operation, now_unix).map_err(EnrollmentMembershipError::from)?;
    let new_state_root = next
        .state_root_hex()
        .map_err(EnrollmentMembershipError::from)?;
    Ok(MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: ctx.update_id,
        operation,
        target: ctx.node_id,
        prev_state_root,
        new_state_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch.saturating_add(1),
        created_at_unix: now_unix,
        expires_at_unix,
        reason_code: ctx.reason_code,
        policy_context: ctx.policy_context,
    })
}

/// Map the operator's `--roles` tokens onto signed role capabilities.
///
/// Delegates to the canonical [`RoleCapability::parse`] and rejects anything it
/// does not recognise. This is ENR-05, and the hand-written table this replaced
/// was wrong in **both** directions — the review executed every token the
/// canonical parser accepts:
///
/// - **8 of 14 were silently dropped to `Client`** by the catch-all arm: the six
///   `anchor.*` sub-capabilities plus `serves_nas` and `serves_llm`. So
///   `--roles anchor.bundle_pull` produced a client-only node and reported
///   success.
/// - **4 tokens the canonical parser REJECTS granted `Anchor`** — `admin`,
///   `tag:owners`, `tag:admins`, `tag:servers`. That is the half that matters:
///   `tag:servers` is plausible operator shorthand, and it handed out a
///   control-plane capability.
///
/// RSA-0015 rated this Info on the rationale that the bridge "can only *drop*
/// privilege, so it is fail-safe". The second bullet is the counter-example, and
/// the review recommends re-rating on exactly that ground.
///
/// Two implications must be re-added after parsing, because
/// `canonicalize_role_capabilities` only sorts and dedups — it does not expand.
/// `validate_membership_node_capabilities` requires `BlindExit` to carry
/// `ExitServer` and `EntryRelay` to carry `Client`, so omitting them would make
/// this function emit rosters that the very next validation step rejects.
fn enrollee_capabilities_from_roles(
    roles: &[String],
) -> Result<Vec<RoleCapability>, EnrollmentMembershipError> {
    let mut capabilities = Vec::new();
    for role in roles.iter().map(|role| role.trim()) {
        if role.is_empty() {
            continue;
        }
        let capability = RoleCapability::parse(role)
            .map_err(|_| EnrollmentMembershipError::UnknownRole(role.to_owned()))?;
        capabilities.push(capability);
        match capability {
            RoleCapability::BlindExit => capabilities.push(RoleCapability::ExitServer),
            RoleCapability::EntryRelay => capabilities.push(RoleCapability::Client),
            _ => {}
        }
    }
    if capabilities.is_empty() {
        // Documented and legitimate: no roles requested means a plain client
        // peer. Reachable only from an empty (or all-whitespace) input now that
        // every other unrecognised token is an error.
        capabilities.push(RoleCapability::Client);
    }
    // Blind-relay phase 1 gate (BlindRelayRoleDesign_2026-08-27.md §16):
    // the token parses, but enrollment admission mints production signed
    // state, so it refuses blind_relay until the §16 wire-format decisions
    // are signed off. Same design-only hold as the membership
    // AddNode/SetNodeCapabilities construction paths.
    if capabilities.contains(&RoleCapability::BlindRelay) {
        return Err(EnrollmentMembershipError::UnknownRole(
            "blind_relay capability is design-only; pending §16 wire-format sign-off".to_owned(),
        ));
    }
    Ok(canonicalize_role_capabilities(capabilities))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{
        MembershipApprover, MembershipApproverRole, MembershipApproverStatus,
        MembershipReplayCache, MembershipSignature, SignedMembershipUpdate, apply_signed_update,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn approver_signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn base_state() -> MembershipState {
        let owner_key = approver_signing_key(0x40);
        let owner_pubkey = owner_key.verifying_key().to_bytes();
        // Need at least one existing node so the state is realistic;
        // the enrollee will be the second.
        let founder_key = approver_signing_key(0x41);
        let founder_pubkey = founder_key.verifying_key().to_bytes();
        let state = MembershipState {
            schema_version: 1,
            network_id: "test-net".to_owned(),
            epoch: 1,
            nodes: vec![MembershipNode {
                node_id: "founder".to_owned(),
                node_pubkey_hex: hex_lower(&founder_pubkey),
                owner: "alice".to_owned(),
                status: MembershipNodeStatus::Active,
                capabilities: vec![RoleCapability::Anchor],
                roles: vec!["admin".to_owned()],
                joined_at_unix: 1_700_000_000,
                updated_at_unix: 1_700_000_000,
            }],
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex_lower(&owner_pubkey),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        state.validate().expect("base state is valid");
        state
    }

    #[test]
    fn build_add_node_record_round_trips_through_apply_signed_update() {
        // Pin the full bridge: build the record under the current
        // snapshot, sign it with a quorum of approver keys, then
        // hand the signed update to the existing apply_signed_update
        // path. The resulting state MUST contain the enrollee as an
        // Active node.
        let state = base_state();
        let enrollee_key = approver_signing_key(0xc3);
        let enrollee_pubkey = enrollee_key.verifying_key().to_bytes();
        let now_unix = 1_700_000_500u64;
        let ctx = EnrolleeAdmitContext {
            node_id: "minipc-2".to_owned(),
            node_pubkey_hex: hex_lower(&enrollee_pubkey),
            owner: "alice".to_owned(),
            roles: vec!["client".to_owned()],
            update_id: "test-update-0001".to_owned(),
            reason_code: "enrollment.token_consume.v1".to_owned(),
            policy_context: None,
            now_unix,
            ttl_secs: 3600,
        };
        let record = build_add_node_record_for_enrollee(&state, ctx)
            .expect("build_add_node_record succeeds");
        assert_eq!(record.epoch_prev, 1);
        assert_eq!(record.epoch_new, 2);
        assert_eq!(record.target, "minipc-2");

        // Sign the record with the owner's approver key.
        let owner_key = approver_signing_key(0x40);
        let payload = record.canonical_payload().expect("payload");
        let signature = owner_key.sign(payload.as_bytes());
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![MembershipSignature {
                approver_id: "owner-1".to_owned(),
                signature_hex: hex_lower(&signature.to_bytes()),
                head_signature_hex: None,
            }],
        };

        let mut replay = MembershipReplayCache::default();
        let next =
            apply_signed_update(&state, &signed, now_unix, &mut replay).expect("apply succeeds");
        assert_eq!(next.epoch, 2);
        assert!(
            next.nodes.iter().any(|n| n.node_id == "minipc-2"),
            "post-apply state must contain the enrollee"
        );
        let added = next.nodes.iter().find(|n| n.node_id == "minipc-2").unwrap();
        assert_eq!(added.status, MembershipNodeStatus::Active);
        assert_eq!(added.owner, "alice");
        assert_eq!(added.node_pubkey_hex, hex_lower(&enrollee_pubkey));
    }

    #[test]
    fn build_add_node_record_rejects_zero_ttl() {
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "x".to_owned(),
            node_pubkey_hex: hex_lower(&[1u8; 32]),
            owner: "bob".to_owned(),
            roles: vec![],
            update_id: "u".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 0,
        };
        let err =
            build_add_node_record_for_enrollee(&state, ctx).expect_err("zero ttl must reject");
        assert!(matches!(err, EnrollmentMembershipError::TtlMustBePositive));
    }

    /// ENR-05, the silent-drop half. Every token the canonical parser accepts
    /// must survive the bridge as the capability the parser named.
    ///
    /// The expectation is *derived from* `RoleCapability::parse` rather than
    /// hand-copied into this test, deliberately: a second hand-written table is
    /// what produced ENR-05 in the first place, and a hand-copied expectation
    /// would drift the same way and keep passing. Adding a new capability to
    /// the canonical parser therefore extends this test automatically.
    #[test]
    fn every_canonical_role_token_survives_the_bridge() {
        const CANONICAL_TOKENS: &[&str] = &[
            "anchor",
            "client",
            "exit_server",
            "blind_exit",
            "relay_host",
            "entry_relay",
            "anchor.gossip_seed",
            "anchor.bundle_pull",
            "anchor.enrollment_endpoint",
            "anchor.relay_colocation",
            "anchor.port_mapping_authoritative",
            "anchor.port_mapping_pinned",
            "serves_nas",
            "serves_llm",
        ];

        for token in CANONICAL_TOKENS {
            let expected = RoleCapability::parse(token)
                .unwrap_or_else(|err| panic!("{token} is not canonical: {err}"));
            let produced = enrollee_capabilities_from_roles(&[(*token).to_owned()])
                .unwrap_or_else(|err| panic!("{token} rejected by the bridge: {err}"));
            assert!(
                produced.contains(&expected),
                "role {token} produced {produced:?}, which does not include {expected:?} \
                 — this is the ENR-05 silent drop"
            );
        }
    }

    /// ENR-05, the privilege-granting half — the reason the finding is not
    /// merely cosmetic. These four are REJECTED by the canonical parser and yet
    /// the old hand-written table mapped every one of them to `Anchor`, a
    /// control-plane capability. `tag:servers` in particular is plausible
    /// operator shorthand.
    #[test]
    fn tokens_the_canonical_parser_rejects_no_longer_grant_anchor() {
        for token in ["admin", "tag:owners", "tag:admins", "tag:servers"] {
            assert!(
                RoleCapability::parse(token).is_err(),
                "{token} is canonical after all — this test's premise is stale"
            );
            let err = enrollee_capabilities_from_roles(&[token.to_owned()])
                .expect_err("a non-canonical token must not silently grant a capability");
            match err {
                EnrollmentMembershipError::UnknownRole(reported) => {
                    assert_eq!(reported, token)
                }
                other => panic!("{token} produced the wrong error: {other:?}"),
            }
        }

        // The aliases the old table invented are gone too. They were never
        // canonical, so accepting them taught operators a vocabulary the rest
        // of the system does not share.
        for token in ["exit", "relay", "entry", "tag:members", "tag:clients"] {
            assert!(
                enrollee_capabilities_from_roles(&[token.to_owned()]).is_err(),
                "non-canonical alias {token} must be rejected"
            );
        }
    }

    /// Blind-relay phase 1: the token parses, but enrollment admission
    /// mints production signed state, so it must refuse blind_relay until
    /// the §16 wire-format decisions are signed off.
    #[test]
    fn enrollment_admission_refuses_blind_relay_pending_sign_off() {
        for token in ["blind_relay", "blind-relay"] {
            let err = enrollee_capabilities_from_roles(&[token.to_owned()])
                .expect_err("design-only capability must not be admitted");
            let rendered = format!("{err}");
            assert!(
                rendered.contains("design-only; pending §16 wire-format sign-off"),
                "{token} produced the wrong refusal: {rendered}"
            );
        }
    }

    /// The two implications `canonicalize_role_capabilities` does not expand.
    /// Without them the bridge emits a roster that
    /// `validate_membership_node_capabilities` immediately rejects, so this
    /// pins the round trip through a real record build rather than just the
    /// helper's return value.
    #[test]
    fn implied_capabilities_survive_the_delegation() {
        let blind = enrollee_capabilities_from_roles(&["blind_exit".to_owned()]).expect("blind");
        assert!(blind.contains(&RoleCapability::BlindExit));
        assert!(
            blind.contains(&RoleCapability::ExitServer),
            "blind_exit must imply exit_server or validate rejects it: {blind:?}"
        );

        let entry = enrollee_capabilities_from_roles(&["entry_relay".to_owned()]).expect("entry");
        assert!(entry.contains(&RoleCapability::EntryRelay));
        assert!(
            entry.contains(&RoleCapability::Client),
            "entry_relay must imply client or validate rejects it: {entry:?}"
        );

        // No roles at all remains a plain client peer, which is documented
        // behaviour rather than an accident of the old catch-all arm.
        assert_eq!(
            enrollee_capabilities_from_roles(&[]).expect("empty"),
            vec![RoleCapability::Client]
        );

        // A record built from blind_exit must actually validate end to end.
        let ctx = EnrolleeAdmitContext {
            node_id: "blind-1".to_owned(),
            node_pubkey_hex: hex_lower(&[7u8; 32]),
            owner: "bob".to_owned(),
            roles: vec!["blind_exit".to_owned()],
            update_id: "u-blind".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 3_600,
        };
        build_add_node_record_for_enrollee(&base_state(), ctx)
            .expect("a blind_exit admit must still build a valid record");
    }

    /// ENR-01: `admit --node-id` carrying a newline was accepted end to end —
    /// the epoch advanced and the snapshot persisted, after which every later
    /// load failed on the forged line. The bridge is the last shared point
    /// before the record's state roots are computed, so it must refuse the
    /// input rather than sign over it.
    #[test]
    fn build_add_node_record_rejects_framing_bytes_in_operator_identifiers() {
        for hostile in [
            "minipc-2\nnode.1.status=revoked",
            "minipc-2\r",
            "minipc-2=x",
        ] {
            let ctx = EnrolleeAdmitContext {
                node_id: hostile.to_owned(),
                node_pubkey_hex: hex_lower(&[1u8; 32]),
                owner: "bob".to_owned(),
                roles: vec![],
                update_id: "u".to_owned(),
                reason_code: "r".to_owned(),
                policy_context: None,
                now_unix: 1_700_000_500,
                ttl_secs: 3_600,
            };
            let err = build_add_node_record_for_enrollee(&base_state(), ctx)
                .expect_err("hostile node id must reject");
            assert!(
                matches!(err, EnrollmentMembershipError::Membership(_)),
                "node_id {hostile:?} produced the wrong error: {err:?}"
            );

            let ctx = EnrolleeAdmitContext {
                node_id: "minipc-2".to_owned(),
                node_pubkey_hex: hex_lower(&[1u8; 32]),
                owner: hostile.to_owned(),
                roles: vec![],
                update_id: "u".to_owned(),
                reason_code: "r".to_owned(),
                policy_context: None,
                now_unix: 1_700_000_500,
                ttl_secs: 3_600,
            };
            assert!(
                build_add_node_record_for_enrollee(&base_state(), ctx).is_err(),
                "owner {hostile:?} must reject"
            );
        }
    }

    #[test]
    fn build_add_node_record_propagates_reducer_reject_for_duplicate_node_id() {
        // The reducer rejects an AddNode whose node_id already
        // exists. The bridge must surface that reject — no silent
        // overwrite, no shortcut.
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "founder".to_owned(), // collision with base_state
            node_pubkey_hex: hex_lower(&[2u8; 32]),
            owner: "carol".to_owned(),
            roles: vec![],
            update_id: "u-2".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 600,
        };
        let err = build_add_node_record_for_enrollee(&state, ctx)
            .expect_err("duplicate node id must reject");
        assert!(matches!(
            err,
            EnrollmentMembershipError::Membership(MembershipError::InvalidTransition(_))
        ));
    }

    #[test]
    fn build_add_node_record_rejects_invalid_pubkey_hex() {
        // The reducer's hex decoder rejects non-32-byte values.
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "minipc-3".to_owned(),
            node_pubkey_hex: "deadbeef".to_owned(),
            owner: "carol".to_owned(),
            roles: vec![],
            update_id: "u-3".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 600,
        };
        let err =
            build_add_node_record_for_enrollee(&state, ctx).expect_err("short pubkey must reject");
        assert!(matches!(err, EnrollmentMembershipError::Membership(_)));
    }
}
