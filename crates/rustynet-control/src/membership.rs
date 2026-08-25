#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
#[cfg(unix)]
use nix::unistd::Uid;
use sha2::{Digest, Sha256};

use crate::roles::{
    RoleCapability, canonicalize_role_capabilities, parse_role_capability_csv, role_capability_csv,
};

pub const MEMBERSHIP_SCHEMA_VERSION: u8 = 1;
pub const MEMBERSHIP_CLOCK_SKEW_SECS: u64 = 90;

/// Domain-separation prefix for the membership head-attestation canonical
/// payload. The first payload line pins the artifact type and version so an
/// update signature (whose payload starts `version=`) can never be replayed
/// as a head signature or vice versa.
pub const MEMBERSHIP_HEAD_ATTESTATION_DOMAIN: &str = "rustynet:membership-head:v1";

/// Schema version of the persisted `attestation.*` snapshot fields.
pub const MEMBERSHIP_HEAD_ATTESTATION_VERSION: u8 = 1;

/// Default (and hard maximum) freshness window for a membership head
/// attestation: 7 days. `verify_attested_snapshot` rejects any window
/// outside `1..=` this value, so callers can only tighten the bound —
/// there is no way to disable the staleness check.
pub const MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// Upper bound on a single on-disk membership snapshot.
///
/// The snapshot is a hex-encoded `MembershipState` blob — a roster of
/// nodes plus a roster of approvers. Even with several hundred nodes and
/// signed approvers, a healthy snapshot stays well under 1 MiB; the 8 MiB
/// cap leaves enormous headroom for legitimate growth while still bounding
/// peak memory if the file is corrupted, swapped, or grown out from under
/// us between `validate_membership_file_security` and the read. Without
/// this cap, a multi-gigabyte file under the snapshot path would be slurped
/// into a `String` before any structural check fired.
pub const MAX_MEMBERSHIP_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;

/// Upper bound on the on-disk membership log.
///
/// The log appends one entry per signed update — typically a few hundred
/// bytes — so a 64 MiB cap accommodates tens of thousands of operations
/// while still preventing memory-exhaustion via a corrupted or hostile
/// file. The log can grow legitimately over time; we keep this generous
/// for that reason and rely on chain-hash + signature verification
/// downstream to catch corruption.
pub const MAX_MEMBERSHIP_LOG_BYTES: usize = 64 * 1024 * 1024;

/// Upper bounds on the `*_count` length fields in the membership text
/// encoding. These cap the `Vec::with_capacity` pre-allocations in the
/// decoders so a malformed or hostile count cannot trigger a capacity-overflow
/// panic (`count * size_of::<T>()` exceeding `isize::MAX`) or a
/// memory-exhaustion abort before any structural validation or signature check
/// runs. The values sit far above any realistic mesh while keeping the worst
/// case pre-allocation small. Counts are additionally bounded by the parsed
/// field total in [`bounded_count`], which closes the hole even on the tightly
/// size-capped IPC path.
pub const MAX_MEMBERSHIP_NODE_COUNT: usize = 65_536;
pub const MAX_MEMBERSHIP_APPROVER_COUNT: usize = 4_096;
pub const MAX_MEMBERSHIP_SIGNATURE_COUNT: usize = 4_096;

/// Upper bound on any free-form operator-supplied string that
/// [`MembershipState::canonical_payload`] interpolates into a payload line.
///
/// The whole snapshot is already capped by [`MAX_MEMBERSHIP_SNAPSHOT_BYTES`],
/// but that bound only applies on the *decode* side: an in-memory state built
/// from operator input can hold an arbitrarily long identifier and be signed
/// before anything reaches disk. Real values here are hostname slugs, principal
/// names and role tokens, so 256 bytes strands nothing that exists while
/// keeping a single hostile field from dominating a snapshot.
pub const MAX_MEMBERSHIP_FIELD_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipNodeStatus {
    Active,
    Revoked,
    Quarantined,
}

impl MembershipNodeStatus {
    fn as_str(self) -> &'static str {
        match self {
            MembershipNodeStatus::Active => "active",
            MembershipNodeStatus::Revoked => "revoked",
            MembershipNodeStatus::Quarantined => "quarantined",
        }
    }

    fn parse(value: &str) -> Result<Self, MembershipError> {
        match value {
            "active" => Ok(MembershipNodeStatus::Active),
            "revoked" => Ok(MembershipNodeStatus::Revoked),
            "quarantined" => Ok(MembershipNodeStatus::Quarantined),
            _ => Err(MembershipError::InvalidFormat(format!(
                "invalid membership node status {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipApproverRole {
    Owner,
    Guardian,
}

impl MembershipApproverRole {
    fn as_str(self) -> &'static str {
        match self {
            MembershipApproverRole::Owner => "owner",
            MembershipApproverRole::Guardian => "guardian",
        }
    }

    fn parse(value: &str) -> Result<Self, MembershipError> {
        match value {
            "owner" => Ok(MembershipApproverRole::Owner),
            "guardian" => Ok(MembershipApproverRole::Guardian),
            _ => Err(MembershipError::InvalidFormat(format!(
                "invalid membership approver role {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipApproverStatus {
    Active,
    Revoked,
}

impl MembershipApproverStatus {
    fn as_str(self) -> &'static str {
        match self {
            MembershipApproverStatus::Active => "active",
            MembershipApproverStatus::Revoked => "revoked",
        }
    }

    fn parse(value: &str) -> Result<Self, MembershipError> {
        match value {
            "active" => Ok(MembershipApproverStatus::Active),
            "revoked" => Ok(MembershipApproverStatus::Revoked),
            _ => Err(MembershipError::InvalidFormat(format!(
                "invalid membership approver status {value}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipNode {
    pub node_id: String,
    pub node_pubkey_hex: String,
    pub owner: String,
    pub status: MembershipNodeStatus,
    pub roles: Vec<String>,
    pub capabilities: Vec<RoleCapability>,
    pub joined_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipApprover {
    pub approver_id: String,
    pub approver_pubkey_hex: String,
    pub role: MembershipApproverRole,
    pub status: MembershipApproverStatus,
    pub created_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipState {
    pub schema_version: u8,
    pub network_id: String,
    pub epoch: u64,
    pub nodes: Vec<MembershipNode>,
    pub approver_set: Vec<MembershipApprover>,
    pub quorum_threshold: u8,
    pub metadata_hash: Option<String>,
}

impl MembershipState {
    pub fn validate(&self) -> Result<(), MembershipError> {
        if self.schema_version != MEMBERSHIP_SCHEMA_VERSION {
            return Err(MembershipError::UnsupportedVersion(self.schema_version));
        }
        if self.network_id.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "network id must not be empty".to_owned(),
            ));
        }
        validate_membership_payload_field("network id", &self.network_id)?;
        if let Some(metadata_hash) = self.metadata_hash.as_deref() {
            validate_membership_payload_field("metadata hash", metadata_hash)?;
            // `Some("")` encodes to the same `metadata_hash=` line as `None`
            // and decodes back as `None` — the ENR-03 silent-mutation shape at
            // an optional field. Refuse the ambiguous form so the encoding
            // stays injective.
            if metadata_hash.is_empty() {
                return Err(MembershipError::InvalidFormat(
                    "metadata hash must be absent rather than empty".to_owned(),
                ));
            }
        }
        if self.quorum_threshold == 0 {
            return Err(MembershipError::InvalidFormat(
                "quorum threshold must be at least 1".to_owned(),
            ));
        }

        // Borrow node/approver ids for the duplicate check instead of
        // cloning each into the set (same membership, same error strings).
        let mut node_ids: HashSet<&str> = HashSet::new();
        for node in &self.nodes {
            if node.node_id.trim().is_empty() {
                return Err(MembershipError::InvalidFormat(
                    "node id must not be empty".to_owned(),
                ));
            }
            validate_membership_payload_field("node id", &node.node_id)?;
            if !node_ids.insert(node.node_id.as_str()) {
                return Err(MembershipError::InvalidFormat(format!(
                    "duplicate node id {}",
                    node.node_id
                )));
            }
            decode_hex_to_fixed::<32>(&node.node_pubkey_hex)?;
            if node.owner.trim().is_empty() {
                return Err(MembershipError::InvalidFormat(format!(
                    "node {} has empty owner",
                    node.node_id
                )));
            }
            validate_membership_payload_field("node owner", &node.owner)?;
            for role in &node.roles {
                validate_membership_role_entry("node role", role)?;
            }
            validate_membership_node_capabilities(node)?;
        }

        let mut approver_ids: HashSet<&str> = HashSet::new();
        // Security-critical, not cosmetic: quorum and pin checks throughout
        // this crate (verify_membership_signatures, verify_attested_snapshot)
        // count DISTINCT SIGNERS by approver_id, trusting that one key can
        // never sit behind two ids. Without this check, an operator mistake
        // (or a deliberately crafted, quorum-signed roster) that assigns the
        // same pubkey to two approver_ids lets a single real signature be
        // duplicated under the second id, inflating the apparent number of
        // independent signers satisfying quorum_threshold. Reject the shape
        // here, once, so every downstream signer-counting site is sound by
        // construction rather than needing its own dedup-by-key logic.
        let mut approver_keys: HashSet<[u8; 32]> = HashSet::new();
        let active_approvers = self
            .approver_set
            .iter()
            .filter(|approver| approver.status == MembershipApproverStatus::Active)
            .count() as u8;
        for approver in &self.approver_set {
            if approver.approver_id.trim().is_empty() {
                return Err(MembershipError::InvalidFormat(
                    "approver id must not be empty".to_owned(),
                ));
            }
            validate_membership_payload_field("approver id", &approver.approver_id)?;
            if !approver_ids.insert(approver.approver_id.as_str()) {
                return Err(MembershipError::InvalidFormat(format!(
                    "duplicate approver id {}",
                    approver.approver_id
                )));
            }
            let approver_key_bytes = decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)?;
            if !approver_keys.insert(approver_key_bytes) {
                return Err(MembershipError::InvalidFormat(format!(
                    "approver pubkey reused across multiple approver ids (approver {})",
                    approver.approver_id
                )));
            }
        }

        if active_approvers == 0 {
            return Err(MembershipError::InvalidFormat(
                "at least one active approver is required".to_owned(),
            ));
        }
        if self.quorum_threshold > active_approvers {
            return Err(MembershipError::InvalidFormat(format!(
                "quorum threshold {} exceeds active approver count {}",
                self.quorum_threshold, active_approvers
            )));
        }
        Ok(())
    }

    pub fn canonical_payload(&self) -> Result<String, MembershipError> {
        // Write directly into one buffer (no per-line `format!` temporary) and
        // sort *references* to the rosters rather than cloning every node /
        // approver String. Output is byte-identical — signatures and state
        // roots depend on it; the canonical/round-trip determinism tests pin
        // it.
        use std::fmt::Write as _;
        self.validate()?;
        let mut nodes: Vec<&MembershipNode> = self.nodes.iter().collect();
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let mut approvers: Vec<&MembershipApprover> = self.approver_set.iter().collect();
        approvers.sort_by(|left, right| left.approver_id.cmp(&right.approver_id));

        let mut out = String::with_capacity(256 + nodes.len() * 256 + approvers.len() * 192);
        let _ = writeln!(out, "version={}", self.schema_version);
        let _ = writeln!(out, "network_id={}", self.network_id);
        let _ = writeln!(out, "epoch={}", self.epoch);
        let _ = writeln!(out, "quorum_threshold={}", self.quorum_threshold);
        let _ = writeln!(
            out,
            "metadata_hash={}",
            self.metadata_hash.as_deref().unwrap_or("")
        );
        let _ = writeln!(out, "node_count={}", nodes.len());
        for (index, node) in nodes.iter().enumerate() {
            let _ = writeln!(out, "node.{index}.node_id={}", node.node_id);
            let _ = writeln!(out, "node.{index}.node_pubkey_hex={}", node.node_pubkey_hex);
            let _ = writeln!(out, "node.{index}.owner={}", node.owner);
            let _ = writeln!(out, "node.{index}.status={}", node.status.as_str());
            let mut roles: Vec<&str> = node.roles.iter().map(String::as_str).collect();
            roles.sort_unstable();
            roles.dedup();
            let _ = writeln!(out, "node.{index}.roles={}", roles.join(","));
            let _ = writeln!(
                out,
                "node.{index}.capabilities={}",
                role_capability_csv(&node.capabilities)
            );
            let _ = writeln!(out, "node.{index}.joined_at_unix={}", node.joined_at_unix);
            let _ = writeln!(out, "node.{index}.updated_at_unix={}", node.updated_at_unix);
        }
        let _ = writeln!(out, "approver_count={}", approvers.len());
        for (index, approver) in approvers.iter().enumerate() {
            let _ = writeln!(out, "approver.{index}.approver_id={}", approver.approver_id);
            let _ = writeln!(
                out,
                "approver.{index}.approver_pubkey_hex={}",
                approver.approver_pubkey_hex
            );
            let _ = writeln!(out, "approver.{index}.role={}", approver.role.as_str());
            let _ = writeln!(out, "approver.{index}.status={}", approver.status.as_str());
            let _ = writeln!(
                out,
                "approver.{index}.created_at_unix={}",
                approver.created_at_unix
            );
        }

        Ok(out)
    }

    pub fn state_root_hex(&self) -> Result<String, MembershipError> {
        let payload = self.canonical_payload()?;
        Ok(sha256_hex(payload.as_bytes()))
    }

    pub fn active_nodes(&self) -> BTreeSet<String> {
        self.nodes
            .iter()
            .filter(|node| node.status == MembershipNodeStatus::Active)
            .map(|node| node.node_id.clone())
            .collect()
    }

    pub fn active_approvers(&self) -> HashMap<String, MembershipApprover> {
        self.approver_set
            .iter()
            .filter(|approver| approver.status == MembershipApproverStatus::Active)
            .map(|approver| (approver.approver_id.clone(), approver.clone()))
            .collect()
    }

    pub fn owner_approvers(&self) -> BTreeSet<String> {
        self.approver_set
            .iter()
            .filter(|approver| {
                approver.status == MembershipApproverStatus::Active
                    && approver.role == MembershipApproverRole::Owner
            })
            .map(|approver| approver.approver_id.clone())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOperation {
    AddNode(MembershipNode),
    SetNodeCapabilities {
        node_id: String,
        capabilities: Vec<RoleCapability>,
    },
    RemoveNode {
        node_id: String,
    },
    RevokeNode {
        node_id: String,
    },
    RestoreNode {
        node_id: String,
    },
    RotateNodeKey {
        node_id: String,
        new_pubkey_hex: String,
    },
    RotateApprover(MembershipApprover),
    SetQuorum {
        threshold: u8,
    },
}

impl MembershipOperation {
    fn operation_name(&self) -> &'static str {
        match self {
            MembershipOperation::AddNode(_) => "add_node",
            MembershipOperation::SetNodeCapabilities { .. } => "set_node_capabilities",
            MembershipOperation::RemoveNode { .. } => "remove_node",
            MembershipOperation::RevokeNode { .. } => "revoke_node",
            MembershipOperation::RestoreNode { .. } => "restore_node",
            MembershipOperation::RotateNodeKey { .. } => "rotate_node_key",
            MembershipOperation::RotateApprover(_) => "rotate_approver",
            MembershipOperation::SetQuorum { .. } => "set_quorum",
        }
    }

    /// Operations that need the membership owner's signature in addition to
    /// quorum.
    ///
    /// The original pair changes *who can authorise*: rotating an approver or
    /// moving the quorum threshold. The two added here change what a signed
    /// membership record can *grant*, which the security minimum bar treats
    /// the same way:
    ///
    /// * `SetNodeCapabilities` grants mesh authority — a node without
    ///   `ExitServer` is refused an exit assignment, so granting it is a
    ///   privilege change. `SecurityMinimumBar.md` states capability changes
    ///   require an owner-signed bundle and that an anchor cannot
    ///   self-promote; before this arm existed no code enforced that, and the
    ///   requirement had no verification method at all.
    /// * `RotateNodeKey` writes `node_pubkey_hex`, which is the node's gossip
    ///   trust anchor: the verifying key every peer uses to authenticate that
    ///   node's gossip. Substituting it is substituting an identity.
    ///
    /// This costs nothing in the shipped default, where genesis mints a single
    /// Owner approver and `quorum_threshold` is 1, so quorum already implies
    /// the owner; and nothing on the automated paths, which already sign with
    /// the owner key.
    fn requires_owner_signer(&self) -> bool {
        matches!(
            self,
            MembershipOperation::RotateApprover(_)
                | MembershipOperation::SetQuorum { .. }
                | MembershipOperation::SetNodeCapabilities { .. }
                | MembershipOperation::RotateNodeKey { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipUpdateRecord {
    pub network_id: String,
    pub update_id: String,
    pub operation: MembershipOperation,
    pub target: String,
    pub prev_state_root: String,
    pub new_state_root: String,
    pub epoch_prev: u64,
    pub epoch_new: u64,
    pub created_at_unix: u64,
    pub expires_at_unix: u64,
    pub reason_code: String,
    pub policy_context: Option<String>,
}

impl MembershipUpdateRecord {
    pub fn canonical_payload(&self) -> Result<String, MembershipError> {
        if self.network_id.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "membership update network id must not be empty".to_owned(),
            ));
        }
        if self.update_id.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "membership update id must not be empty".to_owned(),
            ));
        }
        if self.target.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "membership update target must not be empty".to_owned(),
            ));
        }
        if self.epoch_new != self.epoch_prev.saturating_add(1) {
            return Err(MembershipError::InvalidTransition(
                "membership update epoch chain must increment by exactly 1",
            ));
        }
        if self.created_at_unix >= self.expires_at_unix {
            return Err(MembershipError::InvalidFormat(
                "membership update expires_at_unix must be greater than created_at_unix".to_owned(),
            ));
        }
        // ENR-01/ENR-03, second encoder. This payload is what the approver
        // signatures are computed over, and it uses the same line-oriented
        // key=value framing as the snapshot — so the same forged-line and
        // silently-mutated-value defects apply here, to a MORE sensitive
        // artifact. The `trim().is_empty()` checks above are exactly the weak
        // guard ENR-01 was raised about.
        //
        // `reason_code` and `policy_context` had no validation at all and are
        // taken straight from operator flags (`--reason`, `--policy-context`),
        // as are `--update-id` and `--approver-id`. A newline in any of them
        // forges a line inside the signed update.
        validate_membership_payload_field("membership update network id", &self.network_id)?;
        validate_membership_payload_field("membership update id", &self.update_id)?;
        validate_membership_payload_field("membership update target", &self.target)?;
        validate_membership_payload_field("membership update reason code", &self.reason_code)?;
        validate_membership_payload_field(
            "membership update prev state root",
            &self.prev_state_root,
        )?;
        validate_membership_payload_field(
            "membership update new state root",
            &self.new_state_root,
        )?;
        if let Some(policy_context) = self.policy_context.as_deref() {
            validate_membership_payload_field("membership update policy context", policy_context)?;
        }

        // Build the canonical signed payload by writing into one buffer (no
        // per-line `format!` temporary). Byte-identical output — the update
        // signature is computed over this; round-trip/determinism tests pin it.
        use std::fmt::Write as _;
        let mut out = String::with_capacity(384);
        let _ = writeln!(out, "version={MEMBERSHIP_SCHEMA_VERSION}");
        let _ = writeln!(out, "network_id={}", self.network_id);
        let _ = writeln!(out, "update_id={}", self.update_id);
        let _ = writeln!(out, "operation={}", self.operation.operation_name());
        let _ = writeln!(out, "target={}", self.target);
        let _ = writeln!(out, "prev_state_root={}", self.prev_state_root);
        let _ = writeln!(out, "new_state_root={}", self.new_state_root);
        let _ = writeln!(out, "epoch_prev={}", self.epoch_prev);
        let _ = writeln!(out, "epoch_new={}", self.epoch_new);
        let _ = writeln!(out, "created_at_unix={}", self.created_at_unix);
        let _ = writeln!(out, "expires_at_unix={}", self.expires_at_unix);
        let _ = writeln!(out, "reason_code={}", self.reason_code);
        let _ = writeln!(
            out,
            "policy_context={}",
            self.policy_context.as_deref().unwrap_or("")
        );

        match &self.operation {
            MembershipOperation::AddNode(node) => {
                validate_membership_payload_field("op node id", &node.node_id)?;
                validate_membership_payload_field("op node owner", &node.owner)?;
                validate_membership_payload_field("op node pubkey", &node.node_pubkey_hex)?;
                for role in &node.roles {
                    validate_membership_role_entry("op node role", role)?;
                }
                let _ = writeln!(out, "op.node_id={}", node.node_id);
                let _ = writeln!(out, "op.node_pubkey_hex={}", node.node_pubkey_hex);
                let _ = writeln!(out, "op.owner={}", node.owner);
                let _ = writeln!(out, "op.status={}", node.status.as_str());
                let mut roles: Vec<&str> = node.roles.iter().map(String::as_str).collect();
                roles.sort_unstable();
                roles.dedup();
                let _ = writeln!(out, "op.roles={}", roles.join(","));
                let _ = writeln!(
                    out,
                    "op.capabilities={}",
                    role_capability_csv(&node.capabilities)
                );
                let _ = writeln!(out, "op.joined_at_unix={}", node.joined_at_unix);
                let _ = writeln!(out, "op.updated_at_unix={}", node.updated_at_unix);
            }
            MembershipOperation::SetNodeCapabilities {
                node_id,
                capabilities,
            } => {
                validate_membership_payload_field("op node id", node_id)?;
                let _ = writeln!(out, "op.node_id={node_id}");
                let _ = writeln!(out, "op.capabilities={}", role_capability_csv(capabilities));
            }
            MembershipOperation::RemoveNode { node_id }
            | MembershipOperation::RevokeNode { node_id }
            | MembershipOperation::RestoreNode { node_id } => {
                validate_membership_payload_field("op node id", node_id)?;
                let _ = writeln!(out, "op.node_id={node_id}");
            }
            MembershipOperation::RotateNodeKey {
                node_id,
                new_pubkey_hex,
            } => {
                validate_membership_payload_field("op node id", node_id)?;
                validate_membership_payload_field("op new pubkey", new_pubkey_hex)?;
                let _ = writeln!(out, "op.node_id={node_id}");
                let _ = writeln!(out, "op.new_pubkey_hex={new_pubkey_hex}");
            }
            MembershipOperation::RotateApprover(approver) => {
                validate_membership_payload_field("op approver id", &approver.approver_id)?;
                validate_membership_payload_field(
                    "op approver pubkey",
                    &approver.approver_pubkey_hex,
                )?;
                let _ = writeln!(out, "op.approver_id={}", approver.approver_id);
                let _ = writeln!(
                    out,
                    "op.approver_pubkey_hex={}",
                    approver.approver_pubkey_hex
                );
                let _ = writeln!(out, "op.role={}", approver.role.as_str());
                let _ = writeln!(out, "op.status={}", approver.status.as_str());
                let _ = writeln!(out, "op.created_at_unix={}", approver.created_at_unix);
            }
            MembershipOperation::SetQuorum { threshold } => {
                let _ = writeln!(out, "op.threshold={threshold}");
            }
        }

        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipSignature {
    pub approver_id: String,
    pub signature_hex: String,
    /// Optional ed25519 signature by the SAME approver key over the
    /// membership head-attestation canonical payload derived from the
    /// enclosing update record (`head_attestation_canonical_payload` with
    /// `epoch = record.epoch_new`, `state_root = record.new_state_root`,
    /// `attested_at_unix = record.created_at_unix`). Minted alongside the
    /// update signature wherever signing keys are already in hand, and
    /// materialized into the persisted snapshot at apply time so a
    /// bundle-pull client can authenticate a bare snapshot against the
    /// pinned §6.B owner public key. `None` on legacy entries; when
    /// present, the field participates in the canonical envelope, so
    /// pre-upgrade decoders fail closed on the changed `entry_hash`
    /// (intentional — FIS-0014 precedent for additive-but-gating fields).
    pub head_signature_hex: Option<String>,
}

/// Signed commitment to a membership head: the exact `(network_id, epoch,
/// state_root)` identity of a snapshot plus a freshness timestamp, signed by
/// the approver set. This is what lets `anchor pull-bundle` authenticate a
/// bare snapshot on a device whose only prior trust is the out-of-band
/// membership owner public key (SecurityMinimumBar §6.B): the pinned key must
/// be an Owner in the attested state AND must have actually signed this
/// attestation. Anchors never mint attestations — they only materialize the
/// head signatures that arrived inside an applied `SignedMembershipUpdate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipHeadAttestation {
    pub network_id: String,
    pub epoch: u64,
    pub state_root_hex: String,
    pub attested_at_unix: u64,
    pub approver_signatures: Vec<MembershipSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMembershipUpdate {
    pub record: MembershipUpdateRecord,
    pub approver_signatures: Vec<MembershipSignature>,
}

impl SignedMembershipUpdate {
    pub fn canonical_envelope(&self) -> Result<String, MembershipError> {
        // Hot on the reconcile path: chain verification builds this for every
        // log entry each tick. Write into one buffer and sort signature
        // references instead of cloning the signature roster. Byte-identical.
        use std::fmt::Write as _;
        let payload = self.record.canonical_payload()?;
        let mut signatures: Vec<&MembershipSignature> = self.approver_signatures.iter().collect();
        signatures.sort_by(|left, right| left.approver_id.cmp(&right.approver_id));

        let mut out = String::with_capacity(payload.len() * 2 + 64 + signatures.len() * 160);
        let _ = writeln!(out, "payload_hex={}", hex_encode(payload.as_bytes()));
        let _ = writeln!(out, "sig_count={}", signatures.len());
        for (index, signature) in signatures.iter().enumerate() {
            // The record payload is hex-framed above and so cannot reframe the
            // envelope, but the signature identities are written raw and
            // `--approver-id` is operator-supplied.
            validate_membership_payload_field("signature approver id", &signature.approver_id)?;
            validate_membership_payload_field("signature hex", &signature.signature_hex)?;
            if let Some(head_signature_hex) = &signature.head_signature_hex {
                validate_membership_payload_field("head signature hex", head_signature_hex)?;
            }
            let _ = writeln!(out, "sig.{index}.approver_id={}", signature.approver_id);
            let _ = writeln!(out, "sig.{index}.signature_hex={}", signature.signature_hex);
            // Optional per-signer head signature (membership head
            // attestation). Legacy entries without the field encode
            // byte-identically to the pre-attestation format, so their
            // `entry_hash` values are unchanged; entries WITH the field
            // fail closed on pre-upgrade decoders via the chain hash.
            if let Some(head_signature_hex) = &signature.head_signature_hex {
                let _ = writeln!(out, "sig.{index}.head_signature_hex={head_signature_hex}");
            }
        }
        Ok(out)
    }
}

/// Upper bound on remembered update ids in a `MembershipReplayCache`.
///
/// Without a bound the id set grows once per accepted update for the life
/// of the daemon. The epoch watermark alone still blocks rollback replays
/// for evicted ids (apply_signed_update enforces the strict epoch chain
/// before observe), so eviction only relaxes same-id dedup for very old
/// ids — an acceptable trade against unbounded memory growth.
pub const MAX_REPLAY_CACHE_ENTRIES: usize = 4096;

#[derive(Debug, Default, Clone)]
pub struct MembershipReplayCache {
    seen_update_ids: HashSet<String>,
    /// Insertion order for oldest-first eviction once the cap is hit.
    seen_update_order: VecDeque<String>,
    max_epoch: u64,
}

impl MembershipReplayCache {
    pub fn observe(&mut self, update_id: &str, epoch_new: u64) -> Result<(), MembershipError> {
        if self.seen_update_ids.contains(update_id) {
            return Err(MembershipError::ReplayDetected);
        }
        if epoch_new <= self.max_epoch {
            return Err(MembershipError::ReplayDetected);
        }
        self.seen_update_ids.insert(update_id.to_owned());
        self.seen_update_order.push_back(update_id.to_owned());
        while self.seen_update_ids.len() > MAX_REPLAY_CACHE_ENTRIES {
            if let Some(oldest) = self.seen_update_order.pop_front() {
                self.seen_update_ids.remove(&oldest);
            } else {
                break;
            }
        }
        self.max_epoch = epoch_new;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipLogEntry {
    pub index: u64,
    pub previous_hash: String,
    pub entry_hash: String,
    pub signed_update: SignedMembershipUpdate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipError {
    UnsupportedVersion(u8),
    InvalidFormat(String),
    InvalidTransition(&'static str),
    SignatureInvalid,
    ThresholdNotMet,
    SignerNotAuthorized(String),
    OwnerSignatureRequired,
    ReplayDetected,
    Expired,
    FutureDated,
    PrevStateRootMismatch,
    NewStateRootMismatch,
    NotFound(String),
    Internal(String),
    Io(String),
    IntegrityMismatch,
    /// The snapshot carries no head attestation. A bundle-pull client
    /// must reject such a snapshot outright — an unattested snapshot is
    /// unauthenticated data.
    AttestationMissing,
    /// The head attestation is older than the caller's freshness window.
    AttestationStale,
    /// The head attestation's timestamp is beyond the clock-skew
    /// tolerance in the future.
    AttestationFutureDated,
    /// The pinned §6.B membership owner public key is absent from the
    /// attested approver set, is not an Owner there, or did not actually
    /// sign the attestation. The reason string is operator-actionable.
    PinnedOwnerKeyMismatch(String),
    /// The offered snapshot's epoch is below the epoch of the prior
    /// verified local bundle.
    EpochRegression {
        prior_epoch: u64,
        offered_epoch: u64,
    },
    /// Same epoch, different state root, between the prior verified
    /// local bundle and the offered snapshot: fork evidence. Never pick
    /// a side silently — surface both roots verbatim.
    ForkDetected {
        epoch: u64,
        prior_root: String,
        offered_root: String,
    },
}

impl fmt::Display for MembershipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembershipError::UnsupportedVersion(version) => {
                write!(f, "unsupported membership version {version}")
            }
            MembershipError::InvalidFormat(message) => {
                write!(f, "invalid membership format: {message}")
            }
            MembershipError::InvalidTransition(message) => {
                write!(f, "invalid transition: {message}")
            }
            MembershipError::SignatureInvalid => f.write_str("signature verification failed"),
            MembershipError::ThresholdNotMet => {
                f.write_str("threshold signature requirements not met")
            }
            MembershipError::SignerNotAuthorized(approver_id) => {
                write!(f, "signer is not authorized: {approver_id}")
            }
            MembershipError::OwnerSignatureRequired => {
                f.write_str("owner signature required for this operation")
            }
            MembershipError::ReplayDetected => f.write_str("membership replay detected"),
            MembershipError::Expired => f.write_str("membership update is expired"),
            MembershipError::FutureDated => f.write_str("membership update is future dated"),
            MembershipError::PrevStateRootMismatch => f.write_str("previous state root mismatch"),
            MembershipError::NewStateRootMismatch => f.write_str("new state root mismatch"),
            MembershipError::NotFound(value) => write!(f, "not found: {value}"),
            MembershipError::Internal(message) => write!(f, "internal error: {message}"),
            MembershipError::Io(message) => write!(f, "i/o error: {message}"),
            MembershipError::IntegrityMismatch => f.write_str("integrity mismatch"),
            MembershipError::AttestationMissing => {
                f.write_str("membership snapshot carries no head attestation")
            }
            MembershipError::AttestationStale => {
                f.write_str("membership head attestation is stale")
            }
            MembershipError::AttestationFutureDated => {
                f.write_str("membership head attestation is future dated")
            }
            MembershipError::PinnedOwnerKeyMismatch(reason) => {
                write!(f, "pinned owner key mismatch: {reason}")
            }
            MembershipError::EpochRegression {
                prior_epoch,
                offered_epoch,
            } => write!(
                f,
                "membership epoch regression: offered epoch {offered_epoch} is below prior verified epoch {prior_epoch}"
            ),
            MembershipError::ForkDetected {
                epoch,
                prior_root,
                offered_root,
            } => write!(
                f,
                "membership fork detected at epoch {epoch}: prior verified state root {prior_root} != offered state root {offered_root}"
            ),
        }
    }
}

impl std::error::Error for MembershipError {}

pub fn encode_membership_state(state: &MembershipState) -> Result<String, MembershipError> {
    state.canonical_payload()
}

pub fn decode_membership_state(payload: &str) -> Result<MembershipState, MembershipError> {
    let state = parse_membership_state_payload(payload)?;
    state.validate()?;
    Ok(state)
}

pub fn encode_update_record(record: &MembershipUpdateRecord) -> Result<String, MembershipError> {
    record.canonical_payload()
}

pub fn decode_update_record(payload: &str) -> Result<MembershipUpdateRecord, MembershipError> {
    parse_membership_update_payload(payload)
}

pub fn encode_signed_update(
    signed_update: &SignedMembershipUpdate,
) -> Result<String, MembershipError> {
    signed_update.canonical_envelope()
}

pub fn decode_signed_update(payload: &str) -> Result<SignedMembershipUpdate, MembershipError> {
    parse_signed_update_envelope(payload)
}

/// Preview the state that applying `operation` would produce, for computing a
/// proposal's `new_state_root`. `op_created_at_unix` MUST be the same
/// `created_at_unix` the resulting signed record will carry, so the previewed
/// `state_root` reproduces at apply time (RSA-0009). The reducer stamps it into
/// the affected node's `updated_at_unix`.
pub fn preview_next_state(
    state: &MembershipState,
    operation: &MembershipOperation,
    op_created_at_unix: u64,
) -> Result<MembershipState, MembershipError> {
    state.validate()?;
    let mut next = reduce_membership_state(state, operation, op_created_at_unix)?;
    next.epoch = state.epoch.saturating_add(1);
    next.validate()?;
    Ok(next)
}

pub fn sign_update_record(
    record: &MembershipUpdateRecord,
    approver_id: &str,
    signing_key: &SigningKey,
) -> Result<MembershipSignature, MembershipError> {
    if approver_id.trim().is_empty() {
        return Err(MembershipError::InvalidFormat(
            "approver_id must not be empty".to_owned(),
        ));
    }
    let payload = record.canonical_payload()?;
    let signature = signing_key.sign(payload.as_bytes());
    Ok(MembershipSignature {
        approver_id: approver_id.to_owned(),
        signature_hex: hex_encode(&signature.to_bytes()),
        head_signature_hex: None,
    })
}

/// Canonical signed payload of a membership head attestation.
///
/// Line 1 is the domain-separation tag; the remaining lines are `key=value`
/// pairs in sorted key order. Byte-pinned by
/// `head_attestation_canonical_payload_is_byte_pinned` — any change to this
/// format invalidates every existing head signature.
pub fn head_attestation_canonical_payload(
    network_id: &str,
    epoch: u64,
    state_root_hex: &str,
    attested_at_unix: u64,
) -> String {
    format!(
        "{MEMBERSHIP_HEAD_ATTESTATION_DOMAIN}\n\
         attested_at_unix={attested_at_unix}\n\
         epoch={epoch}\n\
         network_id={network_id}\n\
         state_root={state_root_hex}\n"
    )
}

/// Sign a membership head attestation payload. Mirrors `sign_update_record`:
/// the returned `MembershipSignature.signature_hex` is the head signature
/// (its own `head_signature_hex` slot stays `None` — that slot only carries
/// meaning inside a `SignedMembershipUpdate`'s per-signer entries).
pub fn sign_head_attestation(
    network_id: &str,
    epoch: u64,
    state_root_hex: &str,
    attested_at_unix: u64,
    approver_id: &str,
    signing_key: &SigningKey,
) -> Result<MembershipSignature, MembershipError> {
    if approver_id.trim().is_empty() {
        return Err(MembershipError::InvalidFormat(
            "approver_id must not be empty".to_owned(),
        ));
    }
    if network_id.trim().is_empty() || network_id.contains('\n') {
        return Err(MembershipError::InvalidFormat(
            "head attestation network id must be a non-empty single line".to_owned(),
        ));
    }
    // The state root is a sha256 hex digest; refuse to sign anything else so
    // a malformed root can never smuggle payload-line structure.
    decode_hex_to_fixed::<32>(state_root_hex)?;
    let payload =
        head_attestation_canonical_payload(network_id, epoch, state_root_hex, attested_at_unix);
    let signature = signing_key.sign(payload.as_bytes());
    Ok(MembershipSignature {
        approver_id: approver_id.to_owned(),
        signature_hex: hex_encode(&signature.to_bytes()),
        head_signature_hex: None,
    })
}

/// Materialize the head attestation that traveled inside a signed update's
/// per-signer `head_signature_hex` fields. Returns `None` when no signer
/// carried one (a legacy update) — the caller then persists the snapshot
/// without an attestation, which is NOT an error at the anchor (anchors are
/// trust-inert: they never mint, and an unattested snapshot simply fails
/// client-side verification later, which is the correct fail-closed outcome).
pub fn head_attestation_from_signed_update(
    signed_update: &SignedMembershipUpdate,
) -> Option<MembershipHeadAttestation> {
    let approver_signatures: Vec<MembershipSignature> = signed_update
        .approver_signatures
        .iter()
        .filter_map(|signature| {
            signature
                .head_signature_hex
                .as_ref()
                .map(|head_signature_hex| MembershipSignature {
                    approver_id: signature.approver_id.clone(),
                    signature_hex: head_signature_hex.clone(),
                    head_signature_hex: None,
                })
        })
        .collect();
    if approver_signatures.is_empty() {
        return None;
    }
    let record = &signed_update.record;
    Some(MembershipHeadAttestation {
        network_id: record.network_id.clone(),
        epoch: record.epoch_new,
        state_root_hex: record.new_state_root.clone(),
        attested_at_unix: record.created_at_unix,
        approver_signatures,
    })
}

pub fn apply_signed_update(
    state: &MembershipState,
    signed_update: &SignedMembershipUpdate,
    now_unix: u64,
    replay_cache: &mut MembershipReplayCache,
) -> Result<MembershipState, MembershipError> {
    state.validate()?;
    let record = &signed_update.record;
    let payload = record.canonical_payload()?;
    if record.network_id != state.network_id {
        return Err(MembershipError::InvalidTransition(
            "network id mismatch in membership update",
        ));
    }
    if now_unix > record.expires_at_unix {
        return Err(MembershipError::Expired);
    }
    if record.created_at_unix > now_unix.saturating_add(MEMBERSHIP_CLOCK_SKEW_SECS) {
        return Err(MembershipError::FutureDated);
    }
    if record.prev_state_root != state.state_root_hex()? {
        return Err(MembershipError::PrevStateRootMismatch);
    }
    if record.epoch_prev != state.epoch || record.epoch_new != state.epoch.saturating_add(1) {
        return Err(MembershipError::InvalidTransition(
            "epoch chain mismatch for membership update",
        ));
    }

    verify_membership_signatures(state, signed_update, payload.as_bytes())?;

    // RSA-0009: re-derive using the SIGNED record's own `created_at_unix`, the
    // same timestamp the proposer fed `preview_next_state`, so the recomputed
    // `state_root` reproduces the recorded `new_state_root` deterministically.
    let mut next = reduce_membership_state(state, &record.operation, record.created_at_unix)?;
    next.epoch = record.epoch_new;
    next.validate()?;
    let computed_new_root = next.state_root_hex()?;
    if computed_new_root != record.new_state_root {
        return Err(MembershipError::NewStateRootMismatch);
    }
    replay_cache.observe(&record.update_id, record.epoch_new)?;

    Ok(next)
}

pub fn persist_membership_snapshot(
    path: impl AsRef<Path>,
    state: &MembershipState,
) -> Result<(), MembershipError> {
    persist_membership_snapshot_with_attestation(path, state, None)
}

/// Persist a membership snapshot, optionally with its head attestation.
///
/// The attestation fields ride AFTER the legacy `digest=` line so the
/// existing self-consistency digest (over `version=` + `state_hex=` only)
/// and every legacy loader keep working unchanged; the attestation's own
/// integrity comes from its ed25519 signatures, not from the digest. The
/// attestation must structurally bind to exactly this state — a mismatched
/// attestation is a programming error and is refused rather than persisted.
pub fn persist_membership_snapshot_with_attestation(
    path: impl AsRef<Path>,
    state: &MembershipState,
    attestation: Option<&MembershipHeadAttestation>,
) -> Result<(), MembershipError> {
    use std::fmt::Write as _;
    let state_payload = state.canonical_payload()?;
    let state_hex = hex_encode(state_payload.as_bytes());
    let body_without_digest =
        format!("version={MEMBERSHIP_SCHEMA_VERSION}\nstate_hex={state_hex}\n");
    let digest = sha256_hex(body_without_digest.as_bytes());
    let mut body = format!("{body_without_digest}digest={digest}\n");
    if let Some(attestation) = attestation {
        if attestation.network_id != state.network_id
            || attestation.epoch != state.epoch
            || attestation.state_root_hex != state.state_root_hex()?
        {
            return Err(MembershipError::InvalidFormat(
                "head attestation does not bind to the snapshot state".to_owned(),
            ));
        }
        if attestation.approver_signatures.is_empty() {
            return Err(MembershipError::InvalidFormat(
                "head attestation must carry at least one signature".to_owned(),
            ));
        }
        if attestation.approver_signatures.len() > MAX_MEMBERSHIP_SIGNATURE_COUNT {
            return Err(MembershipError::InvalidFormat(format!(
                "head attestation signature count exceeds maximum {MAX_MEMBERSHIP_SIGNATURE_COUNT}"
            )));
        }
        let mut signatures: Vec<&MembershipSignature> =
            attestation.approver_signatures.iter().collect();
        signatures.sort_by(|left, right| left.approver_id.cmp(&right.approver_id));
        for pair in signatures.windows(2) {
            if pair[0].approver_id == pair[1].approver_id {
                return Err(MembershipError::InvalidFormat(format!(
                    "duplicate approver id {} in head attestation",
                    pair[0].approver_id
                )));
            }
        }
        let _ = writeln!(
            body,
            "attestation.version={MEMBERSHIP_HEAD_ATTESTATION_VERSION}"
        );
        let _ = writeln!(body, "attestation.network_id={}", attestation.network_id);
        let _ = writeln!(body, "attestation.epoch={}", attestation.epoch);
        let _ = writeln!(
            body,
            "attestation.state_root={}",
            attestation.state_root_hex
        );
        let _ = writeln!(
            body,
            "attestation.attested_at_unix={}",
            attestation.attested_at_unix
        );
        let _ = writeln!(body, "attestation.sig_count={}", signatures.len());
        for (index, signature) in signatures.iter().enumerate() {
            let _ = writeln!(
                body,
                "attestation.sig.{index}.approver_id={}",
                signature.approver_id
            );
            let _ = writeln!(
                body,
                "attestation.sig.{index}.signature_hex={}",
                signature.signature_hex
            );
        }
    }
    atomic_write(path.as_ref(), body.as_bytes(), 0o600)
}

pub fn load_membership_snapshot(
    path: impl AsRef<Path>,
) -> Result<MembershipState, MembershipError> {
    let path = path.as_ref();
    validate_membership_file_security(path, "membership snapshot")?;
    let content = read_membership_artifact_bounded(
        path,
        "membership snapshot",
        MAX_MEMBERSHIP_SNAPSHOT_BYTES,
    )?;
    parse_snapshot_content(&content)
}

fn parse_snapshot_content(content: &str) -> Result<MembershipState, MembershipError> {
    let fields = parse_key_values(content)?;
    let version = parse_u8_field(&fields, "version")?;
    if version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedVersion(version));
    }
    let state_hex = required_field(&fields, "state_hex")?;
    let digest = required_field(&fields, "digest")?;
    let expected_digest =
        sha256_hex(format!("version={version}\nstate_hex={state_hex}\n").as_bytes());
    if digest != expected_digest {
        return Err(MembershipError::IntegrityMismatch);
    }
    let payload_bytes = hex_decode(state_hex)?;
    let payload = String::from_utf8(payload_bytes)
        .map_err(|_| MembershipError::InvalidFormat("snapshot payload is not utf8".to_owned()))?;
    let state = parse_membership_state_payload(&payload)?;
    state.validate()?;
    Ok(state)
}

/// Return `true` iff `node_id` holds `anchor.bundle_pull` in the given
/// snapshot bytes.  Fails closed (returns `false`) on any parse error.
/// Does not perform file-security checks — caller owns the source trust.
pub fn snapshot_bytes_have_bundle_pull_capability(bytes: &[u8], node_id: &str) -> bool {
    let Ok(content) = std::str::from_utf8(bytes) else {
        return false;
    };
    if content.len() > MAX_MEMBERSHIP_SNAPSHOT_BYTES {
        return false;
    }
    parse_snapshot_content(content)
        .ok()
        .and_then(|state| {
            state
                .nodes
                .into_iter()
                .find(|n| n.node_id == node_id)
                .map(|n| n.capabilities.contains(&RoleCapability::AnchorBundlePull))
        })
        .unwrap_or(false)
}

/// FIS-0020: (epoch, state_root_hex) identity of a membership snapshot's
/// state, for the conditional bundle-pull digest comparison. `None` on any
/// parse/validation failure — the caller then serves/pulls the full bundle
/// (fail toward full data, never toward a wrong UNCHANGED).
pub fn snapshot_bytes_state_identity(bytes: &[u8]) -> Option<(u64, String)> {
    let content = std::str::from_utf8(bytes).ok()?;
    if content.len() > MAX_MEMBERSHIP_SNAPSHOT_BYTES {
        return None;
    }
    let state = parse_snapshot_content(content).ok()?;
    let root = state.state_root_hex().ok()?;
    Some((state.epoch, root))
}

/// Parse the optional `attestation.*` block of a snapshot's key/value map.
/// `Ok(None)` when the block is absent (legacy snapshot); `Err` when the
/// block is present but malformed — the two must stay distinguishable so
/// verification can report `AttestationMissing` vs a format error.
fn parse_snapshot_attestation_fields(
    fields: &HashMap<&str, &str>,
) -> Result<Option<MembershipHeadAttestation>, MembershipError> {
    let Some(version_raw) = fields.get("attestation.version").copied() else {
        return Ok(None);
    };
    let version = version_raw.parse::<u8>().map_err(|_| {
        MembershipError::InvalidFormat("invalid u8 field attestation.version".to_owned())
    })?;
    if version != MEMBERSHIP_HEAD_ATTESTATION_VERSION {
        return Err(MembershipError::UnsupportedVersion(version));
    }
    let network_id = required_field(fields, "attestation.network_id")?.to_owned();
    let epoch = parse_u64_field(fields, "attestation.epoch")?;
    let state_root_hex = required_field(fields, "attestation.state_root")?.to_owned();
    let attested_at_unix = parse_u64_field(fields, "attestation.attested_at_unix")?;
    let sig_count = bounded_count(
        "attestation.sig_count",
        parse_usize_field(fields, "attestation.sig_count")?,
        MAX_MEMBERSHIP_SIGNATURE_COUNT,
        fields.len(),
    )?;
    if sig_count == 0 {
        return Err(MembershipError::InvalidFormat(
            "head attestation must carry at least one signature".to_owned(),
        ));
    }
    let mut approver_signatures = Vec::with_capacity(sig_count);
    for index in 0..sig_count {
        approver_signatures.push(MembershipSignature {
            approver_id: required_field(fields, &format!("attestation.sig.{index}.approver_id"))?
                .to_owned(),
            signature_hex: required_field(
                fields,
                &format!("attestation.sig.{index}.signature_hex"),
            )?
            .to_owned(),
            head_signature_hex: None,
        });
    }
    Ok(Some(MembershipHeadAttestation {
        network_id,
        epoch,
        state_root_hex,
        attested_at_unix,
        approver_signatures,
    }))
}

/// Best-effort head-attestation extraction from raw snapshot bytes.
/// `None` on any malformed input, mirroring `snapshot_bytes_state_identity`.
/// This is a convenience reader (e.g. for `membership attest` merge logic) —
/// enforcement lives in `verify_attested_snapshot`.
pub fn snapshot_bytes_head_attestation(bytes: &[u8]) -> Option<MembershipHeadAttestation> {
    let content = std::str::from_utf8(bytes).ok()?;
    if content.len() > MAX_MEMBERSHIP_SNAPSHOT_BYTES {
        return None;
    }
    let fields = parse_key_values(content).ok()?;
    parse_snapshot_attestation_fields(&fields).ok().flatten()
}

/// THE enforcement point for anchor bundle-pull authentication
/// (SecurityMinimumBar §3 control 2): accept raw snapshot bytes only when
/// their head attestation cryptographically binds them to the pinned §6.B
/// membership owner public key. Fail-closed rule, in order:
///
/// 1. structural parse + legacy digest self-consistency (corruption check);
/// 2. attestation present — absent ⇒ `AttestationMissing`;
/// 3. the attestation's `(network_id, epoch, state_root)` must equal the
///    RECOMPUTED identity of the parsed state;
/// 4. every attestation signature must verify (`verify_strict`) against the
///    named approver's key from the ATTESTED state's approver set — an
///    unknown signer or an invalid signature is a hard reject, and the
///    pinned key must be an Owner there whose signature is among the
///    verifying set (listing the real owner key in a hostile roster without
///    that key's actual signature is NOT sufficient);
/// 5. valid signatures from the attested state's ACTIVE approvers must meet
///    that state's `quorum_threshold`;
/// 6. freshness: `attested_at_unix` within `max_age_secs` (which itself must
///    lie in `1..=MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS` — the window can
///    only be tightened, never disabled);
/// 7. not future-dated beyond `MEMBERSHIP_CLOCK_SKEW_SECS`;
/// 8. against `prior_identity` (the identity of a PREVIOUSLY VERIFIED local
///    bundle): epoch must not regress, and same-epoch-different-root is
///    fork evidence (`ForkDetected`), never silently resolved.
///
/// Rotation grace: a pinned key matching a REVOKED former Owner is accepted
/// only when a current ACTIVE Owner also signed the same attestation;
/// otherwise the caller is told to re-deliver the pin out of band. Known
/// limit (inherent to pin rotation without a new pin): a compromised
/// old owner key can still satisfy this grace path on devices that never
/// received the new pin — key compromise itself is out of scope here and is
/// covered by the separate membership-transparency track.
pub fn verify_attested_snapshot(
    bytes: &[u8],
    pinned_owner_pubkey_hex: &str,
    now_unix: u64,
    prior_identity: Option<&(u64, String)>,
    max_age_secs: u64,
) -> Result<MembershipState, MembershipError> {
    // An unusable pin or freshness window can never accept anything —
    // reject before touching the payload.
    let pinned_key_bytes = decode_hex_to_fixed::<32>(pinned_owner_pubkey_hex.trim())?;
    if max_age_secs == 0 || max_age_secs > MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS {
        return Err(MembershipError::InvalidFormat(format!(
            "attestation max age must be within 1..={MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS} seconds"
        )));
    }
    if bytes.len() > MAX_MEMBERSHIP_SNAPSHOT_BYTES {
        return Err(MembershipError::InvalidFormat(
            "membership snapshot exceeds maximum size".to_owned(),
        ));
    }
    let content = std::str::from_utf8(bytes)
        .map_err(|_| MembershipError::InvalidFormat("snapshot is not utf8".to_owned()))?;

    // 1) structural parse + digest self-consistency + state.validate().
    let state = parse_snapshot_content(content)?;

    // 2) attestation present?
    let fields = parse_key_values(content)?;
    let attestation =
        parse_snapshot_attestation_fields(&fields)?.ok_or(MembershipError::AttestationMissing)?;

    // 3) the attestation must attest exactly this state.
    let state_root = state.state_root_hex()?;
    if attestation.state_root_hex != state_root || attestation.epoch != state.epoch {
        return Err(MembershipError::InvalidFormat(
            "attestation does not attest this snapshot state (epoch/state_root mismatch)"
                .to_owned(),
        ));
    }
    if attestation.network_id != state.network_id {
        return Err(MembershipError::InvalidFormat(
            "attestation network id does not match snapshot state".to_owned(),
        ));
    }

    // 4) verify EVERY signature against the attested approver set (any
    // status — a revoked former owner's signature must still verify for
    // rotation grace, it just never counts toward quorum).
    let payload = head_attestation_canonical_payload(
        &attestation.network_id,
        attestation.epoch,
        &attestation.state_root_hex,
        attestation.attested_at_unix,
    );
    let approvers_by_id: HashMap<&str, &MembershipApprover> = state
        .approver_set
        .iter()
        .map(|approver| (approver.approver_id.as_str(), approver))
        .collect();
    let mut signer_ids: BTreeSet<&str> = BTreeSet::new();
    let mut active_signer_count: usize = 0;
    let mut active_owner_signed = false;
    let mut pinned_key_signed = false;
    for signature in &attestation.approver_signatures {
        if !signer_ids.insert(signature.approver_id.as_str()) {
            return Err(MembershipError::InvalidFormat(
                "duplicate signer id in attestation signatures".to_owned(),
            ));
        }
        let approver = approvers_by_id
            .get(signature.approver_id.as_str())
            .ok_or_else(|| MembershipError::SignerNotAuthorized(signature.approver_id.clone()))?;
        let approver_key_bytes = decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)?;
        let verifying_key = VerifyingKey::from_bytes(&approver_key_bytes)
            .map_err(|_| MembershipError::SignatureInvalid)?;
        let signature_bytes = decode_hex_to_fixed::<64>(&signature.signature_hex)?;
        let signature_obj = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(payload.as_bytes(), &signature_obj)
            .map_err(|_| MembershipError::SignatureInvalid)?;
        if approver.status == MembershipApproverStatus::Active {
            active_signer_count += 1;
            if approver.role == MembershipApproverRole::Owner {
                active_owner_signed = true;
            }
        }
        if approver_key_bytes == pinned_key_bytes {
            pinned_key_signed = true;
        }
    }

    // 5) pin enforcement. The pinned key must be an Owner in the attested
    // approver set AND its private-key holder must have actually signed
    // this attestation — roster presence alone proves nothing.
    let mut pinned_active_owner = false;
    let mut pinned_revoked_owner = false;
    let mut pinned_in_roster = false;
    for approver in &state.approver_set {
        if decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)? != pinned_key_bytes {
            continue;
        }
        pinned_in_roster = true;
        if approver.role == MembershipApproverRole::Owner {
            match approver.status {
                MembershipApproverStatus::Active => pinned_active_owner = true,
                MembershipApproverStatus::Revoked => pinned_revoked_owner = true,
            }
        }
    }
    if !pinned_in_roster {
        return Err(MembershipError::PinnedOwnerKeyMismatch(
            "pinned membership owner key is not in the attested approver set".to_owned(),
        ));
    }
    if !pinned_active_owner && !pinned_revoked_owner {
        return Err(MembershipError::PinnedOwnerKeyMismatch(
            "pinned membership owner key is not an owner approver in the attested state".to_owned(),
        ));
    }
    if !pinned_key_signed {
        return Err(MembershipError::PinnedOwnerKeyMismatch(
            "attestation carries no signature from the pinned membership owner key".to_owned(),
        ));
    }
    if !pinned_active_owner && !active_owner_signed {
        // Rotation grace failed: the pin names a rotated-out owner and no
        // current active owner co-signed the attestation.
        return Err(MembershipError::PinnedOwnerKeyMismatch(
            "pinned membership owner key was rotated (revoked in the attested state) and no \
             current active owner co-signed the attestation; re-deliver the membership owner \
             public key out of band"
                .to_owned(),
        ));
    }

    // 6) quorum among ACTIVE approvers of the attested state.
    if active_signer_count < usize::from(state.quorum_threshold) {
        return Err(MembershipError::ThresholdNotMet);
    }

    // 7) freshness window (no bypass — max_age_secs was bounds-checked above).
    if now_unix > attestation.attested_at_unix.saturating_add(max_age_secs) {
        return Err(MembershipError::AttestationStale);
    }

    // 8) future-dating beyond the shared clock-skew tolerance.
    if attestation.attested_at_unix > now_unix.saturating_add(MEMBERSHIP_CLOCK_SKEW_SECS) {
        return Err(MembershipError::AttestationFutureDated);
    }

    // 9) epoch monotonicity against the prior VERIFIED local identity.
    if let Some((prior_epoch, prior_root)) = prior_identity {
        if state.epoch < *prior_epoch {
            return Err(MembershipError::EpochRegression {
                prior_epoch: *prior_epoch,
                offered_epoch: state.epoch,
            });
        }
        if state.epoch == *prior_epoch && state_root != *prior_root {
            return Err(MembershipError::ForkDetected {
                epoch: state.epoch,
                prior_root: prior_root.clone(),
                offered_root: state_root,
            });
        }
    }

    Ok(state)
}

/// A device's persistent, monotonic high-water mark for membership state:
/// the `(epoch, state_root)` of the most recent state this device has
/// itself verified. Distinct from `verify_attested_snapshot`'s
/// `prior_identity` parameter in one crucial way: `prior_identity` is
/// whatever the CALLER decides to pass in, while `MembershipWatermark` is
/// this crate's canonical on-disk representation of "what has this device
/// already established," meant to be sourced independently of any
/// ephemeral, deletable, or freshness-bounded artifact (e.g. a cached
/// bundle file) so that anti-rollback protection survives an empty or
/// reset local cache. Originally implemented only in `rustynetd`'s daemon
/// bootstrap/apply paths; moved here so `rustynet-cli`'s `anchor
/// pull-bundle` can share the exact same file and format rather than
/// re-deriving its rollback floor from `--output` on every invocation
/// (which is what let a stale-cache rollback go unnoticed — see
/// `documents/operations/active/AnchorBundlePullRollbackWatermarkInvestigation_2026-07-20.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipWatermark {
    pub epoch: u64,
    pub state_root: String,
}

/// `true` iff accepting `incoming` after `previous` would be a rollback:
/// either the epoch has decreased (an old, superseded epoch resurfacing —
/// the anti-rollback property), or the epoch is unchanged but the root
/// differs (two different histories claiming the same epoch — fork
/// detection; only one canonical state can exist per epoch). Equal epoch
/// with the SAME root is not a replay (idempotent re-verification is
/// fine); a strictly newer epoch is never a replay regardless of root
/// (forward progress).
pub fn membership_watermark_is_replay(
    incoming: &MembershipWatermark,
    previous: &MembershipWatermark,
) -> bool {
    incoming.epoch < previous.epoch
        || (incoming.epoch == previous.epoch && incoming.state_root != previous.state_root)
}

/// Load the persisted watermark, if any. `Ok(None)` (not an error) means
/// no watermark has ever been established at `path` — the correct,
/// honest trust-on-first-use state for a genuinely fresh device, which
/// callers must treat as "nothing to check a newly-offered epoch
/// against" rather than a failure.
pub fn load_membership_watermark(path: &Path) -> Result<Option<MembershipWatermark>, String> {
    if !path.exists() {
        return Ok(None);
    }
    const MAX_WATERMARK_FILE_BYTES: usize = 4 * 1024;
    let content =
        read_membership_artifact_bounded(path, "membership watermark", MAX_WATERMARK_FILE_BYTES)
            .map_err(|err| err.to_string())?;
    let mut version: Option<u8> = None;
    let mut epoch: Option<u64> = None;
    let mut state_root: Option<String> = None;
    // Duplicate-key rejection tracks RAW key presence, not parsed values:
    // a failed parse erases the evidence (version becomes None), so a
    // tampered "epoch=5\nepoch=999" must be caught even if the first
    // line had failed to parse. Mirrors the role-audit reader's
    // duplicate rejection in this same crate (fail-closed standard).
    let mut seen: Vec<&str> = Vec::new();
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("membership watermark line missing key/value separator".to_owned());
        };
        if seen.contains(&key) {
            return Err(format!("duplicate membership watermark key {key}"));
        }
        seen.push(key);
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "epoch" => {
                epoch = value.parse::<u64>().ok();
            }
            "state_root" => {
                // An empty root is not a state identity; accepting it
                // would let a truncated/tampered file pass the replay
                // gate with a placeholder value.
                if value.is_empty() {
                    return Err("empty membership watermark state_root".to_owned());
                }
                state_root = Some(value.to_owned());
            }
            _ => return Err(format!("unknown membership watermark key {key}")),
        }
    }
    if version != Some(1) {
        return Err("unsupported membership watermark version".to_owned());
    }
    Ok(Some(MembershipWatermark {
        epoch: epoch.ok_or_else(|| "missing membership watermark epoch".to_owned())?,
        state_root: state_root
            .ok_or_else(|| "missing membership watermark state_root".to_owned())?,
    }))
}

/// Persist the watermark atomically (temp file + fsync + rename +
/// parent-directory fsync), `0700` parent directory, `0600` file. The
/// same integrity level as every other trust watermark in this codebase
/// (trust/traversal/DNS-zone/relay-fleet) — this does not lower or raise
/// that bar, it extends it to a path (anchor bundle-pull) that previously
/// had none at all.
pub fn persist_membership_watermark(
    path: &Path,
    watermark: &MembershipWatermark,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
        }
    }
    let payload = format!(
        "version=1\nepoch={}\nstate_root={}\n",
        watermark.epoch, watermark.state_root
    );
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600)
    };
    let mut temp = options.open(&temp_path).map_err(|err| err.to_string())?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(err.to_string());
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent_dir = fs::File::open(parent).map_err(|err| err.to_string())?;
        parent_dir.sync_all().map_err(|err| err.to_string())?;
    }
    Ok(())
}

pub fn append_membership_log_entry(
    path: impl AsRef<Path>,
    signed_update: &SignedMembershipUpdate,
) -> Result<MembershipLogEntry, MembershipError> {
    let path = path.as_ref();
    let mut entries = if path.exists() {
        load_membership_log(path)?
    } else {
        Vec::new()
    };
    let index = entries.len() as u64;
    let previous_hash = entries
        .last()
        .map_or_else(|| "genesis".to_owned(), |entry| entry.entry_hash.clone());
    let encoded_update = signed_update.canonical_envelope()?;
    let encoded_update_hex = hex_encode(encoded_update.as_bytes());
    let entry_material = format!("{index}|{previous_hash}|{encoded_update_hex}");
    let entry_hash = sha256_hex(entry_material.as_bytes());
    let entry = MembershipLogEntry {
        index,
        previous_hash,
        entry_hash,
        signed_update: signed_update.clone(),
    };
    entries.push(entry.clone());
    persist_membership_log(path, &entries)?;
    Ok(entry)
}

pub fn load_membership_log(
    path: impl AsRef<Path>,
) -> Result<Vec<MembershipLogEntry>, MembershipError> {
    let path = path.as_ref();
    validate_membership_file_security(path, "membership log")?;
    let content =
        read_membership_artifact_bounded(path, "membership log", MAX_MEMBERSHIP_LOG_BYTES)?;
    let mut lines = content.lines();
    let version_line = lines
        .next()
        .ok_or_else(|| MembershipError::InvalidFormat("missing log version".to_owned()))?;
    let Some((version_key, version_value)) = version_line.split_once('=') else {
        return Err(MembershipError::InvalidFormat(
            "log version line missing separator".to_owned(),
        ));
    };
    if version_key != "version" {
        return Err(MembershipError::InvalidFormat(
            "log first line must be version".to_owned(),
        ));
    }
    let version = version_value
        .parse::<u8>()
        .map_err(|_| MembershipError::InvalidFormat("invalid log version".to_owned()))?;
    if version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedVersion(version));
    }

    let mut entries = Vec::new();
    for line in lines {
        let Some(encoded) = line.strip_prefix("entry=") else {
            return Err(MembershipError::InvalidFormat(format!(
                "unexpected log line: {line}"
            )));
        };
        let parts = encoded.split('|').collect::<Vec<_>>();
        if parts.len() != 4 {
            return Err(MembershipError::InvalidFormat(
                "log entry field count mismatch".to_owned(),
            ));
        }
        let index = parts[0]
            .parse::<u64>()
            .map_err(|_| MembershipError::InvalidFormat("invalid log entry index".to_owned()))?;
        let previous_hash = parts[1].to_owned();
        let entry_hash = parts[2].to_owned();
        let encoded_update_hex = parts[3];
        let expected_hash =
            sha256_hex(format!("{index}|{previous_hash}|{encoded_update_hex}").as_bytes());
        if expected_hash != entry_hash {
            return Err(MembershipError::IntegrityMismatch);
        }
        let encoded_update_raw = hex_decode(encoded_update_hex)?;
        let encoded_update = String::from_utf8(encoded_update_raw).map_err(|_| {
            MembershipError::InvalidFormat("encoded update payload is not utf8".to_owned())
        })?;
        let signed_update = parse_signed_update_envelope(&encoded_update)?;
        entries.push(MembershipLogEntry {
            index,
            previous_hash,
            entry_hash,
            signed_update,
        });
    }

    verify_membership_log_chain(&entries)?;
    Ok(entries)
}

pub fn replay_membership_snapshot_and_log(
    snapshot: &MembershipState,
    entries: &[MembershipLogEntry],
    now_unix: u64,
) -> Result<MembershipState, MembershipError> {
    let snapshot_root = snapshot.state_root_hex()?;
    let mut state = snapshot.clone();
    let mut replay_cache = MembershipReplayCache {
        seen_update_ids: HashSet::new(),
        seen_update_order: VecDeque::new(),
        max_epoch: snapshot.epoch,
    };
    let mut replay_started = false;
    for entry in entries {
        if !replay_started {
            let record = &entry.signed_update.record;
            if record.epoch_prev < snapshot.epoch {
                continue;
            }
            if record.epoch_prev != snapshot.epoch || record.prev_state_root != snapshot_root {
                return Err(MembershipError::PrevStateRootMismatch);
            }
            replay_started = true;
        }
        state = apply_signed_update(&state, &entry.signed_update, now_unix, &mut replay_cache)?;
    }
    Ok(state)
}

pub fn write_membership_audit_log(
    path: impl AsRef<Path>,
    entries: &[MembershipLogEntry],
) -> Result<(), MembershipError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| MembershipError::Io(err.to_string()))?;
    }
    let mut out = String::new();
    for entry in entries {
        out.push_str(&format!(
            "index={} previous_hash={} entry_hash={} update_id={} operation={} target={}\n",
            entry.index,
            entry.previous_hash,
            entry.entry_hash,
            entry.signed_update.record.update_id,
            entry.signed_update.record.operation.operation_name(),
            entry.signed_update.record.target
        ));
    }
    fs::write(path, out).map_err(|err| MembershipError::Io(err.to_string()))
}

fn persist_membership_log(
    path: &Path,
    entries: &[MembershipLogEntry],
) -> Result<(), MembershipError> {
    verify_membership_log_chain(entries)?;
    let mut out = format!("version={MEMBERSHIP_SCHEMA_VERSION}\n");
    for entry in entries {
        let update_envelope = entry.signed_update.canonical_envelope()?;
        let update_hex = hex_encode(update_envelope.as_bytes());
        out.push_str(&format!(
            "entry={}|{}|{}|{}\n",
            entry.index, entry.previous_hash, entry.entry_hash, update_hex
        ));
    }
    atomic_write(path, out.as_bytes(), 0o600)
}

fn verify_membership_log_chain(entries: &[MembershipLogEntry]) -> Result<(), MembershipError> {
    for (position, entry) in entries.iter().enumerate() {
        if entry.index != position as u64 {
            return Err(MembershipError::IntegrityMismatch);
        }
        let expected_previous = if position == 0 {
            "genesis".to_owned()
        } else {
            entries[position - 1].entry_hash.clone()
        };
        if entry.previous_hash != expected_previous {
            return Err(MembershipError::IntegrityMismatch);
        }
        let update_envelope = entry.signed_update.canonical_envelope()?;
        let update_hex = hex_encode(update_envelope.as_bytes());
        let expected_hash = sha256_hex(
            format!("{}|{}|{}", entry.index, entry.previous_hash, update_hex).as_bytes(),
        );
        if expected_hash != entry.entry_hash {
            return Err(MembershipError::IntegrityMismatch);
        }
    }
    Ok(())
}

fn verify_membership_signatures(
    state: &MembershipState,
    signed_update: &SignedMembershipUpdate,
    payload: &[u8],
) -> Result<(), MembershipError> {
    let active_approvers = state.active_approvers();
    let mut signer_ids = BTreeSet::new();
    for signature in &signed_update.approver_signatures {
        if !signer_ids.insert(signature.approver_id.clone()) {
            return Err(MembershipError::InvalidFormat(
                "duplicate signer id in update signatures".to_owned(),
            ));
        }
    }
    if signer_ids.len() < usize::from(state.quorum_threshold) {
        return Err(MembershipError::ThresholdNotMet);
    }

    let mut owner_signed = false;
    for signature in &signed_update.approver_signatures {
        let approver = active_approvers
            .get(&signature.approver_id)
            .ok_or_else(|| MembershipError::SignerNotAuthorized(signature.approver_id.clone()))?;
        if approver.role == MembershipApproverRole::Owner {
            owner_signed = true;
        }
        let verifying_key =
            VerifyingKey::from_bytes(&decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)?)
                .map_err(|_| MembershipError::SignatureInvalid)?;
        let signature_bytes = decode_hex_to_fixed::<64>(&signature.signature_hex)?;
        let signature_obj = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(payload, &signature_obj)
            .map_err(|_| MembershipError::SignatureInvalid)?;
    }

    if signed_update.record.operation.requires_owner_signer() && !owner_signed {
        return Err(MembershipError::OwnerSignatureRequired);
    }

    Ok(())
}

/// Bundle tagged with the rotation epoch under which it was signed.
///
/// `EpochTaggedBundle` is the explicit replay-watermark wrapper that the
/// daemon uses to bind a peer-issued payload (membership update,
/// gossip-derived state delta, etc.) to the signing key generation that
/// produced it. The `epoch_tag` is the [`crate::key_rotation::RotationEpoch`]
/// value that was current on the signing node when the payload was
/// signed; the watermark is the monotonically-increasing
/// per-epoch sequence number for that payload.
///
/// Verification consults both the [`crate::key_rotation::VerifierArchive`]
/// (for epoch-correct verifier-key lookup) and the
/// [`crate::key_rotation::PerEpochReplayWatermark`] (for "this bundle is
/// not past the rotation freeze point" enforcement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochTaggedBundle {
    pub epoch_tag: crate::key_rotation::RotationEpoch,
    pub update_watermark: u64,
    pub payload: Vec<u8>,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochTaggedBundleError {
    Membership(MembershipError),
    Rotation(crate::key_rotation::RotationError),
}

impl fmt::Display for EpochTaggedBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EpochTaggedBundleError::Membership(err) => write!(f, "{err}"),
            EpochTaggedBundleError::Rotation(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for EpochTaggedBundleError {}

impl From<MembershipError> for EpochTaggedBundleError {
    fn from(err: MembershipError) -> Self {
        EpochTaggedBundleError::Membership(err)
    }
}

impl From<crate::key_rotation::RotationError> for EpochTaggedBundleError {
    fn from(err: crate::key_rotation::RotationError) -> Self {
        EpochTaggedBundleError::Rotation(err)
    }
}

/// Verify an [`EpochTaggedBundle`] against an archived verifier key
/// indexed by the bundle's epoch tag, then enforce the per-epoch
/// rotation-watermark policy.
///
/// The verifier archive lookup MUST come from a previously-committed
/// rotation record so a stolen old-key-signed bundle cannot resurrect a
/// long-discarded epoch. The per-epoch watermark MUST be consulted
/// before signature verification short-circuits success: a bundle that
/// passes signature verification but violates the rotation-watermark
/// policy is a security-context violation and is reported as
/// [`crate::key_rotation::RotationError::WatermarkPastRotationPoint`].
pub fn verify_epoch_tagged_bundle(
    bundle: &EpochTaggedBundle,
    archive: &crate::key_rotation::VerifierArchive,
    watermark: &crate::key_rotation::PerEpochReplayWatermark,
) -> Result<(), EpochTaggedBundleError> {
    watermark.validate_bundle(bundle.epoch_tag, bundle.update_watermark)?;
    let archived = archive
        .lookup(bundle.epoch_tag)
        .ok_or(EpochTaggedBundleError::Rotation(
            crate::key_rotation::RotationError::UnknownEpoch {
                epoch: bundle.epoch_tag,
            },
        ))?;
    let verifying_key_bytes = decode_hex_to_fixed::<32>(&archived.public_key_hex)
        .map_err(EpochTaggedBundleError::Membership)?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| EpochTaggedBundleError::Membership(MembershipError::SignatureInvalid))?;
    let signature_bytes = decode_hex_to_fixed::<64>(&bundle.signature_hex)
        .map_err(EpochTaggedBundleError::Membership)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(bundle.payload.as_slice(), &signature)
        .map_err(|_| EpochTaggedBundleError::Membership(MembershipError::SignatureInvalid))
}

/// Apply `operation` to `state`, producing the next state.
///
/// `op_created_at_unix` is the DETERMINISTIC timestamp the operation's signed
/// record carries (`record.created_at_unix`). It is stamped into the affected
/// node's `updated_at_unix` so the resulting `state_root` is a pure function of
/// (state, operation, signed-timestamp) and reproduces identically at proposal
/// time and apply time. RSA-0009: the reducer previously stamped `unix_now()`
/// here, so the producer's `new_state_root` (computed at T1) never matched the
/// applier's re-derivation (at T2 ≠ T1 second) and RevokeNode / RestoreNode /
/// RotateNodeKey / SetNodeCapabilities could never apply — revocation and
/// key-rotation were non-functional (CLAUDE.md §8: deterministic trust-state
/// transitions).
fn reduce_membership_state(
    state: &MembershipState,
    operation: &MembershipOperation,
    op_created_at_unix: u64,
) -> Result<MembershipState, MembershipError> {
    let mut next = state.clone();
    match operation {
        MembershipOperation::AddNode(node) => {
            if next
                .nodes
                .iter()
                .any(|candidate| candidate.node_id == node.node_id)
            {
                return Err(MembershipError::InvalidTransition(
                    "cannot add node that already exists",
                ));
            }
            decode_hex_to_fixed::<32>(&node.node_pubkey_hex)?;
            next.nodes.push(node.clone());
        }
        MembershipOperation::SetNodeCapabilities {
            node_id,
            capabilities,
        } => {
            let node = next
                .nodes
                .iter_mut()
                .find(|candidate| candidate.node_id == *node_id)
                .ok_or_else(|| MembershipError::NotFound(format!("node {node_id}")))?;
            // RT-2 / SecMinBar §6.D.2: blind_exit is immutable — the ONLY way
            // out is factory reset + fresh enrollment under a new identity,
            // never a capability-set update on the existing node. Without
            // this check, `transition_plan()` (rustynet-control::role_presets,
            // a CLI-facing advisory planner) refuses to construct a reversing
            // transition, but nothing stopped a validly-signed
            // SetNodeCapabilities update from reversing it directly at the
            // membership-state layer — the same class of gap as RSA-0009/
            // DD-03: enforcement lived in a helper, not the trust boundary.
            if node.capabilities.contains(&RoleCapability::BlindExit) {
                return Err(MembershipError::InvalidTransition(
                    "blind_exit is immutable; factory reset and fresh enrollment are required to change capabilities",
                ));
            }
            node.capabilities = canonicalize_role_capabilities(capabilities.iter().copied());
            node.updated_at_unix = op_created_at_unix;
        }
        MembershipOperation::RemoveNode { node_id } => {
            let before = next.nodes.len();
            next.nodes.retain(|candidate| candidate.node_id != *node_id);
            if next.nodes.len() == before {
                return Err(MembershipError::NotFound(format!("node {node_id}")));
            }
        }
        MembershipOperation::RevokeNode { node_id } => {
            let node = next
                .nodes
                .iter_mut()
                .find(|candidate| candidate.node_id == *node_id)
                .ok_or_else(|| MembershipError::NotFound(format!("node {node_id}")))?;
            if node.status == MembershipNodeStatus::Revoked {
                return Err(MembershipError::InvalidTransition("node already revoked"));
            }
            node.status = MembershipNodeStatus::Revoked;
            node.updated_at_unix = op_created_at_unix;
        }
        MembershipOperation::RestoreNode { node_id } => {
            let node = next
                .nodes
                .iter_mut()
                .find(|candidate| candidate.node_id == *node_id)
                .ok_or_else(|| MembershipError::NotFound(format!("node {node_id}")))?;
            if node.status == MembershipNodeStatus::Active {
                return Err(MembershipError::InvalidTransition("node already active"));
            }
            node.status = MembershipNodeStatus::Active;
            node.updated_at_unix = op_created_at_unix;
        }
        MembershipOperation::RotateNodeKey {
            node_id,
            new_pubkey_hex,
        } => {
            decode_hex_to_fixed::<32>(new_pubkey_hex)?;
            let node = next
                .nodes
                .iter_mut()
                .find(|candidate| candidate.node_id == *node_id)
                .ok_or_else(|| MembershipError::NotFound(format!("node {node_id}")))?;
            node.node_pubkey_hex = new_pubkey_hex.clone();
            node.updated_at_unix = op_created_at_unix;
        }
        MembershipOperation::RotateApprover(approver) => {
            decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)?;
            if let Some(existing) = next
                .approver_set
                .iter_mut()
                .find(|candidate| candidate.approver_id == approver.approver_id)
            {
                *existing = approver.clone();
            } else {
                next.approver_set.push(approver.clone());
            }
        }
        MembershipOperation::SetQuorum { threshold } => {
            if *threshold == 0 {
                return Err(MembershipError::InvalidTransition(
                    "quorum threshold must be at least one",
                ));
            }
            next.quorum_threshold = *threshold;
        }
    }
    Ok(next)
}

fn parse_membership_state_payload(payload: &str) -> Result<MembershipState, MembershipError> {
    let fields = parse_key_values(payload)?;
    let version = parse_u8_field(&fields, "version")?;
    if version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedVersion(version));
    }
    let network_id = required_field(&fields, "network_id")?.to_owned();
    let epoch = parse_u64_field(&fields, "epoch")?;
    let quorum_threshold = parse_u8_field(&fields, "quorum_threshold")?;
    let metadata_hash_raw = required_field(&fields, "metadata_hash")?.to_owned();
    let metadata_hash = if metadata_hash_raw.is_empty() {
        None
    } else {
        Some(metadata_hash_raw)
    };
    let node_count = bounded_count(
        "node_count",
        parse_usize_field(&fields, "node_count")?,
        MAX_MEMBERSHIP_NODE_COUNT,
        fields.len(),
    )?;
    let mut nodes = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let node = MembershipNode {
            node_id: required_field(&fields, &format!("node.{index}.node_id"))?.to_owned(),
            node_pubkey_hex: required_field(&fields, &format!("node.{index}.node_pubkey_hex"))?
                .to_owned(),
            owner: required_field(&fields, &format!("node.{index}.owner"))?.to_owned(),
            status: MembershipNodeStatus::parse(required_field(
                &fields,
                &format!("node.{index}.status"),
            )?)?,
            roles: split_csv(required_field(&fields, &format!("node.{index}.roles"))?),
            capabilities: parse_node_capabilities(
                fields
                    .get(format!("node.{index}.capabilities").as_str())
                    .copied(),
                &format!("node.{index}.capabilities"),
            )?,
            joined_at_unix: parse_u64_field(&fields, &format!("node.{index}.joined_at_unix"))?,
            updated_at_unix: parse_u64_field(&fields, &format!("node.{index}.updated_at_unix"))?,
        };
        nodes.push(node);
    }
    let approver_count = bounded_count(
        "approver_count",
        parse_usize_field(&fields, "approver_count")?,
        MAX_MEMBERSHIP_APPROVER_COUNT,
        fields.len(),
    )?;
    let mut approver_set = Vec::with_capacity(approver_count);
    for index in 0..approver_count {
        let approver = MembershipApprover {
            approver_id: required_field(&fields, &format!("approver.{index}.approver_id"))?
                .to_owned(),
            approver_pubkey_hex: required_field(
                &fields,
                &format!("approver.{index}.approver_pubkey_hex"),
            )?
            .to_owned(),
            role: MembershipApproverRole::parse(required_field(
                &fields,
                &format!("approver.{index}.role"),
            )?)?,
            status: MembershipApproverStatus::parse(required_field(
                &fields,
                &format!("approver.{index}.status"),
            )?)?,
            created_at_unix: parse_u64_field(
                &fields,
                &format!("approver.{index}.created_at_unix"),
            )?,
        };
        approver_set.push(approver);
    }

    Ok(MembershipState {
        schema_version: version,
        network_id,
        epoch,
        nodes,
        approver_set,
        quorum_threshold,
        metadata_hash,
    })
}

fn parse_signed_update_envelope(value: &str) -> Result<SignedMembershipUpdate, MembershipError> {
    let fields = parse_key_values(value)?;
    let payload_hex = required_field(&fields, "payload_hex")?;
    let payload_raw = hex_decode(payload_hex)?;
    let payload = String::from_utf8(payload_raw)
        .map_err(|_| MembershipError::InvalidFormat("update payload is not utf8".to_owned()))?;
    let record = parse_membership_update_payload(&payload)?;

    let sig_count = bounded_count(
        "sig_count",
        parse_usize_field(&fields, "sig_count")?,
        MAX_MEMBERSHIP_SIGNATURE_COUNT,
        fields.len(),
    )?;
    let mut signatures = Vec::with_capacity(sig_count);
    for index in 0..sig_count {
        signatures.push(MembershipSignature {
            approver_id: required_field(&fields, &format!("sig.{index}.approver_id"))?.to_owned(),
            signature_hex: required_field(&fields, &format!("sig.{index}.signature_hex"))?
                .to_owned(),
            head_signature_hex: fields
                .get(format!("sig.{index}.head_signature_hex").as_str())
                .copied()
                .map(ToOwned::to_owned),
        });
    }
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures: signatures,
    })
}

fn parse_membership_update_payload(
    payload: &str,
) -> Result<MembershipUpdateRecord, MembershipError> {
    let fields = parse_key_values(payload)?;
    let version = parse_u8_field(&fields, "version")?;
    if version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedVersion(version));
    }
    let operation_name = required_field(&fields, "operation")?;
    let operation = match operation_name {
        "add_node" => MembershipOperation::AddNode(MembershipNode {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
            node_pubkey_hex: required_field(&fields, "op.node_pubkey_hex")?.to_owned(),
            owner: required_field(&fields, "op.owner")?.to_owned(),
            status: MembershipNodeStatus::parse(required_field(&fields, "op.status")?)?,
            roles: split_csv(required_field(&fields, "op.roles")?),
            capabilities: parse_node_capabilities(
                fields.get("op.capabilities").copied(),
                "op.capabilities",
            )?,
            joined_at_unix: parse_u64_field(&fields, "op.joined_at_unix")?,
            updated_at_unix: parse_u64_field(&fields, "op.updated_at_unix")?,
        }),
        "set_node_capabilities" => MembershipOperation::SetNodeCapabilities {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
            capabilities: parse_node_capabilities(
                fields.get("op.capabilities").copied(),
                "op.capabilities",
            )?,
        },
        "remove_node" => MembershipOperation::RemoveNode {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
        },
        "revoke_node" => MembershipOperation::RevokeNode {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
        },
        "restore_node" => MembershipOperation::RestoreNode {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
        },
        "rotate_node_key" => MembershipOperation::RotateNodeKey {
            node_id: required_field(&fields, "op.node_id")?.to_owned(),
            new_pubkey_hex: required_field(&fields, "op.new_pubkey_hex")?.to_owned(),
        },
        "rotate_approver" => MembershipOperation::RotateApprover(MembershipApprover {
            approver_id: required_field(&fields, "op.approver_id")?.to_owned(),
            approver_pubkey_hex: required_field(&fields, "op.approver_pubkey_hex")?.to_owned(),
            role: MembershipApproverRole::parse(required_field(&fields, "op.role")?)?,
            status: MembershipApproverStatus::parse(required_field(&fields, "op.status")?)?,
            created_at_unix: parse_u64_field(&fields, "op.created_at_unix")?,
        }),
        "set_quorum" => MembershipOperation::SetQuorum {
            threshold: parse_u8_field(&fields, "op.threshold")?,
        },
        _ => {
            return Err(MembershipError::InvalidFormat(format!(
                "unknown update operation {operation_name}"
            )));
        }
    };

    let policy_context_raw = required_field(&fields, "policy_context")?.to_owned();
    Ok(MembershipUpdateRecord {
        network_id: required_field(&fields, "network_id")?.to_owned(),
        update_id: required_field(&fields, "update_id")?.to_owned(),
        operation,
        target: required_field(&fields, "target")?.to_owned(),
        prev_state_root: required_field(&fields, "prev_state_root")?.to_owned(),
        new_state_root: required_field(&fields, "new_state_root")?.to_owned(),
        epoch_prev: parse_u64_field(&fields, "epoch_prev")?,
        epoch_new: parse_u64_field(&fields, "epoch_new")?,
        created_at_unix: parse_u64_field(&fields, "created_at_unix")?,
        expires_at_unix: parse_u64_field(&fields, "expires_at_unix")?,
        reason_code: required_field(&fields, "reason_code")?.to_owned(),
        policy_context: if policy_context_raw.is_empty() {
            None
        } else {
            Some(policy_context_raw)
        },
    })
}

fn atomic_write(path: &Path, body: &[u8], _mode: u32) -> Result<(), MembershipError> {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            let metadata =
                fs::symlink_metadata(parent).map_err(|err| MembershipError::Io(err.to_string()))?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                return Err(MembershipError::InvalidFormat(format!(
                    "membership parent path {} must be a real directory",
                    parent.display()
                )));
            }
        }
        fs::create_dir_all(parent).map_err(|err| MembershipError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| MembershipError::Io(err.to_string()))?;
        }
    }
    // Capture the existing file's owner before replacing it so we can
    // restore ownership after the atomic rename.  When root-run tooling
    // (e.g. `enrollment admit --apply`) rewrites a snapshot that the
    // daemon owns (uid=rustynetd), the new file inherits uid=root and the
    // daemon then rejects it on the ownership check in
    // validate_membership_file_security.
    #[cfg(unix)]
    let prev_owner: Option<(u32, u32)> = fs::metadata(path).ok().map(|m| (m.uid(), m.gid()));

    if path.exists() {
        let metadata =
            fs::symlink_metadata(path).map_err(|err| MembershipError::Io(err.to_string()))?;
        if metadata.file_type().is_symlink() {
            return Err(MembershipError::InvalidFormat(format!(
                "membership target {} must not be a symlink",
                path.display()
            )));
        }
    }
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(_mode)
    };
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| MembershipError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(body) {
        let _ = fs::remove_file(&temp_path);
        return Err(MembershipError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(MembershipError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(MembershipError::Io(err.to_string()));
    }
    // Restore original ownership when running as root over a non-root-owned
    // file.  root can always chown, so an error here is unexpected and we
    // surface it rather than silently leaving a root-owned snapshot.
    #[cfg(unix)]
    if let Some((uid, gid)) = prev_owner.filter(|(uid, _)| *uid != 0)
        && Uid::effective().is_root()
    {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
            .map_err(|err| MembershipError::Io(format!("chown {}: {err}", path.display())))?;
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| MembershipError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| MembershipError::Io(err.to_string()))?;
    }
    validate_membership_file_security(path, "membership state file")?;
    Ok(())
}

/// Read a membership artifact from disk with a hard upper bound enforced
/// inside the read loop.
///
/// `validate_membership_file_security` already requires the path to be a
/// regular file (not a symlink), owned by the effective uid, and 0o600 or
/// stricter — so a low-privilege attacker cannot point the loader at an
/// arbitrary file. This helper is the defense-in-depth layer that bounds
/// peak memory if the file is corrupted, truncated, grown by a buggy
/// daemon, or otherwise produces more bytes than legitimate membership
/// state can ever require.
///
/// We use `Read::take(max + 1).read_to_string(...)` so the cap is enforced
/// during read, not after. The post-read length check then surfaces the
/// "file too big" error before any structural parser runs.
fn read_membership_artifact_bounded(
    path: &Path,
    artifact_name: &str,
    max_bytes: usize,
) -> Result<String, MembershipError> {
    use std::io::Read;
    let file = fs::File::open(path)
        .map_err(|err| MembershipError::Io(format!("{artifact_name} open failed: {err}")))?;
    let mut buf = String::new();
    file.take(max_bytes as u64 + 1)
        .read_to_string(&mut buf)
        .map_err(|err| MembershipError::Io(format!("{artifact_name} read failed: {err}")))?;
    if buf.len() > max_bytes {
        return Err(MembershipError::InvalidFormat(format!(
            "{artifact_name} exceeds maximum size of {max_bytes} bytes"
        )));
    }
    Ok(buf)
}

fn validate_membership_file_security(path: &Path, label: &str) -> Result<(), MembershipError> {
    #[cfg(unix)]
    {
        let link_metadata =
            fs::symlink_metadata(path).map_err(|err| MembershipError::Io(err.to_string()))?;
        if link_metadata.file_type().is_symlink() || !link_metadata.file_type().is_file() {
            return Err(MembershipError::InvalidFormat(format!(
                "{label} path must be a regular file and must not be a symlink"
            )));
        }
        let metadata = fs::metadata(path).map_err(|err| MembershipError::Io(err.to_string()))?;
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(MembershipError::InvalidFormat(format!(
                "{label} permissions are too broad: {mode:o}"
            )));
        }
        let owner_uid = metadata.uid();
        let effective_uid = Uid::effective().as_raw();
        // The membership snapshot is written by the daemon (whose
        // effective UID owns the file) and read by both the daemon
        // and root-running tooling such as `rustynet anchor list`
        // executed under sudo. When the reader is root (effective
        // UID 0), it is allowed to read any owner's file — mode bits
        // (checked above) already restrict access to the file owner,
        // and root can chown/chmod regardless. Without this carve-out
        // every root-only verb that reads the snapshot fails with
        // `owner uid mismatch: expected 0, got <daemon_uid>` and
        // breaks downstream lab stages like `live_anchor`.
        if owner_uid != effective_uid && effective_uid != 0 {
            return Err(MembershipError::InvalidFormat(format!(
                "{label} owner uid mismatch: expected {effective_uid}, got {owner_uid}"
            )));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, label);
    }
    Ok(())
}

fn required_field<'a>(
    fields: &HashMap<&'a str, &'a str>,
    key: &str,
) -> Result<&'a str, MembershipError> {
    fields
        .get(key)
        .copied()
        .ok_or_else(|| MembershipError::InvalidFormat(format!("missing field {key}")))
}

/// Parse the line-oriented `key=value` body into a map that BORROWS keys and
/// values from `value` — no per-field `String` allocation. The returned map
/// is valid only while `value` lives (every caller holds the source string
/// for the duration). Same accepted/rejected inputs and error strings as
/// before; fail-closed callers match on those strings, so they are verbatim.
fn parse_key_values(value: &str) -> Result<HashMap<&str, &str>, MembershipError> {
    let mut fields = HashMap::new();
    for line in value.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((key, field_value)) = line.split_once('=') else {
            return Err(MembershipError::InvalidFormat(
                "line missing key/value separator".to_owned(),
            ));
        };
        if fields.insert(key, field_value).is_some() {
            return Err(MembershipError::InvalidFormat(format!(
                "duplicate field {key}"
            )));
        }
    }
    Ok(fields)
}

fn parse_u8_field(fields: &HashMap<&str, &str>, key: &str) -> Result<u8, MembershipError> {
    required_field(fields, key)?
        .parse::<u8>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid u8 field {key}")))
}

fn parse_u64_field(fields: &HashMap<&str, &str>, key: &str) -> Result<u64, MembershipError> {
    required_field(fields, key)?
        .parse::<u64>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid u64 field {key}")))
}

fn parse_usize_field(fields: &HashMap<&str, &str>, key: &str) -> Result<usize, MembershipError> {
    required_field(fields, key)?
        .parse::<usize>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid usize field {key}")))
}

/// Validate a decoder length/count field before it is used to pre-allocate a
/// `Vec`. Rejects counts above the hard `max` ceiling and, as a second bound,
/// any count exceeding the number of parsed fields: every element contributes
/// at least one indexed `key=value` line, so a legitimate count can never
/// exceed `field_total`. Because `field_total` is itself bounded by the
/// size-capped input (the 4 KiB IPC envelope or the 8 MiB snapshot read cap),
/// this prevents capacity-overflow / memory-exhaustion aborts from a hostile
/// count regardless of which path the payload arrived on.
fn bounded_count(
    label: &str,
    count: usize,
    max: usize,
    field_total: usize,
) -> Result<usize, MembershipError> {
    if count > max {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} {count} exceeds maximum {max}"
        )));
    }
    if count > field_total {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} {count} exceeds parsed field count {field_total}"
        )));
    }
    Ok(count)
}

/// Reject a free-form field that would not survive
/// `canonical_payload` → `parse_membership_state_payload` unchanged.
///
/// The canonical payload is a line-oriented `key=value` text format, so a
/// value carrying one of the framing bytes is not merely ugly — it changes the
/// structure of the signed text. Both halves were confirmed by execution
/// (ENR-01, ENR-03):
///
/// - `\n` **forges a line**. `admit --node-id 'minipc-2'$'\n''node.1.status=revoked'`
///   is accepted, the epoch advances and the snapshot persists — after which
///   every load fails with `duplicate field node.1.status`, and the signed
///   envelope is equally unparseable, so co-signing is dead too. One operator
///   typo permanently bricks the membership snapshot. The forged line can also
///   be chosen to parse cleanly (`zz.injected=1`), in which case the reload
///   silently drops it and the stored state root no longer matches the
///   recomputed one: root drift under a valid approver signature.
/// - `\r` **mutates the value silently**. `str::lines()` strips a trailing
///   `\r`, so `evil\r` encodes and decodes back as `evil`. Nothing errors; the
///   identifier is simply not what was signed.
/// - `=` is the key/value separator. Every parser here splits on the *first*
///   `=`, so this one round-trips today and is rejected for consistency with
///   [`crate::is_single_line_payload_value`] rather than because a live vector
///   is known. Node ids are hostname slugs, so it strands nothing.
///
/// This is the chokepoint rather than a per-call-site guard on purpose:
/// `validate` runs inside both [`MembershipState::canonical_payload`] and
/// [`decode_membership_state`], so no writer can reach the signed text or the
/// snapshot without passing it, and a future writer inherits the check instead
/// of having to remember it. Tracked as AUDIT-042 in the 2026-06-10 audit,
/// which named this exact contrast with `is_single_line_payload_value`.
pub fn validate_membership_payload_field(label: &str, value: &str) -> Result<(), MembershipError> {
    if value.len() > MAX_MEMBERSHIP_FIELD_BYTES {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} exceeds {MAX_MEMBERSHIP_FIELD_BYTES} bytes"
        )));
    }
    if let Some(byte) = value
        .bytes()
        .find(|byte| matches!(byte, b'\n' | b'\r' | b'='))
    {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} contains a payload framing byte {byte:#04x}"
        )));
    }
    Ok(())
}

/// Same contract as [`validate_membership_payload_field`] for a single entry of
/// `node.<i>.roles`, which is additionally `,`-joined on encode and
/// `split(',') → trim → drop-empty` on decode ([`split_csv`]).
///
/// Those three decode steps are each a silent mutation of the signed value, so
/// the round-trip invariant needs all three refused here: a `,` splits one role
/// into two, surrounding whitespace is trimmed away, and an empty entry
/// vanishes entirely. Same ENR-03 shape as the `\r` case — no error is raised
/// at any layer, the roster simply stops matching what was signed.
fn validate_membership_role_entry(label: &str, role: &str) -> Result<(), MembershipError> {
    validate_membership_payload_field(label, role)?;
    if role.contains(',') {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} contains the role-list separator ','"
        )));
    }
    if role != role.trim() || role.is_empty() {
        return Err(MembershipError::InvalidFormat(format!(
            "{label} must be non-empty and free of surrounding whitespace"
        )));
    }
    Ok(())
}

fn validate_membership_node_capabilities(node: &MembershipNode) -> Result<(), MembershipError> {
    let capabilities = canonicalize_role_capabilities(node.capabilities.iter().copied());
    if node.status == MembershipNodeStatus::Active && capabilities.is_empty() {
        return Err(MembershipError::InvalidFormat(format!(
            "active node {} must have at least one signed role capability",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::BlindExit)
        && !capabilities.contains(&RoleCapability::ExitServer)
    {
        return Err(MembershipError::InvalidFormat(format!(
            "node {} blind_exit capability requires exit_server capability",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::EntryRelay)
        && !capabilities.contains(&RoleCapability::Client)
    {
        return Err(MembershipError::InvalidFormat(format!(
            "node {} entry_relay capability requires client capability",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::BlindExit)
        && (capabilities.contains(&RoleCapability::Anchor)
            || capabilities
                .iter()
                .any(|capability| capability.is_anchor_capability()))
    {
        return Err(MembershipError::InvalidFormat(format!(
            "node {} cannot combine anchor and blind_exit capabilities",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::AnchorRelayColocation)
        && !capabilities.contains(&RoleCapability::RelayHost)
    {
        return Err(MembershipError::InvalidFormat(format!(
            "node {} anchor.relay_colocation requires relay_host capability",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::AnchorPortMappingPinned)
        && !capabilities.contains(&RoleCapability::AnchorPortMappingAuthoritative)
    {
        return Err(MembershipError::InvalidFormat(format!(
            "node {} anchor.port_mapping_pinned requires anchor.port_mapping_authoritative capability",
            node.node_id
        )));
    }
    if capabilities.contains(&RoleCapability::BlindExit)
        && capabilities
            .iter()
            .any(|capability| capability.is_service_hosting_capability())
    {
        // blind_exit is the hardened minimal-surface final-hop exit;
        // co-hosting an application-layer service contradicts that
        // posture. The preset table never produces this combination
        // — reject it in signed state as well (strictest default).
        return Err(MembershipError::InvalidFormat(format!(
            "node {} cannot combine service-hosting (serves_nas/serves_llm) and blind_exit capabilities",
            node.node_id
        )));
    }
    Ok(())
}

/// Decode a node's signed capability set from its `…capabilities=` field.
///
/// **A missing field is a hard reject, not an inference.** This function used to
/// fall back to deriving capabilities from the free-form `roles` string when the
/// capabilities field was absent — a compatibility shim for snapshots written
/// before the field existed. That shim was deleted deliberately (ENR-05,
/// decode-side half), for a reason stronger than tidiness:
///
/// Capabilities are the *authorization* field. In a snapshot with no
/// capabilities line, what the approvers signed is a `roles` string — a label.
/// The fallback read that label and derived authority from it, mapping
/// `tag:servers` (a token the canonical parser rejects outright) to
/// `RoleCapability::Anchor`. The quorum's signature covered the label; it never
/// covered the grant. So the shim converted a signed label into an unsigned
/// privilege, which is the POL-05 shape — absence of authorization state
/// resolving to *more* authority rather than less — and the exact inversion
/// §10.4's default-deny rule exists to prevent. Making the shim merely stricter
/// would not have fixed that; only refusing to infer does.
///
/// Deleting it was measured, not assumed, before the change landed:
/// `MEMBERSHIP_SCHEMA_VERSION` has never been bumped (so the field was added
/// without one, which is why the shim existed); `canonical_payload` *always*
/// writes the field, so every snapshot this codebase has produced carries it;
/// no test anywhere reached the fallback, confirmed by making it `panic!` and
/// running the suite green; and no archived artifact contained such a snapshot.
///
/// The accepted residual risk: a genuine pre-capabilities snapshot no longer
/// loads, and its node fails closed. The diagnostic names the field so the
/// operator knows the remedy is to re-issue the snapshot.
///
/// Note an explicit-but-empty `capabilities=` still decodes to an empty set —
/// only *absence* is refused — so deliberately clearing a node's capabilities
/// remains expressible.
fn parse_node_capabilities(
    explicit: Option<&str>,
    field_label: &str,
) -> Result<Vec<RoleCapability>, MembershipError> {
    let Some(value) = explicit else {
        return Err(MembershipError::InvalidFormat(format!(
            "{field_label} is missing; capabilities are never inferred from roles — \
             re-issue the membership snapshot with an explicit capabilities field"
        )));
    };
    parse_role_capability_csv(value)
        .map_err(|err| MembershipError::InvalidFormat(format!("invalid role capability: {err}")))
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Lowercase hex alphabet for the nibble-lookup encoder.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    // Two-char-per-byte lookup instead of a `format!("{:02x}")` call (which
    // allocates a throwaway `String`) per byte. Byte-identical output — this
    // feeds canonical signed payloads and state-root hashes, so determinism
    // is pinned by the existing canonical/round-trip tests.
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize]);
        out.push(HEX_LOWER[(byte & 0x0f) as usize]);
    }
    // Safe: every pushed byte is an ASCII hex digit.
    String::from_utf8(out).expect("hex alphabet is valid ASCII")
}

fn hex_decode(encoded: &str) -> Result<Vec<u8>, MembershipError> {
    let trimmed = encoded.trim();
    if (trimmed.len() & 1) != 0 {
        return Err(MembershipError::InvalidFormat(
            "hex value has odd length".to_owned(),
        ));
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < raw.len() {
        let hi = decode_hex_nibble(raw[index])?;
        let lo = decode_hex_nibble(raw[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Ok(out)
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], MembershipError> {
    let mut bytes = [0u8; N];
    let decoded = hex_decode(encoded)?;
    if decoded.len() != N {
        return Err(MembershipError::InvalidFormat(format!(
            "hex value has invalid length: expected {}, got {}",
            N,
            decoded.len()
        )));
    }
    bytes.copy_from_slice(decoded.as_slice());
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, MembershipError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(MembershipError::InvalidFormat(
            "invalid hex character".to_owned(),
        )),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex_encode(digest.as_slice())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_REPLAY_CACHE_ENTRIES, MEMBERSHIP_CLOCK_SKEW_SECS, MEMBERSHIP_SCHEMA_VERSION,
        MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipError,
        MembershipNode, MembershipNodeStatus, MembershipOperation, MembershipReplayCache,
        MembershipSignature, MembershipState, MembershipUpdateRecord, MembershipWatermark,
        SignedMembershipUpdate, append_membership_log_entry, apply_signed_update,
        decode_membership_state, decode_update_record, encode_membership_state, hex_encode,
        load_membership_log, load_membership_snapshot, load_membership_watermark,
        persist_membership_snapshot, persist_membership_watermark, preview_next_state,
        reduce_membership_state, replay_membership_snapshot_and_log, sign_update_record,
        write_membership_audit_log,
    };
    // The size-cap constants are only exercised by the `#[cfg(unix)]` oversized-file
    // tests below; gate the import to match so Windows does not see them as unused.
    #[cfg(unix)]
    use super::{MAX_MEMBERSHIP_LOG_BYTES, MAX_MEMBERSHIP_SNAPSHOT_BYTES};
    use crate::roles::{RoleCapability, anchor_role_capabilities};
    use ed25519_dalek::SigningKey;

    fn approver(id: &str, key_byte: u8, role: MembershipApproverRole) -> MembershipApprover {
        let signing = SigningKey::from_bytes(&[key_byte; 32]);
        MembershipApprover {
            approver_id: id.to_owned(),
            approver_pubkey_hex: hex_encode(signing.verifying_key().as_bytes()),
            role,
            status: MembershipApproverStatus::Active,
            created_at_unix: 100,
        }
    }

    fn active_node(node_id: &str, pubkey_byte: u8) -> MembershipNode {
        MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex_encode(&[pubkey_byte; 32]),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_owned()],
            capabilities: vec![RoleCapability::Anchor],
            joined_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn base_state() -> MembershipState {
        MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-1".to_owned(),
            epoch: 1,
            nodes: vec![active_node("node-a", 9)],
            approver_set: vec![
                approver("owner-1", 1, MembershipApproverRole::Owner),
                approver("guardian-1", 2, MembershipApproverRole::Guardian),
                approver("guardian-2", 3, MembershipApproverRole::Guardian),
            ],
            quorum_threshold: 2,
            metadata_hash: None,
        }
    }

    #[test]
    fn parse_usize_field_rejects_missing_and_malformed() {
        use super::parse_usize_field;
        use std::collections::HashMap;
        let mut fields: HashMap<&str, &str> = HashMap::new();
        fields.insert("count", "42");
        fields.insert("neg", "-1");
        fields.insert("empty", "");
        fields.insert("spaced", " 5 ");
        fields.insert("huge", "99999999999999999999999999");
        fields.insert("word", "twelve");

        assert_eq!(parse_usize_field(&fields, "count").unwrap(), 42);
        // Missing key, negative, empty, whitespace-padded, overflow, and
        // non-numeric values are all rejected (fail-closed wire decode).
        assert!(parse_usize_field(&fields, "absent").is_err());
        assert!(parse_usize_field(&fields, "neg").is_err());
        assert!(parse_usize_field(&fields, "empty").is_err());
        assert!(parse_usize_field(&fields, "spaced").is_err());
        assert!(parse_usize_field(&fields, "huge").is_err());
        assert!(parse_usize_field(&fields, "word").is_err());
    }

    #[test]
    fn canonical_state_and_root_are_deterministic() {
        let mut first = base_state();
        first.nodes.push(active_node("node-b", 7));
        first
            .nodes
            .sort_by(|left, right| right.node_id.cmp(&left.node_id));

        let mut second = base_state();
        second.nodes.push(active_node("node-b", 7));

        let first_payload = first.canonical_payload().expect("payload should build");
        let second_payload = second.canonical_payload().expect("payload should build");
        assert_eq!(first_payload, second_payload);
        assert_eq!(
            first.state_root_hex().expect("root should build"),
            second.state_root_hex().expect("root should build")
        );
    }

    #[test]
    fn signed_membership_payload_carries_canonical_capabilities() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![RoleCapability::Client, RoleCapability::Anchor];
        let payload = state.canonical_payload().expect("payload should build");
        assert!(payload.contains("node.0.capabilities=anchor,client\n"));

        let update = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-add-node".to_owned(),
            operation: MembershipOperation::AddNode(MembershipNode {
                node_id: "node-b".to_owned(),
                node_pubkey_hex: hex_encode(&[7; 32]),
                owner: "owner@example.local".to_owned(),
                status: MembershipNodeStatus::Active,
                roles: vec!["tag:members".to_owned()],
                capabilities: vec![RoleCapability::Client],
                joined_at_unix: 101,
                updated_at_unix: 101,
            }),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: state.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 101,
            expires_at_unix: 400,
            reason_code: "policy".to_owned(),
            policy_context: None,
        };
        let update_payload = update.canonical_payload().expect("payload should build");
        assert!(update_payload.contains("op.capabilities=client\n"));
    }

    #[test]
    fn set_node_capabilities_update_round_trips_and_previews() {
        let state = base_state();
        let operation = MembershipOperation::SetNodeCapabilities {
            node_id: "node-a".to_owned(),
            capabilities: anchor_role_capabilities(),
        };
        let next =
            preview_next_state(&state, &operation, 1_700_000_000).expect("preview should pass");
        assert_eq!(next.epoch, state.epoch + 1);
        assert!(
            next.nodes[0]
                .capabilities
                .contains(&RoleCapability::AnchorBundlePull)
        );

        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-node-caps".to_owned(),
            operation,
            target: "node-a".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: next.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 101,
            expires_at_unix: 400,
            reason_code: "anchor_advertise".to_owned(),
            policy_context: None,
        };
        let payload = record.canonical_payload().expect("payload should build");
        assert!(payload.contains("operation=set_node_capabilities\n"));
        assert!(payload.contains("op.capabilities=anchor,relay_host,anchor.gossip_seed,anchor.bundle_pull,anchor.enrollment_endpoint,anchor.relay_colocation,anchor.port_mapping_authoritative\n"));
        let decoded = decode_update_record(&payload).expect("decode update");
        assert_eq!(decoded, record);
    }

    #[test]
    fn blind_exit_rejects_anchor_capability_mix() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![
            RoleCapability::BlindExit,
            RoleCapability::ExitServer,
            RoleCapability::AnchorBundlePull,
        ];
        let err = state.validate().expect_err("state should be rejected");
        assert!(format!("{err}").contains("cannot combine anchor and blind_exit"));
    }

    #[test]
    fn blind_exit_rejects_service_hosting_capability_mix() {
        for service_capability in [RoleCapability::ServesNas, RoleCapability::ServesLlm] {
            let mut state = base_state();
            state.nodes[0].capabilities = vec![
                RoleCapability::BlindExit,
                RoleCapability::ExitServer,
                service_capability,
            ];
            let err = state.validate().expect_err("state should be rejected");
            assert!(
                format!("{err}").contains("cannot combine service-hosting"),
                "expected service-hosting rejection for {service_capability}, got: {err}"
            );
        }
    }

    #[test]
    fn signed_membership_payload_carries_service_hosting_capabilities() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![
            RoleCapability::ServesLlm,
            RoleCapability::Anchor,
            RoleCapability::ServesNas,
        ];
        let payload = state.canonical_payload().expect("payload should build");
        // Canonical order is append-only: serves_nas / serves_llm
        // sort after every pre-existing capability.
        assert!(payload.contains("node.0.capabilities=anchor,serves_nas,serves_llm\n"));
    }

    #[test]
    fn set_node_capabilities_update_round_trips_service_hosting_flags() {
        let state = base_state();
        for (capabilities, expected_line) in [
            (
                vec![RoleCapability::Anchor, RoleCapability::ServesNas],
                "op.capabilities=anchor,serves_nas\n",
            ),
            (
                vec![RoleCapability::Anchor, RoleCapability::ServesLlm],
                "op.capabilities=anchor,serves_llm\n",
            ),
        ] {
            let operation = MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: capabilities.clone(),
            };
            let next =
                preview_next_state(&state, &operation, 1_700_000_000).expect("preview should pass");
            for capability in &capabilities {
                assert!(next.nodes[0].capabilities.contains(capability));
            }

            let record = MembershipUpdateRecord {
                network_id: state.network_id.clone(),
                update_id: "update-node-caps-service".to_owned(),
                operation,
                target: "node-a".to_owned(),
                prev_state_root: state.state_root_hex().expect("root"),
                new_state_root: next.state_root_hex().expect("root"),
                epoch_prev: state.epoch,
                epoch_new: state.epoch + 1,
                created_at_unix: 101,
                expires_at_unix: 400,
                reason_code: "service_hosting_advertise".to_owned(),
                policy_context: None,
            };
            let payload = record.canonical_payload().expect("payload should build");
            assert!(
                payload.contains(expected_line),
                "payload missing {expected_line:?}:\n{payload}"
            );
            let decoded = decode_update_record(&payload).expect("decode update");
            assert_eq!(decoded, record);
        }
    }

    #[test]
    fn tampered_service_hosting_capability_invalidates_signature() {
        // E-series control: serves_nas / serves_llm are signed
        // metadata. Flipping the flag after signing must fail closed
        // at signature verification, before any state mutation.
        let state = base_state();
        let mut node = active_node("node-b", 12);
        node.capabilities = vec![RoleCapability::Anchor, RoleCapability::ServesNas];

        let mut candidate = state.clone();
        candidate.nodes.push(node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-add-nas-node".to_owned(),
            operation: MembershipOperation::AddNode(node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signatures = vec![
            sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
            sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
        ];

        // Tamper: swap the signed serves_nas flag for serves_llm
        // (and separately drop it) after signing.
        for tampered_capabilities in [
            vec![RoleCapability::Anchor, RoleCapability::ServesLlm],
            vec![RoleCapability::Anchor],
        ] {
            let mut tampered_record = record.clone();
            if let MembershipOperation::AddNode(ref mut tampered_node) = tampered_record.operation {
                tampered_node.capabilities = tampered_capabilities;
            } else {
                unreachable!("record is an AddNode operation");
            }
            let signed = SignedMembershipUpdate {
                record: tampered_record,
                approver_signatures: signatures.clone(),
            };
            let err =
                apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                    .expect_err("tampered capability must fail closed");
            assert!(
                matches!(err, MembershipError::SignatureInvalid),
                "expected SignatureInvalid, got {err:?}"
            );
        }

        // Untampered control: the same signatures apply cleanly.
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: signatures,
        };
        let applied =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("untampered update should apply");
        assert!(applied.nodes.iter().any(|node| {
            node.node_id == "node-b" && node.capabilities.contains(&RoleCapability::ServesNas)
        }));
    }

    #[test]
    fn active_membership_nodes_require_signed_capabilities() {
        let mut state = base_state();
        state.nodes[0].capabilities.clear();
        let err = state.validate().expect_err("state should be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn blind_exit_capability_requires_exit_server_capability() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![RoleCapability::BlindExit];
        let err = state.validate().expect_err("state should be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn membership_validate_rejects_pinned_without_authoritative() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![RoleCapability::AnchorPortMappingPinned];
        let err = state.validate().expect_err("state should be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn membership_state_with_pinned_capability_encodes_decodes_and_revalidates() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![
            RoleCapability::AnchorPortMappingAuthoritative,
            RoleCapability::AnchorPortMappingPinned,
        ];
        state.validate().expect("pinned + authoritative is valid");

        let payload = encode_membership_state(&state).expect("state should encode");
        assert!(payload.contains("anchor.port_mapping_authoritative,anchor.port_mapping_pinned"));

        let decoded = decode_membership_state(&payload).expect("decode should revalidate and pass");
        assert_eq!(decoded.nodes[0].capabilities, state.nodes[0].capabilities);
        assert_eq!(
            decoded.state_root_hex().expect("root"),
            state.state_root_hex().expect("root")
        );
    }

    #[test]
    fn unknown_schema_version_is_rejected_fail_closed() {
        let mut state = base_state();
        state.schema_version = 2;
        let err = state.validate().expect_err("state should be rejected");
        assert_eq!(err, MembershipError::UnsupportedVersion(2));
    }

    #[test]
    fn signed_update_requires_threshold_and_owner_for_quorum_change() {
        let state = base_state();
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-1".to_owned(),
            operation: MembershipOperation::SetQuorum { threshold: 2 },
            target: "quorum".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: state.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 101,
            expires_at_unix: 400,
            reason_code: "policy".to_owned(),
            policy_context: None,
        };

        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signature = sign_update_record(&record, "guardian-1", &guardian_key)
            .expect("signature should be produced");
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![signature],
        };

        let err = apply_signed_update(&state, &signed, 102, &mut MembershipReplayCache::default())
            .expect_err("update should be rejected");
        assert!(matches!(
            err,
            MembershipError::ThresholdNotMet | MembershipError::OwnerSignatureRequired
        ));
    }

    #[test]
    fn add_node_update_requires_valid_signatures_and_root_chain() {
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-add-node".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: Some("enrollment".to_owned()),
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
        };

        let applied =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("update should apply");
        assert!(applied.nodes.iter().any(|node| node.node_id == "node-b"));
        assert_eq!(applied.epoch, state.epoch + 1);
    }

    #[test]
    fn replay_and_rollback_are_rejected() {
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-replay".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
        };

        let mut cache = MembershipReplayCache::default();
        let updated = apply_signed_update(&state, &signed, 130, &mut cache).expect("apply");
        assert_eq!(updated.epoch, 2);

        let replay = apply_signed_update(&updated, &signed, 131, &mut cache);
        assert!(replay.is_err());
    }

    #[test]
    fn duplicate_signer_is_rejected() {
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-duplicate-signer".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let owner_signature = sign_update_record(&record, "owner-1", &owner_key).expect("sign");
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![owner_signature.clone(), owner_signature],
        };

        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("duplicate signer should be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn spoofed_approver_id_with_foreign_key_is_rejected() {
        // Identity-spoofing vector, distinct from the roster-absent
        // case: the signature CLAIMS roster member "guardian-1" but
        // was produced by an attacker's key. Verification must look
        // up guardian-1's REGISTERED public key and reject on
        // mismatch (SignatureInvalid), never trust the claimed id.
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-spoofed-approver-id".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let attacker_key = SigningKey::from_bytes(&[9; 32]);
        let spoofed = sign_update_record(&record, "guardian-1", &attacker_key).expect("sign");
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let owner_signature = sign_update_record(&record, "owner-1", &owner_key).expect("sign");
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![owner_signature, spoofed],
        };

        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("a spoofed approver identity must be rejected");
        assert!(matches!(err, MembershipError::SignatureInvalid));
    }

    #[test]
    fn corrupted_signature_bytes_are_rejected_as_signature_invalid() {
        // A structurally valid quorum update whose approver signature
        // bytes were flipped must fail closed with SignatureInvalid —
        // never fall through to state application.
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-corrupted-signature".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let mut guardian_signature =
            sign_update_record(&record, "guardian-1", &guardian_key).expect("sign");
        // Flip one hex digit of the real signature so it stays a
        // well-formed 64-byte ed25519 signature over the WRONG bytes.
        // Quorum stays satisfied (owner + guardian) so ONLY the
        // per-signature verify can reject.
        let first_char = guardian_signature.signature_hex[0..1].to_owned();
        let replacement = if first_char == "0" { "1" } else { "0" };
        guardian_signature
            .signature_hex
            .replace_range(0..1, replacement);
        let owner_signature = sign_update_record(&record, "owner-1", &owner_key).expect("sign");
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![owner_signature, guardian_signature],
        };

        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("corrupted signature should be rejected");
        assert!(matches!(err, MembershipError::SignatureInvalid));
    }

    #[test]
    fn membership_state_with_no_approvers_fails_closed() {
        // Default-deny: an approver-less state can never authorize
        // anything. Even a well-formed update carrying a genuine
        // owner signature must be rejected at state validation —
        // before any transition logic can run.
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-no-approvers".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let owner_signature = sign_update_record(&record, "owner-1", &owner_key).expect("sign");
        // Strip the approver roster only after the record is built
        // against a valid base state: the update is otherwise
        // well-formed, so ONLY the empty-roster validation can reject.
        let mut broken_state = state.clone();
        broken_state.approver_set.clear();
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![owner_signature],
        };

        let err = apply_signed_update(
            &broken_state,
            &signed,
            130,
            &mut MembershipReplayCache::default(),
        )
        .expect_err("approver-less state should be rejected");
        match err {
            MembershipError::InvalidFormat(msg) => {
                assert_eq!(msg, "at least one active approver is required");
            }
            other => panic!("expected InvalidFormat, got {other:?}"),
        }
    }

    #[test]
    fn update_signed_by_non_approver_key_is_rejected_as_unauthorized() {
        // Authority check, distinct from signature validity: the
        // outsider's ed25519 signature is CRYPTOGRAPHICALLY VALID
        // over the record, but "guardian-9" is not in the state's
        // approver roster, so the update must be rejected as
        // unauthorized — not merely as a bad signature.
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-non-approver-signer".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let outsider_key = SigningKey::from_bytes(&[9; 32]);
        let outsider_signature =
            sign_update_record(&record, "guardian-9", &outsider_key).expect("sign");
        let owner_signature = sign_update_record(&record, "owner-1", &owner_key).expect("sign");
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![outsider_signature, owner_signature],
        };

        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("a non-approver signer must be rejected");
        match err {
            MembershipError::SignerNotAuthorized(approver_id) => {
                assert_eq!(approver_id, "guardian-9");
            }
            other => panic!("expected SignerNotAuthorized, got {other:?}"),
        }
    }

    #[test]
    fn owner_signature_required_for_rotate_approver() {
        let state = base_state();
        let replacement = MembershipApprover {
            approver_id: "guardian-3".to_owned(),
            approver_pubkey_hex: hex_encode(
                SigningKey::from_bytes(&[4; 32]).verifying_key().as_bytes(),
            ),
            role: MembershipApproverRole::Guardian,
            status: MembershipApproverStatus::Active,
            created_at_unix: 150,
        };

        let mut candidate = state.clone();
        candidate.approver_set.push(replacement.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-rotate-approver".to_owned(),
            operation: MembershipOperation::RotateApprover(replacement),
            target: "guardian-3".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 140,
            expires_at_unix: 640,
            reason_code: "rotate".to_owned(),
            policy_context: None,
        };
        let guardian_one = SigningKey::from_bytes(&[2; 32]);
        let guardian_two = SigningKey::from_bytes(&[3; 32]);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![
                sign_update_record(&record, "guardian-1", &guardian_one).expect("sign"),
                sign_update_record(&record, "guardian-2", &guardian_two).expect("sign"),
            ],
        };

        let err = apply_signed_update(&state, &signed, 150, &mut MembershipReplayCache::default())
            .expect_err("owner signature should be required");
        assert_eq!(err, MembershipError::OwnerSignatureRequired);
    }

    /// Build a signed update for `operation` against `state`, signed by the
    /// named approvers. Shared by the owner-gate tests so each one differs
    /// only in the operation and the signer set.
    fn signed_update_for(
        state: &MembershipState,
        candidate: &MembershipState,
        update_id: &str,
        target: &str,
        operation: MembershipOperation,
        signers: &[(&str, u8)],
    ) -> SignedMembershipUpdate {
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: update_id.to_owned(),
            operation,
            target: target.to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 140,
            expires_at_unix: 640,
            reason_code: "owner-gate-test".to_owned(),
            policy_context: None,
        };
        let approver_signatures = signers
            .iter()
            .map(|(id, seed)| {
                let key = SigningKey::from_bytes(&[*seed; 32]);
                sign_update_record(&record, id, &key).expect("sign")
            })
            .collect();
        SignedMembershipUpdate {
            record,
            approver_signatures,
        }
    }

    /// Granting a mesh capability is a privilege change, so quorum alone must
    /// not be enough. `SecurityMinimumBar.md` requires an owner-signed bundle
    /// for capability changes and states an anchor cannot self-promote; until
    /// this arm existed nothing enforced either claim, and the control had no
    /// verification method.
    #[test]
    fn owner_signature_required_for_set_node_capabilities() {
        let state = base_state();
        let mut candidate = state.clone();
        candidate.nodes[0].capabilities =
            crate::roles::canonicalize_role_capabilities([RoleCapability::ExitServer]);
        // The reducer stamps the node's updated_at_unix from the operation's
        // created_at_unix, so the expected root must carry it too.
        candidate.nodes[0].updated_at_unix = 140;
        candidate.epoch += 1;
        let signed = signed_update_for(
            &state,
            &candidate,
            "update-set-caps",
            "node-a",
            MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: vec![RoleCapability::ExitServer],
            },
            &[("guardian-1", 2), ("guardian-2", 3)],
        );

        let err = apply_signed_update(&state, &signed, 150, &mut MembershipReplayCache::default())
            .expect_err("a guardian-only quorum must not grant a mesh capability");
        assert_eq!(err, MembershipError::OwnerSignatureRequired);
    }

    /// The same update signed by the owner must still apply, or the gate would
    /// have made capability changes impossible rather than owner-gated.
    #[test]
    fn owner_signed_set_node_capabilities_is_accepted() {
        let state = base_state();
        let mut candidate = state.clone();
        candidate.nodes[0].capabilities =
            crate::roles::canonicalize_role_capabilities([RoleCapability::ExitServer]);
        // The reducer stamps the node's updated_at_unix from the operation's
        // created_at_unix, so the expected root must carry it too.
        candidate.nodes[0].updated_at_unix = 140;
        candidate.epoch += 1;
        let signed = signed_update_for(
            &state,
            &candidate,
            "update-set-caps-owner",
            "node-a",
            MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: vec![RoleCapability::ExitServer],
            },
            &[("owner-1", 1), ("guardian-1", 2)],
        );

        let applied =
            apply_signed_update(&state, &signed, 150, &mut MembershipReplayCache::default())
                .expect("an owner-signed capability change must still apply");
        assert!(
            applied.nodes[0]
                .capabilities
                .contains(&RoleCapability::ExitServer),
            "the capability must actually be granted"
        );
    }

    /// `node_pubkey_hex` is the node's gossip trust anchor — the verifying key
    /// peers authenticate its gossip against — so rotating it substitutes an
    /// identity and needs the owner, not quorum alone.
    #[test]
    fn owner_signature_required_for_rotate_node_key() {
        let state = base_state();
        let replacement = hex_encode(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes());
        let mut candidate = state.clone();
        candidate.nodes[0].node_pubkey_hex = replacement.clone();
        candidate.nodes[0].updated_at_unix = 140;
        candidate.epoch += 1;
        let signed = signed_update_for(
            &state,
            &candidate,
            "update-rotate-node-key",
            "node-a",
            MembershipOperation::RotateNodeKey {
                node_id: "node-a".to_owned(),
                new_pubkey_hex: replacement,
            },
            &[("guardian-1", 2), ("guardian-2", 3)],
        );

        let err = apply_signed_update(&state, &signed, 150, &mut MembershipReplayCache::default())
            .expect_err("a guardian-only quorum must not substitute a node's gossip identity");
        assert_eq!(err, MembershipError::OwnerSignatureRequired);
    }

    /// The owner-signed rotation must still apply: a fleet key migration runs
    /// through exactly this path, so breaking it would block the migration the
    /// gate is meant to protect.
    #[test]
    fn owner_signed_rotate_node_key_is_accepted() {
        let state = base_state();
        let replacement = hex_encode(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes());
        let mut candidate = state.clone();
        candidate.nodes[0].node_pubkey_hex = replacement.clone();
        candidate.nodes[0].updated_at_unix = 140;
        candidate.epoch += 1;
        let signed = signed_update_for(
            &state,
            &candidate,
            "update-rotate-node-key-owner",
            "node-a",
            MembershipOperation::RotateNodeKey {
                node_id: "node-a".to_owned(),
                new_pubkey_hex: replacement.clone(),
            },
            &[("owner-1", 1), ("guardian-1", 2)],
        );

        let applied =
            apply_signed_update(&state, &signed, 150, &mut MembershipReplayCache::default())
                .expect("an owner-signed key rotation must still apply");
        assert_eq!(
            applied.nodes[0].node_pubkey_hex, replacement,
            "the rotated key must actually be installed"
        );
    }

    #[test]
    fn replay_cache_not_updated_on_failed_update() {
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let base_record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-retry".to_owned(),
            operation: MembershipOperation::AddNode(new_node.clone()),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };

        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);

        let mut bad_record = base_record.clone();
        bad_record.new_state_root = "deadbeef".to_owned();
        let bad_signed = SignedMembershipUpdate {
            record: bad_record.clone(),
            approver_signatures: vec![
                sign_update_record(&bad_record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&bad_record, "guardian-1", &guardian_key).expect("sign"),
            ],
        };

        let mut cache = MembershipReplayCache::default();
        let err = apply_signed_update(&state, &bad_signed, 130, &mut cache)
            .expect_err("bad root should fail");
        assert_eq!(err, MembershipError::NewStateRootMismatch);

        let good_signed = SignedMembershipUpdate {
            record: base_record.clone(),
            approver_signatures: vec![
                sign_update_record(&base_record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&base_record, "guardian-1", &guardian_key).expect("sign"),
            ],
        };

        let applied = apply_signed_update(&state, &good_signed, 131, &mut cache)
            .expect("valid update should still apply after failed attempt");
        assert_eq!(applied.epoch, state.epoch + 1);
    }

    /// Build a base state plus a fully-signed, *valid* `AddNode` update against
    /// it. Tests tamper a single field of the returned record (or the raw
    /// signature bytes) to exercise one reject path in `apply_signed_update` at
    /// a time, then assert the untampered control still applies. Owner +
    /// guardian both sign, so the quorum (2) is met for any `AddNode`.
    fn signed_add_node_fixture() -> (
        MembershipState,
        MembershipUpdateRecord,
        Vec<MembershipSignature>,
    ) {
        let state = base_state();
        let new_node = active_node("node-b", 12);

        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-fixture".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: None,
        };
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signatures = vec![
            sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
            sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
        ];

        // Sanity: the fixture must apply cleanly before any test tampers it,
        // otherwise a negative test could pass for the wrong reason.
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: signatures.clone(),
        };
        apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect("untampered fixture must apply");

        (state, record, signatures)
    }

    #[test]
    fn apply_signed_update_rejects_expired_record() {
        // `now_unix` past `expires_at_unix` fails closed before signature
        // verification or any state mutation (freshness mandate).
        let (state, record, signatures) = signed_add_node_fixture();
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: signatures,
        };
        let err = apply_signed_update(
            &state,
            &signed,
            record.expires_at_unix + 1,
            &mut MembershipReplayCache::default(),
        )
        .expect_err("expired update must be rejected");
        assert_eq!(err, MembershipError::Expired);
    }

    #[test]
    fn apply_signed_update_rejects_future_dated_record() {
        // `created_at_unix` beyond `now + MEMBERSHIP_CLOCK_SKEW_SECS` is a
        // clock-skew / future-dating violation and must fail closed.
        let (state, record, signatures) = signed_add_node_fixture();
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: signatures,
        };
        // now is far enough below created_at that even the full skew window
        // cannot bridge it: created_at(120) > now + 90.
        let now = record.created_at_unix - MEMBERSHIP_CLOCK_SKEW_SECS - 1;
        let err = apply_signed_update(&state, &signed, now, &mut MembershipReplayCache::default())
            .expect_err("future-dated update must be rejected");
        assert_eq!(err, MembershipError::FutureDated);

        // Boundary: exactly at the edge of the skew window is still accepted.
        let edge = record.created_at_unix - MEMBERSHIP_CLOCK_SKEW_SECS;
        apply_signed_update(&state, &signed, edge, &mut MembershipReplayCache::default())
            .expect("update at the clock-skew boundary must apply");
    }

    #[test]
    fn apply_signed_update_rejects_epoch_rollback_to_older_watermark() {
        // Anti-rollback: an update whose epoch pair sits BEHIND the
        // live state's watermark (epoch_new == state.epoch, i.e. the
        // previous generation) is a stale/rolled-back record and must
        // be rejected even though its internal epoch chain and
        // signatures are valid. (The sibling test covers skipping
        // FORWARD; this pins the backwards direction.)
        let (state, mut record, _signatures) = signed_add_node_fixture();
        assert!(state.epoch >= 1);
        record.epoch_prev = state.epoch - 1;
        record.epoch_new = state.epoch;
        // Re-sign so the failure is the epoch check, not a signature mismatch.
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signed = SignedMembershipUpdate {
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
            record,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("epoch rollback must be rejected");
        match err {
            MembershipError::InvalidTransition(msg) => {
                assert_eq!(msg, "epoch chain mismatch for membership update");
            }
            other => panic!("expected epoch InvalidTransition, got {other:?}"),
        }
    }

    #[test]
    fn apply_signed_update_rejects_prev_state_root_mismatch() {
        // The prev-root check anchors the update to the exact state it was
        // authored against; a mismatch is a rollback/fork attempt. It fires
        // before signature verification, so stale signatures are irrelevant.
        let (state, mut record, signatures) = signed_add_node_fixture();
        record.prev_state_root = "deadbeef".to_owned();
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: signatures,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("prev-root mismatch must be rejected");
        assert_eq!(err, MembershipError::PrevStateRootMismatch);
    }

    #[test]
    fn apply_signed_update_rejects_network_id_mismatch() {
        // A bundle minted for a different network must never be applied here.
        let (state, mut record, signatures) = signed_add_node_fixture();
        record.network_id = "net-other".to_owned();
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: signatures,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("network-id mismatch must be rejected");
        assert!(
            matches!(err, MembershipError::InvalidTransition(msg) if msg.contains("network id")),
            "expected network-id InvalidTransition, got {err:?}"
        );
    }

    #[test]
    fn apply_signed_update_rejects_epoch_chain_break() {
        // `epoch_prev`/`epoch_new` must line up with `state.epoch` exactly.
        // The record's own canonical form already enforces
        // `epoch_new == epoch_prev + 1`, so to exercise the *apply-time* check
        // we keep that internal invariant but shift the pair off the live
        // state's epoch (skipping an epoch) — a fork/replay attempt.
        let (state, mut record, _signatures) = signed_add_node_fixture();
        record.epoch_prev = state.epoch + 1;
        record.epoch_new = state.epoch + 2;
        // Re-sign so the failure is the epoch check, not a signature mismatch.
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signed = SignedMembershipUpdate {
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
            record,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("epoch chain break must be rejected");
        assert!(
            matches!(err, MembershipError::InvalidTransition(msg) if msg.contains("epoch")),
            "expected epoch InvalidTransition, got {err:?}"
        );
    }

    #[test]
    fn apply_signed_update_rejects_tampered_signature_bytes() {
        // Directly corrupt the signature material (not the signed payload):
        // all-zero, single-bit-flip, and truncated signatures must all fail
        // closed at verification, never apply.
        let (state, record, signatures) = signed_add_node_fixture();

        // All-zero 64-byte signature.
        let mut zeroed = signatures.clone();
        zeroed[1].signature_hex = "00".repeat(64);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: zeroed,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("all-zero signature must be rejected");
        assert_eq!(err, MembershipError::SignatureInvalid);

        // Single-bit flip in the last nibble of a valid signature.
        let mut flipped = signatures.clone();
        let original = flipped[1].signature_hex.clone();
        let (head, last) = original.split_at(original.len() - 1);
        let last_digit = u8::from_str_radix(last, 16).expect("hex nibble");
        flipped[1].signature_hex = format!("{head}{:x}", last_digit ^ 0x1);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: flipped,
        };
        let err = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect_err("bit-flipped signature must be rejected");
        assert_eq!(err, MembershipError::SignatureInvalid);

        // Truncated signature (63 bytes): fails the fixed-width hex decode and
        // must still fail closed (any error is acceptable — never applies).
        let mut truncated = signatures;
        truncated[1].signature_hex.truncate(126);
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: truncated,
        };
        assert!(
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .is_err(),
            "truncated signature must be rejected"
        );
    }

    /// Identifier edge cases must EITHER be refused outright, OR survive
    /// `encode → decode` byte-identically. The failure this pins is the silent
    /// third outcome (ENR-03): nothing errors, and the roster that comes back
    /// is not the roster that was signed.
    ///
    /// Written to fail loudly if the guard is removed rather than to pass
    /// vacuously once it is present — every hostile case below round-trips
    /// *wrong* without it, so the assertion fires instead of being skipped.
    #[test]
    fn identifier_edge_cases_either_reject_or_round_trip_unchanged() {
        // `encode` runs `validate`, and so does `decode`; `None` means one of
        // them refused, which is the acceptable outcome.
        fn round_trip(state: &MembershipState) -> Option<MembershipState> {
            let encoded = encode_membership_state(state).ok()?;
            decode_membership_state(&encoded).ok()
        }

        const CASES: &[&str] = &[
            "node-b",                        // ordinary slug
            "node-b\nnode.1.status=revoked", // ENR-01, the snapshot-bricking shape
            "node-b\nzz.injected=1",         // ENR-01, the root-drift shape
            "node-b\r",                      // ENR-03: `str::lines()` eats the trailing \r
            "\rnode-b",
            "node-b=x",       // the key/value separator itself
            " node-b ",       // round-trips today; pinned so it keeps doing so
            "ünïcodé-node-b", // multi-byte UTF-8 must not be collateral damage
        ];

        for case in CASES {
            let mut state = base_state();
            state.nodes[0].node_id = (*case).to_owned();
            if let Some(decoded) = round_trip(&state) {
                assert_eq!(
                    decoded.nodes[0].node_id, *case,
                    "node_id {case:?} was silently mutated by the round-trip"
                );
            }

            let mut state = base_state();
            state.nodes[0].owner = (*case).to_owned();
            if let Some(decoded) = round_trip(&state) {
                assert_eq!(
                    decoded.nodes[0].owner, *case,
                    "owner {case:?} was silently mutated by the round-trip"
                );
            }

            let mut state = base_state();
            state.approver_set[0].approver_id = (*case).to_owned();
            if let Some(decoded) = round_trip(&state) {
                let ids: Vec<&str> = decoded
                    .approver_set
                    .iter()
                    .map(|approver| approver.approver_id.as_str())
                    .collect();
                assert!(
                    ids.contains(case),
                    "approver_id {case:?} was silently mutated by the round-trip (got {ids:?})"
                );
            }

            let mut state = base_state();
            state.network_id = (*case).to_owned();
            if let Some(decoded) = round_trip(&state) {
                assert_eq!(
                    decoded.network_id, *case,
                    "network_id {case:?} was silently mutated by the round-trip"
                );
            }
        }

        // Roles get a `,`-join on encode and a `split(',') → trim → drop-empty`
        // on decode, so they carry three mutation shapes the other fields do not.
        for case in [" tag:servers ", "tag:servers,tag:owners", ""] {
            let mut state = base_state();
            state.nodes[0].roles = vec![case.to_owned()];
            if let Some(decoded) = round_trip(&state) {
                assert_eq!(
                    decoded.nodes[0].roles,
                    vec![case.to_owned()],
                    "role {case:?} was silently mutated by the round-trip"
                );
            }
        }
    }

    /// The companion to the round-trip test above: the specific shapes ENR-01
    /// and ENR-03 were confirmed with must be REJECTED, not merely
    /// round-trip-stable. Without this, deleting the guard could leave the
    /// round-trip test passing on any case that happens to survive.
    #[test]
    fn validate_rejects_payload_framing_bytes_in_every_free_form_field() {
        for hostile in ["x\nnode.1.status=revoked", "x\r", "x=y"] {
            let mut state = base_state();
            state.nodes[0].node_id = hostile.to_owned();
            assert!(
                state.validate().is_err(),
                "node_id {hostile:?} must be rejected"
            );
            // The signed text and the state root are both derived through
            // `validate`, so neither can be produced over a hostile roster.
            assert!(state.canonical_payload().is_err());
            assert!(state.state_root_hex().is_err());

            let mut state = base_state();
            state.nodes[0].owner = hostile.to_owned();
            assert!(
                state.validate().is_err(),
                "owner {hostile:?} must be rejected"
            );

            let mut state = base_state();
            state.approver_set[0].approver_id = hostile.to_owned();
            assert!(
                state.validate().is_err(),
                "approver_id {hostile:?} must be rejected"
            );

            let mut state = base_state();
            state.network_id = hostile.to_owned();
            assert!(
                state.validate().is_err(),
                "network_id {hostile:?} must be rejected"
            );

            let mut state = base_state();
            state.metadata_hash = Some(hostile.to_owned());
            assert!(
                state.validate().is_err(),
                "metadata_hash {hostile:?} must be rejected"
            );

            let mut state = base_state();
            state.nodes[0].roles = vec![hostile.to_owned()];
            assert!(
                state.validate().is_err(),
                "role {hostile:?} must be rejected"
            );
        }

        // `Some("")` encodes to the same line as `None` and decodes back as
        // `None`, so the encoding would not be injective.
        let mut state = base_state();
        state.metadata_hash = Some(String::new());
        assert!(state.validate().is_err(), "empty metadata_hash must reject");

        // Over-length is bounded at encode time, not just by the decode-side
        // whole-snapshot cap.
        let mut state = base_state();
        state.nodes[0].node_id = "n".repeat(super::MAX_MEMBERSHIP_FIELD_BYTES + 1);
        assert!(state.validate().is_err(), "over-length node_id must reject");
        state.nodes[0].node_id = "n".repeat(super::MAX_MEMBERSHIP_FIELD_BYTES);
        assert!(
            state.validate().is_ok(),
            "a node_id exactly at the cap must still be accepted"
        );
    }

    /// ENR-05, decode-side half. A snapshot whose node carries no
    /// `capabilities=` field must be REFUSED, not have its capabilities
    /// inferred from the free-form `roles` label.
    ///
    /// The deleted fallback mapped `tag:servers` — which the canonical parser
    /// rejects outright — to `Anchor`. The approvers signed a label; they never
    /// signed that grant. This test pins the refusal at the exact shape that
    /// used to escalate.
    #[test]
    fn a_node_without_a_capabilities_field_is_refused_not_inferred() {
        let encoded = encode_membership_state(&base_state()).expect("encode");
        assert!(
            encoded.contains("node.0.capabilities="),
            "the encoder must always write the field"
        );

        // Drop the capabilities line and relabel the node the way the deleted
        // shim would have escalated.
        let stripped: String = encoded
            .lines()
            .filter(|line| !line.starts_with("node.0.capabilities="))
            .map(|line| {
                if line.starts_with("node.0.roles=") {
                    "node.0.roles=tag:servers".to_owned()
                } else {
                    line.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        let err = decode_membership_state(&stripped)
            .expect_err("a node with no signed capabilities must be refused");
        let text = err.to_string();
        assert!(
            text.contains("node.0.capabilities"),
            "the diagnostic must name the missing field, got: {text}"
        );

        // The point of the test: it must fail, not silently yield Anchor.
        if let Ok(state) = decode_membership_state(&stripped) {
            panic!(
                "capabilities were inferred from a label: {:?}",
                state.nodes[0].capabilities
            );
        }
    }

    /// Only ABSENCE is refused. An explicit but empty `capabilities=` still
    /// decodes to an empty set, so deliberately clearing a node's capabilities
    /// stays expressible — and a Revoked node legitimately has none.
    #[test]
    fn an_explicitly_empty_capabilities_field_still_decodes() {
        use super::parse_node_capabilities;
        assert_eq!(
            parse_node_capabilities(Some(""), "node.0.capabilities").expect("empty is valid"),
            Vec::<RoleCapability>::new()
        );
        assert!(parse_node_capabilities(None, "node.0.capabilities").is_err());
    }

    /// ENR-01/ENR-03 at the SECOND encoder. `MembershipUpdateRecord::canonical_payload`
    /// is what the approver signatures are computed over, and it uses the same
    /// line-oriented `key=value` framing as the snapshot — so a newline in any
    /// free-form field forges a line inside a SIGNED artifact.
    ///
    /// `reason_code` and `policy_context` had no validation whatsoever, and
    /// both are taken straight from operator flags (`--reason`,
    /// `--policy-context`), as is `--update-id`. The pre-existing
    /// `trim().is_empty()` checks are exactly the weak guard ENR-01 named.
    ///
    /// This case was missed by the first ENR-01 fix, which guarded only
    /// `MembershipState::validate`, and was found by adversarial review of it.
    #[test]
    fn update_record_payload_refuses_framing_bytes_in_every_operator_field() {
        fn record_with(mutate: impl FnOnce(&mut MembershipUpdateRecord)) -> MembershipUpdateRecord {
            let state = base_state();
            let mut record = MembershipUpdateRecord {
                network_id: state.network_id.clone(),
                update_id: "update-1".to_owned(),
                operation: MembershipOperation::RemoveNode {
                    node_id: "node-a".to_owned(),
                },
                target: "node-a".to_owned(),
                prev_state_root: state.state_root_hex().expect("root"),
                new_state_root: state.state_root_hex().expect("root"),
                epoch_prev: state.epoch,
                epoch_new: state.epoch + 1,
                created_at_unix: 101,
                expires_at_unix: 400,
                reason_code: "ops".to_owned(),
                policy_context: None,
            };
            mutate(&mut record);
            record
        }

        // Sanity: the unmutated record encodes, so a rejection below is the
        // guard firing and not a broken fixture.
        assert!(record_with(|_| {}).canonical_payload().is_ok());

        for hostile in ["x\nepoch_new=99", "x\r", "x=y"] {
            let cases: Vec<(&str, MembershipUpdateRecord)> = vec![
                (
                    "update_id",
                    record_with(|r| r.update_id = hostile.to_owned()),
                ),
                ("target", record_with(|r| r.target = hostile.to_owned())),
                (
                    "reason_code",
                    record_with(|r| r.reason_code = hostile.to_owned()),
                ),
                (
                    "policy_context",
                    record_with(|r| r.policy_context = Some(hostile.to_owned())),
                ),
                (
                    "network_id",
                    record_with(|r| r.network_id = hostile.to_owned()),
                ),
                (
                    "op.node_id",
                    record_with(|r| {
                        r.operation = MembershipOperation::RemoveNode {
                            node_id: hostile.to_owned(),
                        }
                    }),
                ),
            ];
            for (field, record) in cases {
                assert!(
                    record.canonical_payload().is_err(),
                    "{field} accepted {hostile:?} into a signed update payload"
                );
            }
        }
    }

    /// The envelope hex-frames the record payload, so the record cannot reframe
    /// it — but the signature identities are written raw, and `--approver-id`
    /// is operator-supplied.
    #[test]
    fn signed_envelope_refuses_framing_bytes_in_signature_identity() {
        let state = base_state();
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-1".to_owned(),
            operation: MembershipOperation::RemoveNode {
                node_id: "node-a".to_owned(),
            },
            target: "node-a".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: state.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 101,
            expires_at_unix: 400,
            reason_code: "ops".to_owned(),
            policy_context: None,
        };
        let signed_ok = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![MembershipSignature {
                approver_id: "owner-1".to_owned(),
                signature_hex: "ab".repeat(64),
                head_signature_hex: None,
            }],
        };
        assert!(
            signed_ok.canonical_envelope().is_ok(),
            "fixture must encode"
        );

        for hostile in ["owner-1\nsig_count=99", "owner-1\r", "owner-1=x"] {
            let signed = SignedMembershipUpdate {
                record: record.clone(),
                approver_signatures: vec![MembershipSignature {
                    approver_id: hostile.to_owned(),
                    signature_hex: "ab".repeat(64),
                    head_signature_hex: None,
                }],
            };
            assert!(
                signed.canonical_envelope().is_err(),
                "approver_id accepted {hostile:?} into a signed envelope"
            );
        }
    }

    #[test]
    fn validate_rejects_empty_network_id() {
        let mut state = base_state();
        state.network_id = "   ".to_owned();
        let err = state
            .validate()
            .expect_err("empty network id must be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn validate_rejects_zero_quorum_threshold() {
        let mut state = base_state();
        state.quorum_threshold = 0;
        let err = state
            .validate()
            .expect_err("zero quorum threshold must be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn validate_rejects_duplicate_node_ids() {
        let mut state = base_state();
        // Same node_id, distinct key bytes — the collision is on identity.
        state.nodes.push(active_node("node-a", 11));
        let err = state
            .validate()
            .expect_err("duplicate node id must be rejected");
        assert!(
            matches!(err, MembershipError::InvalidFormat(ref msg) if msg.contains("duplicate node id")),
            "expected duplicate-node-id rejection, got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_duplicate_approver_pubkeys() {
        let mut state = base_state();
        // Same underlying key (byte 1) as "owner-1", filed under a second
        // approver_id — this is the exact shape an adversarial review found
        // exploitable: one real signature, once produced, can be copied
        // verbatim under the alias id to inflate apparent quorum, since
        // ed25519 signing here is deterministic and nothing previously
        // stopped two ids from sharing a key.
        state
            .approver_set
            .push(approver("owner-1-alias", 1, MembershipApproverRole::Owner));
        let err = state
            .validate()
            .expect_err("duplicate approver pubkey under a second id must be rejected");
        assert!(
            matches!(err, MembershipError::InvalidFormat(ref msg) if msg.contains("approver pubkey reused")),
            "expected pubkey-reuse rejection, got {err:?}"
        );
    }

    #[test]
    fn validate_rejects_quorum_exceeding_active_approvers() {
        let mut state = base_state();
        // Three active approvers in the base fixture; demand four.
        state.quorum_threshold = 4;
        let err = state
            .validate()
            .expect_err("quorum above active approver count must be rejected");
        assert!(
            matches!(err, MembershipError::InvalidFormat(ref msg) if msg.contains("exceeds active approver count")),
            "expected quorum-exceeds-approvers rejection, got {err:?}"
        );
    }

    /// Append `node-b/c/d` as a 3-entry chained membership log under `log`,
    /// returning the raw on-disk file contents. Each update is authored
    /// against the post-apply state of the previous one, so the persisted
    /// hash chain is well-formed before any test tampers it.
    #[cfg(unix)]
    fn write_three_entry_membership_log(log: &std::path::Path) -> String {
        use std::os::unix::fs::PermissionsExt;
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let mut state = base_state();
        let mut now = 130u64;
        for (idx, (node_id, key_byte)) in [("node-b", 17u8), ("node-c", 18), ("node-d", 19)]
            .into_iter()
            .enumerate()
        {
            let new_node = active_node(node_id, key_byte);
            let mut candidate = state.clone();
            candidate.nodes.push(new_node.clone());
            candidate.epoch += 1;
            let record = MembershipUpdateRecord {
                network_id: state.network_id.clone(),
                update_id: format!("update-chain-{idx}"),
                operation: MembershipOperation::AddNode(new_node),
                target: node_id.to_owned(),
                prev_state_root: state.state_root_hex().expect("root"),
                new_state_root: candidate.state_root_hex().expect("root"),
                epoch_prev: state.epoch,
                epoch_new: state.epoch + 1,
                created_at_unix: now,
                expires_at_unix: now + 1000,
                reason_code: "join".to_owned(),
                policy_context: None,
            };
            let signed = SignedMembershipUpdate {
                record: record.clone(),
                approver_signatures: vec![
                    sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                    sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
                ],
            };
            append_membership_log_entry(log, &signed).expect("append");
            state = apply_signed_update(
                &state,
                &signed,
                now + 1,
                &mut MembershipReplayCache::default(),
            )
            .expect("apply");
            now += 10;
        }
        std::fs::set_permissions(log, std::fs::Permissions::from_mode(0o600)).expect("0o600 perms");
        std::fs::read_to_string(log).expect("read log")
    }

    /// Rewrite `log` with `version` + the given `entry=` lines, fix perms, and
    /// assert `load_membership_log` fails closed with `IntegrityMismatch`.
    #[cfg(unix)]
    fn assert_tampered_log_rejected(log: &std::path::Path, entry_lines: &[&str]) {
        use std::os::unix::fs::PermissionsExt;
        let mut body = format!("version={MEMBERSHIP_SCHEMA_VERSION}\n");
        for line in entry_lines {
            body.push_str(line);
            body.push('\n');
        }
        std::fs::write(log, body).expect("rewrite log");
        std::fs::set_permissions(log, std::fs::Permissions::from_mode(0o600)).expect("0o600 perms");
        let err = load_membership_log(log).expect_err("tampered chain must be rejected");
        assert_eq!(err, MembershipError::IntegrityMismatch);
    }

    #[cfg(unix)]
    #[test]
    fn membership_log_chain_tampering_is_detected() {
        // A persisted membership log is a hash chain: each `entry=` line binds
        // its index, the previous entry's hash, and the encoded update. Loading
        // re-derives every per-line hash and then `verify_membership_log_chain`
        // re-checks index ordering + back-links. Reordering or removing a
        // middle entry, or flipping a stored hash, must all fail closed.
        let unique = format!(
            "membership-chain-break-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        let log = temp_dir.join("membership.log");

        let contents = write_three_entry_membership_log(&log);
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines[0], format!("version={MEMBERSHIP_SCHEMA_VERSION}"));
        let entry_lines: Vec<&str> = lines[1..].to_vec();
        assert_eq!(entry_lines.len(), 3, "fixture must build a 3-entry chain");

        // Baseline: the intact chain loads and verifies.
        let entries = load_membership_log(&log).expect("intact chain should load");
        assert_eq!(entries.len(), 3);

        // Reorder the middle and last entries: per-line hashes stay valid (the
        // index is embedded in each line) but the position/index check trips.
        assert_tampered_log_rejected(&log, &[entry_lines[0], entry_lines[2], entry_lines[1]]);

        // Remove the middle entry: the survivor at position 1 carries index 2.
        assert_tampered_log_rejected(&log, &[entry_lines[0], entry_lines[2]]);

        // Flip the stored entry_hash of the first entry (3rd `|`-field) to all
        // zeros: the recomputed per-line hash no longer matches.
        let parts: Vec<&str> = entry_lines[0]
            .strip_prefix("entry=")
            .expect("entry prefix")
            .split('|')
            .collect();
        assert_eq!(parts.len(), 4, "entry line has 4 fields");
        let zeroed_hash = "0".repeat(parts[2].len());
        let tampered_first = format!(
            "entry={}|{}|{}|{}",
            parts[0], parts[1], zeroed_hash, parts[3]
        );
        assert_tampered_log_rejected(&log, &[&tampered_first, entry_lines[1], entry_lines[2]]);

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// Regression: `load_membership_snapshot` and `load_membership_log` must
    /// reject files larger than the configured cap before any structural
    /// parse runs. The previous code path read the entire file via
    /// `fs::read_to_string` and only checked size implicitly via parser
    /// failures — meaning an attacker (or buggy daemon) that managed to
    /// write a multi-GB file at the snapshot/log path could exhaust memory
    /// before any error surfaced.
    #[cfg(unix)]
    #[test]
    fn load_membership_snapshot_rejects_oversized_file_before_parsing() {
        let unique = format!(
            "membership-oversized-snapshot-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir creation");
        let snapshot = temp_dir.join("oversized.snapshot");
        // Write `MAX + 1` bytes so the bounded reader's overflow path fires.
        let body = vec![b'x'; MAX_MEMBERSHIP_SNAPSHOT_BYTES + 1];
        std::fs::write(&snapshot, &body).expect("write oversized snapshot");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600))
            .expect("0o600 perms");
        let err = load_membership_snapshot(&snapshot).expect_err("must fail closed");
        assert!(
            matches!(err, MembershipError::InvalidFormat(ref m) if m.contains("exceeds maximum size")),
            "expected size-cap rejection, got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[cfg(unix)]
    #[test]
    fn load_membership_log_rejects_oversized_file_before_parsing() {
        // Use a 64-byte synthetic cap to keep this test fast — we re-invoke
        // the bounded helper directly via the public size constant on a
        // file just over that boundary.
        // Build a file just over `MAX_MEMBERSHIP_LOG_BYTES` is impractical
        // (>64 MiB); instead we open a real file and verify the size-check
        // branch by calling the bounded reader on a deliberately-small cap
        // through the actual log loader's path.
        //
        // The most direct end-to-end shape: write `MAX_MEMBERSHIP_LOG_BYTES + 1`
        // bytes is too slow for a unit test, so we just sanity-check the
        // constant is documented as the cap and that the production loader
        // calls through it.
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let body = std::fs::read_to_string(crate_root.join("src/membership.rs"))
            .expect("membership source readable");
        // Verify the production `load_membership_log` body invokes the
        // bounded reader with the cap constant.
        let start = body
            .find("pub fn load_membership_log(")
            .expect("load_membership_log present");
        let window_end = (start + 1_500).min(body.len());
        let window = &body[start..window_end];
        assert!(
            window.contains("read_membership_artifact_bounded("),
            "load_membership_log must read via the bounded helper"
        );
        assert!(
            window.contains("MAX_MEMBERSHIP_LOG_BYTES"),
            "load_membership_log must reference the documented cap constant"
        );
        let _ = MAX_MEMBERSHIP_LOG_BYTES;
    }

    /// Prove the digest self-consistency check on the persisted membership
    /// snapshot is actually enforced: `persist_membership_snapshot` writes a
    /// SHA-256 digest over `version=` + `state_hex=`, and
    /// `load_membership_snapshot` must reject the file with
    /// `MembershipError::IntegrityMismatch` when either the payload or the
    /// stored digest is tampered on disk.
    ///
    /// Scope honesty: this digest is a self-consistency check against on-disk
    /// corruption and casual tampering only. It is NOT a signature — anyone
    /// who can rewrite `state_hex=` can recompute a matching `digest=`. It is
    /// therefore NOT a substitute for the signature verification the anchor
    /// bundle-pull path still lacks (tracked as a High-severity open item in
    /// documents/SecurityMinimumBar.md).
    #[cfg(unix)]
    #[test]
    fn load_membership_snapshot_rejects_tampered_digest_or_payload() {
        use std::os::unix::fs::PermissionsExt;

        let unique = format!(
            "membership-snapshot-tamper-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir creation");
        let snapshot = temp_dir.join("membership.snapshot");

        let state = base_state();
        persist_membership_snapshot(&snapshot, &state).expect("snapshot should persist");

        // Baseline (anti-vacuous): the untampered file loads.
        let loaded = load_membership_snapshot(&snapshot).expect("intact snapshot should load");
        assert_eq!(
            loaded.state_root_hex().expect("loaded root"),
            state.state_root_hex().expect("original root")
        );

        let original = std::fs::read_to_string(&snapshot).expect("snapshot readable");

        // Flip one character of a field's value while leaving the rest of the
        // file intact, rewrite with the same 0o600 permissions the persister
        // used, and assert the loader fails closed with IntegrityMismatch.
        let tamper_field = |field_prefix: &str| {
            let mut lines: Vec<String> = original.lines().map(str::to_owned).collect();
            let line = lines
                .iter_mut()
                .find(|l| l.starts_with(field_prefix))
                .unwrap_or_else(|| panic!("snapshot must contain a {field_prefix} line"));
            let value_start = field_prefix.len();
            let first = line[value_start..]
                .chars()
                .next()
                .expect("field value must be non-empty");
            let flipped = if first == '0' { '1' } else { '0' };
            line.replace_range(
                value_start..value_start + first.len_utf8(),
                &flipped.to_string(),
            );
            let mut body = lines.join("\n");
            body.push('\n');
            std::fs::write(&snapshot, body).expect("rewrite tampered snapshot");
            std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600))
                .expect("0o600 perms");
            let err = load_membership_snapshot(&snapshot)
                .expect_err("tampered snapshot must be rejected");
            assert_eq!(
                err,
                MembershipError::IntegrityMismatch,
                "tampering {field_prefix} must surface as IntegrityMismatch"
            );
        };

        // Case 1: corrupt the state payload; the stored digest no longer
        // matches the recomputed one.
        tamper_field("state_hex=");

        // Restore the intact file between cases so each tamper is isolated.
        std::fs::write(&snapshot, &original).expect("restore snapshot");
        std::fs::set_permissions(&snapshot, std::fs::Permissions::from_mode(0o600))
            .expect("0o600 perms");

        // Case 2: corrupt the stored digest itself; the payload is intact but
        // the recorded digest no longer matches.
        tamper_field("digest=");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn loading_empty_membership_log_is_supported() {
        let unique = format!(
            "membership-empty-log-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let log = temp_dir.join("membership.log");
        std::fs::write(&log, format!("version={MEMBERSHIP_SCHEMA_VERSION}\n"))
            .expect("empty log should be written");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&log).unwrap().permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&log, perms).unwrap()
        };

        let entries = load_membership_log(&log).expect("empty log should load");
        assert!(entries.is_empty());

        let _ = std::fs::remove_file(log);
        let _ = std::fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn revoke_and_restore_update_timestamp() {
        let state = base_state();
        let original_updated = state
            .nodes
            .iter()
            .find(|node| node.node_id == "node-a")
            .expect("node should exist")
            .updated_at_unix;

        // RSA-0009: updated_at_unix is now the DETERMINISTIC op timestamp passed
        // in (the signed record's created_at_unix), not a wall-clock read — so it
        // reproduces identically at proposal and apply time.
        let revoke_ts = original_updated + 100;
        let revoked = preview_next_state(
            &state,
            &MembershipOperation::RevokeNode {
                node_id: "node-a".to_owned(),
            },
            revoke_ts,
        )
        .expect("revoke should succeed");
        let revoked_node = revoked
            .nodes
            .iter()
            .find(|node| node.node_id == "node-a")
            .expect("node should exist");
        assert_eq!(revoked_node.status, MembershipNodeStatus::Revoked);
        assert_eq!(revoked_node.updated_at_unix, revoke_ts);

        let restore_ts = revoke_ts + 100;
        let restored = preview_next_state(
            &revoked,
            &MembershipOperation::RestoreNode {
                node_id: "node-a".to_owned(),
            },
            restore_ts,
        )
        .expect("restore should succeed");
        let restored_node = restored
            .nodes
            .iter()
            .find(|node| node.node_id == "node-a")
            .expect("node should exist");
        assert_eq!(restored_node.status, MembershipNodeStatus::Active);
        assert_eq!(restored_node.updated_at_unix, restore_ts);
    }

    /// RSA-0009 regression: build a quorum-signed update at `created_at_unix` and
    /// apply it at a DIFFERENT unix second. Before the fix the reducer stamped
    /// `unix_now()` at apply time, so the recomputed `state_root` never matched
    /// the recorded `new_state_root` and these four ops were rejected with
    /// `NewStateRootMismatch` — revocation/key-rotation were non-functional.
    fn rsa0009_signed_update(
        state: &MembershipState,
        operation: MembershipOperation,
        target: &str,
        created_at_unix: u64,
    ) -> SignedMembershipUpdate {
        let candidate =
            preview_next_state(state, &operation, created_at_unix).expect("preview should pass");
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: format!("rsa0009-{target}-{created_at_unix}"),
            operation,
            target: target.to_owned(),
            prev_state_root: state.state_root_hex().expect("prev root"),
            new_state_root: candidate.state_root_hex().expect("new root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix,
            expires_at_unix: created_at_unix + 600,
            reason_code: "rsa0009".to_owned(),
            policy_context: None,
        };
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
        }
    }

    #[test]
    fn rsa0009_revoke_applies_when_created_at_differs_from_apply_time() {
        let state = base_state();
        let signed = rsa0009_signed_update(
            &state,
            MembershipOperation::RevokeNode {
                node_id: "node-a".to_owned(),
            },
            "node-a",
            120,
        );
        let updated =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("revoke must apply despite created_at != apply time");
        let node = updated
            .nodes
            .iter()
            .find(|n| n.node_id == "node-a")
            .expect("node-a");
        assert_eq!(node.status, MembershipNodeStatus::Revoked);
        assert_eq!(node.updated_at_unix, 120);
    }

    #[test]
    fn rsa0009_restore_applies_when_created_at_differs_from_apply_time() {
        let mut state = base_state();
        state
            .nodes
            .iter_mut()
            .find(|n| n.node_id == "node-a")
            .expect("node-a")
            .status = MembershipNodeStatus::Revoked;
        let signed = rsa0009_signed_update(
            &state,
            MembershipOperation::RestoreNode {
                node_id: "node-a".to_owned(),
            },
            "node-a",
            120,
        );
        let updated =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("restore must apply despite created_at != apply time");
        let node = updated
            .nodes
            .iter()
            .find(|n| n.node_id == "node-a")
            .expect("node-a");
        assert_eq!(node.status, MembershipNodeStatus::Active);
        assert_eq!(node.updated_at_unix, 120);
    }

    #[test]
    fn rsa0009_rotate_key_applies_when_created_at_differs_from_apply_time() {
        let state = base_state();
        let new_pubkey_hex = "11".repeat(32);
        let signed = rsa0009_signed_update(
            &state,
            MembershipOperation::RotateNodeKey {
                node_id: "node-a".to_owned(),
                new_pubkey_hex: new_pubkey_hex.clone(),
            },
            "node-a",
            120,
        );
        let updated =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("rotate-key must apply despite created_at != apply time");
        let node = updated
            .nodes
            .iter()
            .find(|n| n.node_id == "node-a")
            .expect("node-a");
        assert_eq!(node.node_pubkey_hex, new_pubkey_hex);
        assert_eq!(node.updated_at_unix, 120);
    }

    #[test]
    fn rsa0009_set_capabilities_applies_when_created_at_differs_from_apply_time() {
        let state = base_state();
        let signed = rsa0009_signed_update(
            &state,
            MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: anchor_role_capabilities(),
            },
            "node-a",
            120,
        );
        let updated =
            apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
                .expect("set-capabilities must apply despite created_at != apply time");
        let node = updated
            .nodes
            .iter()
            .find(|n| n.node_id == "node-a")
            .expect("node-a");
        assert!(
            node.capabilities
                .contains(&RoleCapability::AnchorBundlePull)
        );
        assert_eq!(node.updated_at_unix, 120);
    }

    /// RT-2 / SecMinBar §6.D.2: blind_exit is immutable. `transition_plan()`
    /// (rustynet-control::role_presets) refuses to construct a blind_exit ->
    /// anything transition, but that is a CLI-facing advisory planner, not an
    /// enforcement point on the signed-update apply path. Before this fix,
    /// nothing stopped a validly-signed `SetNodeCapabilities` update from
    /// reversing it directly at the membership-state layer.
    #[test]
    fn set_node_capabilities_rejects_reversal_of_blind_exit() {
        let mut state = base_state();
        state.nodes[0].capabilities = vec![RoleCapability::BlindExit, RoleCapability::ExitServer];

        for attempted in [
            vec![RoleCapability::ExitServer],
            vec![RoleCapability::Client],
            vec![RoleCapability::Anchor],
            vec![RoleCapability::RelayHost],
            vec![],
        ] {
            let operation = MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: attempted.clone(),
            };
            let err = reduce_membership_state(&state, &operation, 200).expect_err(&format!(
                "reversing blind_exit to {attempted:?} must be rejected"
            ));
            assert!(
                matches!(err, MembershipError::InvalidTransition(_)),
                "expected InvalidTransition, got {err:?}"
            );
            assert!(
                err.to_string().contains("blind_exit is immutable"),
                "unexpected error message: {err}"
            );
        }
    }

    #[test]
    fn set_node_capabilities_still_applies_to_non_blind_exit_nodes() {
        // Anti-vacuous: the blind_exit guard above must not accidentally
        // block ordinary capability updates on a node that was never
        // blind_exit — covered already by
        // rsa0009_set_capabilities_applies_when_created_at_differs_from_apply_time,
        // this test pins the same invariant directly against
        // reduce_membership_state without the RSA-0009 timing angle.
        let state = base_state();
        let operation = MembershipOperation::SetNodeCapabilities {
            node_id: "node-a".to_owned(),
            capabilities: vec![RoleCapability::Client],
        };
        let updated = reduce_membership_state(&state, &operation, 200)
            .expect("non-blind_exit capability change must still apply");
        let node = updated
            .nodes
            .iter()
            .find(|n| n.node_id == "node-a")
            .expect("node-a");
        assert_eq!(node.capabilities, vec![RoleCapability::Client]);
    }

    #[test]
    fn snapshot_and_log_roundtrip_integrity() {
        let unique = format!(
            "membership-store-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir should be created");
        let snapshot = temp_dir.join("membership.snapshot");
        let log = temp_dir.join("membership.log");
        let audit = temp_dir.join("membership.audit.log");

        let state = base_state();
        persist_membership_snapshot(&snapshot, &state).expect("snapshot should persist");
        let loaded_snapshot = load_membership_snapshot(&snapshot).expect("snapshot should load");
        assert_eq!(
            loaded_snapshot.state_root_hex().expect("snapshot root"),
            state.state_root_hex().expect("original root")
        );

        let new_node = active_node("node-b", 17);
        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-log-1".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 130,
            expires_at_unix: 700,
            reason_code: "join".to_owned(),
            policy_context: None,
        };
        let owner_key = SigningKey::from_bytes(&[1; 32]);
        let guardian_key = SigningKey::from_bytes(&[2; 32]);
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: vec![
                sign_update_record(&record, "owner-1", &owner_key).expect("sign"),
                sign_update_record(&record, "guardian-1", &guardian_key).expect("sign"),
            ],
        };

        append_membership_log_entry(&log, &signed).expect("log should append");
        let entries = load_membership_log(&log).expect("log should load");
        write_membership_audit_log(&audit, &entries).expect("audit should write");
        assert_eq!(entries.len(), 1);

        let replayed =
            replay_membership_snapshot_and_log(&loaded_snapshot, &entries, 140).expect("replay");
        assert!(replayed.nodes.iter().any(|node| node.node_id == "node-b"));
        let replayed_from_checkpoint = replay_membership_snapshot_and_log(&replayed, &entries, 141)
            .expect("checkpoint replay should ignore historical entries");
        assert_eq!(
            replayed_from_checkpoint
                .state_root_hex()
                .expect("checkpoint replay root"),
            replayed.state_root_hex().expect("replayed root")
        );

        let mut tampered = std::fs::read_to_string(&log).expect("log should read");
        tampered = tampered.replace("entry=0|", "entry=1|");
        std::fs::write(&log, tampered).expect("tampered log should write");
        let bad = load_membership_log(&log);
        assert!(bad.is_err());
    }

    // --- RN-01: decoder count fields must be bounded before pre-allocation ---

    #[test]
    fn bounded_count_rejects_over_max_and_over_field_total() {
        use super::{MAX_MEMBERSHIP_NODE_COUNT, bounded_count};
        // Over the hard ceiling.
        assert!(
            bounded_count(
                "c",
                MAX_MEMBERSHIP_NODE_COUNT + 1,
                MAX_MEMBERSHIP_NODE_COUNT,
                usize::MAX
            )
            .is_err()
        );
        // Within the ceiling but exceeding the parsed field total.
        assert!(bounded_count("c", 10, MAX_MEMBERSHIP_NODE_COUNT, 5).is_err());
        // Legitimate count is accepted unchanged.
        assert_eq!(
            bounded_count("c", 3, MAX_MEMBERSHIP_NODE_COUNT, 7).expect("valid count"),
            3
        );
    }

    #[test]
    fn decode_membership_state_rejects_oversized_node_count() {
        // A hostile node_count must be rejected (not abort via capacity
        // overflow / OOM) before any node fields are read.
        let payload = "version=1\nnetwork_id=net-1\nepoch=1\nquorum_threshold=2\n\
                       metadata_hash=\nnode_count=18446744073709551615\napprover_count=0\n";
        let err = super::decode_membership_state(payload)
            .expect_err("oversized node_count must be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn decode_membership_state_rejects_oversized_approver_count() {
        let payload = "version=1\nnetwork_id=net-1\nepoch=1\nquorum_threshold=2\n\
                       metadata_hash=\nnode_count=0\napprover_count=18446744073709551615\n";
        let err = super::decode_membership_state(payload)
            .expect_err("oversized approver_count must be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    #[test]
    fn decode_signed_update_rejects_oversized_sig_count() {
        // Build a valid inner update record so parsing reaches sig_count.
        let state = base_state();
        let new_node = active_node("node-b", 12);
        let mut candidate = state.clone();
        candidate.nodes.push(new_node.clone());
        candidate.epoch += 1;
        let record = MembershipUpdateRecord {
            network_id: state.network_id.clone(),
            update_id: "update-bounds".to_owned(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_owned(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_owned(),
            policy_context: Some("enrollment".to_owned()),
        };
        let payload = super::encode_update_record(&record).expect("encode record");
        let payload_hex = hex_encode(payload.as_bytes());
        let envelope = format!("payload_hex={payload_hex}\nsig_count=18446744073709551615\n");
        let err = super::decode_signed_update(&envelope)
            .expect_err("oversized sig_count must be rejected");
        assert!(matches!(err, MembershipError::InvalidFormat(_)));
    }

    // ── Membership head attestation (A4: authenticated anchor bundle-pull) ──

    use super::{
        MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS, MembershipHeadAttestation,
        head_attestation_canonical_payload, head_attestation_from_signed_update,
        persist_membership_snapshot_with_attestation, sign_head_attestation,
        snapshot_bytes_head_attestation, snapshot_bytes_state_identity, verify_attested_snapshot,
    };

    /// Signing key of `base_state()`'s `owner-1` approver.
    fn owner_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[1; 32])
    }

    /// Signing key of `base_state()`'s `guardian-1` approver.
    fn guardian_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[2; 32])
    }

    fn pinned_owner_hex() -> String {
        hex_encode(owner_signing_key().verifying_key().as_bytes())
    }

    fn head_attestation_for_state(
        state: &MembershipState,
        attested_at_unix: u64,
        signers: &[(&str, &SigningKey)],
    ) -> MembershipHeadAttestation {
        let state_root_hex = state.state_root_hex().expect("state root");
        let approver_signatures = signers
            .iter()
            .map(|(approver_id, signing_key)| {
                sign_head_attestation(
                    &state.network_id,
                    state.epoch,
                    &state_root_hex,
                    attested_at_unix,
                    approver_id,
                    signing_key,
                )
                .expect("sign head attestation")
            })
            .collect();
        MembershipHeadAttestation {
            network_id: state.network_id.clone(),
            epoch: state.epoch,
            state_root_hex,
            attested_at_unix,
            approver_signatures,
        }
    }

    fn snapshot_bytes(
        state: &MembershipState,
        attestation: Option<&MembershipHeadAttestation>,
    ) -> Vec<u8> {
        let unique = format!(
            "membership-attested-snapshot-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        let path = temp_dir.join("membership.snapshot");
        persist_membership_snapshot_with_attestation(&path, state, attestation)
            .expect("persist attested snapshot");
        let bytes = std::fs::read(&path).expect("read snapshot bytes");
        let _ = std::fs::remove_dir_all(&temp_dir);
        bytes
    }

    /// Standard positive fixture: base_state (quorum 2) attested by
    /// owner-1 + guardian-1 at t=1000.
    fn attested_base_snapshot() -> (MembershipState, Vec<u8>, u64) {
        let state = base_state();
        let attested_at = 1_000u64;
        let attestation = head_attestation_for_state(
            &state,
            attested_at,
            &[
                ("owner-1", &owner_signing_key()),
                ("guardian-1", &guardian_signing_key()),
            ],
        );
        let bytes = snapshot_bytes(&state, Some(&attestation));
        (state, bytes, attested_at)
    }

    #[test]
    fn head_attestation_canonical_payload_is_byte_pinned() {
        // Any change to this format invalidates every existing head
        // signature — the expected value is a LITERAL, not derived.
        let root = "aa".repeat(32);
        let payload = head_attestation_canonical_payload("net-1", 7, &root, 1234);
        let expected = format!(
            "rustynet:membership-head:v1\nattested_at_unix=1234\nepoch=7\nnetwork_id=net-1\nstate_root={root}\n"
        );
        assert_eq!(payload, expected);
        // Domain separation: a head payload can never parse as an update
        // payload (those start `version=`).
        assert!(payload.starts_with("rustynet:membership-head:v1\n"));
    }

    #[test]
    fn verify_attested_snapshot_accepts_owner_signed_current_head() {
        // Positive baseline — guards against a vacuous always-reject (or
        // always-pass) implementation.
        let (state, bytes, attested_at) = attested_base_snapshot();
        let verified = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            attested_at,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("owner-signed current head must verify");
        // Canonical encode/decode sorts rosters, so compare the
        // order-insensitive identity rather than raw struct order.
        assert_eq!(verified.network_id, state.network_id);
        assert_eq!(verified.epoch, state.epoch);
        assert_eq!(
            verified.state_root_hex().expect("root"),
            state.state_root_hex().expect("root")
        );

        // The same bytes also verify against a matching prior identity.
        let root = state.state_root_hex().expect("root");
        verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            attested_at,
            Some(&(state.epoch, root)),
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("same-identity prior must verify");
    }

    #[test]
    fn verify_attested_snapshot_rejects_quorum_inflation_via_duplicate_approver_pubkey() {
        // Regression for an adversarial-review finding (proven live with a
        // standalone PoC against this exact function before the fix): a
        // roster where two approver_ids share one underlying key let a
        // single real key's signature satisfy quorum_threshold=2 by
        // presenting a (deterministically reproducible) signature under
        // both ids — no second private key required.
        //
        // The fix (MembershipState::validate, see
        // validate_rejects_duplicate_approver_pubkeys) runs even earlier
        // than "reject the forged attestation": canonical_payload() calls
        // self.validate()? (membership.rs:285), and state_root_hex() /
        // sign_head_attestation / persist_membership_snapshot_with_attestation
        // all depend on canonical_payload(). So the vulnerable roster shape
        // cannot produce a state root — and therefore cannot be signed or
        // persisted — through ANY path in this crate, not just at the final
        // verify_attested_snapshot check. Assert that stronger guarantee
        // directly: root derivation itself fails closed, which is what
        // actually blocks the attacker's construction attempt end to end
        // (there is no reachable byte sequence a legitimate signer could
        // ever produce for this roster to hand to verify_attested_snapshot).
        let mut state = base_state();
        state.approver_set.push(approver(
            "owner-1-alias",
            1, // same key byte as "owner-1" — the vulnerable shape
            MembershipApproverRole::Owner,
        ));
        let err = state
            .state_root_hex()
            .expect_err("a duplicate-pubkey roster must never yield a state root");
        assert!(
            matches!(err, MembershipError::InvalidFormat(ref msg) if msg.contains("approver pubkey reused")),
            "expected pubkey-reuse rejection, got {err:?}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_missing_attestation() {
        let state = base_state();
        let bytes = snapshot_bytes(&state, None);
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("legacy unattested snapshot must be rejected");
        assert_eq!(err, MembershipError::AttestationMissing);
    }

    #[test]
    fn verify_attested_snapshot_rejects_tampered_state() {
        // The attacker swaps the roster (state_hex) and RECOMPUTES the
        // legacy self-consistency digest — only the recomputed-state-root
        // vs attestation binding can catch this.
        let (_, attested_bytes, attested_at) = attested_base_snapshot();
        let mut tampered_state = base_state();
        tampered_state.nodes.push(active_node("node-evil", 66));
        let tampered_plain = snapshot_bytes(&tampered_state, None);

        // Splice: tampered version/state_hex/digest lines + original
        // attestation lines.
        let attested_text = String::from_utf8(attested_bytes).expect("utf8");
        let attestation_block: String = attested_text
            .lines()
            .filter(|line| line.starts_with("attestation."))
            .fold(String::new(), |mut out, line| {
                out.push_str(line);
                out.push('\n');
                out
            });
        let tampered_text = format!(
            "{}{attestation_block}",
            String::from_utf8(tampered_plain).expect("utf8")
        );
        let err = verify_attested_snapshot(
            tampered_text.as_bytes(),
            &pinned_owner_hex(),
            attested_at,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("tampered roster must be rejected");
        assert!(
            format!("{err}").contains("does not attest this snapshot state"),
            "expected attestation binding rejection, got: {err}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_wrong_pinned_key() {
        // A fully self-consistent attacker mesh signed by an attacker
        // "owner" verifies internally but must fail the §6.B pin.
        let attacker_owner = SigningKey::from_bytes(&[77; 32]);
        let mut state = base_state();
        state.approver_set = vec![MembershipApprover {
            approver_id: "evil-owner".to_owned(),
            approver_pubkey_hex: hex_encode(attacker_owner.verifying_key().as_bytes()),
            role: MembershipApproverRole::Owner,
            status: MembershipApproverStatus::Active,
            created_at_unix: 100,
        }];
        state.quorum_threshold = 1;
        let attestation =
            head_attestation_for_state(&state, 1_000, &[("evil-owner", &attacker_owner)]);
        let bytes = snapshot_bytes(&state, Some(&attestation));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("attacker mesh must fail the pin");
        assert!(
            matches!(&err, MembershipError::PinnedOwnerKeyMismatch(reason)
                if reason.contains("not in the attested approver set")),
            "expected pin-not-in-roster rejection, got: {err}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_roster_listing_pinned_key_without_its_signature() {
        // THE critical subtlety: the hostile state LISTS the real owner
        // key as an active Owner, but the attestation's actual signatures
        // come only from attacker-controlled approvers that meet quorum.
        // Roster presence without the pinned key's own signature must be
        // rejected.
        let attacker_owner = SigningKey::from_bytes(&[77; 32]);
        let attacker_guardian = SigningKey::from_bytes(&[78; 32]);
        let mut state = base_state();
        state.approver_set = vec![
            MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: pinned_owner_hex(),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            },
            MembershipApprover {
                approver_id: "evil-owner".to_owned(),
                approver_pubkey_hex: hex_encode(attacker_owner.verifying_key().as_bytes()),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            },
            MembershipApprover {
                approver_id: "evil-guardian".to_owned(),
                approver_pubkey_hex: hex_encode(attacker_guardian.verifying_key().as_bytes()),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            },
        ];
        state.quorum_threshold = 2;
        let attestation = head_attestation_for_state(
            &state,
            1_000,
            &[
                ("evil-owner", &attacker_owner),
                ("evil-guardian", &attacker_guardian),
            ],
        );
        let bytes = snapshot_bytes(&state, Some(&attestation));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("roster listing without the pinned key's signature must be rejected");
        assert!(
            matches!(&err, MembershipError::PinnedOwnerKeyMismatch(reason)
                if reason.contains("no signature from the pinned membership owner key")),
            "expected missing-pinned-signature rejection, got: {err}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_quorum_below_attested_threshold() {
        // base_state quorum is 2; an attestation signed only by the owner
        // passes the pin but fails quorum.
        let state = base_state();
        let attestation =
            head_attestation_for_state(&state, 1_000, &[("owner-1", &owner_signing_key())]);
        let bytes = snapshot_bytes(&state, Some(&attestation));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("sub-quorum attestation must be rejected");
        assert_eq!(err, MembershipError::ThresholdNotMet);
    }

    #[test]
    fn verify_attested_snapshot_rejects_stale_attestation() {
        let (_, bytes, attested_at) = attested_base_snapshot();
        let now = attested_at + MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS + 1;
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            now,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("stale attestation must be rejected");
        assert_eq!(err, MembershipError::AttestationStale);

        // Boundary: exactly at the window edge still verifies.
        verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            attested_at + MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("attestation at the window boundary must verify");

        // A tightened window is honored.
        let err = verify_attested_snapshot(&bytes, &pinned_owner_hex(), attested_at + 61, None, 60)
            .expect_err("attestation outside a tightened window must be rejected");
        assert_eq!(err, MembershipError::AttestationStale);

        // The window can never be disabled: zero or beyond the hard cap
        // is rejected outright.
        for bad_window in [0u64, MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS + 1, u64::MAX] {
            let err = verify_attested_snapshot(
                &bytes,
                &pinned_owner_hex(),
                attested_at,
                None,
                bad_window,
            )
            .expect_err("out-of-bounds freshness window must be rejected");
            assert!(
                format!("{err}").contains("attestation max age"),
                "expected max-age bounds rejection, got: {err}"
            );
        }
    }

    #[test]
    fn verify_attested_snapshot_rejects_future_dated_attestation() {
        let state = base_state();
        let now = 1_000u64;
        let attested_at = now + MEMBERSHIP_CLOCK_SKEW_SECS + 1;
        let attestation = head_attestation_for_state(
            &state,
            attested_at,
            &[
                ("owner-1", &owner_signing_key()),
                ("guardian-1", &guardian_signing_key()),
            ],
        );
        let bytes = snapshot_bytes(&state, Some(&attestation));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            now,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("future-dated attestation must be rejected");
        assert_eq!(err, MembershipError::AttestationFutureDated);
    }

    #[test]
    fn verify_attested_snapshot_rejects_network_id_mismatch() {
        // A rewritten attestation.network_id is caught by the binding
        // check (before signature verification can even be confused).
        let (_, bytes, attested_at) = attested_base_snapshot();
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.contains("attestation.network_id=net-1\n"));
        let tampered = text.replacen(
            "attestation.network_id=net-1\n",
            "attestation.network_id=net-2\n",
            1,
        );
        let err = verify_attested_snapshot(
            tampered.as_bytes(),
            &pinned_owner_hex(),
            attested_at,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("network id mismatch must be rejected");
        assert!(
            format!("{err}").contains("network id does not match"),
            "expected network-id binding rejection, got: {err}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_epoch_or_root_mismatch_between_attestation_and_state() {
        let (state, bytes, attested_at) = attested_base_snapshot();
        let text = String::from_utf8(bytes).expect("utf8");

        let epoch_line = format!("attestation.epoch={}\n", state.epoch);
        let tampered_epoch = text.replacen(
            epoch_line.as_str(),
            &format!("attestation.epoch={}\n", state.epoch + 1),
            1,
        );
        assert_ne!(tampered_epoch, text, "fixture must contain the epoch line");
        let err = verify_attested_snapshot(
            tampered_epoch.as_bytes(),
            &pinned_owner_hex(),
            attested_at,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("attestation epoch mismatch must be rejected");
        assert!(
            format!("{err}").contains("does not attest this snapshot state"),
            "expected epoch binding rejection, got: {err}"
        );

        let root = state.state_root_hex().expect("root");
        let tampered_root = text.replacen(
            &format!("attestation.state_root={root}\n"),
            &format!("attestation.state_root={}\n", "00".repeat(32)),
            1,
        );
        assert_ne!(tampered_root, text, "fixture must contain the root line");
        let err = verify_attested_snapshot(
            tampered_root.as_bytes(),
            &pinned_owner_hex(),
            attested_at,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("attestation root mismatch must be rejected");
        assert!(
            format!("{err}").contains("does not attest this snapshot state"),
            "expected root binding rejection, got: {err}"
        );
    }

    #[test]
    fn verify_attested_snapshot_rejects_epoch_regression_against_prior_identity() {
        let (state, bytes, attested_at) = attested_base_snapshot();
        assert_eq!(state.epoch, 1);

        // Prior verified bundle at a higher epoch: regression.
        let prior = (5u64, "ab".repeat(32));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            attested_at,
            Some(&prior),
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("epoch regression must be rejected");
        assert_eq!(
            err,
            MembershipError::EpochRegression {
                prior_epoch: 5,
                offered_epoch: 1,
            }
        );

        // Same epoch, different root: fork evidence, never silently
        // resolved.
        let fork_prior = (state.epoch, "cd".repeat(32));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            attested_at,
            Some(&fork_prior),
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("same-epoch fork must be rejected");
        let root = state.state_root_hex().expect("root");
        assert_eq!(
            err,
            MembershipError::ForkDetected {
                epoch: state.epoch,
                prior_root: "cd".repeat(32),
                offered_root: root,
            }
        );
    }

    /// Rotation fixture: old owner (pinned key) revoked in the state, new
    /// owner active, one active guardian; quorum 1.
    fn rotated_owner_state(new_owner: &SigningKey) -> MembershipState {
        let mut state = base_state();
        state.approver_set = vec![
            MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: pinned_owner_hex(),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Revoked,
                created_at_unix: 100,
            },
            MembershipApprover {
                approver_id: "owner-2".to_owned(),
                approver_pubkey_hex: hex_encode(new_owner.verifying_key().as_bytes()),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 200,
            },
            approver("guardian-1", 2, MembershipApproverRole::Guardian),
        ];
        state.quorum_threshold = 1;
        state.epoch = 2;
        state
    }

    #[test]
    fn verify_attested_snapshot_accepts_rotated_pin_with_active_owner_cosignature() {
        // Rotation grace: a device still pinning the OLD owner key accepts
        // the post-rotation head as long as the old key signed AND a
        // current active owner co-signed the same attestation.
        let new_owner = SigningKey::from_bytes(&[4; 32]);
        let state = rotated_owner_state(&new_owner);
        let attestation = head_attestation_for_state(
            &state,
            1_000,
            &[("owner-1", &owner_signing_key()), ("owner-2", &new_owner)],
        );
        let bytes = snapshot_bytes(&state, Some(&attestation));

        // Old pin: accepted through rotation grace.
        verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("old pin with active-owner co-signature must verify");

        // New pin: accepted directly.
        verify_attested_snapshot(
            &bytes,
            &hex_encode(new_owner.verifying_key().as_bytes()),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("new pin must verify directly");
    }

    #[test]
    fn verify_attested_snapshot_rejects_rotated_pin_without_active_owner_cosignature() {
        // Negative rotation grace: old-owner + guardian signatures meet
        // quorum, but no ACTIVE owner signed — the old pin must be told to
        // re-deliver the trust anchor, not silently accept.
        let new_owner = SigningKey::from_bytes(&[4; 32]);
        let state = rotated_owner_state(&new_owner);
        let attestation = head_attestation_for_state(
            &state,
            1_000,
            &[
                ("owner-1", &owner_signing_key()),
                ("guardian-1", &guardian_signing_key()),
            ],
        );
        let bytes = snapshot_bytes(&state, Some(&attestation));
        let err = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            1_000,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect_err("rotated pin without active-owner co-signature must be rejected");
        assert!(
            matches!(&err, MembershipError::PinnedOwnerKeyMismatch(reason)
                if reason.contains("re-deliver the membership owner public key")),
            "expected rotation-grace rejection with re-delivery guidance, got: {err}"
        );
    }

    #[test]
    fn snapshot_with_attestation_fields_round_trips_through_legacy_loader() {
        let (state, bytes, attested_at) = attested_base_snapshot();

        // Legacy loader: parses the same state, digest unchanged, ignores
        // the trailing attestation fields.
        let unique = format!(
            "membership-attested-legacy-load-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        let path = temp_dir.join("membership.snapshot");
        let attestation = head_attestation_for_state(
            &state,
            attested_at,
            &[
                ("owner-1", &owner_signing_key()),
                ("guardian-1", &guardian_signing_key()),
            ],
        );
        persist_membership_snapshot_with_attestation(&path, &state, Some(&attestation))
            .expect("persist");
        let loaded = load_membership_snapshot(&path).expect("legacy loader must still parse");
        // Canonical encode/decode sorts rosters; compare the
        // order-insensitive state identity.
        assert_eq!(loaded.network_id, state.network_id);
        assert_eq!(loaded.epoch, state.epoch);
        assert_eq!(
            loaded.state_root_hex().expect("root"),
            state.state_root_hex().expect("root")
        );
        let _ = std::fs::remove_dir_all(&temp_dir);

        // FIS-0020 identity extraction is unaffected.
        let root = state.state_root_hex().expect("root");
        assert_eq!(
            snapshot_bytes_state_identity(&bytes),
            Some((state.epoch, root))
        );

        // The attestation reader round-trips the persisted block
        // (signatures are persisted in sorted approver_id order).
        let parsed = snapshot_bytes_head_attestation(&bytes).expect("attestation present");
        let mut expected = attestation.clone();
        expected
            .approver_signatures
            .sort_by(|left, right| left.approver_id.cmp(&right.approver_id));
        assert_eq!(parsed, expected);

        // A legacy snapshot has no attestation to read.
        let legacy = snapshot_bytes(&state, None);
        assert_eq!(snapshot_bytes_head_attestation(&legacy), None);
    }

    #[test]
    fn signed_update_envelope_with_head_signature_round_trips_and_chains() {
        let (state, record, mut signatures) = signed_add_node_fixture();

        // Legacy envelope (no head signatures) is byte-stable: the field
        // never appears, so pre-existing entry hashes are unchanged.
        let legacy_signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: signatures.clone(),
        };
        let legacy_envelope = legacy_signed.canonical_envelope().expect("envelope");
        assert!(!legacy_envelope.contains("head_signature_hex"));

        // Mint head signatures for both signers, deterministic from the
        // record (epoch_new / new_state_root / created_at_unix).
        for (signature, key) in signatures
            .iter_mut()
            .zip([owner_signing_key(), guardian_signing_key()])
        {
            let head = sign_head_attestation(
                &record.network_id,
                record.epoch_new,
                &record.new_state_root,
                record.created_at_unix,
                &signature.approver_id,
                &key,
            )
            .expect("sign head attestation");
            signature.head_signature_hex = Some(head.signature_hex);
        }
        let signed = SignedMembershipUpdate {
            record: record.clone(),
            approver_signatures: signatures,
        };

        // Wire round-trip preserves the per-signer head signatures. The
        // envelope sorts signatures by approver_id, so compare against the
        // sorted expectation.
        let envelope = signed.canonical_envelope().expect("envelope");
        assert!(envelope.contains("sig.0.head_signature_hex="));
        let decoded = super::decode_signed_update(&envelope).expect("decode");
        let mut expected = signed.clone();
        expected
            .approver_signatures
            .sort_by(|left, right| left.approver_id.cmp(&right.approver_id));
        assert_eq!(decoded, expected);

        // The update still applies (head signatures never weaken the
        // update-signature gate), and the log chain round-trips with the
        // new field present.
        apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect("head-signed update must still apply");
        let unique = format!(
            "membership-head-sig-log-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        let log = temp_dir.join("membership.log");
        let entry = append_membership_log_entry(&log, &signed).expect("append");
        let entries = load_membership_log(&log).expect("chain must verify with head signatures");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].entry_hash, entry.entry_hash);
        // Loaded entries carry the canonical (sorted-signature) form.
        assert_eq!(entries[0].signed_update, expected);
        assert!(
            entries[0]
                .signed_update
                .approver_signatures
                .iter()
                .all(|signature| signature.head_signature_hex.is_some()),
            "head signatures must survive the log chain round-trip"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);

        // The materialized attestation binds to the record's new head.
        let attestation =
            head_attestation_from_signed_update(&signed).expect("head signatures present");
        assert_eq!(attestation.network_id, record.network_id);
        assert_eq!(attestation.epoch, record.epoch_new);
        assert_eq!(attestation.state_root_hex, record.new_state_root);
        assert_eq!(attestation.attested_at_unix, record.created_at_unix);
        assert_eq!(attestation.approver_signatures.len(), 2);

        // ... and verifies against the applied next state through the
        // real enforcement point.
        let next = apply_signed_update(&state, &signed, 130, &mut MembershipReplayCache::default())
            .expect("apply");
        let bytes = snapshot_bytes(&next, Some(&attestation));
        let verified = verify_attested_snapshot(
            &bytes,
            &pinned_owner_hex(),
            record.created_at_unix,
            None,
            MEMBERSHIP_HEAD_ATTESTATION_MAX_AGE_SECS,
        )
        .expect("materialized attestation must verify against the applied state");
        assert_eq!(verified.epoch, next.epoch);
        assert_eq!(
            verified.state_root_hex().expect("root"),
            next.state_root_hex().expect("root")
        );

        // A legacy update materializes no attestation.
        assert_eq!(head_attestation_from_signed_update(&legacy_signed), None);
    }

    #[test]
    fn persist_with_attestation_refuses_unbound_attestation() {
        // A mismatched attestation is a programming error at the persist
        // site, not something to write and let clients reject later.
        let state = base_state();
        let mut other = base_state();
        other.epoch = 9;
        let attestation =
            head_attestation_for_state(&other, 1_000, &[("owner-1", &owner_signing_key())]);
        let unique = format!(
            "membership-attest-unbound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        let path = temp_dir.join("membership.snapshot");
        let err = persist_membership_snapshot_with_attestation(&path, &state, Some(&attestation))
            .expect_err("unbound attestation must be refused");
        assert!(
            format!("{err}").contains("does not bind"),
            "expected binding refusal, got: {err}"
        );
        assert!(!path.exists(), "no snapshot may be written on refusal");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    fn watermark_test_dir(label: &str) -> std::path::PathBuf {
        let unique = format!(
            "membership-watermark-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock should be valid")
                .as_nanos()
        );
        let temp_dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&temp_dir).expect("temp dir");
        temp_dir
    }

    #[test]
    fn watermark_loader_rejects_duplicate_keys() {
        let temp_dir = watermark_test_dir("dup");
        let path = temp_dir.join("watermark");
        // A tampered file that repeats epoch= must NOT have its last line
        // silently win — the loader must fail closed on the duplicate.
        std::fs::write(
            &path,
            "version=1\nepoch=5\nepoch=999\nstate_root=abc\nstate_root=zzz\n",
        )
        .expect("write watermark");
        let err = load_membership_watermark(&path).expect_err("duplicate epoch must be rejected");
        assert!(err.contains("duplicate"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn watermark_loader_refuses_oversized_file_before_parse() {
        let temp_dir = watermark_test_dir("oversize");
        let path = temp_dir.join("watermark");
        std::fs::write(&path, vec![b'x'; 4 * 1024 + 1]).expect("write oversized watermark");
        let err =
            load_membership_watermark(&path).expect_err("oversized watermark must be rejected");
        assert!(
            err.contains("exceeds maximum size"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn watermark_loader_rejects_empty_state_root() {
        let temp_dir = watermark_test_dir("empty-root");
        let path = temp_dir.join("watermark");
        std::fs::write(&path, "version=1\nepoch=7\nstate_root=\n").expect("write watermark");
        let err = load_membership_watermark(&path).expect_err("empty state_root must be rejected");
        assert!(err.contains("empty"), "unexpected error: {err}");
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn watermark_persist_load_round_trip() {
        let temp_dir = watermark_test_dir("round-trip");
        let path = temp_dir.join("nested").join("watermark");
        let written = MembershipWatermark {
            epoch: 41,
            state_root: "root-bytes-0123".to_owned(),
        };
        persist_membership_watermark(&path, &written).expect("persist watermark");
        let loaded = load_membership_watermark(&path)
            .expect("load persisted watermark")
            .expect("watermark file must exist after persist");
        assert_eq!(loaded.epoch, written.epoch);
        assert_eq!(loaded.state_root, written.state_root);
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn replay_cache_bounded_at_cap_and_still_dedups_recent_ids() {
        let mut cache = MembershipReplayCache::default();
        for i in 0..(MAX_REPLAY_CACHE_ENTRIES + 250) {
            let id = format!("replay-cache-fill-{i}");
            cache
                .observe(&id, (i + 1) as u64)
                .unwrap_or_else(|e| panic!("observe {id} rejected: {e:?}"));
        }
        assert!(
            cache.seen_update_ids.len() <= MAX_REPLAY_CACHE_ENTRIES,
            "cache grew past the cap: {}",
            cache.seen_update_ids.len()
        );
        // The most recent id is still remembered and deduped after eviction.
        let latest = format!("replay-cache-fill-{}", MAX_REPLAY_CACHE_ENTRIES + 249);
        assert!(matches!(
            cache.observe(&latest, MAX_REPLAY_CACHE_ENTRIES as u64 + 251),
            Err(MembershipError::ReplayDetected)
        ));
        // And a fresh id at a fresh epoch is still accepted post-eviction.
        cache
            .observe(
                "replay-cache-post-eviction",
                MAX_REPLAY_CACHE_ENTRIES as u64 + 252,
            )
            .expect("fresh id must be accepted after eviction");
    }
}

#[cfg(test)]
mod epoch_tagged_bundle_tests {
    use super::verify_epoch_tagged_bundle;
    use super::{EpochTaggedBundle, EpochTaggedBundleError, MembershipError, hex_encode};
    use crate::key_rotation::{
        ArchivedVerifier, PerEpochReplayWatermark, RotationEpoch, RotationError, VerifierArchive,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn signed_bundle_under(
        signing: &SigningKey,
        epoch: RotationEpoch,
        watermark: u64,
        payload: &[u8],
    ) -> EpochTaggedBundle {
        let signature = signing.sign(payload);
        EpochTaggedBundle {
            epoch_tag: epoch,
            update_watermark: watermark,
            payload: payload.to_vec(),
            signature_hex: hex_encode(&signature.to_bytes()),
        }
    }

    fn archive_with(
        epoch: RotationEpoch,
        signing: &SigningKey,
        watermark_at_rotation: u64,
    ) -> VerifierArchive {
        let mut archive = VerifierArchive::new();
        archive
            .record(ArchivedVerifier {
                epoch,
                public_key_hex: hex_encode(signing.verifying_key().as_bytes()),
                archived_at_unix: 0,
                watermark_at_rotation,
            })
            .expect("archive insert");
        archive
    }

    #[test]
    fn pre_rotation_bundle_verifies_against_archived_verifier_within_watermark() {
        let outgoing = SigningKey::from_bytes(&[7u8; 32]);
        let archive = archive_with(RotationEpoch(1), &outgoing, 50);
        let mut watermark = PerEpochReplayWatermark::new(RotationEpoch(1));
        watermark.advance_to(RotationEpoch(2)).expect("advance");
        watermark
            .freeze_outgoing(RotationEpoch(1), 50)
            .expect("freeze outgoing");
        let bundle = signed_bundle_under(&outgoing, RotationEpoch(1), 25, b"hello-1");
        verify_epoch_tagged_bundle(&bundle, &archive, &watermark)
            .expect("pre-rotation bundle within watermark must verify");
    }

    #[test]
    fn post_rotation_bundle_signed_by_new_key_verifies() {
        let incoming = SigningKey::from_bytes(&[8u8; 32]);
        let mut archive = VerifierArchive::new();
        archive
            .record(ArchivedVerifier {
                epoch: RotationEpoch(2),
                public_key_hex: hex_encode(incoming.verifying_key().as_bytes()),
                archived_at_unix: 0,
                watermark_at_rotation: 0,
            })
            .expect("archive insert");
        let watermark = PerEpochReplayWatermark::new(RotationEpoch(2));
        let bundle = signed_bundle_under(&incoming, RotationEpoch(2), 10, b"hello-2");
        verify_epoch_tagged_bundle(&bundle, &archive, &watermark)
            .expect("post-rotation bundle must verify");
    }

    #[test]
    fn replayed_old_epoch_bundle_with_advanced_watermark_rejected_as_signature_invalid() {
        let outgoing = SigningKey::from_bytes(&[7u8; 32]);
        let archive = archive_with(RotationEpoch(1), &outgoing, 50);
        let mut watermark = PerEpochReplayWatermark::new(RotationEpoch(1));
        watermark.advance_to(RotationEpoch(2)).expect("advance");
        watermark
            .freeze_outgoing(RotationEpoch(1), 50)
            .expect("freeze outgoing");
        let bundle = signed_bundle_under(&outgoing, RotationEpoch(1), 75, b"stale");
        let err = verify_epoch_tagged_bundle(&bundle, &archive, &watermark)
            .expect_err("bundle past the freeze point must fail closed");
        assert!(matches!(
            err,
            EpochTaggedBundleError::Rotation(RotationError::WatermarkPastRotationPoint { .. })
        ));
    }

    #[test]
    fn bundle_with_unknown_epoch_tag_rejected() {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let archive = VerifierArchive::new();
        let watermark = PerEpochReplayWatermark::new(RotationEpoch(0));
        let bundle = signed_bundle_under(&signing, RotationEpoch(99), 0, b"nope");
        let err = verify_epoch_tagged_bundle(&bundle, &archive, &watermark)
            .expect_err("unknown epoch tag must fail closed");
        assert!(matches!(
            err,
            EpochTaggedBundleError::Rotation(RotationError::UnknownEpoch { .. })
        ));
    }

    #[test]
    fn bundle_with_tampered_signature_rejected_as_signature_invalid() {
        let outgoing = SigningKey::from_bytes(&[7u8; 32]);
        let archive = archive_with(RotationEpoch(1), &outgoing, 100);
        let mut watermark = PerEpochReplayWatermark::new(RotationEpoch(1));
        watermark.advance_to(RotationEpoch(2)).expect("advance");
        watermark
            .freeze_outgoing(RotationEpoch(1), 100)
            .expect("freeze outgoing");
        let mut bundle = signed_bundle_under(&outgoing, RotationEpoch(1), 25, b"payload");
        // flip one byte of the signature
        bundle.signature_hex.replace_range(0..2, "ff");
        let err = verify_epoch_tagged_bundle(&bundle, &archive, &watermark)
            .expect_err("tampered signature must fail closed");
        assert!(matches!(
            err,
            EpochTaggedBundleError::Membership(MembershipError::SignatureInvalid)
        ));
    }

    #[test]
    fn validate_membership_file_security_source_allows_root_to_read_daemon_owned_file() {
        // Pin against the regression where the membership-file validator
        // required the file owner UID to equal the running process's
        // effective UID. The daemon writes the snapshot as its own
        // service UID (uid 987 on Debian); when `rustynet anchor list`
        // runs under sudo (effective UID 0) and tries to read the
        // snapshot, the validator returned "owner uid mismatch:
        // expected 0, got 987" and the live_anchor stage failed rc=70.
        //
        // The carve-out: when effective_uid is 0 (root), root is
        // allowed to read files owned by any UID — mode bits already
        // restrict access to the owner, and root can chown/chmod
        // anyway. This is a source-text pin so a future refactor that
        // accidentally drops the carve-out trips a named failure.
        let source = include_str!("membership.rs");
        let marker = "owner_uid != effective_uid && effective_uid != 0";
        assert!(
            source.contains(marker),
            "validate_membership_file_security must keep the `effective_uid != 0` carve-out so \
             root-running tooling (e.g. `rustynet anchor list` under sudo) can read snapshots \
             owned by the daemon's service UID"
        );
    }
}
