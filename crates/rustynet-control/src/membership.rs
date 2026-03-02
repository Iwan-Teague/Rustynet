#![forbid(unsafe_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const MEMBERSHIP_SCHEMA_VERSION: u8 = 1;
pub const MEMBERSHIP_CLOCK_SKEW_SECS: u64 = 90;

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
                "network id must not be empty".to_string(),
            ));
        }
        if self.quorum_threshold == 0 {
            return Err(MembershipError::InvalidFormat(
                "quorum threshold must be at least 1".to_string(),
            ));
        }

        let mut node_ids = HashSet::new();
        for node in &self.nodes {
            if node.node_id.trim().is_empty() {
                return Err(MembershipError::InvalidFormat(
                    "node id must not be empty".to_string(),
                ));
            }
            if !node_ids.insert(node.node_id.clone()) {
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
        }

        let mut approver_ids = HashSet::new();
        let active_approvers = self
            .approver_set
            .iter()
            .filter(|approver| approver.status == MembershipApproverStatus::Active)
            .count() as u8;
        for approver in &self.approver_set {
            if approver.approver_id.trim().is_empty() {
                return Err(MembershipError::InvalidFormat(
                    "approver id must not be empty".to_string(),
                ));
            }
            if !approver_ids.insert(approver.approver_id.clone()) {
                return Err(MembershipError::InvalidFormat(format!(
                    "duplicate approver id {}",
                    approver.approver_id
                )));
            }
            decode_hex_to_fixed::<32>(&approver.approver_pubkey_hex)?;
        }

        if active_approvers == 0 {
            return Err(MembershipError::InvalidFormat(
                "at least one active approver is required".to_string(),
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
        self.validate()?;
        let mut nodes = self.nodes.clone();
        nodes.sort_by(|left, right| left.node_id.cmp(&right.node_id));
        let mut approvers = self.approver_set.clone();
        approvers.sort_by(|left, right| left.approver_id.cmp(&right.approver_id));

        let mut out = String::new();
        out.push_str(&format!("version={}\n", self.schema_version));
        out.push_str(&format!("network_id={}\n", self.network_id));
        out.push_str(&format!("epoch={}\n", self.epoch));
        out.push_str(&format!("quorum_threshold={}\n", self.quorum_threshold));
        out.push_str(&format!(
            "metadata_hash={}\n",
            self.metadata_hash.as_deref().unwrap_or("")
        ));
        out.push_str(&format!("node_count={}\n", nodes.len()));
        for (index, node) in nodes.iter().enumerate() {
            out.push_str(&format!("node.{index}.node_id={}\n", node.node_id));
            out.push_str(&format!(
                "node.{index}.node_pubkey_hex={}\n",
                node.node_pubkey_hex
            ));
            out.push_str(&format!("node.{index}.owner={}\n", node.owner));
            out.push_str(&format!("node.{index}.status={}\n", node.status.as_str()));
            let mut roles = node.roles.clone();
            roles.sort();
            roles.dedup();
            out.push_str(&format!("node.{index}.roles={}\n", roles.join(",")));
            out.push_str(&format!(
                "node.{index}.joined_at_unix={}\n",
                node.joined_at_unix
            ));
            out.push_str(&format!(
                "node.{index}.updated_at_unix={}\n",
                node.updated_at_unix
            ));
        }
        out.push_str(&format!("approver_count={}\n", approvers.len()));
        for (index, approver) in approvers.iter().enumerate() {
            out.push_str(&format!(
                "approver.{index}.approver_id={}\n",
                approver.approver_id
            ));
            out.push_str(&format!(
                "approver.{index}.approver_pubkey_hex={}\n",
                approver.approver_pubkey_hex
            ));
            out.push_str(&format!(
                "approver.{index}.role={}\n",
                approver.role.as_str()
            ));
            out.push_str(&format!(
                "approver.{index}.status={}\n",
                approver.status.as_str()
            ));
            out.push_str(&format!(
                "approver.{index}.created_at_unix={}\n",
                approver.created_at_unix
            ));
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
            MembershipOperation::RemoveNode { .. } => "remove_node",
            MembershipOperation::RevokeNode { .. } => "revoke_node",
            MembershipOperation::RestoreNode { .. } => "restore_node",
            MembershipOperation::RotateNodeKey { .. } => "rotate_node_key",
            MembershipOperation::RotateApprover(_) => "rotate_approver",
            MembershipOperation::SetQuorum { .. } => "set_quorum",
        }
    }

    fn requires_owner_signer(&self) -> bool {
        matches!(
            self,
            MembershipOperation::RotateApprover(_) | MembershipOperation::SetQuorum { .. }
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
                "membership update network id must not be empty".to_string(),
            ));
        }
        if self.update_id.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "membership update id must not be empty".to_string(),
            ));
        }
        if self.target.trim().is_empty() {
            return Err(MembershipError::InvalidFormat(
                "membership update target must not be empty".to_string(),
            ));
        }
        if self.epoch_new != self.epoch_prev.saturating_add(1) {
            return Err(MembershipError::InvalidTransition(
                "membership update epoch chain must increment by exactly 1",
            ));
        }
        if self.created_at_unix >= self.expires_at_unix {
            return Err(MembershipError::InvalidFormat(
                "membership update expires_at_unix must be greater than created_at_unix"
                    .to_string(),
            ));
        }

        let mut out = String::new();
        out.push_str(&format!("version={MEMBERSHIP_SCHEMA_VERSION}\n"));
        out.push_str(&format!("network_id={}\n", self.network_id));
        out.push_str(&format!("update_id={}\n", self.update_id));
        out.push_str(&format!("operation={}\n", self.operation.operation_name()));
        out.push_str(&format!("target={}\n", self.target));
        out.push_str(&format!("prev_state_root={}\n", self.prev_state_root));
        out.push_str(&format!("new_state_root={}\n", self.new_state_root));
        out.push_str(&format!("epoch_prev={}\n", self.epoch_prev));
        out.push_str(&format!("epoch_new={}\n", self.epoch_new));
        out.push_str(&format!("created_at_unix={}\n", self.created_at_unix));
        out.push_str(&format!("expires_at_unix={}\n", self.expires_at_unix));
        out.push_str(&format!("reason_code={}\n", self.reason_code));
        out.push_str(&format!(
            "policy_context={}\n",
            self.policy_context.as_deref().unwrap_or("")
        ));

        match &self.operation {
            MembershipOperation::AddNode(node) => {
                out.push_str(&format!("op.node_id={}\n", node.node_id));
                out.push_str(&format!("op.node_pubkey_hex={}\n", node.node_pubkey_hex));
                out.push_str(&format!("op.owner={}\n", node.owner));
                out.push_str(&format!("op.status={}\n", node.status.as_str()));
                let mut roles = node.roles.clone();
                roles.sort();
                roles.dedup();
                out.push_str(&format!("op.roles={}\n", roles.join(",")));
                out.push_str(&format!("op.joined_at_unix={}\n", node.joined_at_unix));
                out.push_str(&format!("op.updated_at_unix={}\n", node.updated_at_unix));
            }
            MembershipOperation::RemoveNode { node_id }
            | MembershipOperation::RevokeNode { node_id }
            | MembershipOperation::RestoreNode { node_id } => {
                out.push_str(&format!("op.node_id={node_id}\n"));
            }
            MembershipOperation::RotateNodeKey {
                node_id,
                new_pubkey_hex,
            } => {
                out.push_str(&format!("op.node_id={node_id}\n"));
                out.push_str(&format!("op.new_pubkey_hex={new_pubkey_hex}\n"));
            }
            MembershipOperation::RotateApprover(approver) => {
                out.push_str(&format!("op.approver_id={}\n", approver.approver_id));
                out.push_str(&format!(
                    "op.approver_pubkey_hex={}\n",
                    approver.approver_pubkey_hex
                ));
                out.push_str(&format!("op.role={}\n", approver.role.as_str()));
                out.push_str(&format!("op.status={}\n", approver.status.as_str()));
                out.push_str(&format!(
                    "op.created_at_unix={}\n",
                    approver.created_at_unix
                ));
            }
            MembershipOperation::SetQuorum { threshold } => {
                out.push_str(&format!("op.threshold={threshold}\n"));
            }
        }

        Ok(out)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipSignature {
    pub approver_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedMembershipUpdate {
    pub record: MembershipUpdateRecord,
    pub approver_signatures: Vec<MembershipSignature>,
}

impl SignedMembershipUpdate {
    pub fn canonical_envelope(&self) -> Result<String, MembershipError> {
        let payload = self.record.canonical_payload()?;
        let mut signatures = self.approver_signatures.clone();
        signatures.sort_by(|left, right| left.approver_id.cmp(&right.approver_id));

        let mut out = String::new();
        out.push_str(&format!("payload_hex={}\n", hex_encode(payload.as_bytes())));
        out.push_str(&format!("sig_count={}\n", signatures.len()));
        for (index, signature) in signatures.iter().enumerate() {
            out.push_str(&format!(
                "sig.{index}.approver_id={}\n",
                signature.approver_id
            ));
            out.push_str(&format!(
                "sig.{index}.signature_hex={}\n",
                signature.signature_hex
            ));
        }
        Ok(out)
    }
}

#[derive(Debug, Default, Clone)]
pub struct MembershipReplayCache {
    seen_update_ids: HashSet<String>,
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
        self.seen_update_ids.insert(update_id.to_string());
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

pub fn preview_next_state(
    state: &MembershipState,
    operation: &MembershipOperation,
) -> Result<MembershipState, MembershipError> {
    state.validate()?;
    let mut next = reduce_membership_state(state, operation)?;
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
            "approver_id must not be empty".to_string(),
        ));
    }
    let payload = record.canonical_payload()?;
    let signature = signing_key.sign(payload.as_bytes());
    Ok(MembershipSignature {
        approver_id: approver_id.to_string(),
        signature_hex: hex_encode(&signature.to_bytes()),
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
    replay_cache.observe(&record.update_id, record.epoch_new)?;

    let mut next = reduce_membership_state(state, &record.operation)?;
    next.epoch = record.epoch_new;
    next.validate()?;
    let computed_new_root = next.state_root_hex()?;
    if computed_new_root != record.new_state_root {
        return Err(MembershipError::NewStateRootMismatch);
    }

    Ok(next)
}

pub fn persist_membership_snapshot(
    path: impl AsRef<Path>,
    state: &MembershipState,
) -> Result<(), MembershipError> {
    let state_payload = state.canonical_payload()?;
    let state_hex = hex_encode(state_payload.as_bytes());
    let body_without_digest =
        format!("version={MEMBERSHIP_SCHEMA_VERSION}\nstate_hex={state_hex}\n");
    let digest = sha256_hex(body_without_digest.as_bytes());
    let body = format!("{body_without_digest}digest={digest}\n");
    atomic_write(path.as_ref(), body.as_bytes(), 0o600)
}

pub fn load_membership_snapshot(
    path: impl AsRef<Path>,
) -> Result<MembershipState, MembershipError> {
    let path = path.as_ref();
    validate_membership_file_security(path, "membership snapshot")?;
    let content = fs::read_to_string(path).map_err(|err| MembershipError::Io(err.to_string()))?;
    let fields = parse_key_values(&content)?;
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
        .map_err(|_| MembershipError::InvalidFormat("snapshot payload is not utf8".to_string()))?;
    let state = parse_membership_state_payload(&payload)?;
    state.validate()?;
    Ok(state)
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
        .map(|entry| entry.entry_hash.clone())
        .unwrap_or_else(|| "genesis".to_string());
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
    let content = fs::read_to_string(path).map_err(|err| MembershipError::Io(err.to_string()))?;
    let mut lines = content.lines();
    let version_line = lines
        .next()
        .ok_or_else(|| MembershipError::InvalidFormat("missing log version".to_string()))?;
    let Some((version_key, version_value)) = version_line.split_once('=') else {
        return Err(MembershipError::InvalidFormat(
            "log version line missing separator".to_string(),
        ));
    };
    if version_key != "version" {
        return Err(MembershipError::InvalidFormat(
            "log first line must be version".to_string(),
        ));
    }
    let version = version_value
        .parse::<u8>()
        .map_err(|_| MembershipError::InvalidFormat("invalid log version".to_string()))?;
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
                "log entry field count mismatch".to_string(),
            ));
        }
        let index = parts[0]
            .parse::<u64>()
            .map_err(|_| MembershipError::InvalidFormat("invalid log entry index".to_string()))?;
        let previous_hash = parts[1].to_string();
        let entry_hash = parts[2].to_string();
        let encoded_update_hex = parts[3];
        let expected_hash =
            sha256_hex(format!("{index}|{previous_hash}|{encoded_update_hex}").as_bytes());
        if expected_hash != entry_hash {
            return Err(MembershipError::IntegrityMismatch);
        }
        let encoded_update_raw = hex_decode(encoded_update_hex)?;
        let encoded_update = String::from_utf8(encoded_update_raw).map_err(|_| {
            MembershipError::InvalidFormat("encoded update payload is not utf8".to_string())
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
    let mut state = snapshot.clone();
    let mut replay_cache = MembershipReplayCache {
        seen_update_ids: HashSet::new(),
        max_epoch: snapshot.epoch,
    };
    for entry in entries {
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
            "genesis".to_string()
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
                "duplicate signer id in update signatures".to_string(),
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
            .verify(payload, &signature_obj)
            .map_err(|_| MembershipError::SignatureInvalid)?;
    }

    if signed_update.record.operation.requires_owner_signer() && !owner_signed {
        return Err(MembershipError::OwnerSignatureRequired);
    }

    Ok(())
}

fn reduce_membership_state(
    state: &MembershipState,
    operation: &MembershipOperation,
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
            node.updated_at_unix = unix_now();
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
    let network_id = required_field(&fields, "network_id")?.to_string();
    let epoch = parse_u64_field(&fields, "epoch")?;
    let quorum_threshold = parse_u8_field(&fields, "quorum_threshold")?;
    let metadata_hash_raw = required_field(&fields, "metadata_hash")?.to_string();
    let metadata_hash = if metadata_hash_raw.is_empty() {
        None
    } else {
        Some(metadata_hash_raw)
    };
    let node_count = parse_usize_field(&fields, "node_count")?;
    let mut nodes = Vec::with_capacity(node_count);
    for index in 0..node_count {
        let node = MembershipNode {
            node_id: required_field(&fields, &format!("node.{index}.node_id"))?.to_string(),
            node_pubkey_hex: required_field(&fields, &format!("node.{index}.node_pubkey_hex"))?
                .to_string(),
            owner: required_field(&fields, &format!("node.{index}.owner"))?.to_string(),
            status: MembershipNodeStatus::parse(required_field(
                &fields,
                &format!("node.{index}.status"),
            )?)?,
            roles: split_csv(required_field(&fields, &format!("node.{index}.roles"))?),
            joined_at_unix: parse_u64_field(&fields, &format!("node.{index}.joined_at_unix"))?,
            updated_at_unix: parse_u64_field(&fields, &format!("node.{index}.updated_at_unix"))?,
        };
        nodes.push(node);
    }
    let approver_count = parse_usize_field(&fields, "approver_count")?;
    let mut approver_set = Vec::with_capacity(approver_count);
    for index in 0..approver_count {
        let approver = MembershipApprover {
            approver_id: required_field(&fields, &format!("approver.{index}.approver_id"))?
                .to_string(),
            approver_pubkey_hex: required_field(
                &fields,
                &format!("approver.{index}.approver_pubkey_hex"),
            )?
            .to_string(),
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
        .map_err(|_| MembershipError::InvalidFormat("update payload is not utf8".to_string()))?;
    let record = parse_membership_update_payload(&payload)?;

    let sig_count = parse_usize_field(&fields, "sig_count")?;
    let mut signatures = Vec::with_capacity(sig_count);
    for index in 0..sig_count {
        signatures.push(MembershipSignature {
            approver_id: required_field(&fields, &format!("sig.{index}.approver_id"))?.to_string(),
            signature_hex: required_field(&fields, &format!("sig.{index}.signature_hex"))?
                .to_string(),
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
            node_id: required_field(&fields, "op.node_id")?.to_string(),
            node_pubkey_hex: required_field(&fields, "op.node_pubkey_hex")?.to_string(),
            owner: required_field(&fields, "op.owner")?.to_string(),
            status: MembershipNodeStatus::parse(required_field(&fields, "op.status")?)?,
            roles: split_csv(required_field(&fields, "op.roles")?),
            joined_at_unix: parse_u64_field(&fields, "op.joined_at_unix")?,
            updated_at_unix: parse_u64_field(&fields, "op.updated_at_unix")?,
        }),
        "remove_node" => MembershipOperation::RemoveNode {
            node_id: required_field(&fields, "op.node_id")?.to_string(),
        },
        "revoke_node" => MembershipOperation::RevokeNode {
            node_id: required_field(&fields, "op.node_id")?.to_string(),
        },
        "restore_node" => MembershipOperation::RestoreNode {
            node_id: required_field(&fields, "op.node_id")?.to_string(),
        },
        "rotate_node_key" => MembershipOperation::RotateNodeKey {
            node_id: required_field(&fields, "op.node_id")?.to_string(),
            new_pubkey_hex: required_field(&fields, "op.new_pubkey_hex")?.to_string(),
        },
        "rotate_approver" => MembershipOperation::RotateApprover(MembershipApprover {
            approver_id: required_field(&fields, "op.approver_id")?.to_string(),
            approver_pubkey_hex: required_field(&fields, "op.approver_pubkey_hex")?.to_string(),
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

    let policy_context_raw = required_field(&fields, "policy_context")?.to_string();
    Ok(MembershipUpdateRecord {
        network_id: required_field(&fields, "network_id")?.to_string(),
        update_id: required_field(&fields, "update_id")?.to_string(),
        operation,
        target: required_field(&fields, "target")?.to_string(),
        prev_state_root: required_field(&fields, "prev_state_root")?.to_string(),
        new_state_root: required_field(&fields, "new_state_root")?.to_string(),
        epoch_prev: parse_u64_field(&fields, "epoch_prev")?,
        epoch_new: parse_u64_field(&fields, "epoch_new")?,
        created_at_unix: parse_u64_field(&fields, "created_at_unix")?,
        expires_at_unix: parse_u64_field(&fields, "expires_at_unix")?,
        reason_code: required_field(&fields, "reason_code")?.to_string(),
        policy_context: if policy_context_raw.is_empty() {
            None
        } else {
            Some(policy_context_raw)
        },
    })
}

fn atomic_write(path: &Path, body: &[u8], mode: u32) -> Result<(), MembershipError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| MembershipError::Io(err.to_string()))?;
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
        options.mode(mode);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| MembershipError::Io(err.to_string()))?;
    temp.write_all(body)
        .map_err(|err| MembershipError::Io(err.to_string()))?;
    temp.sync_all()
        .map_err(|err| MembershipError::Io(err.to_string()))?;
    fs::rename(&temp_path, path).map_err(|err| MembershipError::Io(err.to_string()))?;
    validate_membership_file_security(path, "membership state file")?;
    Ok(())
}

fn validate_membership_file_security(path: &Path, label: &str) -> Result<(), MembershipError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::metadata(path).map_err(|err| MembershipError::Io(err.to_string()))?;
        if !metadata.is_file() {
            return Err(MembershipError::InvalidFormat(format!(
                "{label} path is not a regular file"
            )));
        }
        let mode = metadata.mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(MembershipError::InvalidFormat(format!(
                "{label} permissions are too broad: {mode:o}"
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
    fields: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, MembershipError> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| MembershipError::InvalidFormat(format!("missing field {key}")))
}

fn parse_key_values(value: &str) -> Result<HashMap<String, String>, MembershipError> {
    let mut fields = HashMap::new();
    for line in value.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Some((key, field_value)) = line.split_once('=') else {
            return Err(MembershipError::InvalidFormat(
                "line missing key/value separator".to_string(),
            ));
        };
        if fields
            .insert(key.to_string(), field_value.to_string())
            .is_some()
        {
            return Err(MembershipError::InvalidFormat(format!(
                "duplicate field {key}"
            )));
        }
    }
    Ok(fields)
}

fn parse_u8_field(fields: &HashMap<String, String>, key: &str) -> Result<u8, MembershipError> {
    required_field(fields, key)?
        .parse::<u8>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid u8 field {key}")))
}

fn parse_u64_field(fields: &HashMap<String, String>, key: &str) -> Result<u64, MembershipError> {
    required_field(fields, key)?
        .parse::<u64>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid u64 field {key}")))
}

fn parse_usize_field(
    fields: &HashMap<String, String>,
    key: &str,
) -> Result<usize, MembershipError> {
    required_field(fields, key)?
        .parse::<usize>()
        .map_err(|_| MembershipError::InvalidFormat(format!("invalid usize field {key}")))
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_decode(encoded: &str) -> Result<Vec<u8>, MembershipError> {
    let trimmed = encoded.trim();
    if !trimmed.len().is_multiple_of(2) {
        return Err(MembershipError::InvalidFormat(
            "hex value has odd length".to_string(),
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
            "invalid hex character".to_string(),
        )),
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    hex_encode(digest.as_slice())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipError, MembershipNode, MembershipNodeStatus,
        MembershipOperation, MembershipReplayCache, MembershipState, MembershipUpdateRecord,
        SignedMembershipUpdate, append_membership_log_entry, apply_signed_update, hex_encode,
        load_membership_log, load_membership_snapshot, persist_membership_snapshot,
        replay_membership_snapshot_and_log, sign_update_record, write_membership_audit_log,
    };
    use ed25519_dalek::SigningKey;

    fn approver(id: &str, key_byte: u8, role: MembershipApproverRole) -> MembershipApprover {
        let signing = SigningKey::from_bytes(&[key_byte; 32]);
        MembershipApprover {
            approver_id: id.to_string(),
            approver_pubkey_hex: hex_encode(signing.verifying_key().as_bytes()),
            role,
            status: MembershipApproverStatus::Active,
            created_at_unix: 100,
        }
    }

    fn active_node(node_id: &str, pubkey_byte: u8) -> MembershipNode {
        MembershipNode {
            node_id: node_id.to_string(),
            node_pubkey_hex: hex_encode(&[pubkey_byte; 32]),
            owner: "owner@example.local".to_string(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_string()],
            joined_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn base_state() -> MembershipState {
        MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-1".to_string(),
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
            update_id: "update-1".to_string(),
            operation: MembershipOperation::SetQuorum { threshold: 2 },
            target: "quorum".to_string(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: state.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 101,
            expires_at_unix: 400,
            reason_code: "policy".to_string(),
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
            update_id: "update-add-node".to_string(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_string(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_string(),
            policy_context: Some("enrollment".to_string()),
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
            update_id: "update-replay".to_string(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_string(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 120,
            expires_at_unix: 600,
            reason_code: "join".to_string(),
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
            update_id: "update-log-1".to_string(),
            operation: MembershipOperation::AddNode(new_node),
            target: "node-b".to_string(),
            prev_state_root: state.state_root_hex().expect("root"),
            new_state_root: candidate.state_root_hex().expect("root"),
            epoch_prev: state.epoch,
            epoch_new: state.epoch + 1,
            created_at_unix: 130,
            expires_at_unix: 700,
            reason_code: "join".to_string(),
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

        let mut tampered = std::fs::read_to_string(&log).expect("log should read");
        tampered = tampered.replace("entry=0|", "entry=1|");
        std::fs::write(&log, tampered).expect("tampered log should write");
        let bad = load_membership_log(&log);
        assert!(bad.is_err());
    }
}
