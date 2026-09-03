#![allow(dead_code)]
use std::fmt;
use std::path::PathBuf;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::role::NodeRole;
use rustynet_control::roles::RoleCapability;
use serde::{Deserialize, Serialize};

// ── Domain value types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireguardPublicKey(pub String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeId(pub String);

#[derive(Debug, Clone)]
pub struct InstallReport {
    pub daemon_path: PathBuf,
    pub service_name: String,
}

#[derive(Debug, Clone)]
pub struct MembershipOwnerKey {
    pub public_key_pem: String,
}

#[derive(Debug, Clone)]
pub struct MembershipSnapshot {
    pub data: Vec<u8>,
}

/// What a node can publish into signed membership's `node_pubkey_hex`.
///
/// That field is contractually the node's derived GOSSIP verifying key, and a
/// node publishing anything else has its gossip rejected by every peer as an
/// unknown source. Deliberately has **no `Default`**: a node must state which of
/// these it is, so a platform cannot reach the aligned branch by omission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GossipIdentity {
    /// The node's real derived gossip verifying key.
    Published(String),
    /// This platform cannot produce a gossip identity yet, so it publishes its
    /// WireGuard key and its gossip stays dormant. Windows has no gossip
    /// transport at all; the lab macOS path never mints a secret.
    DeferredPlatform,
}

pub struct NodeMembershipPeer {
    pub alias: String,
    pub role: NodeRole,
    pub capabilities: Vec<RoleCapability>,
    pub node_id: String,
    pub public_key_hex: String,
    /// Kept ALONGSIDE `public_key_hex`, never replacing it: the WireGuard value
    /// still configures the real tunnel, while this one is what membership
    /// publishes.
    pub gossip_identity: GossipIdentity,
}

impl NodeMembershipPeer {
    pub fn is_valid_public_key_hex(value: &str) -> bool {
        value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelsList {
    pub tunnels: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficTestResult {
    Reachable,
    Blocked,
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BundleKind {
    Membership,
    Assignment,
    Traversal,
    DnsZone,
}

impl fmt::Display for BundleKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BundleKind::Membership => write!(f, "membership"),
            BundleKind::Assignment => write!(f, "assignment"),
            BundleKind::Traversal => write!(f, "traversal"),
            BundleKind::DnsZone => write!(f, "dns-zone"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatorReport {
    pub op_label: String,
    pub output: String,
    pub passed: bool,
    /// Every successfully parsed daemon report object, verbatim (§5.2 Item 2
    /// structured-drift evidence threading). Copied from
    /// `adapter::ssh::ValidatorVerdict.reports`; empty when the output
    /// contained no parseable JSON object.
    pub reports: Vec<serde_json::Value>,
}

// ── AdapterError ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum AdapterError {
    /// Platform not yet implemented. Message must name specific security barriers.
    UnsupportedPlatform {
        platform: VmGuestPlatform,
        message: String,
    },
    /// Connection type incompatible with platform (e.g. Adb for Linux).
    ConnectionPlatformMismatch {
        platform: VmGuestPlatform,
        connection_kind: &'static str,
    },
    /// SSH transport error.
    Ssh { message: String },
    /// I/O error.
    Io { message: String },
    /// Remote command failed.
    Command {
        exit_code: Option<i32>,
        stderr: String,
    },
    /// Path validation failed at construction.
    InvalidPath { path: PathBuf, reason: String },
    /// Protocol-level error (e.g. parse failure, unexpected output).
    Protocol { message: String },
    /// Key material found in artifact archive — security invariant violation.
    KeyExclusionViolation { path: String },
}

impl fmt::Display for AdapterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdapterError::UnsupportedPlatform { platform, message } => {
                write!(f, "platform {platform:?} not supported: {message}")
            }
            AdapterError::ConnectionPlatformMismatch {
                platform,
                connection_kind,
            } => {
                write!(
                    f,
                    "connection type '{connection_kind}' is not valid for platform {platform:?}"
                )
            }
            AdapterError::Ssh { message } => write!(f, "SSH error: {message}"),
            AdapterError::Io { message } => write!(f, "I/O error: {message}"),
            AdapterError::Command { exit_code, stderr } => {
                write!(f, "remote command failed (exit {exit_code:?}): {stderr}")
            }
            AdapterError::InvalidPath { path, reason } => {
                write!(f, "invalid path '{}': {reason}", path.display())
            }
            AdapterError::Protocol { message } => write!(f, "protocol error: {message}"),
            AdapterError::KeyExclusionViolation { path } => {
                write!(
                    f,
                    "key material found in artifact archive at '{path}': key-exclusion invariant violated"
                )
            }
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<std::io::Error> for AdapterError {
    fn from(e: std::io::Error) -> Self {
        AdapterError::Io {
            message: e.to_string(),
        }
    }
}

// ── StageError + StageOutcome ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum StageError {
    AdapterFailure { alias: String, message: String },
    DependencyFailed { dependency: String },
    ValidationFailed { details: String },
    Io { message: String },
}

impl fmt::Display for StageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StageError::AdapterFailure { alias, message } => {
                write!(f, "adapter failure for '{alias}': {message}")
            }
            StageError::DependencyFailed { dependency } => {
                write!(f, "dependency '{dependency}' failed or was skipped")
            }
            StageError::ValidationFailed { details } => {
                write!(f, "validation failed: {details}")
            }
            StageError::Io { message } => write!(f, "I/O error: {message}"),
        }
    }
}

impl std::error::Error for StageError {}

/// Typed classification for a [`StageOutcome::NotProven`]. The code is the
/// classification that drives remediation and evidence accounting; a free-form
/// detail string is supporting context only, never the classification (an
/// `Option`-of-string would have arrived empty the first time someone was in a
/// hurry, exactly the failure `Skipped`'s mandatory payload was added to
/// prevent). Each variant is a *distinct* remediation:
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    /// A required witness/observation was never produced (fix: run the probe).
    MissingWitness,
    /// Evidence exists but cannot be attributed to the intended node or run
    /// instance — wrong node id, or a foreign/prior generation (fix: bind it).
    Unattributable,
    /// Evidence exists but belongs to a prior run generation and is stale for
    /// this invocation (fix: re-run producing current-generation evidence).
    StaleEvidence,
    /// Evidence exists but could not be read or parsed (fix: repair the
    /// producer/schema).
    UnreadableEvidence,
    /// Two independent witnesses disagree (fix: resolve which is authoritative).
    ContradictoryEvidence,
    /// A fault was requested but its application could not be independently
    /// verified — unverified fault application is never a pass (fix: prove the
    /// fault took effect).
    FaultUnverified,
    /// A capability required by a release-selected cell is absent. Distinct from
    /// `Skipped`, which asserts the *profile* legitimately does not claim the
    /// scenario; here the release cell DOES claim it and it is missing.
    RequiredCapabilityAbsent,
}

impl ReasonCode {
    /// Stable snake_case token recorded verbatim into evidence artifacts
    /// (TSV/JSON/CSV) and parsed back by the verifier. Never localize.
    pub fn as_str(self) -> &'static str {
        match self {
            ReasonCode::MissingWitness => "missing_witness",
            ReasonCode::Unattributable => "unattributable",
            ReasonCode::StaleEvidence => "stale_evidence",
            ReasonCode::UnreadableEvidence => "unreadable_evidence",
            ReasonCode::ContradictoryEvidence => "contradictory_evidence",
            ReasonCode::FaultUnverified => "fault_unverified",
            ReasonCode::RequiredCapabilityAbsent => "required_capability_absent",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    Passed,
    Failed(String),
    /// Not executed, with the reason WHY — which is the whole point of the
    /// payload.
    ///
    /// `Failed` has always explained itself and `Skipped` never did, so a run
    /// reporting 33 skips gave no way to tell "no node was assigned this role"
    /// (fix: elect a role) from "its platform is absent" (fix: add a guest)
    /// from "a dependency never passed" (fix: upstream, and the skip is a
    /// cascade) from "unsupported on this backend" (not fixable) from
    /// "the operator excluded it". Those have completely different remedies and
    /// three of them looked identical in the evidence.
    ///
    /// The payload is mandatory rather than optional precisely so an
    /// unexplained skip cannot be written: an `Option` would be `None` the first
    /// time someone was in a hurry, which is how the field arrived empty on
    /// 33 of 33 stages.
    Skipped(String),
    /// Deliberately not executed in this invocation. Unlike `Skipped`, this is
    /// an operator-selected focused-run omission and blocks dependencies.
    NotRun,
    /// Satisfied by a terminal pass from a prior report whose evidence digest
    /// was validated before execution. Never rendered as a fresh pass.
    Reused {
        evidence_sha256: String,
    },
    /// A required observation is missing or unattributable, so the stage's
    /// exact claim could not be proven. Distinct from `Skipped` (which asserts
    /// the scenario is outside the selected profile) and from `Failed` (which
    /// disproves an invariant): `NotProven` says "we do not know", and that is
    /// a **blocking** non-pass that must never be converted to skip or pass.
    /// The typed `ReasonCode` is the classification; `detail` is supporting
    /// context only.
    NotProven {
        reason: ReasonCode,
        detail: String,
    },
}

impl StageOutcome {
    pub fn is_blocking(&self) -> bool {
        matches!(
            self,
            StageOutcome::Failed(_) | StageOutcome::NotRun | StageOutcome::NotProven { .. }
        )
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            StageOutcome::Passed
                | StageOutcome::Failed(_)
                | StageOutcome::Skipped(..)
                | StageOutcome::NotRun
                | StageOutcome::Reused { .. }
                | StageOutcome::NotProven { .. }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn not_proven(reason: ReasonCode) -> StageOutcome {
        StageOutcome::NotProven {
            reason,
            detail: String::new(),
        }
    }

    #[test]
    fn not_proven_is_a_blocking_terminal_non_pass() {
        let np = not_proven(ReasonCode::MissingWitness);
        // Blocking: a NotProven prerequisite must cascade-block dependents,
        // exactly like Failed/NotRun — never like Skipped (which does not block).
        assert!(np.is_blocking(), "NotProven must block dependents");
        assert!(np.is_terminal(), "NotProven is a terminal state");
        // It is NOT a pass and NOT a skip.
        assert!(!matches!(np, StageOutcome::Passed));
        // Skipped is deliberately non-blocking; NotProven must not be confused
        // with it — a regression that made NotProven non-blocking would let an
        // evidence gap silently satisfy a truth prerequisite.
        assert!(!StageOutcome::Skipped("out of profile".into()).is_blocking());
    }

    #[test]
    fn reason_code_tokens_are_stable_and_distinct() {
        // These tokens are written into TSV/JSON/CSV evidence and parsed back
        // by the verifier; a silent rename would orphan historical evidence.
        let all = [
            (ReasonCode::MissingWitness, "missing_witness"),
            (ReasonCode::Unattributable, "unattributable"),
            (ReasonCode::StaleEvidence, "stale_evidence"),
            (ReasonCode::UnreadableEvidence, "unreadable_evidence"),
            (ReasonCode::ContradictoryEvidence, "contradictory_evidence"),
            (ReasonCode::FaultUnverified, "fault_unverified"),
            (
                ReasonCode::RequiredCapabilityAbsent,
                "required_capability_absent",
            ),
        ];
        for (code, token) in all {
            assert_eq!(code.as_str(), token);
        }
        // All tokens distinct.
        let mut seen = std::collections::HashSet::new();
        for (code, _) in all {
            assert!(seen.insert(code.as_str()), "duplicate reason token");
        }
    }
}
