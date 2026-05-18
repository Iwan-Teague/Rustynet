#![allow(dead_code)]
use std::fmt;
use std::path::PathBuf;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::role::NodeRole;

// ── Domain value types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeMembershipPeer {
    pub alias: String,
    pub role: NodeRole,
    pub node_id: String,
    pub public_key_hex: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    Passed,
    Failed(String),
    Skipped,
}

impl StageOutcome {
    pub fn is_blocking(&self) -> bool {
        matches!(self, StageOutcome::Failed(_))
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            StageOutcome::Passed | StageOutcome::Failed(_) | StageOutcome::Skipped
        )
    }
}
