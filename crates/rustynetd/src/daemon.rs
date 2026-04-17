#![forbid(unsafe_code)]
#![allow(clippy::collapsible_if)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
#[cfg(target_os = "linux")]
use std::net::SocketAddrV4;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize};
#[cfg(not(windows))]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
#[cfg(not(windows))]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::ipc::{
    CommandEnvelope, IpcCommand, IpcResponse, RemoteCommandEnvelope,
    read_command_envelope as ipc_read_command_envelope, validate_cidr,
};
#[cfg(target_os = "macos")]
use crate::key_material::read_passphrase_file;
use crate::key_material::{
    apply_interface_private_key, decrypt_private_key, encrypt_private_key,
    generate_wireguard_keypair, remove_file_if_present, set_interface_down, write_public_key,
    write_runtime_private_key,
};
#[cfg(target_os = "macos")]
use crate::phase10::MacosCommandSystem;
use crate::phase10::{
    ApplyOptions, DataplaneState, DataplaneSystem, ManagementCidr, PathMode, Phase10Controller,
    RouteGrantRequest, RuntimeSystem, TraversalProbeDecision, TraversalProbeEvaluation,
    TraversalProbeReason, TrustEvidence, TrustPolicy,
};
#[cfg(target_os = "linux")]
use crate::phase10::{LinuxCommandSystem, LinuxDataplaneMode};
use crate::privileged_helper::{
    DEFAULT_PRIVILEGED_HELPER_SOCKET_PATH as HELPER_DEFAULT_SOCKET_PATH,
    DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS as HELPER_DEFAULT_TIMEOUT_MS, PrivilegedCommandClient,
    PrivilegedCommandProgram,
};
use crate::relay_client::{RelayClient, RelayClientConfig, RelayClientError};
use crate::resilience::{
    ResilienceError, SessionStateSnapshot, load_session_snapshot, persist_session_snapshot,
};
use crate::stun_client::{StunClient, StunResult, StunTransportRoundTrip};
use crate::traversal::{
    CandidateSource as ProbeCandidateSource, CoordinationReplayWindow, CoordinationSchedule,
    DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES as TRAVERSAL_DEFAULT_MAX_CANDIDATES,
    DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS as TRAVERSAL_DEFAULT_MAX_PAIRS,
    DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES as TRAVERSAL_DEFAULT_RELAY_SWITCH_AFTER_FAILURES,
    DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS as TRAVERSAL_DEFAULT_ROUND_SPACING_MS,
    DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS as TRAVERSAL_DEFAULT_SIMULTANEOUS_ROUNDS,
    DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS as TRAVERSAL_DEFAULT_STUN_GATHER_TIMEOUT_MS,
    EndpointMonitor, TraversalCandidate as ProbeTraversalCandidate, TraversalEngine,
    TraversalEngineConfig, VerifiedTraversalIndex, VerifiedTraversalRecord,
};
use crate::windows_backend_gate::{
    WINDOWS_UNSUPPORTED_BACKEND_LABEL, WindowsBackendMode, require_supported_windows_backend,
};
#[cfg(windows)]
use crate::windows_ipc::{
    DEFAULT_WINDOWS_DAEMON_PIPE_PATH, WindowsLocalIpcRole, validate_windows_pipe_path,
    windows_ipc_blocker_reason,
};
#[cfg(windows)]
use crate::windows_paths::{
    DEFAULT_WINDOWS_AUTO_TUNNEL_BUNDLE_PATH, DEFAULT_WINDOWS_AUTO_TUNNEL_VERIFIER_KEY_PATH,
    DEFAULT_WINDOWS_AUTO_TUNNEL_WATERMARK_PATH, DEFAULT_WINDOWS_DNS_ZONE_BUNDLE_PATH,
    DEFAULT_WINDOWS_DNS_ZONE_VERIFIER_KEY_PATH, DEFAULT_WINDOWS_DNS_ZONE_WATERMARK_PATH,
    DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH, DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH,
    DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH, DEFAULT_WINDOWS_MEMBERSHIP_WATERMARK_PATH,
    DEFAULT_WINDOWS_STATE_PATH, DEFAULT_WINDOWS_TRAVERSAL_BUNDLE_PATH,
    DEFAULT_WINDOWS_TRAVERSAL_VERIFIER_KEY_PATH, DEFAULT_WINDOWS_TRAVERSAL_WATERMARK_PATH,
    DEFAULT_WINDOWS_TRUST_EVIDENCE_PATH, DEFAULT_WINDOWS_TRUST_VERIFIER_KEY_PATH,
    DEFAULT_WINDOWS_TRUST_WATERMARK_PATH, DEFAULT_WINDOWS_WG_ENCRYPTED_PRIVATE_KEY_PATH,
    DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH, DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH,
    DEFAULT_WINDOWS_WG_RUNTIME_PRIVATE_KEY_PATH, validate_windows_runtime_file_path,
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
#[cfg(target_os = "linux")]
use nix::ifaddrs;
#[cfg(not(windows))]
use nix::sys::socket::getsockopt;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "visionos"
))]
use nix::sys::socket::sockopt::LocalPeerCred;
#[cfg(any(target_os = "linux", target_os = "android"))]
use nix::sys::socket::sockopt::PeerCredentials;
#[cfg(not(windows))]
use nix::unistd::{Gid, Uid};
use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RouteKind,
    RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};
use rustynet_backend_wireguard::LinuxUserspaceSharedBackend;
#[cfg(target_os = "linux")]
use rustynet_backend_wireguard::LinuxWireguardBackend;
#[cfg(target_os = "macos")]
use rustynet_backend_wireguard::MacosWireguardBackend;
#[cfg(test)]
use rustynet_backend_wireguard::RecordedAuthoritativeTransportOperation;
use rustynet_backend_wireguard::WireguardBackend;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use rustynet_backend_wireguard::{WireguardCommandOutput, WireguardCommandRunner};
use rustynet_control::membership::{
    MembershipNodeStatus, MembershipState, load_membership_log, load_membership_snapshot,
    replay_membership_snapshot_and_log,
};
use rustynet_control::{SignedTraversalCoordinationRecord, derive_endpoint_hint_signing_key};
use rustynet_dns_zone::{
    DnsZoneError, DnsZoneWatermark, SignedDnsZoneBundle as DnsZoneBundle,
    canonicalize_dns_zone_name, dns_zone_payload_digest, dns_zone_watermark_ordering,
    parse_dns_zone_verifying_key, parse_signed_dns_zone_bundle_wire,
    verify_signed_dns_zone_bundle as verify_dns_zone_bundle,
};
use rustynet_policy::{
    ContextualAccessRequest, ContextualPolicyRule, ContextualPolicySet, Decision,
    MembershipDirectory, MembershipStatus, Protocol, RuleAction, TrafficContext,
};
use sha2::{Digest, Sha256};

#[cfg(not(windows))]
pub const DEFAULT_SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
#[cfg(windows)]
pub const DEFAULT_SOCKET_PATH: &str = DEFAULT_WINDOWS_DAEMON_PIPE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";
#[cfg(windows)]
pub const DEFAULT_STATE_PATH: &str = DEFAULT_WINDOWS_STATE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_TRUST_EVIDENCE_PATH: &str = "/var/lib/rustynet/rustynetd.trust";
#[cfg(windows)]
pub const DEFAULT_TRUST_EVIDENCE_PATH: &str = DEFAULT_WINDOWS_TRUST_EVIDENCE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_TRUST_VERIFIER_KEY_PATH: &str = "/etc/rustynet/trust-evidence.pub";
#[cfg(windows)]
pub const DEFAULT_TRUST_VERIFIER_KEY_PATH: &str = DEFAULT_WINDOWS_TRUST_VERIFIER_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_TRUST_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.trust.watermark";
#[cfg(windows)]
pub const DEFAULT_TRUST_WATERMARK_PATH: &str = DEFAULT_WINDOWS_TRUST_WATERMARK_PATH;
#[cfg(not(windows))]
pub const DEFAULT_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
#[cfg(windows)]
pub const DEFAULT_MEMBERSHIP_SNAPSHOT_PATH: &str = DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH;
#[cfg(not(windows))]
pub const DEFAULT_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
#[cfg(windows)]
pub const DEFAULT_MEMBERSHIP_LOG_PATH: &str = DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH;
#[cfg(not(windows))]
pub const DEFAULT_MEMBERSHIP_WATERMARK_PATH: &str = "/var/lib/rustynet/membership.watermark";
#[cfg(windows)]
pub const DEFAULT_MEMBERSHIP_WATERMARK_PATH: &str = DEFAULT_WINDOWS_MEMBERSHIP_WATERMARK_PATH;
#[cfg(not(windows))]
pub const DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH: &str = "/etc/rustynet/membership.owner.key";
#[cfg(windows)]
pub const DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH: &str =
    DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_AUTO_TUNNEL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
#[cfg(windows)]
pub const DEFAULT_AUTO_TUNNEL_BUNDLE_PATH: &str = DEFAULT_WINDOWS_AUTO_TUNNEL_BUNDLE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH: &str = "/etc/rustynet/assignment.pub";
#[cfg(windows)]
pub const DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH: &str =
    DEFAULT_WINDOWS_AUTO_TUNNEL_VERIFIER_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_AUTO_TUNNEL_WATERMARK_PATH: &str =
    "/var/lib/rustynet/rustynetd.assignment.watermark";
#[cfg(windows)]
pub const DEFAULT_AUTO_TUNNEL_WATERMARK_PATH: &str = DEFAULT_WINDOWS_AUTO_TUNNEL_WATERMARK_PATH;
pub const DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS: u64 = 300;
const ASSIGNMENT_SIGNING_SECRET_ENV: &str = "RUSTYNET_ASSIGNMENT_SIGNING_SECRET";
const ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV: &str =
    "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE";
#[cfg(not(windows))]
pub const DEFAULT_TRAVERSAL_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.traversal";
#[cfg(windows)]
pub const DEFAULT_TRAVERSAL_BUNDLE_PATH: &str = DEFAULT_WINDOWS_TRAVERSAL_BUNDLE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH: &str = "/etc/rustynet/traversal.pub";
#[cfg(windows)]
pub const DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH: &str = DEFAULT_WINDOWS_TRAVERSAL_VERIFIER_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_TRAVERSAL_WATERMARK_PATH: &str =
    "/var/lib/rustynet/rustynetd.traversal.watermark";
#[cfg(windows)]
pub const DEFAULT_TRAVERSAL_WATERMARK_PATH: &str = DEFAULT_WINDOWS_TRAVERSAL_WATERMARK_PATH;
pub const DEFAULT_TRAVERSAL_MAX_AGE_SECS: u64 = 120;
const DEFAULT_RELAY_SESSION_TOKEN_TTL_SECS: u64 = 120;
const DEFAULT_RELAY_SESSION_REFRESH_MARGIN_SECS: u64 = 15;
const DEFAULT_RELAY_SESSION_IDLE_TIMEOUT_SECS: u64 = 30;
#[cfg(not(windows))]
pub const DEFAULT_DNS_ZONE_BUNDLE_PATH: &str = "/var/lib/rustynet/rustynetd.dns-zone";
#[cfg(windows)]
pub const DEFAULT_DNS_ZONE_BUNDLE_PATH: &str = DEFAULT_WINDOWS_DNS_ZONE_BUNDLE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH: &str = "/etc/rustynet/dns-zone.pub";
#[cfg(windows)]
pub const DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH: &str = DEFAULT_WINDOWS_DNS_ZONE_VERIFIER_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_DNS_ZONE_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.dns-zone.watermark";
#[cfg(windows)]
pub const DEFAULT_DNS_ZONE_WATERMARK_PATH: &str = DEFAULT_WINDOWS_DNS_ZONE_WATERMARK_PATH;
pub const DEFAULT_DNS_ZONE_MAX_AGE_SECS: u64 = 300;
pub const DEFAULT_DNS_ZONE_NAME: &str = "rustynet";
pub const DEFAULT_DNS_RESOLVER_BIND_ADDR: &str = "127.0.0.1:53535";
pub const DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES: usize = TRAVERSAL_DEFAULT_MAX_CANDIDATES;
pub const DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS: usize = TRAVERSAL_DEFAULT_MAX_PAIRS;
pub const DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS: u8 =
    TRAVERSAL_DEFAULT_SIMULTANEOUS_ROUNDS;
pub const DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS: u64 = TRAVERSAL_DEFAULT_ROUND_SPACING_MS;
pub const DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES: u8 =
    TRAVERSAL_DEFAULT_RELAY_SWITCH_AFTER_FAILURES;
pub const DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS: u64 = TRAVERSAL_DEFAULT_STUN_GATHER_TIMEOUT_MS;
pub const DEFAULT_TRAVERSAL_STUN_GATHER_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS: u64 = 30;
pub const DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS: u64 = 30;
#[cfg(any(target_os = "linux", test))]
#[cfg_attr(test, allow(dead_code))]
const TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_ATTEMPTS: usize = 10;
#[cfg(any(target_os = "linux", test))]
const TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_DELAY_MS: u64 = 100;
pub const DEFAULT_WG_INTERFACE: &str = "rustynet0";
pub const DEFAULT_WG_LISTEN_PORT: u16 = 51820;
#[cfg(not(windows))]
pub const DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH: &str = "/run/rustynet/wireguard.key";
#[cfg(windows)]
pub const DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH: &str = DEFAULT_WINDOWS_WG_RUNTIME_PRIVATE_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.key.enc";
#[cfg(windows)]
pub const DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str =
    DEFAULT_WINDOWS_WG_ENCRYPTED_PRIVATE_KEY_PATH;
#[cfg(not(windows))]
pub const DEFAULT_WG_KEY_PASSPHRASE_PATH: &str = "/var/lib/rustynet/keys/wireguard.passphrase";
#[cfg(windows)]
pub const DEFAULT_WG_KEY_PASSPHRASE_PATH: &str = DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH;
#[cfg(not(windows))]
pub const DEFAULT_WG_PUBLIC_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";
#[cfg(windows)]
pub const DEFAULT_WG_PUBLIC_KEY_PATH: &str = DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH;
pub const DEFAULT_EGRESS_INTERFACE: &str = "auto";
pub const DEFAULT_RECONCILE_INTERVAL_MS: u64 = 1_000;
pub const DEFAULT_MAX_RECONCILE_FAILURES: u32 = 5;
pub const DEFAULT_AUTO_PORT_FORWARD_EXIT: bool = false;
pub const DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS: u32 = 1_200;
pub const DEFAULT_NODE_ID: &str = "daemon-local";
pub const DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT: &str = "user:local";
pub const DEFAULT_FAIL_CLOSED_SSH_ALLOW: bool = false;
pub const DEFAULT_TRUST_MAX_AGE_SECS: u64 = 300;
pub const DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS: u64 = 300;
pub const DEFAULT_TRUSTED_HELPER_SOCKET_PATH: &str = HELPER_DEFAULT_SOCKET_PATH;
pub const DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS: u64 = HELPER_DEFAULT_TIMEOUT_MS;
const BLIND_EXIT_DEFAULT_ROUTE_CIDR: &str = "0.0.0.0/0";
const MAX_BUNDLE_VERIFIER_KEY_BYTES: usize = 4 * 1024;
const MAX_TRUST_EVIDENCE_BYTES: usize = 8 * 1024;
const MAX_TRUST_EVIDENCE_LINES: usize = 32;
const MAX_TRUST_EVIDENCE_LINE_BYTES: usize = 512;
const MAX_TRUST_EVIDENCE_KEY_BYTES: usize = 64;
const MAX_TRUST_EVIDENCE_VALUE_BYTES: usize = 256;
const MAX_TRUST_EVIDENCE_KEY_DEPTH: usize = 1;
const MAX_AUTO_TUNNEL_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_AUTO_TUNNEL_BUNDLE_LINES: usize = 4_096;
const MAX_AUTO_TUNNEL_LINE_BYTES: usize = 2_048;
const MAX_AUTO_TUNNEL_KEY_BYTES: usize = 64;
const MAX_AUTO_TUNNEL_VALUE_BYTES: usize = 1_536;
const MAX_AUTO_TUNNEL_KEY_DEPTH: usize = 3;
const MAX_AUTO_TUNNEL_FIELD_COUNT: usize = 3_072;
const MAX_AUTO_TUNNEL_PEER_COUNT: usize = 128;
const MAX_AUTO_TUNNEL_ROUTE_COUNT: usize = 256;
const MAX_DNS_ZONE_BUNDLE_BYTES: usize = 256 * 1024;
const MAX_TRAVERSAL_BUNDLE_BYTES: usize = 64 * 1024;
const MAX_TRAVERSAL_BUNDLE_LINES: usize = 1_024;
const MAX_TRAVERSAL_LINE_BYTES: usize = 1_024;
const MAX_TRAVERSAL_KEY_BYTES: usize = 64;
const MAX_TRAVERSAL_VALUE_BYTES: usize = 512;
const MAX_TRAVERSAL_KEY_DEPTH: usize = 3;
const MAX_TRAVERSAL_FIELD_COUNT: usize = 1_024;
const MAX_TRAVERSAL_CANDIDATE_COUNT: usize = 8;
const MAX_TRAVERSAL_BUNDLE_ENTRY_COUNT: usize = MAX_AUTO_TUNNEL_PEER_COUNT * 2;
const MAX_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS: u8 = 8;
const MAX_TRAVERSAL_PROBE_ROUND_SPACING_MS: u64 = 5_000;
const MAX_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES: u8 = 16;
const MAX_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS: u64 = 3_600;
const MIN_DNS_ZONE_REFRESH_MARGIN_SECS: u64 = 30;
const MIN_DNS_ZONE_REFRESH_COOLDOWN_SECS: u64 = 10;
const MAX_DNS_ZONE_REFRESH_JITTER_SECS: u64 = 45;
const MIN_TRAVERSAL_REFRESH_MARGIN_SECS: u64 = 15;
const MIN_TRAVERSAL_REFRESH_COOLDOWN_SECS: u64 = 5;
const MIN_ENDPOINT_CHANGE_STABILITY_SECS: u64 = 10;
const MAX_TRAVERSAL_REFRESH_JITTER_SECS: u64 = 30;

// Minimal network-based signed state fetcher (B1 - pull based). This implements a
// conservative pull path: if a URL environment variable is provided for a state
// artifact, attempt a minimal HTTP GET, verify the returned artifact using the
// existing verification functions, and only persist watermark after success.
// If the endpoint is not configured or the network is unreachable, fall back to
// existing disk-based behavior (do not fail). Any signature/freshness/watermark
// verification failure is treated as a hard error and will be returned.

#[derive(Debug, PartialEq, Eq)]
pub enum FetchDecision {
    Skipped, // endpoint not configured or network unreachable -> fallback to disk
    Applied, // fetched and verified; persisted
}

pub struct StateFetcher {
    // The daemon paths are passed in for verifier keys and watermark locations.
    trust_verifier_key_path: PathBuf,
    trust_watermark_path: PathBuf,
    trust_evidence_path: PathBuf,
    traversal_verifier_key_path: PathBuf,
    traversal_watermark_path: PathBuf,
    traversal_bundle_path: PathBuf,
    assignment_verifier_key_path: Option<PathBuf>,
    assignment_watermark_path: Option<PathBuf>,
    assignment_bundle_path: Option<PathBuf>,
    dns_zone_verifier_key_path: PathBuf,
    dns_zone_watermark_path: PathBuf,
    dns_zone_bundle_path: PathBuf,
    dns_zone_max_age_secs: NonZeroU64,
    dns_zone_name: String,
    local_node_id: String,
    _auto_tunnel_enforce: bool,
    trust_url: Option<String>,
    traversal_url: Option<String>,
    assignment_url: Option<String>,
    dns_zone_url: Option<String>,
}

impl StateFetcher {
    pub fn new_from_daemon(cfg: &DaemonConfig) -> Self {
        Self {
            trust_verifier_key_path: PathBuf::from(&cfg.trust_verifier_key_path),
            trust_watermark_path: PathBuf::from(&cfg.trust_watermark_path),
            trust_evidence_path: PathBuf::from(&cfg.trust_evidence_path),
            traversal_verifier_key_path: PathBuf::from(&cfg.traversal_verifier_key_path),
            traversal_watermark_path: PathBuf::from(&cfg.traversal_watermark_path),
            traversal_bundle_path: PathBuf::from(&cfg.traversal_bundle_path),
            assignment_verifier_key_path: cfg.auto_tunnel_verifier_key_path.clone(),
            assignment_watermark_path: cfg.auto_tunnel_watermark_path.clone(),
            assignment_bundle_path: cfg.auto_tunnel_bundle_path.clone(),
            dns_zone_verifier_key_path: PathBuf::from(&cfg.dns_zone_verifier_key_path),
            dns_zone_watermark_path: PathBuf::from(&cfg.dns_zone_watermark_path),
            dns_zone_bundle_path: PathBuf::from(&cfg.dns_zone_bundle_path),
            dns_zone_max_age_secs: cfg.dns_zone_max_age_secs,
            dns_zone_name: cfg.dns_zone_name.clone(),
            local_node_id: cfg.node_id.clone(),
            _auto_tunnel_enforce: cfg.auto_tunnel_enforce,
            // Hardened daemon paths only consume pinned local custody artifacts.
            trust_url: None,
            traversal_url: None,
            assignment_url: None,
            dns_zone_url: None,
        }
    }

    // Minimal HTTP GET using TcpStream. Returns Ok(body_bytes) on success, Err on network error.
    fn http_get_raw(url: &str) -> Result<Vec<u8>, String> {
        // Expect form: http://host[:port]/path
        let url = url.trim();
        if !url.starts_with("http://") {
            return Err("only http:// URLs are supported in this minimal fetcher".to_string());
        }
        let without_proto = &url[7..];
        let parts: Vec<&str> = without_proto.splitn(2, '/').collect();
        let host_port = parts.first().ok_or_else(|| "invalid url".to_string())?;
        let path = format!("/{}", parts.get(1).unwrap_or(&""));
        let mut host = host_port.to_string();
        let mut port = 80u16;
        if host_port.contains(':') {
            let mut hp = host_port.splitn(2, ':');
            host = hp.next().unwrap_or("").to_string();
            if let Some(p) = hp.next() {
                port = p
                    .parse::<u16>()
                    .map_err(|_| "invalid port in url".to_string())?;
            }
        }
        let addr = format!("{host}:{port}");
        let mut stream = match std::net::TcpStream::connect_timeout(
            &addr
                .to_socket_addrs()
                .map_err(|_| "resolve failed".to_string())?
                .next()
                .ok_or_else(|| "resolve returned no addresses".to_string())?,
            Duration::from_secs(3),
        ) {
            Ok(s) => s,
            Err(_) => return Err("network unreachable".to_string()),
        };
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .map_err(|_| "write to socket failed".to_string())?;
        let mut buf = Vec::new();
        stream
            .read_to_end(&mut buf)
            .map_err(|_| "read from socket failed".to_string())?;
        // Very minimal HTTP response parsing: look for \r\n\r\n and take the rest as body.
        if let Some(idx) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let body = buf.split_off(idx + 4);
            Ok(body)
        } else {
            Err("malformed http response".to_string())
        }
    }

    pub fn fetch_trust(&self) -> Result<FetchDecision, String> {
        if let Some(url) = &self.trust_url {
            match Self::http_get_raw(url.as_str()) {
                Ok(body) => {
                    let tmp = write_secure_staged_artifact(
                        &self.trust_evidence_path,
                        &body,
                        "trust evidence",
                    )?;

                    // Load previous watermark (may be missing)
                    let previous_watermark = match load_trust_watermark(&self.trust_watermark_path)
                    {
                        Ok(val) => val,
                        Err(err) => return Err(format!("read previous watermark failed: {err}")),
                    };

                    // Use the existing loading/verification routine which enforces signature, age, clock skew, and replay checks.
                    match load_trust_evidence(
                        &tmp,
                        &self.trust_verifier_key_path,
                        TrustPolicy {
                            max_signed_data_age_secs: DEFAULT_TRUST_MAX_AGE_SECS,
                            max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
                        },
                        previous_watermark,
                    ) {
                        Ok(envelope) => {
                            // Atomically persist artifact then persist watermark only after full validation success
                            std::fs::rename(&tmp, &self.trust_evidence_path)
                                .map_err(|e| format!("persist trust evidence failed: {e}"))?;
                            persist_trust_watermark(&self.trust_watermark_path, envelope.watermark)
                                .map_err(|e| format!("persist trust watermark failed: {e}"))?;
                            eprintln!(
                                "statefetch: applied trust bundle: nonce={}",
                                envelope.watermark.nonce
                            );
                            Ok(FetchDecision::Applied)
                        }
                        Err(err) => {
                            let _ = fs::remove_file(&tmp);
                            Err(format!("trust fetch verification failed: {err}"))
                        }
                    }
                }
                Err(_network_err) => Ok(FetchDecision::Skipped),
            }
        } else {
            Ok(FetchDecision::Skipped)
        }
    }

    pub fn fetch_traversal(&self) -> Result<FetchDecision, String> {
        if let Some(url) = &self.traversal_url {
            match Self::http_get_raw(url.as_str()) {
                Ok(body) => {
                    let tmp = write_secure_staged_artifact(
                        &self.traversal_bundle_path,
                        &body,
                        "traversal bundle",
                    )?;

                    let previous_watermark =
                        match load_traversal_watermark(&self.traversal_watermark_path) {
                            Ok(val) => val,
                            Err(err) => {
                                return Err(format!(
                                    "read previous traversal watermark failed: {err}"
                                ));
                            }
                        };

                    match load_traversal_bundle_set(
                        &tmp,
                        &self.traversal_verifier_key_path,
                        DEFAULT_TRAVERSAL_MAX_AGE_SECS,
                        TrustPolicy {
                            max_signed_data_age_secs: DEFAULT_TRAVERSAL_MAX_AGE_SECS,
                            max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
                        },
                        previous_watermark,
                    ) {
                        Ok(envelope) => {
                            std::fs::rename(&tmp, &self.traversal_bundle_path)
                                .map_err(|e| format!("persist traversal bundle failed: {e}"))?;
                            persist_traversal_watermark(
                                &self.traversal_watermark_path,
                                envelope.watermark,
                            )
                            .map_err(|e| format!("persist traversal watermark failed: {e}"))?;
                            eprintln!(
                                "statefetch: applied traversal bundle: nonce={}",
                                envelope.watermark.nonce
                            );
                            Ok(FetchDecision::Applied)
                        }
                        Err(err) => {
                            let _ = fs::remove_file(&tmp);
                            Err(format!("traversal fetch verification failed: {err}"))
                        }
                    }
                }
                Err(_network_err) => Ok(FetchDecision::Skipped),
            }
        } else {
            Ok(FetchDecision::Skipped)
        }
    }

    pub fn fetch_assignment(&self) -> Result<FetchDecision, String> {
        if let Some(url) = &self.assignment_url {
            // require assignment paths configured
            let bundle_path = match &self.assignment_bundle_path {
                Some(p) => p,
                None => return Ok(FetchDecision::Skipped),
            };
            let verifier_path = match &self.assignment_verifier_key_path {
                Some(p) => p,
                None => return Ok(FetchDecision::Skipped),
            };
            let watermark_path = match &self.assignment_watermark_path {
                Some(p) => p,
                None => return Ok(FetchDecision::Skipped),
            };
            match Self::http_get_raw(url.as_str()) {
                Ok(body) => {
                    let tmp =
                        write_secure_staged_artifact(bundle_path, &body, "assignment bundle")?;

                    let previous_watermark = match load_auto_tunnel_watermark(watermark_path) {
                        Ok(val) => val,
                        Err(err) => {
                            return Err(format!(
                                "read previous assignment watermark failed: {err}"
                            ));
                        }
                    };

                    match load_auto_tunnel_bundle(
                        &tmp,
                        verifier_path,
                        self.assignment_bundle_path
                            .as_deref()
                            .map(|_| DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)
                            .unwrap_or(DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS),
                        TrustPolicy {
                            max_signed_data_age_secs: self
                                .assignment_bundle_path
                                .as_deref()
                                .map(|_| DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)
                                .unwrap_or(DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS),
                            max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
                        },
                        previous_watermark,
                    ) {
                        Ok(envelope) => {
                            std::fs::rename(&tmp, bundle_path)
                                .map_err(|e| format!("persist assignment bundle failed: {e}"))?;
                            persist_auto_tunnel_watermark(watermark_path, envelope.watermark)
                                .map_err(|e| format!("persist assignment watermark failed: {e}"))?;
                            eprintln!(
                                "statefetch: applied assignment bundle: nonce={}",
                                envelope.watermark.nonce
                            );
                            Ok(FetchDecision::Applied)
                        }
                        Err(err) => {
                            let _ = fs::remove_file(&tmp);
                            Err(format!("assignment fetch verification failed: {err}"))
                        }
                    }
                }
                Err(_network_err) => Ok(FetchDecision::Skipped),
            }
        } else {
            Ok(FetchDecision::Skipped)
        }
    }

    pub fn fetch_dns_zone(
        &self,
        auto_bundle: Option<&AutoTunnelBundle>,
    ) -> Result<FetchDecision, String> {
        if let Some(url) = &self.dns_zone_url {
            match Self::http_get_raw(url.as_str()) {
                Ok(body) => {
                    let tmp = write_secure_staged_artifact(
                        &self.dns_zone_bundle_path,
                        &body,
                        "dns zone bundle",
                    )?;

                    // parse verifier key
                    let verifier_key = std::fs::read_to_string(&self.dns_zone_verifier_key_path)
                        .map_err(|e| format!("read dns verifier key failed: {e}"))?;
                    let _verifier = parse_dns_zone_verifying_key(&verifier_key)
                        .map_err(|e| format!("parse dns verifier key failed: {e}"))?;

                    // load previous watermark (may be missing)
                    let previous = load_dns_zone_watermark(&self.dns_zone_watermark_path)
                        .map_err(|e| format!("read previous dns watermark failed: {e}"))?;

                    let dummy_bundle = AutoTunnelBundle {
                        node_id: String::new(),
                        mesh_cidr: String::new(),
                        assigned_cidr: String::new(),
                        peers: Vec::new(),
                        routes: Vec::new(),
                        selected_exit_node: None,
                    };
                    let context_bundle = auto_bundle.unwrap_or(&dummy_bundle);

                    match load_dns_zone_bundle(DnsZoneLoadContext {
                        path: &tmp,
                        verifier_key_path: &self.dns_zone_verifier_key_path,
                        max_age_secs: self.dns_zone_max_age_secs.get(),
                        trust_policy: TrustPolicy {
                            max_signed_data_age_secs: self.dns_zone_max_age_secs.get(),
                            max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
                        },
                        previous_watermark: previous,
                        expected_zone_name: &self.dns_zone_name,
                        local_node_id: &self.local_node_id,
                        auto_tunnel: context_bundle,
                    }) {
                        Ok(envelope) => {
                            std::fs::rename(&tmp, &self.dns_zone_bundle_path)
                                .map_err(|e| format!("persist dns zone bundle failed: {e}"))?;
                            persist_dns_zone_watermark(
                                &self.dns_zone_watermark_path,
                                envelope.watermark,
                            )
                            .map_err(|e| format!("persist dns zone watermark failed: {e}"))?;
                            eprintln!(
                                "statefetch: applied dns zone bundle: updated_at={}",
                                envelope.watermark.generated_at_unix
                            );
                            Ok(FetchDecision::Applied)
                        }
                        Err(err) => {
                            let _ = fs::remove_file(&tmp);
                            Err(format!("dns zone fetch verification failed: {err}"))
                        }
                    }
                }
                Err(_network_err) => Ok(FetchDecision::Skipped),
            }
        } else {
            Ok(FetchDecision::Skipped)
        }
    }
}

fn write_secure_staged_artifact(
    destination: &Path,
    body: &[u8],
    label: &str,
) -> Result<PathBuf, String> {
    let parent = destination.parent().ok_or_else(|| {
        format!(
            "{label} destination must have a parent directory: {}",
            destination.display()
        )
    })?;
    let basename = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("artifact");
    for attempt in 0..32u32 {
        let salt = rand::random::<u64>();
        let candidate = parent.join(format!(
            ".{basename}.incoming.{}.{}.{}",
            std::process::id(),
            salt,
            attempt
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(not(windows))]
        {
            options.mode(0o600);
        }
        match options.open(&candidate) {
            Ok(mut file) => {
                file.write_all(body).map_err(|err| {
                    let _ = fs::remove_file(&candidate);
                    format!(
                        "write staged {label} failed ({}): {err}",
                        candidate.display()
                    )
                })?;
                file.flush().map_err(|err| {
                    let _ = fs::remove_file(&candidate);
                    format!(
                        "flush staged {label} failed ({}): {err}",
                        candidate.display()
                    )
                })?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create staged {label} failed ({}): {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to allocate unique staged {label} near {}",
        destination.display()
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DaemonDataplaneMode {
    #[default]
    Shell,
    HybridNative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonBackendMode {
    InMemory,
    LinuxWireguard,
    LinuxWireguardUserspaceShared,
    MacosWireguard,
    MacosWireguardUserspaceShared,
    WindowsUnsupported,
}

#[allow(clippy::derivable_impls)]
impl Default for DaemonBackendMode {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        {
            return DaemonBackendMode::LinuxWireguard;
        }
        #[cfg(target_os = "macos")]
        {
            return DaemonBackendMode::MacosWireguard;
        }
        #[cfg(windows)]
        {
            return DaemonBackendMode::WindowsUnsupported;
        }
        #[allow(unreachable_code)]
        DaemonBackendMode::LinuxWireguard
    }
}

impl DaemonBackendMode {
    fn as_str(self) -> &'static str {
        match self {
            DaemonBackendMode::InMemory => "in-memory",
            DaemonBackendMode::LinuxWireguard => "linux-wireguard",
            DaemonBackendMode::LinuxWireguardUserspaceShared => "linux-wireguard-userspace-shared",
            DaemonBackendMode::MacosWireguard => "macos-wireguard",
            DaemonBackendMode::MacosWireguardUserspaceShared => "macos-wireguard-userspace-shared",
            DaemonBackendMode::WindowsUnsupported => WINDOWS_UNSUPPORTED_BACKEND_LABEL,
        }
    }

    fn userspace_shared_blocker(self) -> Option<&'static str> {
        match self {
            DaemonBackendMode::MacosWireguardUserspaceShared => Some(
                "macos-wireguard-userspace-shared backend is not implemented: crates/rustynet-backend-wireguard currently contains only the command-only macOS wireguard-go adapter plus the in-memory shared-transport test backend, and the repository does not yet provide a backend-owned Rust userspace WireGuard engine or TUN/runtime datapath that can own the authoritative peer UDP socket for peer traffic, STUN, and relay control on the same transport identity",
            ),
            _ => None,
        }
    }

    fn requires_runtime_wireguard_key_material(self) -> bool {
        matches!(
            self,
            DaemonBackendMode::LinuxWireguard
                | DaemonBackendMode::LinuxWireguardUserspaceShared
                | DaemonBackendMode::MacosWireguard
        )
    }
}

#[cfg(not(windows))]
fn validate_control_socket_path(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "socket path must be absolute".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_control_socket_path(path: &Path) -> Result<(), DaemonError> {
    validate_windows_pipe_path(path, WindowsLocalIpcRole::DaemonControl)
        .map_err(DaemonError::InvalidConfig)
}

#[cfg(not(windows))]
fn validate_privileged_helper_control_path(path: &Path) -> Result<(), DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::InvalidConfig(
            "privileged helper socket path must be absolute".to_string(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_privileged_helper_control_path(path: &Path) -> Result<(), DaemonError> {
    validate_windows_pipe_path(path, WindowsLocalIpcRole::PrivilegedHelper)
        .map_err(DaemonError::InvalidConfig)
}

#[cfg(not(windows))]
fn validate_runtime_file_path(path: &Path, label: &str) -> Result<(), DaemonError> {
    if !path.is_absolute() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} path must be absolute"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_runtime_file_path(path: &Path, label: &str) -> Result<(), DaemonError> {
    validate_windows_runtime_file_path(path, label).map_err(DaemonError::InvalidConfig)
}

#[cfg(not(windows))]
fn validate_backend_supported_on_current_host(
    backend_mode: DaemonBackendMode,
) -> Result<(), DaemonError> {
    if matches!(backend_mode, DaemonBackendMode::WindowsUnsupported) {
        return Err(DaemonError::InvalidConfig(format!(
            "backend '{}' is only valid on Windows daemon hosts and remains fail-closed because no reviewed Windows dataplane/backend exists on the current branch",
            backend_mode.as_str()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_backend_supported_on_current_host(
    backend_mode: DaemonBackendMode,
) -> Result<(), DaemonError> {
    match backend_mode {
        DaemonBackendMode::WindowsUnsupported => {
            require_supported_windows_backend(WindowsBackendMode::Unsupported)
                .map_err(DaemonError::InvalidConfig)
        }
        _ => Err(DaemonError::InvalidConfig(format!(
            "backend '{}' is not supported on Windows daemon hosts; the Windows service/config host is present, but reviewed backend/dataplane support remains unavailable on the current branch",
            backend_mode.as_str()
        ))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NodeRole {
    #[default]
    Admin,
    Client,
    BlindExit,
}

impl NodeRole {
    fn as_str(self) -> &'static str {
        match self {
            NodeRole::Admin => "admin",
            NodeRole::Client => "client",
            NodeRole::BlindExit => "blind_exit",
        }
    }

    fn is_blind_exit(self) -> bool {
        matches!(self, NodeRole::BlindExit)
    }

    fn is_admin(self) -> bool {
        matches!(self, NodeRole::Admin)
    }

    fn allows_command(self, command: &IpcCommand) -> bool {
        match self {
            NodeRole::Admin => true,
            NodeRole::Client => matches!(
                command,
                IpcCommand::Status
                    | IpcCommand::Netcheck
                    | IpcCommand::StateRefresh
                    | IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::DnsInspect
            ),
            NodeRole::BlindExit => matches!(
                command,
                IpcCommand::Status
                    | IpcCommand::Netcheck
                    | IpcCommand::StateRefresh
                    | IpcCommand::DnsInspect
            ),
        }
    }
}

impl std::str::FromStr for NodeRole {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "admin" => Ok(NodeRole::Admin),
            "client" => Ok(NodeRole::Client),
            "blind_exit" | "blind-exit" => Ok(NodeRole::BlindExit),
            _ => Err("invalid node role: expected admin, client, or blind_exit".to_string()),
        }
    }
}

fn sanitize_dataplane_routes_for_node_role(node_role: NodeRole, routes: Vec<Route>) -> Vec<Route> {
    if !node_role.is_blind_exit() {
        return routes;
    }

    routes
        .into_iter()
        .filter(|route| {
            !matches!(
                route.kind,
                RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan
            )
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonConfig {
    pub node_id: String,
    pub node_role: NodeRole,
    pub socket_path: PathBuf,
    pub state_path: PathBuf,
    pub trust_evidence_path: PathBuf,
    pub trust_verifier_key_path: PathBuf,
    pub trust_watermark_path: PathBuf,
    pub membership_snapshot_path: PathBuf,
    pub membership_log_path: PathBuf,
    pub membership_watermark_path: PathBuf,
    pub auto_tunnel_enforce: bool,
    pub auto_tunnel_bundle_path: Option<PathBuf>,
    pub auto_tunnel_verifier_key_path: Option<PathBuf>,
    pub auto_tunnel_watermark_path: Option<PathBuf>,
    pub auto_tunnel_max_age_secs: NonZeroU64,
    pub dns_zone_bundle_path: PathBuf,
    pub dns_zone_verifier_key_path: PathBuf,
    pub dns_zone_watermark_path: PathBuf,
    pub dns_zone_max_age_secs: NonZeroU64,
    pub dns_zone_name: String,
    pub dns_resolver_bind_addr: SocketAddr,
    pub traversal_bundle_path: PathBuf,
    pub traversal_verifier_key_path: PathBuf,
    pub traversal_watermark_path: PathBuf,
    pub traversal_max_age_secs: NonZeroU64,
    pub traversal_probe_max_candidates: NonZeroUsize,
    pub traversal_probe_max_pairs: NonZeroUsize,
    pub traversal_probe_simultaneous_open_rounds: NonZeroU8,
    pub traversal_probe_round_spacing_ms: NonZeroU64,
    pub traversal_probe_relay_switch_after_failures: NonZeroU8,
    pub traversal_probe_handshake_freshness_secs: NonZeroU64,
    pub traversal_probe_reprobe_interval_secs: NonZeroU64,
    pub traversal_stun_servers: Vec<SocketAddr>,
    pub traversal_stun_gather_timeout_ms: NonZeroU64,
    pub backend_mode: DaemonBackendMode,
    pub wg_interface: String,
    pub wg_listen_port: u16,
    pub wg_private_key_path: Option<PathBuf>,
    pub wg_encrypted_private_key_path: Option<PathBuf>,
    pub wg_key_passphrase_path: Option<PathBuf>,
    pub wg_public_key_path: Option<PathBuf>,
    pub relay_session_signing_secret_path: Option<PathBuf>,
    pub relay_session_signing_secret_passphrase_path: Option<PathBuf>,
    pub relay_session_token_ttl_secs: NonZeroU64,
    pub relay_session_refresh_margin_secs: NonZeroU64,
    pub relay_session_idle_timeout_secs: NonZeroU64,
    pub egress_interface: String,
    pub remote_ops_token_verifier_key_path: Option<PathBuf>,
    pub remote_ops_expected_subject: String,
    pub auto_port_forward_exit: bool,
    pub auto_port_forward_lease_secs: NonZeroU32,
    pub dataplane_mode: DaemonDataplaneMode,
    pub privileged_helper_socket_path: Option<PathBuf>,
    pub privileged_helper_timeout_ms: NonZeroU64,
    pub reconcile_interval_ms: NonZeroU64,
    pub max_reconcile_failures: NonZeroU32,
    pub fail_closed_ssh_allow: bool,
    pub fail_closed_ssh_allow_cidrs: Vec<ManagementCidr>,
    pub max_requests: Option<NonZeroUsize>,
    pub trust_url: Option<String>,
    pub traversal_url: Option<String>,
    pub assignment_url: Option<String>,
    pub dns_zone_url: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            node_id: DEFAULT_NODE_ID.to_string(),
            node_role: NodeRole::default(),
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            state_path: PathBuf::from(DEFAULT_STATE_PATH),
            trust_evidence_path: PathBuf::from(DEFAULT_TRUST_EVIDENCE_PATH),
            trust_verifier_key_path: PathBuf::from(DEFAULT_TRUST_VERIFIER_KEY_PATH),
            trust_watermark_path: PathBuf::from(DEFAULT_TRUST_WATERMARK_PATH),
            membership_snapshot_path: PathBuf::from(DEFAULT_MEMBERSHIP_SNAPSHOT_PATH),
            membership_log_path: PathBuf::from(DEFAULT_MEMBERSHIP_LOG_PATH),
            membership_watermark_path: PathBuf::from(DEFAULT_MEMBERSHIP_WATERMARK_PATH),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_BUNDLE_PATH)),
            auto_tunnel_verifier_key_path: Some(PathBuf::from(
                DEFAULT_AUTO_TUNNEL_VERIFIER_KEY_PATH,
            )),
            auto_tunnel_watermark_path: Some(PathBuf::from(DEFAULT_AUTO_TUNNEL_WATERMARK_PATH)),
            auto_tunnel_max_age_secs: NonZeroU64::new(DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)
                .expect("default auto tunnel max age must be non-zero"),
            dns_zone_bundle_path: PathBuf::from(DEFAULT_DNS_ZONE_BUNDLE_PATH),
            dns_zone_verifier_key_path: PathBuf::from(DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH),
            dns_zone_watermark_path: PathBuf::from(DEFAULT_DNS_ZONE_WATERMARK_PATH),
            dns_zone_max_age_secs: NonZeroU64::new(DEFAULT_DNS_ZONE_MAX_AGE_SECS)
                .expect("default dns zone max age must be non-zero"),
            dns_zone_name: DEFAULT_DNS_ZONE_NAME.to_string(),
            dns_resolver_bind_addr: DEFAULT_DNS_RESOLVER_BIND_ADDR
                .parse()
                .expect("default dns resolver bind addr must parse"),
            traversal_bundle_path: PathBuf::from(DEFAULT_TRAVERSAL_BUNDLE_PATH),
            traversal_verifier_key_path: PathBuf::from(DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH),
            traversal_watermark_path: PathBuf::from(DEFAULT_TRAVERSAL_WATERMARK_PATH),
            traversal_max_age_secs: NonZeroU64::new(DEFAULT_TRAVERSAL_MAX_AGE_SECS)
                .expect("default traversal max age must be non-zero"),
            traversal_probe_max_candidates: NonZeroUsize::new(
                DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES,
            )
            .expect("default traversal probe max candidates must be non-zero"),
            traversal_probe_max_pairs: NonZeroUsize::new(DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS)
                .expect("default traversal probe max pairs must be non-zero"),
            traversal_probe_simultaneous_open_rounds: NonZeroU8::new(
                DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS,
            )
            .expect("default traversal probe rounds must be non-zero"),
            traversal_probe_round_spacing_ms: NonZeroU64::new(
                DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS,
            )
            .expect("default traversal probe round spacing must be non-zero"),
            traversal_probe_relay_switch_after_failures: NonZeroU8::new(
                DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES,
            )
            .expect("default traversal relay switch threshold must be non-zero"),
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(
                DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS,
            )
            .expect("default traversal probe handshake freshness must be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(
                DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS,
            )
            .expect("default traversal probe reprobe interval must be non-zero"),
            traversal_stun_servers: Vec::new(),
            traversal_stun_gather_timeout_ms: NonZeroU64::new(
                DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS,
            )
            .expect("default traversal stun gather timeout must be non-zero"),
            backend_mode: DaemonBackendMode::default(),
            wg_interface: DEFAULT_WG_INTERFACE.to_string(),
            wg_listen_port: DEFAULT_WG_LISTEN_PORT,
            wg_private_key_path: Some(PathBuf::from(DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH)),
            wg_encrypted_private_key_path: Some(PathBuf::from(
                DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            )),
            wg_key_passphrase_path: Some(PathBuf::from(DEFAULT_WG_KEY_PASSPHRASE_PATH)),
            wg_public_key_path: Some(PathBuf::from(DEFAULT_WG_PUBLIC_KEY_PATH)),
            relay_session_signing_secret_path: std::env::var_os(ASSIGNMENT_SIGNING_SECRET_ENV)
                .map(PathBuf::from),
            relay_session_signing_secret_passphrase_path: std::env::var_os(
                ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV,
            )
            .map(PathBuf::from),
            relay_session_token_ttl_secs: NonZeroU64::new(DEFAULT_RELAY_SESSION_TOKEN_TTL_SECS)
                .expect("default relay session token ttl must be non-zero"),
            relay_session_refresh_margin_secs: NonZeroU64::new(
                DEFAULT_RELAY_SESSION_REFRESH_MARGIN_SECS,
            )
            .expect("default relay session refresh margin must be non-zero"),
            relay_session_idle_timeout_secs: NonZeroU64::new(
                DEFAULT_RELAY_SESSION_IDLE_TIMEOUT_SECS,
            )
            .expect("default relay session idle timeout must be non-zero"),
            egress_interface: DEFAULT_EGRESS_INTERFACE.to_string(),
            remote_ops_token_verifier_key_path: None,
            remote_ops_expected_subject: DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT.to_string(),
            auto_port_forward_exit: DEFAULT_AUTO_PORT_FORWARD_EXIT,
            auto_port_forward_lease_secs: NonZeroU32::new(DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS)
                .expect("default auto port-forward lease must be non-zero"),
            dataplane_mode: DaemonDataplaneMode::default(),
            privileged_helper_socket_path: Some(PathBuf::from(DEFAULT_TRUSTED_HELPER_SOCKET_PATH)),
            privileged_helper_timeout_ms: NonZeroU64::new(DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS)
                .expect("default privileged helper timeout must be non-zero"),
            reconcile_interval_ms: NonZeroU64::new(DEFAULT_RECONCILE_INTERVAL_MS)
                .expect("default reconcile interval must be non-zero"),
            max_reconcile_failures: NonZeroU32::new(DEFAULT_MAX_RECONCILE_FAILURES)
                .expect("default max reconcile failures must be non-zero"),
            fail_closed_ssh_allow: DEFAULT_FAIL_CLOSED_SSH_ALLOW,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            max_requests: None,
            trust_url: None,
            traversal_url: None,
            assignment_url: None,
            dns_zone_url: None,
        }
    }
}

#[derive(Debug)]
pub enum DaemonError {
    Io(String),
    InvalidConfig(String),
    State(String),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DaemonError::Io(message) => write!(f, "i/o error: {message}"),
            DaemonError::InvalidConfig(message) => write!(f, "invalid config: {message}"),
            DaemonError::State(message) => write!(f, "state error: {message}"),
        }
    }
}

impl std::error::Error for DaemonError {}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
enum RemoteOpsAuthError {
    KeyLoad(String),
    SignatureInvalid,
    SubjectDenied,
    ReplayDetected,
    TokenInvalid,
}

impl fmt::Display for RemoteOpsAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RemoteOpsAuthError::KeyLoad(message) => {
                write!(f, "remote ops verifier key load failed: {message}")
            }
            RemoteOpsAuthError::SignatureInvalid => {
                f.write_str("remote ops signature verification failed")
            }
            RemoteOpsAuthError::SubjectDenied => {
                f.write_str("remote ops subject is not authorized")
            }
            RemoteOpsAuthError::ReplayDetected => f.write_str("remote ops replay detected"),
            RemoteOpsAuthError::TokenInvalid => f.write_str("remote ops token lifetime is invalid"),
        }
    }
}

impl std::error::Error for RemoteOpsAuthError {}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TrustBootstrapError {
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
}

impl fmt::Display for TrustBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustBootstrapError::Missing => f.write_str("trust evidence is missing"),
            TrustBootstrapError::Io(message) => write!(f, "trust evidence io failure: {message}"),
            TrustBootstrapError::InvalidFormat(message) => {
                write!(f, "trust evidence invalid format: {message}")
            }
            TrustBootstrapError::KeyInvalid => {
                f.write_str("trust evidence verifier key is invalid")
            }
            TrustBootstrapError::SignatureInvalid => {
                f.write_str("trust evidence signature verification failed")
            }
            TrustBootstrapError::ReplayDetected => f.write_str("trust evidence replay detected"),
            TrustBootstrapError::FutureDated => {
                f.write_str("trust evidence timestamp exceeds allowable clock skew")
            }
            TrustBootstrapError::Stale => f.write_str("trust evidence is stale"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustWatermark {
    updated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustEvidenceEnvelope {
    evidence: TrustEvidence,
    watermark: TrustWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AutoTunnelBootstrapError {
    #[allow(dead_code)]
    Disabled,
    MissingConfig(&'static str),
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
    WrongNode,
    PolicyDenied(String),
}

impl fmt::Display for AutoTunnelBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AutoTunnelBootstrapError::Disabled => f.write_str("auto-tunnel is disabled"),
            AutoTunnelBootstrapError::MissingConfig(field) => {
                write!(f, "auto-tunnel missing config: {field}")
            }
            AutoTunnelBootstrapError::Missing => f.write_str("auto-tunnel bundle is missing"),
            AutoTunnelBootstrapError::Io(message) => {
                write!(f, "auto-tunnel bundle io failure: {message}")
            }
            AutoTunnelBootstrapError::InvalidFormat(message) => {
                write!(f, "auto-tunnel bundle invalid format: {message}")
            }
            AutoTunnelBootstrapError::KeyInvalid => {
                f.write_str("auto-tunnel verifier key is invalid")
            }
            AutoTunnelBootstrapError::SignatureInvalid => {
                f.write_str("auto-tunnel signature verification failed")
            }
            AutoTunnelBootstrapError::ReplayDetected => {
                f.write_str("auto-tunnel bundle replay detected")
            }
            AutoTunnelBootstrapError::FutureDated => {
                f.write_str("auto-tunnel bundle is future dated")
            }
            AutoTunnelBootstrapError::Stale => f.write_str("auto-tunnel bundle is stale"),
            AutoTunnelBootstrapError::WrongNode => {
                f.write_str("auto-tunnel bundle node id does not match local node")
            }
            AutoTunnelBootstrapError::PolicyDenied(reason) => {
                write!(f, "auto-tunnel bundle denied by local policy: {reason}")
            }
        }
    }
}

impl std::error::Error for AutoTunnelBootstrapError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AutoTunnelWatermark {
    generated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone)]
struct AutoTunnelBundleEnvelope {
    bundle: AutoTunnelBundle,
    watermark: AutoTunnelWatermark,
}

#[derive(Debug, Clone)]
pub struct AutoTunnelBundle {
    pub node_id: String,
    pub mesh_cidr: String,
    pub assigned_cidr: String,
    pub peers: Vec<PeerConfig>,
    pub routes: Vec<Route>,
    pub selected_exit_node: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DnsZoneBundleEnvelope {
    bundle: DnsZoneBundle,
    watermark: DnsZoneWatermark,
}

#[derive(Debug, Clone, Copy)]
struct DnsZoneLoadContext<'a> {
    path: &'a Path,
    verifier_key_path: &'a Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<DnsZoneWatermark>,
    expected_zone_name: &'a str,
    local_node_id: &'a str,
    auto_tunnel: &'a AutoTunnelBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalCandidateType {
    Host,
    ServerReflexive,
    Relay,
}

impl TraversalCandidateType {
    fn as_str(self) -> &'static str {
        match self {
            TraversalCandidateType::Host => "host",
            TraversalCandidateType::ServerReflexive => "srflx",
            TraversalCandidateType::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalCandidate {
    candidate_type: TraversalCandidateType,
    endpoint: std::net::SocketAddr,
    relay_id: Option<String>,
    priority: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalBundle {
    source_node_id: String,
    target_node_id: String,
    generated_at_unix: u64,
    expires_at_unix: u64,
    nonce: u64,
    candidates: Vec<TraversalCandidate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraversalWatermark {
    generated_at_unix: u64,
    nonce: u64,
    payload_digest: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalBundleEnvelope {
    bundle: TraversalBundle,
    watermark: TraversalWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalCoordinationEnvelope {
    record: SignedTraversalCoordinationRecord,
    payload_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalBundleSetEnvelope {
    bundles: Vec<TraversalBundleEnvelope>,
    coordinations: Vec<TraversalCoordinationEnvelope>,
    verifier_key_bytes: [u8; 32],
    watermark: TraversalWatermark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraversalSectionEnvelope {
    Bundle(TraversalBundleEnvelope),
    Coordination(TraversalCoordinationEnvelope),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraversalProbeStatus {
    remote_node_id: String,
    decision: TraversalProbeDecision,
    reason: TraversalProbeReason,
    attempts: usize,
    selected_endpoint: SocketEndpoint,
    latest_handshake_unix: Option<u64>,
    evaluated_at_unix: u64,
    next_reprobe_unix: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TraversalProbeCurrentState {
    path: Option<PathMode>,
    endpoint: Option<SocketEndpoint>,
    latest_handshake_unix: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimePathStateSummary {
    live_mode: &'static str,
    live_reason: String,
    programmed_mode: &'static str,
    programmed_reason: String,
    live_proven: bool,
    programmed_peer_count: usize,
    live_peer_count: usize,
    programmed_direct_peers: usize,
    programmed_relay_peers: usize,
    live_direct_peers: usize,
    live_relay_peers: usize,
    latest_live_handshake_unix: Option<u64>,
    relay_session_configured: bool,
    relay_session_state: &'static str,
    relay_session_established_peers: usize,
    relay_session_expired_peers: usize,
    relay_session_next_expiry_unix: Option<u64>,
}

fn format_stun_local_addrs(observations: &[StunResult]) -> String {
    if observations.is_empty() {
        return "none".to_string();
    }
    observations
        .iter()
        .map(|result| result.local_addr.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn stun_local_port_match_state(observations: &[StunResult], wg_listen_port: u16) -> &'static str {
    let mut any_match = false;
    let mut any_mismatch = false;
    for observation in observations {
        if observation.local_addr.port() == wg_listen_port {
            any_match = true;
        } else {
            any_mismatch = true;
        }
    }
    match (any_match, any_mismatch) {
        (false, false) => "none",
        (true, false) => "all_match_wg_listen_port",
        (false, true) => "all_mismatch_wg_listen_port",
        (true, true) => "mixed",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TraversalBootstrapError {
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsZoneBootstrapError {
    Missing,
    Io(String),
    InvalidFormat(String),
    KeyInvalid,
    SignatureInvalid,
    ReplayDetected,
    FutureDated,
    Stale,
    WrongNode,
    AssignmentMismatch(String),
}

impl fmt::Display for TraversalBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraversalBootstrapError::Missing => f.write_str("traversal bundle is missing"),
            TraversalBootstrapError::Io(message) => {
                write!(f, "traversal bundle io failure: {message}")
            }
            TraversalBootstrapError::InvalidFormat(message) => {
                write!(f, "traversal bundle invalid format: {message}")
            }
            TraversalBootstrapError::KeyInvalid => f.write_str("traversal verifier key is invalid"),
            TraversalBootstrapError::SignatureInvalid => {
                f.write_str("traversal signature verification failed")
            }
            TraversalBootstrapError::ReplayDetected => {
                f.write_str("traversal bundle replay detected")
            }
            TraversalBootstrapError::FutureDated => f.write_str("traversal bundle is future dated"),
            TraversalBootstrapError::Stale => f.write_str("traversal bundle is stale"),
        }
    }
}

impl std::error::Error for TraversalBootstrapError {}

impl fmt::Display for DnsZoneBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsZoneBootstrapError::Missing => f.write_str("dns zone bundle is missing"),
            DnsZoneBootstrapError::Io(message) => {
                write!(f, "dns zone bundle io failure: {message}")
            }
            DnsZoneBootstrapError::InvalidFormat(message) => {
                write!(f, "dns zone bundle invalid format: {message}")
            }
            DnsZoneBootstrapError::KeyInvalid => f.write_str("dns zone verifier key is invalid"),
            DnsZoneBootstrapError::SignatureInvalid => {
                f.write_str("dns zone signature verification failed")
            }
            DnsZoneBootstrapError::ReplayDetected => f.write_str("dns zone bundle replay detected"),
            DnsZoneBootstrapError::FutureDated => f.write_str("dns zone bundle is future dated"),
            DnsZoneBootstrapError::Stale => f.write_str("dns zone bundle is stale"),
            DnsZoneBootstrapError::WrongNode => {
                f.write_str("dns zone bundle subject node id does not match local node")
            }
            DnsZoneBootstrapError::AssignmentMismatch(message) => {
                write!(f, "dns zone bundle assignment mismatch: {message}")
            }
        }
    }
}

impl std::error::Error for DnsZoneBootstrapError {}

fn map_dns_zone_parse_error(err: DnsZoneError) -> DnsZoneBootstrapError {
    match err {
        DnsZoneError::InvalidFormat(message) => DnsZoneBootstrapError::InvalidFormat(message),
        DnsZoneError::KeyInvalid => DnsZoneBootstrapError::KeyInvalid,
        DnsZoneError::SignatureInvalid => DnsZoneBootstrapError::SignatureInvalid,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTrustVerificationReport {
    pub updated_at_unix: u64,
    pub nonce: u64,
    pub payload_digest_sha256: String,
    pub tls13_valid: bool,
    pub signed_control_valid: bool,
    pub signed_data_age_secs: u64,
    pub clock_skew_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAssignmentVerificationReport {
    pub node_id: String,
    pub generated_at_unix: u64,
    pub nonce: u64,
    pub payload_digest_sha256: String,
    pub peer_count: usize,
    pub route_count: usize,
    pub selected_exit_node: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTraversalVerificationReport {
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: u64,
    pub payload_digest_sha256: String,
    pub bundle_count: usize,
    pub source_node_ids: Vec<String>,
    pub target_node_ids: Vec<String>,
}

pub fn verify_signed_trust_state_artifact(
    evidence_path: &Path,
    verifier_key_path: &Path,
    watermark_path: &Path,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
) -> Result<SignedTrustVerificationReport, String> {
    if max_age_secs == 0 {
        return Err("trust max age seconds must be greater than zero".to_string());
    }
    if max_clock_skew_secs == 0 {
        return Err("trust max clock skew seconds must be greater than zero".to_string());
    }

    let previous_watermark = load_trust_watermark(watermark_path).map_err(|err| err.to_string())?;
    let previous_watermark = previous_watermark
        .ok_or_else(|| format!("trust watermark is missing: {}", watermark_path.display()))?;
    let trust_policy = TrustPolicy {
        max_signed_data_age_secs: max_age_secs,
        max_clock_skew_secs,
    };
    let envelope = load_trust_evidence(
        evidence_path,
        verifier_key_path,
        trust_policy,
        Some(previous_watermark),
    )
    .map_err(|err| err.to_string())?;
    if !envelope.evidence.tls13_valid {
        return Err("trust evidence tls13_valid=false".to_string());
    }
    if !envelope.evidence.signed_control_valid {
        return Err("trust evidence signed_control_valid=false".to_string());
    }
    if envelope.evidence.signed_data_age_secs > max_age_secs {
        return Err(format!(
            "trust evidence signed_data_age_secs exceeds max age: {} > {}",
            envelope.evidence.signed_data_age_secs, max_age_secs
        ));
    }
    if envelope.evidence.clock_skew_secs > max_clock_skew_secs {
        return Err(format!(
            "trust evidence clock_skew_secs exceeds max skew: {} > {}",
            envelope.evidence.clock_skew_secs, max_clock_skew_secs
        ));
    }
    let payload_digest = envelope
        .watermark
        .payload_digest
        .ok_or_else(|| "trust watermark payload digest is missing".to_string())?;

    Ok(SignedTrustVerificationReport {
        updated_at_unix: envelope.watermark.updated_at_unix,
        nonce: envelope.watermark.nonce,
        payload_digest_sha256: encode_hex(&payload_digest),
        tls13_valid: envelope.evidence.tls13_valid,
        signed_control_valid: envelope.evidence.signed_control_valid,
        signed_data_age_secs: envelope.evidence.signed_data_age_secs,
        clock_skew_secs: envelope.evidence.clock_skew_secs,
    })
}

pub fn verify_signed_assignment_state_artifact(
    bundle_path: &Path,
    verifier_key_path: &Path,
    watermark_path: &Path,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
    expected_node_id: Option<&str>,
) -> Result<SignedAssignmentVerificationReport, String> {
    if max_age_secs == 0 {
        return Err("assignment max age seconds must be greater than zero".to_string());
    }
    if max_clock_skew_secs == 0 {
        return Err("assignment max clock skew seconds must be greater than zero".to_string());
    }

    let previous_watermark =
        load_auto_tunnel_watermark(watermark_path).map_err(|err| err.to_string())?;
    let previous_watermark = previous_watermark.ok_or_else(|| {
        format!(
            "assignment watermark is missing: {}",
            watermark_path.display()
        )
    })?;
    let trust_policy = TrustPolicy {
        max_signed_data_age_secs: max_age_secs,
        max_clock_skew_secs,
    };
    let envelope = load_auto_tunnel_bundle(
        bundle_path,
        verifier_key_path,
        max_age_secs,
        trust_policy,
        Some(previous_watermark),
    )
    .map_err(|err| err.to_string())?;
    if let Some(expected_node_id) = expected_node_id
        && envelope.bundle.node_id != expected_node_id
    {
        return Err(format!(
            "assignment bundle node_id mismatch: expected {}, got {}",
            expected_node_id, envelope.bundle.node_id
        ));
    }
    let payload_digest = envelope
        .watermark
        .payload_digest
        .ok_or_else(|| "assignment watermark payload digest is missing".to_string())?;

    Ok(SignedAssignmentVerificationReport {
        node_id: envelope.bundle.node_id,
        generated_at_unix: envelope.watermark.generated_at_unix,
        nonce: envelope.watermark.nonce,
        payload_digest_sha256: encode_hex(&payload_digest),
        peer_count: envelope.bundle.peers.len(),
        route_count: envelope.bundle.routes.len(),
        selected_exit_node: envelope.bundle.selected_exit_node,
    })
}

pub fn verify_signed_traversal_state_artifact(
    bundle_path: &Path,
    verifier_key_path: &Path,
    watermark_path: &Path,
    max_age_secs: u64,
    max_clock_skew_secs: u64,
    expected_source_node_id: Option<&str>,
) -> Result<SignedTraversalVerificationReport, String> {
    if max_age_secs == 0 {
        return Err("traversal max age seconds must be greater than zero".to_string());
    }
    if max_clock_skew_secs == 0 {
        return Err("traversal max clock skew seconds must be greater than zero".to_string());
    }

    let previous_watermark =
        load_traversal_watermark(watermark_path).map_err(|err| err.to_string())?;
    let previous_watermark = previous_watermark.ok_or_else(|| {
        format!(
            "traversal watermark is missing: {}",
            watermark_path.display()
        )
    })?;
    let trust_policy = TrustPolicy {
        max_signed_data_age_secs: max_age_secs,
        max_clock_skew_secs,
    };
    let envelope = load_traversal_bundle_set(
        bundle_path,
        verifier_key_path,
        max_age_secs,
        trust_policy,
        Some(previous_watermark),
    )
    .map_err(|err| err.to_string())?;
    if envelope.bundles.is_empty() {
        return Err("verified traversal bundle set is empty".to_string());
    }

    let mut source_node_ids = BTreeSet::new();
    let mut target_node_ids = BTreeSet::new();
    for bundle in &envelope.bundles {
        if let Some(expected_source_node_id) = expected_source_node_id
            && bundle.bundle.source_node_id != expected_source_node_id
        {
            return Err(format!(
                "traversal bundle source_node_id mismatch: expected {}, got {}",
                expected_source_node_id, bundle.bundle.source_node_id
            ));
        }
        source_node_ids.insert(bundle.bundle.source_node_id.clone());
        target_node_ids.insert(bundle.bundle.target_node_id.clone());
    }

    let first_bundle = envelope
        .bundles
        .first()
        .ok_or_else(|| "verified traversal bundle set is empty".to_string())?;
    let payload_digest = envelope
        .watermark
        .payload_digest
        .ok_or_else(|| "traversal watermark payload digest is missing".to_string())?;

    Ok(SignedTraversalVerificationReport {
        generated_at_unix: first_bundle.bundle.generated_at_unix,
        expires_at_unix: first_bundle.bundle.expires_at_unix,
        nonce: first_bundle.bundle.nonce,
        payload_digest_sha256: encode_hex(&payload_digest),
        bundle_count: envelope.bundles.len(),
        source_node_ids: source_node_ids.into_iter().collect(),
        target_node_ids: target_node_ids.into_iter().collect(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MembershipBootstrapError {
    MissingSnapshot,
    MissingLog,
    SnapshotLoad(String),
    LogLoad(String),
    Replay(String),
    InvalidRoot,
    WatermarkReplay,
    LocalNodeNotActive,
    ExitNodeNotActive(String),
    Io(String),
}

impl fmt::Display for MembershipBootstrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MembershipBootstrapError::MissingSnapshot => {
                f.write_str("membership snapshot is missing")
            }
            MembershipBootstrapError::MissingLog => f.write_str("membership log is missing"),
            MembershipBootstrapError::SnapshotLoad(msg) => {
                write!(f, "membership snapshot load failed: {msg}")
            }
            MembershipBootstrapError::LogLoad(msg) => {
                write!(f, "membership log load failed: {msg}")
            }
            MembershipBootstrapError::Replay(msg) => {
                write!(f, "membership replay failed: {msg}")
            }
            MembershipBootstrapError::InvalidRoot => {
                f.write_str("membership root verification failed")
            }
            MembershipBootstrapError::WatermarkReplay => {
                f.write_str("membership replay/rollback detected by watermark")
            }
            MembershipBootstrapError::LocalNodeNotActive => {
                f.write_str("local node is not active in membership state")
            }
            MembershipBootstrapError::ExitNodeNotActive(node_id) => {
                write!(f, "selected exit node is not active: {node_id}")
            }
            MembershipBootstrapError::Io(msg) => write!(f, "membership io failure: {msg}"),
        }
    }
}

impl std::error::Error for MembershipBootstrapError {}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MembershipWatermark {
    epoch: u64,
    state_root: String,
}

enum DaemonBackend {
    #[allow(dead_code)]
    InMemory(WireguardBackend),
    #[allow(dead_code)]
    LinuxUserspaceShared(LinuxUserspaceSharedBackend),
    #[cfg(target_os = "linux")]
    Linux(LinuxWireguardBackend<PrivilegedHelperWireguardRunner>),
    #[cfg(target_os = "macos")]
    Macos(MacosWireguardBackend<PrivilegedHelperWireguardRunner>),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone)]
struct PrivilegedHelperWireguardRunner {
    helper_client: PrivilegedCommandClient,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PrivilegedHelperWireguardRunner {
    fn new(helper_client: PrivilegedCommandClient) -> Self {
        Self { helper_client }
    }

    fn helper_program_for(program: &str) -> Result<PrivilegedCommandProgram, BackendError> {
        match program {
            "ip" => Ok(PrivilegedCommandProgram::Ip),
            "wg" => Ok(PrivilegedCommandProgram::Wg),
            "ifconfig" => Ok(PrivilegedCommandProgram::Ifconfig),
            "route" => Ok(PrivilegedCommandProgram::Route),
            "wireguard-go" => Ok(PrivilegedCommandProgram::WireguardGo),
            "kill" => Ok(PrivilegedCommandProgram::Kill),
            _ => Err(BackendError::invalid_input(
                "unsupported privileged wireguard backend command",
            )),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl WireguardCommandRunner for PrivilegedHelperWireguardRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), BackendError> {
        let _ = self.run_capture(program, args)?;
        Ok(())
    }

    fn run_capture(
        &mut self,
        program: &str,
        args: &[String],
    ) -> Result<WireguardCommandOutput, BackendError> {
        let helper_program = Self::helper_program_for(program)?;
        let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = self
            .helper_client
            .run_capture(helper_program, &arg_refs)
            .map_err(|err| {
                BackendError::internal(format!(
                    "privileged helper {program} invocation failed: {err}"
                ))
            })?;

        if output.success() {
            return Ok(WireguardCommandOutput {
                stdout: output.stdout,
                stderr: output.stderr,
            });
        }

        let stderr = output.stderr.trim();
        if stderr.is_empty() {
            return Err(BackendError::internal(format!(
                "privileged helper {program} exited with status {}",
                output.status
            )));
        }

        Err(BackendError::internal(format!(
            "privileged helper {program} exited with status {}: {stderr}",
            output.status
        )))
    }
}

impl DaemonBackend {
    fn from_config(config: &DaemonConfig) -> Result<Self, DaemonError> {
        match config.backend_mode {
            DaemonBackendMode::InMemory => {
                #[cfg(test)]
                {
                    Ok(Self::InMemory(WireguardBackend::default()))
                }
                #[cfg(not(test))]
                {
                    Err(DaemonError::InvalidConfig(
                        "in-memory backend is disabled in production daemon paths".to_string(),
                    ))
                }
            }
            DaemonBackendMode::LinuxWireguard => {
                #[cfg(target_os = "linux")]
                {
                    let helper_socket = config
                        .privileged_helper_socket_path
                        .as_ref()
                        .ok_or_else(|| {
                            DaemonError::InvalidConfig(
                                "privileged helper socket path is required for linux-wireguard backend"
                                    .to_string(),
                            )
                        })?;
                    let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                        DaemonError::InvalidConfig(
                            "wg private key path is required for linux-wireguard backend"
                                .to_string(),
                        )
                    })?;
                    validate_private_key_permissions(private_key)?;
                    let helper_client = PrivilegedCommandClient::new(
                        helper_socket.clone(),
                        Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                    )
                    .map_err(DaemonError::InvalidConfig)?;
                    let backend = LinuxWireguardBackend::new(
                        PrivilegedHelperWireguardRunner::new(helper_client),
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.wg_listen_port,
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::Linux(backend))
                }
                #[cfg(not(target_os = "linux"))]
                {
                    Err(DaemonError::InvalidConfig(
                        "linux-wireguard backend is only supported on linux".to_string(),
                    ))
                }
            }
            DaemonBackendMode::LinuxWireguardUserspaceShared => {
                let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                    DaemonError::InvalidConfig(
                        "wg private key path is required for linux-wireguard-userspace-shared backend"
                            .to_string(),
                    )
                })?;
                validate_private_key_permissions(private_key)?;
                #[cfg(test)]
                {
                    let backend = LinuxUserspaceSharedBackend::new_for_test(
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.wg_listen_port,
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::LinuxUserspaceShared(backend))
                }
                #[cfg(all(not(test), target_os = "linux"))]
                {
                    let helper_socket = config
                        .privileged_helper_socket_path
                        .as_ref()
                        .ok_or_else(|| {
                            DaemonError::InvalidConfig(
                                "privileged helper socket path is required for linux-wireguard-userspace-shared backend"
                                    .to_string(),
                            )
                        })?;
                    let helper_client = PrivilegedCommandClient::new(
                        helper_socket.clone(),
                        Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                    )
                    .map_err(DaemonError::InvalidConfig)?;
                    let backend = LinuxUserspaceSharedBackend::new_with_helper_runner(
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.wg_listen_port,
                        PrivilegedHelperWireguardRunner::new(helper_client),
                        Uid::effective().as_raw(),
                        Gid::effective().as_raw(),
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::LinuxUserspaceShared(backend))
                }
                #[cfg(all(not(test), not(target_os = "linux")))]
                {
                    Err(DaemonError::InvalidConfig(
                        "linux-wireguard-userspace-shared backend is only supported on linux"
                            .to_string(),
                    ))
                }
            }
            DaemonBackendMode::MacosWireguard => {
                #[cfg(target_os = "macos")]
                {
                    let helper_socket = config
                        .privileged_helper_socket_path
                        .as_ref()
                        .ok_or_else(|| {
                            DaemonError::InvalidConfig(
                                "privileged helper socket path is required for macos-wireguard backend"
                                    .to_string(),
                            )
                        })?;
                    let private_key = config.wg_private_key_path.as_ref().ok_or_else(|| {
                        DaemonError::InvalidConfig(
                            "wg private key path is required for macos-wireguard backend"
                                .to_string(),
                        )
                    })?;
                    validate_private_key_permissions(private_key)?;
                    let helper_client = PrivilegedCommandClient::new(
                        helper_socket.clone(),
                        Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                    )
                    .map_err(DaemonError::InvalidConfig)?;
                    let backend = MacosWireguardBackend::new(
                        PrivilegedHelperWireguardRunner::new(helper_client),
                        config.wg_interface.clone(),
                        private_key.to_string_lossy().to_string(),
                        config.egress_interface.clone(),
                        config.wg_listen_port,
                    )
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
                    Ok(Self::Macos(backend))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    Err(DaemonError::InvalidConfig(
                        "macos-wireguard backend is only supported on macos".to_string(),
                    ))
                }
            }
            DaemonBackendMode::MacosWireguardUserspaceShared => Err(DaemonError::InvalidConfig(
                DaemonBackendMode::MacosWireguardUserspaceShared
                    .userspace_shared_blocker()
                    .expect("macos shared backend blocker should exist")
                    .to_string(),
            )),
            DaemonBackendMode::WindowsUnsupported => Err(DaemonError::InvalidConfig(
                require_supported_windows_backend(WindowsBackendMode::Unsupported)
                    .expect_err("windows unsupported backend must fail closed"),
            )),
        }
    }
}

impl TunnelBackend for DaemonBackend {
    fn name(&self) -> &'static str {
        match self {
            DaemonBackend::InMemory(backend) => backend.name(),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.name(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.name(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.name(),
        }
    }

    fn capabilities(&self) -> BackendCapabilities {
        match self {
            DaemonBackend::InMemory(backend) => backend.capabilities(),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.capabilities(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.capabilities(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.capabilities(),
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.start(context),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.start(context),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.start(context),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.start(context),
        }
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.configure_peer(peer),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.configure_peer(peer),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.configure_peer(peer),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.configure_peer(peer),
        }
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.update_peer_endpoint(node_id, endpoint),
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.update_peer_endpoint(node_id, endpoint)
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.update_peer_endpoint(node_id, endpoint),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.update_peer_endpoint(node_id, endpoint),
        }
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.current_peer_endpoint(node_id),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.current_peer_endpoint(node_id),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.current_peer_endpoint(node_id),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.current_peer_endpoint(node_id),
        }
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.cached_peer_latest_handshake_unix_for_test(node_id)
            }
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.peer_latest_handshake_unix(node_id)
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.peer_latest_handshake_unix(node_id),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.peer_latest_handshake_unix(node_id),
        }
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.remove_peer(node_id),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.remove_peer(node_id),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.remove_peer(node_id),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.remove_peer(node_id),
        }
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.apply_routes(routes),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.apply_routes(routes),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.apply_routes(routes),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.apply_routes(routes),
        }
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.set_exit_mode(mode),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.set_exit_mode(mode),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.set_exit_mode(mode),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.set_exit_mode(mode),
        }
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.stats(),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.stats(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.stats(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.stats(),
        }
    }

    fn authoritative_transport_identity(
        &self,
    ) -> Option<rustynet_backend_api::AuthoritativeTransportIdentity> {
        match self {
            DaemonBackend::InMemory(backend) => backend.authoritative_transport_identity(),
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.authoritative_transport_identity()
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.authoritative_transport_identity(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.authoritative_transport_identity(),
        }
    }

    fn authoritative_transport_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<rustynet_backend_api::AuthoritativeTransportResponse, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.authoritative_transport_round_trip(remote_addr, payload, timeout)
            }
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.authoritative_transport_round_trip(remote_addr, payload, timeout)
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => {
                backend.authoritative_transport_round_trip(remote_addr, payload, timeout)
            }
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => {
                backend.authoritative_transport_round_trip(remote_addr, payload, timeout)
            }
        }
    }

    fn authoritative_transport_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<rustynet_backend_api::AuthoritativeTransportIdentity, BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.authoritative_transport_send(remote_addr, payload)
            }
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.authoritative_transport_send(remote_addr, payload)
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => {
                backend.authoritative_transport_send(remote_addr, payload)
            }
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => {
                backend.authoritative_transport_send(remote_addr, payload)
            }
        }
    }

    fn transport_socket_identity_blocker(&self) -> Option<String> {
        match self {
            DaemonBackend::InMemory(backend) => backend.transport_socket_identity_blocker(),
            DaemonBackend::LinuxUserspaceShared(backend) => {
                backend.transport_socket_identity_blocker()
            }
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.transport_socket_identity_blocker(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.transport_socket_identity_blocker(),
        }
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => backend.shutdown(),
            DaemonBackend::LinuxUserspaceShared(backend) => backend.shutdown(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(backend) => backend.shutdown(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(backend) => backend.shutdown(),
        }
    }
}

#[cfg(test)]
impl DaemonBackend {
    fn set_test_endpoint_latest_handshake_unix(
        &mut self,
        endpoint: SocketEndpoint,
        latest_handshake_unix: Option<u64>,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend
                    .set_endpoint_latest_handshake_unix_for_test(endpoint, latest_handshake_unix);
                Ok(())
            }
            DaemonBackend::LinuxUserspaceShared(_) => Err(BackendError::invalid_input(
                "test handshake injection is only supported for in-memory backend",
            )),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Err(BackendError::invalid_input(
                "test handshake injection is only supported for in-memory backend",
            )),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Err(BackendError::invalid_input(
                "test handshake injection is only supported for in-memory backend",
            )),
        }
    }

    fn configure_authoritative_shared_transport_for_test(
        &mut self,
        local_addr: SocketAddr,
        label: &str,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.configure_authoritative_shared_transport_for_test(
                    local_addr,
                    label.to_string(),
                );
                Ok(())
            }
            DaemonBackend::LinuxUserspaceShared(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
        }
    }

    fn script_authoritative_round_trip_for_test(
        &mut self,
        result: Result<rustynet_backend_api::AuthoritativeTransportResponse, BackendError>,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.script_authoritative_round_trip_for_test(result);
                Ok(())
            }
            DaemonBackend::LinuxUserspaceShared(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
        }
    }

    fn script_authoritative_stun_round_trip_for_test(
        &mut self,
        remote_addr: SocketAddr,
        mapped_endpoint: SocketAddr,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.script_authoritative_stun_round_trip_for_test(remote_addr, mapped_endpoint);
                Ok(())
            }
            DaemonBackend::LinuxUserspaceShared(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
        }
    }

    fn script_authoritative_send_result_for_test(
        &mut self,
        result: Result<(), BackendError>,
    ) -> Result<(), BackendError> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.script_authoritative_send_result_for_test(result);
                Ok(())
            }
            DaemonBackend::LinuxUserspaceShared(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Err(BackendError::invalid_input(
                "authoritative shared transport test harness is only supported for in-memory backend",
            )),
        }
    }

    fn authoritative_transport_operations_for_test(
        &self,
    ) -> Vec<RecordedAuthoritativeTransportOperation> {
        match self {
            DaemonBackend::InMemory(backend) => {
                backend.recorded_authoritative_transport_operations_for_test()
            }
            DaemonBackend::LinuxUserspaceShared(_) => Vec::new(),
            #[cfg(target_os = "linux")]
            DaemonBackend::Linux(_) => Vec::new(),
            #[cfg(target_os = "macos")]
            DaemonBackend::Macos(_) => Vec::new(),
        }
    }
}

struct DaemonRuntime {
    controller: Phase10Controller<DaemonBackend, RuntimeSystem>,
    policy: ContextualPolicySet,
    backend_mode: DaemonBackendMode,
    node_role: NodeRole,
    local_node_id: String,
    wg_interface: String,
    wg_listen_port: u16,
    wg_private_key_path: Option<PathBuf>,
    wg_encrypted_private_key_path: Option<PathBuf>,
    wg_key_passphrase_path: Option<PathBuf>,
    wg_public_key_path: Option<PathBuf>,
    relay_client: Option<RelayClient>,
    relay_session_token_ttl_secs: u64,
    relay_session_refresh_margin_secs: u64,
    relay_session_idle_timeout_secs: u64,
    privileged_helper_client: Option<PrivilegedCommandClient>,
    state_fetcher: StateFetcher,
    #[cfg(target_os = "linux")]
    egress_interface: String,
    state_path: PathBuf,
    trust_evidence_path: PathBuf,
    trust_verifier_key_path: PathBuf,
    trust_watermark_path: PathBuf,
    membership_snapshot_path: PathBuf,
    membership_log_path: PathBuf,
    membership_watermark_path: PathBuf,
    auto_tunnel_enforce: bool,
    auto_tunnel_bundle_path: Option<PathBuf>,
    auto_tunnel_verifier_key_path: Option<PathBuf>,
    auto_tunnel_watermark_path: Option<PathBuf>,
    auto_tunnel_max_age_secs: u64,
    dns_zone_name: String,
    dns_zone_bundle_path: PathBuf,
    dns_zone_verifier_key_path: PathBuf,
    dns_zone_watermark_path: PathBuf,
    dns_zone_max_age_secs: u64,
    traversal_bundle_path: PathBuf,
    traversal_verifier_key_path: PathBuf,
    traversal_watermark_path: PathBuf,
    traversal_max_age_secs: u64,
    traversal_probe_config: TraversalEngineConfig,
    traversal_probe_handshake_freshness_secs: u64,
    traversal_probe_reprobe_interval_secs: u64,
    local_host_candidates: BTreeMap<String, Vec<IpAddr>>,
    #[cfg(test)]
    test_local_host_candidates_snapshot: Option<BTreeMap<String, Vec<IpAddr>>>,
    local_stun_observations: Vec<StunResult>,
    local_stun_candidates: Vec<SocketAddr>,
    transport_socket_identity_blocker: Option<String>,
    next_stun_refresh_at: Option<Instant>,
    trust_policy: TrustPolicy,
    selected_exit_node: Option<String>,
    lan_access_enabled: bool,
    advertised_routes: BTreeSet<String>,
    restriction_mode: RestrictionMode,
    bootstrap_error: Option<String>,
    reconcile_attempts: u64,
    reconcile_failures: u64,
    last_reconcile_unix: Option<u64>,
    last_reconcile_error: Option<String>,
    last_applied_assignment: Option<AutoTunnelWatermark>,
    local_route_reconcile_pending: bool,
    max_reconcile_failures: u32,
    remote_ops_expected_subject: String,
    remote_ops_seen_nonces: BTreeMap<String, BTreeSet<u64>>,
    remote_ops_verifying_key: Option<VerifyingKey>,
    membership_state: Option<MembershipState>,
    membership_directory: MembershipDirectory,
    dns_zone: Option<DnsZoneBundleEnvelope>,
    dns_zone_error: Option<String>,
    dns_zone_stale_rejections: u64,
    dns_zone_replay_rejections: u64,
    dns_zone_future_dated_rejections: u64,
    dns_zone_preexpiry_refresh_events: u64,
    dns_zone_last_preexpiry_refresh_unix: Option<u64>,
    traversal_hints: Option<TraversalBundleSetEnvelope>,
    verified_traversal_index: VerifiedTraversalIndex,
    verified_traversal_coordination_index:
        BTreeMap<(String, String), SignedTraversalCoordinationRecord>,
    traversal_coordination_replay_window: CoordinationReplayWindow,
    traversal_hint_error: Option<String>,
    traversal_probe_statuses: BTreeMap<NodeId, TraversalProbeStatus>,
    traversal_stale_rejections: u64,
    traversal_replay_rejections: u64,
    traversal_future_dated_rejections: u64,
    traversal_preexpiry_refresh_events: u64,
    traversal_last_preexpiry_refresh_unix: Option<u64>,
    traversal_endpoint_change_events: u64,
    traversal_last_endpoint_fingerprint: Option<String>,
    traversal_last_endpoint_change_unix: Option<u64>,
    _endpoint_monitor: EndpointMonitor,
    auto_port_forward_exit: bool,
    #[cfg(target_os = "linux")]
    auto_port_forward_lease_secs: u32,
    exit_port_forward_last_error: Option<String>,
    #[cfg(target_os = "linux")]
    exit_port_forward_lease: Option<ExitPortForwardLease>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExitPortForwardLease {
    gateway: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lease_secs: u32,
    renewed_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestrictionMode {
    None,
    Recoverable,
    Permanent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraversalAuthorityMode {
    StaticAssignment,
    EnforcedV1,
}

impl TraversalAuthorityMode {
    fn as_str(self) -> &'static str {
        match self {
            TraversalAuthorityMode::StaticAssignment => "static_assignment",
            TraversalAuthorityMode::EnforcedV1 => "enforced_v1",
        }
    }

    fn is_enforced(self) -> bool {
        matches!(self, TraversalAuthorityMode::EnforcedV1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignedStateRefreshReason {
    PreExpiry,
    EndpointChange,
    Command,
}

impl SignedStateRefreshReason {
    fn as_str(self) -> &'static str {
        match self {
            SignedStateRefreshReason::PreExpiry => "preexpiry",
            SignedStateRefreshReason::EndpointChange => "endpoint_change",
            SignedStateRefreshReason::Command => "command",
        }
    }
}

fn load_relay_client(config: &DaemonConfig) -> Result<Option<RelayClient>, DaemonError> {
    match (
        config.relay_session_signing_secret_path.as_ref(),
        config.relay_session_signing_secret_passphrase_path.as_ref(),
    ) {
        (None, None) => Ok(None),
        (Some(_), None) => Err(DaemonError::InvalidConfig(format!(
            "{ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV} is required when {ASSIGNMENT_SIGNING_SECRET_ENV} is set"
        ))),
        (None, Some(_)) => Err(DaemonError::InvalidConfig(format!(
            "{ASSIGNMENT_SIGNING_SECRET_ENV} is required when {ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV} is set"
        ))),
        (Some(secret_path), Some(passphrase_path)) => {
            let signing_secret =
                decrypt_private_key(secret_path, passphrase_path).map_err(DaemonError::Io)?;
            let signing_key = derive_endpoint_hint_signing_key(signing_secret);
            let relay_client = RelayClient::new(
                NodeId::new(config.node_id.clone())
                    .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?,
                Arc::new(signing_key),
                RelayClientConfig::default(),
            );
            Ok(Some(relay_client))
        }
    }
}

impl DaemonRuntime {
    fn new(config: &DaemonConfig) -> Result<Self, DaemonError> {
        NodeId::new(config.node_id.clone())
            .map_err(|err| DaemonError::InvalidConfig(format!("invalid node id: {err}")))?;
        let policy = ContextualPolicySet {
            rules: vec![ContextualPolicyRule {
                src: "user:local".to_string(),
                dst: "*".to_string(),
                protocol: Protocol::Any,
                action: RuleAction::Allow,
                contexts: vec![TrafficContext::Mesh, TrafficContext::SharedExit],
            }],
        };
        let trust_policy = TrustPolicy::default();
        let backend = DaemonBackend::from_config(config)?;
        let relay_client = load_relay_client(config)?;
        let transport_socket_identity_blocker = backend
            .transport_socket_identity_blocker()
            .filter(|_| !config.traversal_stun_servers.is_empty() || relay_client.is_some());
        let transport_socket_identity_blocked = transport_socket_identity_blocker.is_some();
        let controller = Phase10Controller::new(
            backend,
            daemon_system(config)?,
            policy.clone(),
            trust_policy,
        );
        let privileged_helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        let remote_ops_verifying_key = config
            .remote_ops_token_verifier_key_path
            .as_ref()
            .map(|path| load_remote_ops_access_token_verifying_key(path))
            .transpose()?;
        Ok(Self {
            controller,
            policy,
            backend_mode: config.backend_mode,
            node_role: config.node_role,
            local_node_id: config.node_id.clone(),
            wg_interface: config.wg_interface.clone(),
            wg_listen_port: config.wg_listen_port,
            wg_private_key_path: config.wg_private_key_path.clone(),
            wg_encrypted_private_key_path: config.wg_encrypted_private_key_path.clone(),
            wg_key_passphrase_path: config.wg_key_passphrase_path.clone(),
            wg_public_key_path: config.wg_public_key_path.clone(),
            relay_client,
            relay_session_token_ttl_secs: config.relay_session_token_ttl_secs.get(),
            relay_session_refresh_margin_secs: config.relay_session_refresh_margin_secs.get(),
            relay_session_idle_timeout_secs: config.relay_session_idle_timeout_secs.get(),
            privileged_helper_client,
            state_fetcher: StateFetcher::new_from_daemon(config),
            #[cfg(target_os = "linux")]
            egress_interface: config.egress_interface.clone(),
            state_path: config.state_path.clone(),
            trust_evidence_path: config.trust_evidence_path.clone(),
            trust_verifier_key_path: config.trust_verifier_key_path.clone(),
            trust_watermark_path: config.trust_watermark_path.clone(),
            membership_snapshot_path: config.membership_snapshot_path.clone(),
            membership_log_path: config.membership_log_path.clone(),
            membership_watermark_path: config.membership_watermark_path.clone(),
            auto_tunnel_enforce: config.auto_tunnel_enforce,
            auto_tunnel_bundle_path: config.auto_tunnel_bundle_path.clone(),
            auto_tunnel_verifier_key_path: config.auto_tunnel_verifier_key_path.clone(),
            auto_tunnel_watermark_path: config.auto_tunnel_watermark_path.clone(),
            auto_tunnel_max_age_secs: config.auto_tunnel_max_age_secs.get(),
            dns_zone_name: config.dns_zone_name.clone(),
            dns_zone_bundle_path: config.dns_zone_bundle_path.clone(),
            dns_zone_verifier_key_path: config.dns_zone_verifier_key_path.clone(),
            dns_zone_watermark_path: config.dns_zone_watermark_path.clone(),
            dns_zone_max_age_secs: config.dns_zone_max_age_secs.get(),
            traversal_bundle_path: config.traversal_bundle_path.clone(),
            traversal_verifier_key_path: config.traversal_verifier_key_path.clone(),
            traversal_watermark_path: config.traversal_watermark_path.clone(),
            traversal_max_age_secs: config.traversal_max_age_secs.get(),
            traversal_probe_config: TraversalEngineConfig {
                max_candidates: config.traversal_probe_max_candidates.get(),
                max_probe_pairs: config.traversal_probe_max_pairs.get(),
                simultaneous_open_rounds: config.traversal_probe_simultaneous_open_rounds.get(),
                round_spacing_ms: config.traversal_probe_round_spacing_ms.get(),
                relay_switch_after_failures: config
                    .traversal_probe_relay_switch_after_failures
                    .get(),
                stun_servers: config.traversal_stun_servers.clone(),
                stun_gather_timeout_ms: config.traversal_stun_gather_timeout_ms.get(),
                pre_expiry_refresh_margin_secs: MIN_TRAVERSAL_REFRESH_MARGIN_SECS,
                pre_expiry_jitter_max_secs: MAX_TRAVERSAL_REFRESH_JITTER_SECS,
            },
            traversal_probe_handshake_freshness_secs: config
                .traversal_probe_handshake_freshness_secs
                .get(),
            traversal_probe_reprobe_interval_secs: config
                .traversal_probe_reprobe_interval_secs
                .get(),
            local_host_candidates: BTreeMap::new(),
            #[cfg(test)]
            test_local_host_candidates_snapshot: None,
            local_stun_observations: Vec::new(),
            local_stun_candidates: Vec::new(),
            next_stun_refresh_at: if config.traversal_stun_servers.is_empty()
                || transport_socket_identity_blocked
            {
                None
            } else {
                Some(Instant::now())
            },
            transport_socket_identity_blocker,
            trust_policy,
            selected_exit_node: None,
            lan_access_enabled: false,
            advertised_routes: BTreeSet::new(),
            restriction_mode: RestrictionMode::None,
            bootstrap_error: None,
            reconcile_attempts: 0,
            reconcile_failures: 0,
            last_reconcile_unix: None,
            last_reconcile_error: None,
            last_applied_assignment: None,
            local_route_reconcile_pending: false,
            max_reconcile_failures: config.max_reconcile_failures.get(),
            remote_ops_expected_subject: config.remote_ops_expected_subject.clone(),
            remote_ops_seen_nonces: BTreeMap::new(),
            remote_ops_verifying_key,
            membership_state: None,
            membership_directory: MembershipDirectory::default(),
            dns_zone: None,
            dns_zone_error: None,
            dns_zone_stale_rejections: 0,
            dns_zone_replay_rejections: 0,
            dns_zone_future_dated_rejections: 0,
            dns_zone_preexpiry_refresh_events: 0,
            dns_zone_last_preexpiry_refresh_unix: None,
            traversal_hints: None,
            verified_traversal_index: VerifiedTraversalIndex::new(),
            verified_traversal_coordination_index: BTreeMap::new(),
            traversal_coordination_replay_window: CoordinationReplayWindow::default(),
            traversal_hint_error: None,
            traversal_probe_statuses: BTreeMap::new(),
            traversal_stale_rejections: 0,
            traversal_replay_rejections: 0,
            traversal_future_dated_rejections: 0,
            traversal_preexpiry_refresh_events: 0,
            traversal_last_preexpiry_refresh_unix: None,
            traversal_endpoint_change_events: 0,
            traversal_last_endpoint_fingerprint: None,
            traversal_last_endpoint_change_unix: None,
            _endpoint_monitor: EndpointMonitor::new(vec![config.wg_interface.clone()]),
            auto_port_forward_exit: config.auto_port_forward_exit,
            #[cfg(target_os = "linux")]
            auto_port_forward_lease_secs: config.auto_port_forward_lease_secs.get(),
            exit_port_forward_last_error: None,
            #[cfg(target_os = "linux")]
            exit_port_forward_lease: None,
        })
    }

    fn load_verified_trust(&self) -> Result<TrustEvidence, TrustBootstrapError> {
        let previous_watermark = load_trust_watermark(&self.trust_watermark_path)?;
        let envelope = load_trust_evidence(
            &self.trust_evidence_path,
            &self.trust_verifier_key_path,
            self.trust_policy,
            previous_watermark,
        )?;
        persist_trust_watermark(&self.trust_watermark_path, envelope.watermark)?;
        Ok(envelope.evidence)
    }

    fn load_verified_membership(&self) -> Result<MembershipState, MembershipBootstrapError> {
        if !self.membership_snapshot_path.exists() {
            return Err(MembershipBootstrapError::MissingSnapshot);
        }
        if !self.membership_log_path.exists() {
            return Err(MembershipBootstrapError::MissingLog);
        }

        let snapshot = load_membership_snapshot(&self.membership_snapshot_path)
            .map_err(|err| MembershipBootstrapError::SnapshotLoad(err.to_string()))?;
        let entries = load_membership_log(&self.membership_log_path)
            .map_err(|err| MembershipBootstrapError::LogLoad(err.to_string()))?;
        let replayed = replay_membership_snapshot_and_log(&snapshot, &entries, unix_now())
            .map_err(|err| MembershipBootstrapError::Replay(err.to_string()))?;
        let state_root = replayed
            .state_root_hex()
            .map_err(|_| MembershipBootstrapError::InvalidRoot)?;
        let watermark = MembershipWatermark {
            epoch: replayed.epoch,
            state_root: state_root.clone(),
        };
        let previous = load_membership_watermark(&self.membership_watermark_path)
            .map_err(|err| MembershipBootstrapError::Io(err.to_string()))?;
        if let Some(previous) = previous {
            if watermark.epoch < previous.epoch
                || (watermark.epoch == previous.epoch
                    && watermark.state_root != previous.state_root)
            {
                return Err(MembershipBootstrapError::WatermarkReplay);
            }
        }
        persist_membership_watermark(&self.membership_watermark_path, &watermark)
            .map_err(|err| MembershipBootstrapError::Io(err.to_string()))?;

        let local_active = replayed.nodes.iter().any(|node| {
            node.node_id == self.local_node_id && node.status == MembershipNodeStatus::Active
        });
        if !local_active {
            return Err(MembershipBootstrapError::LocalNodeNotActive);
        }
        if let Some(exit_node) = self.selected_exit_node.as_deref() {
            let exit_active = replayed.nodes.iter().any(|node| {
                node.node_id == exit_node && node.status == MembershipNodeStatus::Active
            });
            if !exit_active {
                return Err(MembershipBootstrapError::ExitNodeNotActive(
                    exit_node.to_string(),
                ));
            }
        }

        Ok(replayed)
    }

    fn auto_tunnel_paths(&self) -> Result<(&Path, &Path, &Path), AutoTunnelBootstrapError> {
        // if !self.auto_tunnel_enforce {
        //     return Err(AutoTunnelBootstrapError::Disabled);
        // }
        let bundle_path = self.auto_tunnel_bundle_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_bundle_path"),
        )?;
        let verifier_path = self.auto_tunnel_verifier_key_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_verifier_key_path"),
        )?;
        let watermark_path = self.auto_tunnel_watermark_path.as_deref().ok_or(
            AutoTunnelBootstrapError::MissingConfig("auto_tunnel_watermark_path"),
        )?;
        Ok((bundle_path, verifier_path, watermark_path))
    }

    fn load_verified_auto_tunnel(
        &self,
        membership_directory: &MembershipDirectory,
    ) -> Result<AutoTunnelBundleEnvelope, AutoTunnelBootstrapError> {
        let (bundle_path, verifier_path, watermark_path) = self.auto_tunnel_paths()?;
        let previous_watermark = load_auto_tunnel_watermark(watermark_path)?;
        let envelope = load_auto_tunnel_bundle(
            bundle_path,
            verifier_path,
            self.auto_tunnel_max_age_secs,
            self.trust_policy,
            previous_watermark,
        )?;
        if envelope.bundle.node_id != self.local_node_id {
            return Err(AutoTunnelBootstrapError::WrongNode);
        }
        self.policy_gate_auto_tunnel(&envelope.bundle, membership_directory)?;
        persist_auto_tunnel_watermark(watermark_path, envelope.watermark)?;
        Ok(envelope)
    }

    fn policy_gate_auto_tunnel(
        &self,
        bundle: &AutoTunnelBundle,
        membership_directory: &MembershipDirectory,
    ) -> Result<(), AutoTunnelBootstrapError> {
        let subject = DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT;

        for peer in &bundle.peers {
            let decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: format!("node:{}", peer.node_id.as_str()),
                    protocol: Protocol::Any,
                    context: TrafficContext::Mesh,
                },
                membership_directory,
            );
            if decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "peer {} denied",
                    peer.node_id
                )));
            }
        }

        for route in &bundle.routes {
            let context = match route.kind {
                RouteKind::Mesh => TrafficContext::Mesh,
                RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan => TrafficContext::SharedExit,
            };
            let cidr_decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: route.destination_cidr.clone(),
                    protocol: Protocol::Any,
                    context,
                },
                membership_directory,
            );
            if cidr_decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "route {} denied",
                    route.destination_cidr
                )));
            }
            let via_decision = self.policy.evaluate_with_membership(
                &ContextualAccessRequest {
                    src: subject.to_string(),
                    dst: format!("node:{}", route.via_node.as_str()),
                    protocol: Protocol::Any,
                    context,
                },
                membership_directory,
            );
            if via_decision != Decision::Allow {
                return Err(AutoTunnelBootstrapError::PolicyDenied(format!(
                    "route via node {} denied",
                    route.via_node
                )));
            }
        }

        Ok(())
    }

    fn refresh_dns_zone_state(&mut self, auto_tunnel: Option<&AutoTunnelBundleEnvelope>) {
        self.dns_zone = None;
        self.dns_zone_error = None;

        if !self.dns_zone_bundle_path.exists() {
            return;
        }

        let Some(auto_tunnel) = auto_tunnel else {
            self.dns_zone_error = Some(
                "dns zone bundle present but signed assignment context is unavailable".to_string(),
            );
            return;
        };

        let previous_watermark = match load_dns_zone_watermark(&self.dns_zone_watermark_path) {
            Ok(value) => value,
            Err(err) => {
                self.dns_zone_error = Some(err.to_string());
                return;
            }
        };

        match load_dns_zone_bundle(DnsZoneLoadContext {
            path: &self.dns_zone_bundle_path,
            verifier_key_path: &self.dns_zone_verifier_key_path,
            max_age_secs: self.dns_zone_max_age_secs,
            trust_policy: self.trust_policy,
            previous_watermark,
            expected_zone_name: &self.dns_zone_name,
            local_node_id: &self.local_node_id,
            auto_tunnel: &auto_tunnel.bundle,
        }) {
            Ok(envelope) => {
                if let Err(err) =
                    persist_dns_zone_watermark(&self.dns_zone_watermark_path, envelope.watermark)
                {
                    self.dns_zone_error = Some(err.to_string());
                    return;
                }
                self.dns_zone = Some(envelope);
            }
            Err(err) => {
                self.record_dns_zone_bootstrap_error(&err);
                self.dns_zone_error = Some(err.to_string());
            }
        }
    }

    fn record_dns_zone_bootstrap_error(&mut self, err: &DnsZoneBootstrapError) {
        match err {
            DnsZoneBootstrapError::Stale => {
                self.dns_zone_stale_rejections = self.dns_zone_stale_rejections.saturating_add(1);
            }
            DnsZoneBootstrapError::ReplayDetected => {
                self.dns_zone_replay_rejections = self.dns_zone_replay_rejections.saturating_add(1);
            }
            DnsZoneBootstrapError::FutureDated => {
                self.dns_zone_future_dated_rejections =
                    self.dns_zone_future_dated_rejections.saturating_add(1);
            }
            DnsZoneBootstrapError::Missing
            | DnsZoneBootstrapError::Io(_)
            | DnsZoneBootstrapError::InvalidFormat(_)
            | DnsZoneBootstrapError::KeyInvalid
            | DnsZoneBootstrapError::SignatureInvalid
            | DnsZoneBootstrapError::WrongNode
            | DnsZoneBootstrapError::AssignmentMismatch(_) => {}
        }
    }

    fn dns_zone_next_preexpiry_refresh_target(&self, now_unix: u64) -> Option<u64> {
        let envelope = self.dns_zone.as_ref()?;
        let expires_at_unix = envelope.bundle.expires_at_unix;
        if expires_at_unix <= now_unix {
            return Some(now_unix);
        }
        let ttl_window = expires_at_unix.saturating_sub(now_unix);
        let margin = ttl_window.saturating_div(4).clamp(
            MIN_DNS_ZONE_REFRESH_MARGIN_SECS,
            MAX_DNS_ZONE_REFRESH_JITTER_SECS,
        );
        Some(expires_at_unix.saturating_sub(margin))
    }

    fn dns_zone_refresh_jitter_offset_secs(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.local_node_id.as_bytes());
        hasher.update(self.wg_interface.as_bytes());
        hasher.update(b"dns-zone-refresh");
        let digest = hasher.finalize();
        u64::from(digest[0]) % MAX_DNS_ZONE_REFRESH_JITTER_SECS
    }

    fn dns_zone_preexpiry_refresh_due(&self, now_unix: u64) -> bool {
        let Some(target_unix) = self.dns_zone_next_preexpiry_refresh_target(now_unix) else {
            return false;
        };
        let scheduled_unix = target_unix.saturating_sub(self.dns_zone_refresh_jitter_offset_secs());
        if now_unix < scheduled_unix {
            return false;
        }
        if let Some(last_refresh_unix) = self.dns_zone_last_preexpiry_refresh_unix
            && now_unix.saturating_sub(last_refresh_unix) < MIN_DNS_ZONE_REFRESH_COOLDOWN_SECS
        {
            return false;
        }
        true
    }

    fn maybe_preexpiry_refresh_dns_zone(
        &mut self,
        now_unix: u64,
        auto_tunnel: Option<&AutoTunnelBundleEnvelope>,
    ) {
        if !self.dns_zone_preexpiry_refresh_due(now_unix) {
            return;
        }
        self.dns_zone_preexpiry_refresh_events =
            self.dns_zone_preexpiry_refresh_events.saturating_add(1);
        self.dns_zone_last_preexpiry_refresh_unix = Some(now_unix);
        self.refresh_dns_zone_state(auto_tunnel);
    }

    fn dns_zone_status_summary(&self) -> (String, String, String) {
        let state = if self.dns_zone.is_some() {
            "valid"
        } else if self.dns_zone_error.is_some() {
            "invalid"
        } else {
            "absent"
        };
        let record_count = self
            .dns_zone
            .as_ref()
            .map(|envelope| envelope.bundle.records.len().to_string())
            .unwrap_or_else(|| "0".to_string());
        let error = self
            .dns_zone_error
            .as_deref()
            .map(sanitize_netcheck_value)
            .unwrap_or_else(|| "none".to_string());
        (state.to_string(), record_count, error)
    }

    fn dns_inspect_message(&self) -> String {
        let Some(envelope) = self.dns_zone.as_ref() else {
            if let Some(error) = self.dns_zone_error.as_deref() {
                return format!(
                    "dns inspect: state=invalid error={}",
                    sanitize_netcheck_value(error)
                );
            }
            return "dns inspect: state=absent".to_string();
        };

        let mut message = format!(
            "dns inspect: state=valid zone_name={} subject_node_id={} generated_at_unix={} expires_at_unix={} record_count={}",
            sanitize_netcheck_value(&envelope.bundle.zone_name),
            sanitize_netcheck_value(&envelope.bundle.subject_node_id),
            envelope.bundle.generated_at_unix,
            envelope.bundle.expires_at_unix,
            envelope.bundle.records.len()
        );
        for (index, record) in envelope.bundle.records.iter().enumerate() {
            let aliases = if record.aliases.is_empty() {
                "none".to_string()
            } else {
                sanitize_netcheck_value(
                    &record
                        .aliases
                        .iter()
                        .map(|alias| format!("{alias}.{}", envelope.bundle.zone_name))
                        .collect::<Vec<_>>()
                        .join(","),
                )
            };
            message.push('\n');
            message.push_str(&format!(
                "record.{index}.fqdn={} target_node_id={} rr_type={} target_addr_kind={} expected_ip={} ttl_secs={} aliases={}",
                sanitize_netcheck_value(&record.fqdn),
                sanitize_netcheck_value(&record.target_node_id),
                record.rr_type.as_str(),
                record.target_addr_kind.as_str(),
                sanitize_netcheck_value(&record.expected_ip),
                record.ttl_secs,
                aliases
            ));
        }
        message
    }

    fn resolve_dns_ipv4_record(&self, fqdn: &str) -> Option<(Ipv4Addr, u32)> {
        let envelope = self.dns_zone.as_ref()?;
        let normalized = fqdn.trim_end_matches('.').to_ascii_lowercase();
        for record in &envelope.bundle.records {
            if normalized == record.fqdn
                || record
                    .aliases
                    .iter()
                    .any(|alias| normalized == format!("{alias}.{}", envelope.bundle.zone_name))
            {
                let ip = record.expected_ip.parse::<Ipv4Addr>().ok()?;
                let ttl = u32::try_from(record.ttl_secs).ok()?;
                return Some((ip, ttl));
            }
        }
        None
    }

    fn update_verified_traversal_index(&mut self, envelope: &TraversalBundleSetEnvelope) {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();

        self.verified_traversal_index = VerifiedTraversalIndex::new();
        self.verified_traversal_coordination_index = BTreeMap::new();
        self.traversal_coordination_replay_window = CoordinationReplayWindow::default();

        for bundle_envelope in &envelope.bundles {
            let bundle = &bundle_envelope.bundle;

            let mut candidates = Vec::new();
            for cand in &bundle.candidates {
                let endpoint = SocketEndpoint {
                    addr: cand.endpoint.ip(),
                    port: cand.endpoint.port(),
                };
                let source = match cand.candidate_type {
                    TraversalCandidateType::Host => ProbeCandidateSource::Host,
                    TraversalCandidateType::ServerReflexive => {
                        ProbeCandidateSource::ServerReflexive
                    }
                    TraversalCandidateType::Relay => ProbeCandidateSource::Relay,
                };

                candidates.push(ProbeTraversalCandidate {
                    endpoint,
                    source,
                    priority: cand.priority,
                    observed_at_unix: bundle.generated_at_unix,
                });
            }

            let record = VerifiedTraversalRecord {
                candidates,
                generated_at_unix: bundle.generated_at_unix,
                expires_at_unix: bundle.expires_at_unix,
                nonce: bundle.nonce,
                verified_at_unix: now_unix,
            };

            self.verified_traversal_index.insert(
                bundle.source_node_id.clone(),
                bundle.target_node_id.clone(),
                record,
            );
        }

        for coordination in &envelope.coordinations {
            let key = traversal_coordination_pair_key(
                coordination.record.node_a.as_str(),
                coordination.record.node_b.as_str(),
            );
            self.verified_traversal_coordination_index
                .insert(key, coordination.record.clone());
        }
    }

    fn refresh_traversal_hint_state(&mut self, force_reprobe: bool) {
        let previous_watermark = match load_traversal_watermark(&self.traversal_watermark_path) {
            Ok(value) => value,
            Err(err) => {
                self.traversal_hints = None;
                self.traversal_hint_error = Some(err.to_string());
                self.traversal_coordination_replay_window = CoordinationReplayWindow::default();
                self.traversal_probe_statuses.clear();
                return;
            }
        };
        match load_traversal_bundle_set(
            &self.traversal_bundle_path,
            &self.traversal_verifier_key_path,
            self.traversal_max_age_secs,
            self.trust_policy,
            previous_watermark,
        ) {
            Ok(envelope) => {
                if let Err(err) =
                    persist_traversal_watermark(&self.traversal_watermark_path, envelope.watermark)
                {
                    self.traversal_hints = None;
                    self.traversal_hint_error = Some(err.to_string());
                    self.traversal_probe_statuses.clear();
                    return;
                }
                self.update_verified_traversal_index(&envelope);
                self.traversal_hints = Some(envelope);
                self.traversal_hint_error = None;
            }
            Err(TraversalBootstrapError::Missing) => {
                self.traversal_hints = None;
                self.verified_traversal_index = VerifiedTraversalIndex::new();
                self.verified_traversal_coordination_index = BTreeMap::new();
                self.traversal_coordination_replay_window = CoordinationReplayWindow::default();
                self.traversal_hint_error = None;
                self.traversal_probe_statuses.clear();
            }
            Err(err) => {
                self.record_traversal_bootstrap_error(&err);
                self.traversal_hints = None;
                self.verified_traversal_index = VerifiedTraversalIndex::new();
                self.verified_traversal_coordination_index = BTreeMap::new();
                self.traversal_coordination_replay_window = CoordinationReplayWindow::default();
                self.traversal_hint_error = Some(err.to_string());
                self.traversal_probe_statuses.clear();
            }
        }
        if let Err(err) = self.sync_traversal_runtime_state(force_reprobe) {
            self.traversal_hint_error = Some(err.clone());
            if self.traversal_authority_mode().is_enforced() {
                self.restrict_recoverable(format!("traversal runtime sync failed: {err}"));
                let _ = self
                    .controller
                    .force_fail_closed("traversal_runtime_sync_failed");
            }
        }
    }

    fn refresh_signed_state_with_reason(
        &mut self,
        force_reprobe: bool,
        reason: SignedStateRefreshReason,
    ) -> Result<(), String> {
        match self.state_fetcher.fetch_trust() {
            Ok(FetchDecision::Applied) => eprintln!("statefetch: trust applied during refresh"),
            Ok(FetchDecision::Skipped) => {}
            Err(e) => return Err(format!("remote trust fetch failed: {e}")),
        }
        match self.state_fetcher.fetch_traversal() {
            Ok(FetchDecision::Applied) => eprintln!("statefetch: traversal applied during refresh"),
            Ok(FetchDecision::Skipped) => {}
            Err(e) => return Err(format!("remote traversal fetch failed: {e}")),
        }
        if self.auto_tunnel_enforce {
            match self.state_fetcher.fetch_assignment() {
                Ok(FetchDecision::Applied) => {
                    eprintln!("statefetch: assignment applied during refresh")
                }
                Ok(FetchDecision::Skipped) => {}
                Err(e) => return Err(format!("remote assignment fetch failed: {e}")),
            }
        }
        // For dns_zone: load auto_bundle from disk first if enforced, for accurate context.
        let auto_bundle_for_dns = if self.auto_tunnel_enforce {
            // Load assignment bundle for context; if this fails, treat as no context.
            // Use a local load, not the full load_verified_auto_tunnel (which does full policy
            // enforcement) — we just need the bundle content for DNS zone context.
            // If load fails here, pass None (dns zone will use empty bundle context).
            self.try_load_auto_tunnel_bundle_for_dns_context().ok()
        } else {
            None
        };
        match self
            .state_fetcher
            .fetch_dns_zone(auto_bundle_for_dns.as_ref())
        {
            Ok(FetchDecision::Applied) => eprintln!("statefetch: dns zone applied during refresh"),
            Ok(FetchDecision::Skipped) => {}
            Err(e) => return Err(format!("remote dns zone fetch failed: {e}")),
        }

        let _trust = self
            .load_verified_trust()
            .map_err(|err| format!("signed trust refresh failed: {err}"))?;
        let membership_state = self
            .load_verified_membership()
            .map_err(|err| format!("signed membership refresh failed: {err}"))?;
        let membership_directory = membership_directory_from_state(&membership_state);
        let auto_bundle = if self.auto_tunnel_enforce {
            Some(
                self.load_verified_auto_tunnel(&membership_directory)
                    .map_err(|err| format!("signed assignment refresh failed: {err}"))?,
            )
        } else {
            None
        };

        self.membership_state = Some(membership_state);
        self.membership_directory = membership_directory;
        self.refresh_dns_zone_state(auto_bundle.as_ref());
        self.refresh_traversal_hint_state(force_reprobe);

        if self.traversal_authority_mode().is_enforced()
            && self.traversal_hints.is_none()
            && !self.controller.managed_peer_ids().is_empty()
        {
            return Err(
                "signed traversal refresh failed: traversal state missing while peers are managed"
                    .to_string(),
            );
        }

        self.restriction_mode = RestrictionMode::None;
        self.bootstrap_error = None;
        self.reconcile_failures = 0;
        self.last_reconcile_error = None;
        eprintln!(
            "rustynetd: signed state refresh completed (reason={})",
            reason.as_str()
        );
        Ok(())
    }

    fn record_traversal_bootstrap_error(&mut self, err: &TraversalBootstrapError) {
        match err {
            TraversalBootstrapError::Stale => {
                self.traversal_stale_rejections = self.traversal_stale_rejections.saturating_add(1);
            }
            TraversalBootstrapError::ReplayDetected => {
                self.traversal_replay_rejections =
                    self.traversal_replay_rejections.saturating_add(1);
            }
            TraversalBootstrapError::FutureDated => {
                self.traversal_future_dated_rejections =
                    self.traversal_future_dated_rejections.saturating_add(1);
            }
            TraversalBootstrapError::Missing
            | TraversalBootstrapError::Io(_)
            | TraversalBootstrapError::InvalidFormat(_)
            | TraversalBootstrapError::KeyInvalid
            | TraversalBootstrapError::SignatureInvalid => {}
        }
    }

    fn traversal_next_preexpiry_refresh_target(&self, now_unix: u64) -> Option<u64> {
        let envelope = self.traversal_hints.as_ref()?;
        let expires_at_unix = envelope
            .bundles
            .first()
            .map(|bundle| bundle.bundle.expires_at_unix)?;
        if expires_at_unix <= now_unix {
            return Some(now_unix);
        }
        let ttl_window = expires_at_unix.saturating_sub(now_unix);
        let margin = ttl_window.saturating_div(4).clamp(
            MIN_TRAVERSAL_REFRESH_MARGIN_SECS,
            MAX_TRAVERSAL_REFRESH_JITTER_SECS,
        );
        Some(expires_at_unix.saturating_sub(margin))
    }

    fn traversal_refresh_jitter_offset_secs(&self) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(self.local_node_id.as_bytes());
        hasher.update(self.wg_interface.as_bytes());
        let digest = hasher.finalize();
        u64::from(digest[0]) % MAX_TRAVERSAL_REFRESH_JITTER_SECS
    }

    fn traversal_preexpiry_refresh_due(&self, now_unix: u64) -> bool {
        let Some(target_unix) = self.traversal_next_preexpiry_refresh_target(now_unix) else {
            return false;
        };
        let scheduled_unix =
            target_unix.saturating_sub(self.traversal_refresh_jitter_offset_secs());
        if now_unix < scheduled_unix {
            return false;
        }
        if let Some(last_refresh_unix) = self.traversal_last_preexpiry_refresh_unix
            && now_unix.saturating_sub(last_refresh_unix) < MIN_TRAVERSAL_REFRESH_COOLDOWN_SECS
        {
            return false;
        }
        true
    }

    fn maybe_preexpiry_refresh_traversal(&mut self, now_unix: u64) {
        if !self.traversal_preexpiry_refresh_due(now_unix) {
            return;
        }
        self.traversal_preexpiry_refresh_events =
            self.traversal_preexpiry_refresh_events.saturating_add(1);
        self.traversal_last_preexpiry_refresh_unix = Some(now_unix);
        if let Err(err) =
            self.refresh_signed_state_with_reason(true, SignedStateRefreshReason::PreExpiry)
        {
            self.restrict_recoverable(err);
            let _ = self
                .controller
                .force_fail_closed("preexpiry_signed_state_refresh_failed");
        }
    }

    fn compute_runtime_endpoint_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.local_node_id.as_bytes());
        hasher.update(self.wg_interface.as_bytes());
        #[cfg(target_os = "linux")]
        {
            hasher.update(self.egress_interface.as_bytes());
            match detect_ipv4_default_gateway_for_interface(self.egress_interface.as_str()) {
                Ok(gateway) => hasher.update(gateway.octets()),
                Err(err) => hasher.update(format!("gateway-error:{err}").as_bytes()),
            }
        }
        hasher.update(self.wg_listen_port.to_be_bytes());
        if let Some(envelope) = self.traversal_hints.as_ref() {
            for bundle in &envelope.bundles {
                hasher.update(bundle.bundle.source_node_id.as_bytes());
                hasher.update(bundle.bundle.target_node_id.as_bytes());
                for candidate in &bundle.bundle.candidates {
                    hasher.update(candidate.candidate_type.as_str().as_bytes());
                    hasher.update(candidate.endpoint.ip().to_string().as_bytes());
                    hasher.update(candidate.endpoint.port().to_be_bytes());
                    hasher.update(candidate.priority.to_be_bytes());
                    if let Some(relay_id) = candidate.relay_id.as_deref() {
                        hasher.update(relay_id.as_bytes());
                    }
                }
            }
        } else if let Some(err) = self.traversal_hint_error.as_deref() {
            hasher.update(err.as_bytes());
        } else {
            hasher.update(b"no-traversal-hints");
        }
        encode_hex(&hasher.finalize())
    }

    fn maybe_trigger_endpoint_change_refresh(&mut self) {
        let fingerprint = self.compute_runtime_endpoint_fingerprint();
        match self.traversal_last_endpoint_fingerprint.as_deref() {
            Some(previous) if previous == fingerprint.as_str() => {}
            Some(_) => {
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                if let Some(last) = self.traversal_last_endpoint_change_unix {
                    if now_unix < last.saturating_add(MIN_ENDPOINT_CHANGE_STABILITY_SECS) {
                        return;
                    }
                }

                self.traversal_endpoint_change_events =
                    self.traversal_endpoint_change_events.saturating_add(1);
                self.traversal_last_endpoint_fingerprint = Some(fingerprint);
                self.traversal_last_endpoint_change_unix = Some(now_unix);
                if let Err(err) = self.refresh_signed_state_with_reason(
                    true,
                    SignedStateRefreshReason::EndpointChange,
                ) {
                    self.restrict_recoverable(err);
                    let _ = self
                        .controller
                        .force_fail_closed("endpoint_change_signed_state_refresh_failed");
                }
            }
            None => {
                self.traversal_last_endpoint_fingerprint = Some(fingerprint);
            }
        }
    }

    /// Poll the EndpointMonitor for NIC address changes; trigger a signed-state
    /// refresh whenever a routable address is added, removed, or changes on any
    /// non-WireGuard interface.  This supplements the coarser fingerprint-based
    /// detection in `maybe_trigger_endpoint_change_refresh`.
    #[cfg(target_os = "linux")]
    fn poll_endpoint_monitor_and_maybe_refresh(&mut self) {
        let current = collect_linux_interface_addrs();
        if snapshot_has_usable_traversal_host_candidates(&current) {
            self.local_host_candidates = current.clone();
        }
        if self._endpoint_monitor.poll_with_addrs(current).is_some() {
            self.maybe_trigger_endpoint_change_refresh();
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn poll_endpoint_monitor_and_maybe_refresh(&mut self) {
        // EndpointMonitor NIC polling is Linux-only; the fingerprint-based
        // change detection in maybe_trigger_endpoint_change_refresh() handles
        // other platforms.
    }

    fn traversal_alarm_state(&self, now_unix: u64) -> (&'static str, String) {
        if let Some(err) = self.traversal_hint_error.as_deref() {
            return ("error", sanitize_netcheck_value(err));
        }
        let Some(envelope) = self.traversal_hints.as_ref() else {
            return ("missing", "signed_traversal_state_missing".to_string());
        };
        let Some(expires_at) = envelope
            .bundles
            .first()
            .map(|bundle| bundle.bundle.expires_at_unix)
        else {
            return ("error", "signed_traversal_bundle_set_empty".to_string());
        };
        let remaining_secs = expires_at.saturating_sub(now_unix);
        if remaining_secs == 0 {
            ("critical", "signed_traversal_state_expired".to_string())
        } else if remaining_secs <= MIN_TRAVERSAL_REFRESH_MARGIN_SECS {
            ("warning", "signed_traversal_state_near_expiry".to_string())
        } else {
            ("ok", "none".to_string())
        }
    }

    fn dns_zone_alarm_state(&self, now_unix: u64) -> (&'static str, String) {
        if let Some(err) = self.dns_zone_error.as_deref() {
            return ("error", sanitize_netcheck_value(err));
        }
        let Some(envelope) = self.dns_zone.as_ref() else {
            return ("missing", "signed_dns_zone_state_missing".to_string());
        };
        let expires_at = envelope.bundle.expires_at_unix;
        let remaining_secs = expires_at.saturating_sub(now_unix);
        if remaining_secs == 0 {
            ("critical", "signed_dns_zone_state_expired".to_string())
        } else if remaining_secs <= MIN_DNS_ZONE_REFRESH_MARGIN_SECS {
            ("warning", "signed_dns_zone_state_near_expiry".to_string())
        } else {
            ("ok", "none".to_string())
        }
    }

    fn poll_stun_results(&mut self) {
        let Some(next_refresh_at) = self.next_stun_refresh_at else {
            return;
        };
        let now = Instant::now();
        if now < next_refresh_at {
            return;
        }
        self.next_stun_refresh_at =
            Some(now + Duration::from_secs(DEFAULT_TRAVERSAL_STUN_GATHER_INTERVAL_SECS));
        if self.transport_socket_identity_blocker.is_some()
            || self.traversal_probe_config.stun_servers.is_empty()
        {
            return;
        }

        let client = StunClient::new(
            self.traversal_probe_config
                .stun_servers
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            Duration::from_millis(self.traversal_probe_config.stun_gather_timeout_ms),
        );
        let results = client.gather_mapped_endpoints_with_round_trip(|target, request, timeout| {
            self.controller
                .authoritative_transport_round_trip(target, request, timeout)
                .map(|response| StunTransportRoundTrip {
                    response: response.payload,
                    remote_addr: response.remote_addr,
                    local_addr: response.local_addr,
                })
                .map_err(|err| err.to_string())
        });
        self.local_stun_observations = results.clone();
        self.local_stun_candidates = results
            .into_iter()
            .map(|result| result.mapped_endpoint)
            .collect();
        if !self.local_stun_candidates.is_empty() {
            eprintln!(
                "rustynetd: authoritative stun candidates updated: {:?}",
                self.local_stun_candidates
            );
        }
    }

    fn stun_candidate_local_addrs(&self) -> String {
        format_stun_local_addrs(&self.local_stun_observations)
    }

    fn stun_transport_port_binding(&self) -> &'static str {
        stun_local_port_match_state(&self.local_stun_observations, self.wg_listen_port)
    }

    fn transport_socket_identity_requested(&self) -> bool {
        self.relay_client.is_some() || !self.traversal_probe_config.stun_servers.is_empty()
    }

    fn transport_socket_identity_state(&self) -> &'static str {
        if self.transport_socket_identity_blocker.is_some() {
            "blocked_backend_opaque_socket"
        } else if self.controller.authoritative_transport_identity().is_some() {
            "authoritative_backend_shared_transport"
        } else if self.transport_socket_identity_requested() {
            "authoritative_backend_shared_transport_unavailable"
        } else {
            "not_required"
        }
    }

    fn transport_socket_identity_error(&self) -> String {
        if let Some(blocker) = self.transport_socket_identity_blocker.as_deref() {
            sanitize_netcheck_value(blocker)
        } else if self.transport_socket_identity_requested()
            && self.controller.authoritative_transport_identity().is_none()
        {
            "backend_authoritative_shared_transport_not_exposed".to_string()
        } else {
            "none".to_string()
        }
    }

    fn transport_socket_identity_label(&self) -> String {
        self.controller
            .authoritative_transport_identity()
            .map(|identity| sanitize_netcheck_value(&identity.label))
            .unwrap_or_else(|| "none".to_string())
    }

    fn transport_socket_identity_local_addr(&self) -> String {
        self.controller
            .authoritative_transport_identity()
            .map(|identity| sanitize_netcheck_value(&identity.local_addr.to_string()))
            .unwrap_or_else(|| "none".to_string())
    }

    fn selected_exit_peer_endpoint_summary(&self) -> (String, String) {
        let Some(selected_exit_node) = self.selected_exit_node.as_deref() else {
            return ("none".to_string(), "none".to_string());
        };
        let node_id = match NodeId::new(selected_exit_node.to_string()) {
            Ok(node_id) => node_id,
            Err(err) => {
                return (
                    "none".to_string(),
                    sanitize_netcheck_value(&err.to_string()),
                );
            }
        };
        match self.controller.current_peer_endpoint(&node_id) {
            Ok(Some(endpoint)) => (
                sanitize_netcheck_value(&format!("{}:{}", endpoint.addr, endpoint.port)),
                "none".to_string(),
            ),
            Ok(None) => ("none".to_string(), "none".to_string()),
            Err(err) => (
                "none".to_string(),
                sanitize_netcheck_value(&err.to_string()),
            ),
        }
    }

    fn managed_peer_endpoints_summary(&self) -> (String, String) {
        match self.controller.current_peer_endpoints() {
            Ok(endpoints) => {
                if endpoints.is_empty() {
                    return ("none".to_string(), "none".to_string());
                }
                let summary = endpoints
                    .into_iter()
                    .map(|(node_id, endpoint)| match endpoint {
                        Some(endpoint) => format!(
                            "{node_id}/{addr}:{port}",
                            addr = endpoint.addr,
                            port = endpoint.port
                        ),
                        None => format!("{node_id}/none"),
                    })
                    .collect::<Vec<_>>()
                    .join("+");
                (sanitize_netcheck_value(&summary), "none".to_string())
            }
            Err(err) => (
                "none".to_string(),
                sanitize_netcheck_value(&err.to_string()),
            ),
        }
    }

    fn relay_session_inactive_state(&self) -> &'static str {
        if self.relay_client.is_some() {
            if self.transport_socket_identity_blocker.is_some() {
                "blocked_transport_identity"
            } else if self.controller.authoritative_transport_identity().is_none() {
                "unavailable_authoritative_transport"
            } else {
                "unused"
            }
        } else {
            "disabled"
        }
    }

    fn netcheck_response_line(&self) -> String {
        let path_state = self.runtime_path_state_summary();
        let path_mode = path_state.live_mode;
        let path_reason = sanitize_netcheck_value(path_state.live_reason.as_str());
        let path_programmed_mode = path_state.programmed_mode;
        let path_programmed_reason = sanitize_netcheck_value(path_state.programmed_reason.as_str());
        let path_live_proven = if path_state.live_proven {
            "true"
        } else {
            "false"
        };
        let path_latest_live_handshake_unix = path_state
            .latest_live_handshake_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        let relay_session_configured = if path_state.relay_session_configured {
            "true"
        } else {
            "false"
        };
        let relay_session_next_expiry_unix = path_state
            .relay_session_next_expiry_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        let traversal_authority = self.traversal_authority_mode().as_str();
        let (
            probe_result,
            probe_reason,
            probe_attempts,
            probe_endpoint,
            probe_handshake_unix,
            probe_next_reprobe_unix,
            probe_peer_count,
            probe_direct_peers,
            probe_relay_peers,
        ) = self.traversal_probe_summary();

        let now = unix_now();
        let (traversal_status, source, target, generated_at, expires_at, age_secs, remaining_secs) =
            if let Some(envelope) = self.traversal_hints.as_ref() {
                let generated = envelope
                    .bundles
                    .first()
                    .map(|bundle| bundle.bundle.generated_at_unix)
                    .unwrap_or(0);
                let expires = envelope
                    .bundles
                    .first()
                    .map(|bundle| bundle.bundle.expires_at_unix)
                    .unwrap_or(0);
                let age = now.saturating_sub(generated);
                let remaining = expires.saturating_sub(now);
                let mut sources = BTreeSet::new();
                let mut targets = BTreeSet::new();
                for bundle in &envelope.bundles {
                    sources.insert(bundle.bundle.source_node_id.as_str());
                    targets.insert(bundle.bundle.target_node_id.as_str());
                }
                (
                    "valid",
                    if sources.len() == 1 {
                        sources.iter().next().copied().unwrap_or("none")
                    } else {
                        "multiple"
                    },
                    if targets.len() == 1 {
                        targets.iter().next().copied().unwrap_or("none")
                    } else {
                        "multiple"
                    },
                    generated.to_string(),
                    expires.to_string(),
                    age.to_string(),
                    remaining.to_string(),
                )
            } else if self.traversal_hint_error.is_some() {
                (
                    "invalid",
                    "none",
                    "none",
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                )
            } else {
                (
                    "missing",
                    "none",
                    "none",
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                    "none".to_string(),
                )
            };

        let mut host_candidates = 0usize;
        let mut srflx_candidates = 0usize;
        let mut relay_candidates = 0usize;
        let mut candidate_count = 0usize;
        let mut max_candidate_priority: Option<u32> = None;
        let traversal_peer_count = self
            .traversal_hints
            .as_ref()
            .map(|envelope| envelope.bundles.len())
            .unwrap_or(0);
        if let Some(envelope) = self.traversal_hints.as_ref() {
            for bundle in &envelope.bundles {
                candidate_count = candidate_count.saturating_add(bundle.bundle.candidates.len());
                for candidate in &bundle.bundle.candidates {
                    max_candidate_priority =
                        Some(max_candidate_priority.unwrap_or(0).max(candidate.priority));
                    match candidate.candidate_type {
                        TraversalCandidateType::Host => {
                            host_candidates = host_candidates.saturating_add(1)
                        }
                        TraversalCandidateType::ServerReflexive => {
                            srflx_candidates = srflx_candidates.saturating_add(1)
                        }
                        TraversalCandidateType::Relay => {
                            relay_candidates = relay_candidates.saturating_add(1)
                        }
                    }
                }
            }
        }

        let traversal_error = self
            .traversal_hint_error
            .as_deref()
            .map(sanitize_netcheck_value)
            .unwrap_or_else(|| "none".to_string());
        let traversal_probe_max_candidates = self.traversal_probe_config.max_candidates;
        let traversal_probe_max_pairs = self.traversal_probe_config.max_probe_pairs;
        let traversal_probe_rounds = self.traversal_probe_config.simultaneous_open_rounds;
        let traversal_probe_round_spacing_ms = self.traversal_probe_config.round_spacing_ms;
        let traversal_probe_relay_switch_after_failures =
            self.traversal_probe_config.relay_switch_after_failures;
        let traversal_probe_handshake_freshness_secs =
            self.traversal_probe_handshake_freshness_secs;
        let traversal_probe_reprobe_interval_secs = self.traversal_probe_reprobe_interval_secs;
        let max_candidate_priority = max_candidate_priority
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        let traversal_preexpiry_refresh_events = self.traversal_preexpiry_refresh_events;
        let traversal_last_preexpiry_refresh_unix = self
            .traversal_last_preexpiry_refresh_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        let traversal_stale_rejections = self.traversal_stale_rejections;
        let traversal_replay_rejections = self.traversal_replay_rejections;
        let traversal_future_dated_rejections = self.traversal_future_dated_rejections;
        let traversal_endpoint_change_events = self.traversal_endpoint_change_events;
        let traversal_endpoint_fingerprint = self
            .traversal_last_endpoint_fingerprint
            .as_deref()
            .map(sanitize_netcheck_value)
            .unwrap_or_else(|| "none".to_string());
        let (traversal_alarm_state, traversal_alarm_reason) = self.traversal_alarm_state(now);
        let (dns_alarm_state, dns_alarm_reason) = self.dns_zone_alarm_state(now);
        let dns_preexpiry_refresh_events = self.dns_zone_preexpiry_refresh_events;
        let dns_last_preexpiry_refresh_unix = self
            .dns_zone_last_preexpiry_refresh_unix
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".to_string());
        let dns_stale_rejections = self.dns_zone_stale_rejections;
        let dns_replay_rejections = self.dns_zone_replay_rejections;
        let dns_future_dated_rejections = self.dns_zone_future_dated_rejections;
        let stun_candidates = if self.local_stun_candidates.is_empty() {
            "none".to_string()
        } else {
            self.local_stun_candidates
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<_>>()
                .join(",")
        };
        let stun_candidate_local_addrs = self.stun_candidate_local_addrs();
        let stun_transport_port_binding = self.stun_transport_port_binding();
        let transport_socket_identity_state = self.transport_socket_identity_state();
        let transport_socket_identity_error = self.transport_socket_identity_error();
        let transport_socket_identity_label = self.transport_socket_identity_label();
        let transport_socket_identity_local_addr = self.transport_socket_identity_local_addr();
        let local_host_candidates = if self.local_host_candidates.is_empty() {
            "none".to_string()
        } else {
            self.local_host_candidates
                .iter()
                .map(|(iface, addrs)| {
                    let ips = addrs
                        .iter()
                        .map(|addr| addr.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    format!("{iface}={ips}")
                })
                .collect::<Vec<_>>()
                .join(",")
        };
        format!(
            "netcheck: path_mode={path_mode} path_reason={path_reason} path_programmed_mode={path_programmed_mode} path_programmed_reason={path_programmed_reason} path_live_proven={path_live_proven} path_programmed_peer_count={} path_live_peer_count={} path_programmed_direct_peers={} path_programmed_relay_peers={} path_live_direct_peers={} path_live_relay_peers={} path_latest_live_handshake_unix={path_latest_live_handshake_unix} relay_session_configured={relay_session_configured} relay_session_state={} relay_session_established_peers={} relay_session_expired_peers={} relay_session_next_expiry_unix={relay_session_next_expiry_unix} transport_socket_identity_state={transport_socket_identity_state} transport_socket_identity_error={transport_socket_identity_error} transport_socket_identity_label={transport_socket_identity_label} transport_socket_identity_local_addr={transport_socket_identity_local_addr} traversal_authority={traversal_authority} traversal_status={traversal_status} traversal_source={source} traversal_target={target} traversal_generated_at_unix={generated_at} traversal_expires_at_unix={expires_at} traversal_age_secs={age_secs} traversal_remaining_secs={remaining_secs} traversal_peer_count={traversal_peer_count} candidate_count={candidate_count} host_candidates={host_candidates} srflx_candidates={srflx_candidates} relay_candidates={relay_candidates} max_candidate_priority={max_candidate_priority} traversal_probe_max_candidates={traversal_probe_max_candidates} traversal_probe_max_pairs={traversal_probe_max_pairs} traversal_probe_rounds={traversal_probe_rounds} traversal_probe_round_spacing_ms={traversal_probe_round_spacing_ms} traversal_probe_relay_switch_after_failures={traversal_probe_relay_switch_after_failures} traversal_probe_handshake_freshness_secs={traversal_probe_handshake_freshness_secs} traversal_probe_reprobe_interval_secs={traversal_probe_reprobe_interval_secs} traversal_probe_result={probe_result} traversal_probe_reason={probe_reason} traversal_probe_attempts={probe_attempts} traversal_probe_endpoint={probe_endpoint} traversal_probe_latest_handshake_unix={probe_handshake_unix} traversal_probe_next_reprobe_unix={probe_next_reprobe_unix} traversal_probe_peer_count={probe_peer_count} traversal_probe_direct_peers={probe_direct_peers} traversal_probe_relay_peers={probe_relay_peers} traversal_preexpiry_refresh_events={traversal_preexpiry_refresh_events} traversal_last_preexpiry_refresh_unix={traversal_last_preexpiry_refresh_unix} traversal_stale_rejections={traversal_stale_rejections} traversal_replay_rejections={traversal_replay_rejections} traversal_future_dated_rejections={traversal_future_dated_rejections} traversal_endpoint_change_events={traversal_endpoint_change_events} traversal_endpoint_fingerprint={traversal_endpoint_fingerprint} traversal_alarm_state={traversal_alarm_state} traversal_alarm_reason={traversal_alarm_reason} dns_alarm_state={dns_alarm_state} dns_alarm_reason={dns_alarm_reason} dns_preexpiry_refresh_events={dns_preexpiry_refresh_events} dns_last_preexpiry_refresh_unix={dns_last_preexpiry_refresh_unix} dns_stale_rejections={dns_stale_rejections} dns_replay_rejections={dns_replay_rejections} dns_future_dated_rejections={dns_future_dated_rejections} traversal_error={traversal_error} stun_candidates={stun_candidates} stun_candidate_local_addrs={stun_candidate_local_addrs} stun_transport_port_binding={stun_transport_port_binding} local_host_candidates={local_host_candidates}",
            path_state.programmed_peer_count,
            path_state.live_peer_count,
            path_state.programmed_direct_peers,
            path_state.programmed_relay_peers,
            path_state.live_direct_peers,
            path_state.live_relay_peers,
            path_state.relay_session_state,
            path_state.relay_session_established_peers,
            path_state.relay_session_expired_peers,
        )
    }

    fn all_local_candidates(&self) -> Vec<ProbeTraversalCandidate> {
        let mut candidates = Vec::new();
        // Host candidates
        for (iface, addrs) in &self.local_host_candidates {
            if !interface_name_is_usable_for_traversal_host_candidate(iface.as_str()) {
                continue;
            }
            for ip in addrs {
                if !ip_is_usable_for_traversal_host_candidate(*ip) {
                    continue;
                }

                candidates.push(ProbeTraversalCandidate {
                    endpoint: SocketEndpoint {
                        addr: *ip,
                        port: self.wg_listen_port,
                    },
                    source: ProbeCandidateSource::Host,
                    priority: 300,
                    observed_at_unix: unix_now(),
                });
            }
        }
        // STUN candidates
        for endpoint in &self.local_stun_candidates {
            candidates.push(ProbeTraversalCandidate {
                endpoint: SocketEndpoint {
                    addr: endpoint.ip(),
                    port: endpoint.port(),
                },
                source: ProbeCandidateSource::ServerReflexive,
                priority: 200,
                observed_at_unix: unix_now(),
            });
        }
        candidates
    }

    fn refresh_local_host_candidates_for_traversal(&mut self) {
        #[cfg(test)]
        if let Some(snapshot) = self.test_local_host_candidates_snapshot.clone() {
            self.local_host_candidates = snapshot;
        }

        #[cfg(target_os = "linux")]
        {
            let current = collect_linux_interface_addrs_for_traversal();
            if snapshot_has_usable_traversal_host_candidates(&current) {
                self.local_host_candidates = current;
            }
        }
    }

    fn sync_traversal_runtime_state(&mut self, force_reprobe: bool) -> Result<(), String> {
        let now_unix = unix_now();
        if let Some(mut relay_client) = self.relay_client.take() {
            let freshness_secs = self.traversal_probe_handshake_freshness_secs;
            let active_relay_peers = self
                .traversal_probe_statuses
                .iter()
                .filter(|(_node_id, status)| {
                    status.decision == TraversalProbeDecision::Relay
                        && status
                            .latest_handshake_unix
                            .map(|timestamp| now_unix.saturating_sub(timestamp) <= freshness_secs)
                            .unwrap_or(false)
                })
                .map(|(node_id, _status)| node_id.clone())
                .collect::<Vec<_>>();
            for node_id in active_relay_peers {
                relay_client.touch_session(&node_id);
            }
            if self.transport_socket_identity_blocker.is_none() {
                for peer_node_id in relay_client.sessions_needing_keepalive() {
                    if let Err(err) = relay_client.send_keepalive_with_sender(
                        &peer_node_id,
                        |remote_addr, payload| {
                            self.controller
                                .authoritative_transport_send(remote_addr, payload)
                                .map(|_| ())
                                .map_err(|error| {
                                    RelayClientError::AuthoritativeTransport(error.to_string())
                                })
                        },
                    ) {
                        eprintln!(
                            "rustynetd: relay keepalive failed for peer {}: {err}",
                            peer_node_id.as_str()
                        );
                    }
                }
            }
            relay_client
                .cleanup_idle_sessions(Duration::from_secs(self.relay_session_idle_timeout_secs));
            self.relay_client = Some(relay_client);
        }
        if !matches!(
            self.controller.state(),
            DataplaneState::DataplaneApplied | DataplaneState::ExitActive
        ) {
            self.traversal_probe_statuses.clear();
            return Ok(());
        }

        if let Some(err) = self.traversal_hint_error.as_deref()
            && self.traversal_authority_mode().is_enforced()
        {
            self.traversal_probe_statuses.clear();
            return Err(format!(
                "traversal authority rejected invalid traversal state: {err}"
            ));
        }

        let Some(envelope) = self.traversal_hints.clone() else {
            self.traversal_probe_statuses.clear();
            if self.traversal_authority_mode().is_enforced()
                && !self.controller.managed_peer_ids().is_empty()
            {
                return Err(
                    "traversal authority requires signed traversal state for all managed peers"
                        .to_string(),
                );
            }
            return Ok(());
        };

        let traversal_index =
            self.build_verified_traversal_index(&self.membership_directory, &envelope)?;
        let managed_peer_ids = self.controller.managed_peer_ids();
        let managed_peer_set = managed_peer_ids.iter().cloned().collect::<BTreeSet<_>>();
        let indexed_peer_set = traversal_index.keys().cloned().collect::<BTreeSet<_>>();
        let extra_peers = indexed_peer_set
            .difference(&managed_peer_set)
            .map(|node_id| node_id.as_str().to_string())
            .collect::<Vec<_>>();
        if !extra_peers.is_empty() {
            self.traversal_probe_statuses.clear();
            return Err(format!(
                "traversal authority snapshot contains unmanaged peers: {}",
                extra_peers.join(",")
            ));
        }
        self.refresh_local_host_candidates_for_traversal();
        let local_candidates = self.all_local_candidates();
        let previous_statuses = self.traversal_probe_statuses.clone();
        let mut statuses = BTreeMap::new();
        for remote_node_id in managed_peer_ids {
            let Some(bundle) = traversal_index.get(&remote_node_id) else {
                self.traversal_probe_statuses.clear();
                return Err(format!(
                    "traversal authority is missing signed traversal state for managed peer {}",
                    remote_node_id.as_str()
                ));
            };
            let endpoints = select_runtime_traversal_endpoints(&bundle.bundle.candidates);
            let relay_endpoint = endpoints.1;
            let direct_candidates = traversal_direct_probe_candidates(
                &bundle.bundle.candidates,
                bundle.bundle.generated_at_unix,
            );
            if direct_candidates.is_empty() && relay_endpoint.is_none() {
                self.traversal_probe_statuses.clear();
                return Err(format!(
                    "traversal bundle for peer {} contains no usable runtime endpoints",
                    remote_node_id.as_str()
                ));
            }

            let existing_status = previous_statuses.get(&remote_node_id);
            let current = TraversalProbeCurrentState {
                path: self.controller.peer_path(&remote_node_id),
                endpoint: self.controller.managed_peer_endpoint(&remote_node_id),
                latest_handshake_unix: self
                    .controller
                    .managed_peer_latest_handshake_unix(&remote_node_id)
                    .map_err(|err| {
                        format!(
                            "traversal authority failed to read handshake evidence for peer {}: {err}",
                            remote_node_id.as_str()
                        )
                    })?,
            };
            if self.relay_client.is_some()
                && matches!(current.path, Some(PathMode::Relay))
                && relay_endpoint.is_none()
            {
                self.close_relay_session(&remote_node_id);
                self.traversal_probe_statuses.clear();
                return Err(format!(
                    "traversal authority removed the relay candidate required for active relay peer {}",
                    remote_node_id.as_str()
                ));
            }

            let relay_refresh_due =
                self.relay_session_refresh_due(&remote_node_id, bundle, now_unix)?;
            let probe_due = self.traversal_probe_due(
                current,
                &direct_candidates,
                existing_status,
                now_unix,
                force_reprobe,
            );

            let relay_endpoint = if self.relay_client.is_some() {
                if probe_due
                    || relay_refresh_due
                    || matches!(current.path, Some(PathMode::Relay))
                    || matches!(
                        existing_status.map(|status| status.decision),
                        Some(TraversalProbeDecision::Relay)
                    )
                {
                    self.resolve_relay_client_endpoint(&remote_node_id, bundle, now_unix)?
                } else {
                    self.relay_client
                        .as_ref()
                        .and_then(|client| client.relay_endpoint_for_peer(&remote_node_id))
                }
            } else {
                relay_endpoint
            };

            self.controller
                .configure_traversal_paths(&remote_node_id, None, relay_endpoint)
                .map_err(|err| {
                    format!(
                        "traversal authority failed to refresh relay path for peer {}: {err}",
                        remote_node_id.as_str()
                    )
                })?;

            let current_endpoint = self.controller.managed_peer_endpoint(&remote_node_id);
            let latest_handshake_unix = self
                .controller
                .managed_peer_latest_handshake_unix(&remote_node_id)
                .map_err(|err| {
                    format!(
                        "traversal authority failed to read handshake evidence for peer {}: {err}",
                        remote_node_id.as_str()
                    )
                })?;
            if matches!(current.path, Some(PathMode::Relay))
                && self.traversal_handshake_is_fresh(latest_handshake_unix, now_unix)
                && let Some(relay_client) = self.relay_client.as_mut()
            {
                relay_client.touch_session(&remote_node_id);
            }

            if !probe_due {
                let mut retained = existing_status.cloned().ok_or_else(|| {
                    format!(
                        "traversal probe scheduling lost prior state for managed peer {}",
                        remote_node_id.as_str()
                    )
                })?;
                if let Some(endpoint) = current_endpoint {
                    retained.selected_endpoint = endpoint;
                }
                retained.latest_handshake_unix =
                    latest_handshake_unix.or(retained.latest_handshake_unix);
                statuses.insert(remote_node_id.clone(), retained);
                continue;
            }

            let (coordination_schedule, coordination_error) = if direct_candidates.is_empty() {
                (None, None)
            } else {
                match self.validated_traversal_coordination_schedule(&remote_node_id, now_unix) {
                    Ok(schedule) => (schedule, None),
                    Err(err) => (None, Some(err)),
                }
            };

            let report = self
                .controller
                .evaluate_traversal_probes(
                    &remote_node_id,
                    TraversalProbeEvaluation {
                        local_candidates: &local_candidates,
                        direct_candidates: &direct_candidates,
                        relay_endpoint,
                        now_unix,
                        engine_config: self.traversal_probe_config.clone(),
                        handshake_freshness_secs: self.traversal_probe_handshake_freshness_secs,
                        coordination_schedule,
                        coordination_error,
                    },
                )
                .map_err(|err| {
                    format!(
                        "traversal authority failed to program peer {}: {err}",
                        remote_node_id.as_str()
                    )
                })?;
            if report.decision == TraversalProbeDecision::Direct {
                self.close_relay_session(&remote_node_id);
            } else if self.traversal_handshake_is_fresh(report.latest_handshake_unix, now_unix)
                && let Some(relay_client) = self.relay_client.as_mut()
            {
                relay_client.touch_session(&remote_node_id);
            }
            statuses.insert(
                remote_node_id.clone(),
                TraversalProbeStatus {
                    remote_node_id: remote_node_id.as_str().to_string(),
                    decision: report.decision,
                    reason: report.reason,
                    attempts: report.attempts,
                    selected_endpoint: report.selected_endpoint,
                    latest_handshake_unix: report.latest_handshake_unix,
                    evaluated_at_unix: now_unix,
                    next_reprobe_unix: (report.decision == TraversalProbeDecision::Relay).then(
                        || now_unix.saturating_add(self.traversal_probe_reprobe_interval_secs),
                    ),
                },
            );
        }
        self.traversal_probe_statuses = statuses;
        Ok(())
    }

    fn traversal_probe_due(
        &self,
        current: TraversalProbeCurrentState,
        direct_candidates: &[ProbeTraversalCandidate],
        existing_status: Option<&TraversalProbeStatus>,
        now_unix: u64,
        force_reprobe: bool,
    ) -> bool {
        if force_reprobe {
            return true;
        }
        let Some(status) = existing_status else {
            return true;
        };

        match current.path {
            Some(PathMode::Direct) => {
                let current_endpoint_is_direct_candidate = current
                    .endpoint
                    .map(|endpoint| {
                        direct_candidates
                            .iter()
                            .any(|candidate| candidate.endpoint == endpoint)
                    })
                    .unwrap_or(false);
                !current_endpoint_is_direct_candidate
                    || !self.traversal_handshake_is_fresh(
                        current
                            .latest_handshake_unix
                            .or(status.latest_handshake_unix),
                        now_unix,
                    )
            }
            Some(PathMode::Relay) => status
                .next_reprobe_unix
                .map(|next| now_unix >= next)
                .unwrap_or(true),
            None => true,
        }
    }

    fn relay_session_refresh_due(
        &self,
        remote_node_id: &NodeId,
        bundle: &TraversalBundleEnvelope,
        now_unix: u64,
    ) -> Result<bool, String> {
        let Some(relay_client) = self.relay_client.as_ref() else {
            return Ok(false);
        };
        let Some(relay_candidate) = select_runtime_relay_candidate(&bundle.bundle.candidates)?
        else {
            return Ok(false);
        };
        let Some(session) = relay_client.session_for_peer(remote_node_id) else {
            return Ok(true);
        };
        Ok(session.relay_addr != relay_candidate.endpoint
            || session.relay_id != relay_candidate.relay_id
            || session.token_refresh_due(now_unix, self.relay_session_refresh_margin_secs))
    }

    fn resolve_relay_client_endpoint(
        &mut self,
        remote_node_id: &NodeId,
        bundle: &TraversalBundleEnvelope,
        now_unix: u64,
    ) -> Result<Option<SocketEndpoint>, String> {
        if self.transport_socket_identity_blocker.is_some() {
            return Ok(None);
        }
        let Some(relay_candidate) = select_runtime_relay_candidate(&bundle.bundle.candidates)?
        else {
            return Ok(None);
        };
        let Some(relay_client) = self.relay_client.as_ref() else {
            return Ok(None);
        };
        let needs_refresh = match relay_client.session_for_peer(remote_node_id) {
            Some(session) => {
                session.relay_addr != relay_candidate.endpoint
                    || session.relay_id != relay_candidate.relay_id
                    || session.token_refresh_due(now_unix, self.relay_session_refresh_margin_secs)
            }
            None => true,
        };
        if !needs_refresh {
            return Ok(relay_client.relay_endpoint_for_peer(remote_node_id));
        }
        let mut relay_client = self
            .relay_client
            .take()
            .expect("relay client should remain available during establish");
        let endpoint = relay_client.establish_session_with_round_trip(
            remote_node_id,
            relay_candidate.endpoint,
            relay_candidate.relay_id,
            self.relay_session_token_ttl_secs,
            |remote_addr, payload, timeout| {
                self.controller
                    .authoritative_transport_round_trip(remote_addr, payload, timeout)
                    .map(|response| (response.payload, response.remote_addr))
                    .map_err(|err| RelayClientError::AuthoritativeTransport(err.to_string()))
            },
        );
        self.relay_client = Some(relay_client);
        let endpoint = endpoint.map_err(|err| {
            format!(
                "relay session establishment failed for peer {} via {}: {err}",
                remote_node_id.as_str(),
                relay_candidate.endpoint
            )
        })?;
        Ok(Some(endpoint))
    }

    fn close_relay_session(&mut self, remote_node_id: &NodeId) {
        if let Some(relay_client) = self.relay_client.as_mut() {
            relay_client.close_session(remote_node_id);
        }
    }

    fn traversal_handshake_is_fresh(&self, value: Option<u64>, now_unix: u64) -> bool {
        value
            .map(|timestamp| {
                now_unix.saturating_sub(timestamp) <= self.traversal_probe_handshake_freshness_secs
            })
            .unwrap_or(false)
    }

    fn traversal_authority_mode(&self) -> TraversalAuthorityMode {
        if self.auto_tunnel_enforce {
            TraversalAuthorityMode::EnforcedV1
        } else {
            TraversalAuthorityMode::StaticAssignment
        }
    }

    fn apply_traversal_authority_to_peers(
        &self,
        mut peers: Vec<PeerConfig>,
        membership_directory: &MembershipDirectory,
    ) -> Result<Vec<PeerConfig>, String> {
        if !self.traversal_authority_mode().is_enforced() {
            return Ok(peers);
        }
        if let Some(err) = self.traversal_hint_error.as_deref() {
            return Err(format!(
                "traversal authority requires valid signed traversal state: {err}"
            ));
        }

        let Some(envelope) = self.traversal_hints.as_ref() else {
            return Err(
                "traversal authority requires signed traversal state for all managed peers"
                    .to_string(),
            );
        };
        let traversal_index =
            self.build_verified_traversal_index(membership_directory, envelope)?;
        let expected_peers = peers
            .iter()
            .map(|peer| peer.node_id.clone())
            .collect::<BTreeSet<_>>();
        let indexed_peers = traversal_index.keys().cloned().collect::<BTreeSet<_>>();
        let missing_peers = expected_peers
            .difference(&indexed_peers)
            .map(|node_id| node_id.as_str().to_string())
            .collect::<Vec<_>>();
        if !missing_peers.is_empty() {
            return Err(format!(
                "traversal authority is missing signed traversal state for managed peers: {}",
                missing_peers.join(",")
            ));
        }
        let extra_peers = indexed_peers
            .difference(&expected_peers)
            .map(|node_id| node_id.as_str().to_string())
            .collect::<Vec<_>>();
        if !extra_peers.is_empty() {
            return Err(format!(
                "traversal authority snapshot contains unmanaged peers: {}",
                extra_peers.join(",")
            ));
        }

        for peer in &mut peers {
            let bundle = traversal_index.get(&peer.node_id).ok_or_else(|| {
                format!(
                    "traversal authority is missing signed traversal state for managed peer {}",
                    peer.node_id.as_str()
                )
            })?;
            if let Some(status) = self.traversal_probe_statuses.get(&peer.node_id) {
                peer.endpoint = status.selected_endpoint;
            } else {
                peer.endpoint = self.static_traversal_endpoint(bundle, &peer.node_id)?;
            }
        }
        Ok(peers)
    }

    fn static_traversal_endpoint(
        &self,
        bundle: &TraversalBundleEnvelope,
        remote_node_id: &NodeId,
    ) -> Result<SocketEndpoint, String> {
        let endpoints = select_runtime_traversal_endpoints(&bundle.bundle.candidates);
        endpoints.1.or(endpoints.0).ok_or_else(|| {
            format!(
                "traversal authority bundle for peer {} contains no usable runtime endpoints",
                remote_node_id.as_str()
            )
        })
    }

    fn validated_traversal_coordination_schedule(
        &mut self,
        remote_node_id: &NodeId,
        now_unix: u64,
    ) -> Result<Option<CoordinationSchedule>, String> {
        let key =
            traversal_coordination_pair_key(self.local_node_id.as_str(), remote_node_id.as_str());
        let Some(record) = self
            .verified_traversal_coordination_index
            .get(&key)
            .cloned()
        else {
            return Ok(None);
        };
        let verifier_key_bytes = self
            .traversal_hints
            .as_ref()
            .map(|envelope| envelope.verifier_key_bytes)
            .ok_or_else(|| {
                format!(
                    "validated traversal coordination for peer {} is unavailable because traversal state is not loaded",
                    remote_node_id.as_str()
                )
            })?;
        let local_node_id = NodeId::new(self.local_node_id.clone()).map_err(|err| {
            format!(
                "local traversal coordination identity is invalid for peer {}: {err}",
                remote_node_id.as_str()
            )
        })?;
        let engine = TraversalEngine::new(self.traversal_probe_config.clone())
            .map_err(|err| format!("invalid traversal engine config: {err}"))?;
        engine
            .validate_signed_coordination_record(
                &record,
                &local_node_id,
                remote_node_id,
                &verifier_key_bytes,
                &mut self.traversal_coordination_replay_window,
                now_unix,
            )
            .map(Some)
            .map_err(|err| {
                format!(
                    "validated traversal coordination for peer {} is unavailable: {err}",
                    remote_node_id.as_str()
                )
            })
    }

    fn build_verified_traversal_index(
        &self,
        membership_directory: &MembershipDirectory,
        envelope: &TraversalBundleSetEnvelope,
    ) -> Result<BTreeMap<NodeId, TraversalBundleEnvelope>, String> {
        let mut index = BTreeMap::new();
        for bundle in &envelope.bundles {
            let Some(remote_node_id) = self.traversal_remote_node_id(
                bundle.bundle.source_node_id.as_str(),
                bundle.bundle.target_node_id.as_str(),
            ) else {
                return Err(format!(
                    "traversal authority bundle {} -> {} does not include local node {}",
                    bundle.bundle.source_node_id, bundle.bundle.target_node_id, self.local_node_id
                ));
            };
            if membership_directory.node_status(remote_node_id.as_str()) != MembershipStatus::Active
            {
                return Err(format!(
                    "traversal authority target {} is not active in membership state",
                    remote_node_id.as_str()
                ));
            }
            if index
                .insert(remote_node_id.clone(), bundle.clone())
                .is_some()
            {
                return Err(format!(
                    "traversal authority contains duplicate bundle entries for peer {}",
                    remote_node_id.as_str()
                ));
            }
        }
        Ok(index)
    }

    fn traversal_probe_summary(
        &self,
    ) -> (
        String,
        String,
        String,
        String,
        String,
        String,
        usize,
        usize,
        usize,
    ) {
        if self.traversal_probe_statuses.is_empty() {
            return (
                "none".to_string(),
                "none".to_string(),
                "0".to_string(),
                "none".to_string(),
                "none".to_string(),
                "none".to_string(),
                0,
                0,
                0,
            );
        }

        let direct_peers = self
            .traversal_probe_statuses
            .values()
            .filter(|status| status.decision == TraversalProbeDecision::Direct)
            .count();
        let relay_peers = self
            .traversal_probe_statuses
            .values()
            .filter(|status| status.decision == TraversalProbeDecision::Relay)
            .count();
        if self.traversal_probe_statuses.len() == 1 {
            let status = self
                .traversal_probe_statuses
                .values()
                .next()
                .expect("single traversal probe status should exist");
            return (
                status.decision.as_str().to_string(),
                status.reason.as_str().to_string(),
                status.attempts.to_string(),
                sanitize_netcheck_value(&format!(
                    "{}:{}",
                    status.selected_endpoint.addr, status.selected_endpoint.port
                )),
                status
                    .latest_handshake_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                status
                    .next_reprobe_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string()),
                1,
                direct_peers,
                relay_peers,
            );
        }

        let combined_result = if direct_peers == self.traversal_probe_statuses.len() {
            "direct"
        } else if relay_peers == self.traversal_probe_statuses.len() {
            "relay"
        } else {
            "mixed"
        };
        (
            combined_result.to_string(),
            "multi_peer_summary".to_string(),
            self.traversal_probe_statuses
                .values()
                .map(|status| status.attempts)
                .sum::<usize>()
                .to_string(),
            "multiple".to_string(),
            "multiple".to_string(),
            "multiple".to_string(),
            self.traversal_probe_statuses.len(),
            direct_peers,
            relay_peers,
        )
    }

    fn runtime_path_state_summary(&self) -> RuntimePathStateSummary {
        let now_unix = unix_now();
        match self.controller.state() {
            DataplaneState::FailClosed => {
                return RuntimePathStateSummary {
                    live_mode: "fail_closed",
                    live_reason: "fail_closed".to_string(),
                    programmed_mode: "fail_closed",
                    programmed_reason: "fail_closed".to_string(),
                    live_proven: false,
                    programmed_peer_count: 0,
                    live_peer_count: 0,
                    programmed_direct_peers: 0,
                    programmed_relay_peers: 0,
                    live_direct_peers: 0,
                    live_relay_peers: 0,
                    latest_live_handshake_unix: None,
                    relay_session_configured: self.relay_client.is_some(),
                    relay_session_state: self.relay_session_inactive_state(),
                    relay_session_established_peers: 0,
                    relay_session_expired_peers: 0,
                    relay_session_next_expiry_unix: None,
                };
            }
            DataplaneState::ControlTrusted => {
                return RuntimePathStateSummary {
                    live_mode: "control_trusted",
                    live_reason: "control_trusted".to_string(),
                    programmed_mode: "control_trusted",
                    programmed_reason: "control_trusted".to_string(),
                    live_proven: false,
                    programmed_peer_count: 0,
                    live_peer_count: 0,
                    programmed_direct_peers: 0,
                    programmed_relay_peers: 0,
                    live_direct_peers: 0,
                    live_relay_peers: 0,
                    latest_live_handshake_unix: None,
                    relay_session_configured: self.relay_client.is_some(),
                    relay_session_state: self.relay_session_inactive_state(),
                    relay_session_established_peers: 0,
                    relay_session_expired_peers: 0,
                    relay_session_next_expiry_unix: None,
                };
            }
            DataplaneState::Init => {
                return RuntimePathStateSummary {
                    live_mode: "initializing",
                    live_reason: "init".to_string(),
                    programmed_mode: "initializing",
                    programmed_reason: "init".to_string(),
                    live_proven: false,
                    programmed_peer_count: 0,
                    live_peer_count: 0,
                    programmed_direct_peers: 0,
                    programmed_relay_peers: 0,
                    live_direct_peers: 0,
                    live_relay_peers: 0,
                    latest_live_handshake_unix: None,
                    relay_session_configured: self.relay_client.is_some(),
                    relay_session_state: self.relay_session_inactive_state(),
                    relay_session_established_peers: 0,
                    relay_session_expired_peers: 0,
                    relay_session_next_expiry_unix: None,
                };
            }
            DataplaneState::DataplaneApplied | DataplaneState::ExitActive => {}
        }

        let relay_session_configured = self.relay_client.is_some();
        let managed_peer_ids = self.controller.managed_peer_ids();
        let programmed_peer_count = managed_peer_ids.len();
        let mut programmed_direct_peers = 0usize;
        let mut programmed_relay_peers = 0usize;
        let mut live_direct_peers = 0usize;
        let mut live_relay_peers = 0usize;
        let mut latest_live_handshake_unix: Option<u64> = None;
        let mut relay_session_established_peers = 0usize;
        let mut relay_session_expired_peers = 0usize;
        let mut relay_session_selected_endpoint_peers = 0usize;
        let mut relay_session_next_expiry_unix: Option<u64> = None;
        let mut direct_live_reasons = BTreeSet::new();

        for node_id in managed_peer_ids {
            let Some(path) = self.controller.peer_path(&node_id) else {
                continue;
            };
            let status = self.traversal_probe_statuses.get(&node_id);
            let handshake_unix = status.and_then(|entry| entry.latest_handshake_unix);
            let handshake_fresh = self.traversal_handshake_is_fresh(handshake_unix, now_unix);

            match path {
                PathMode::Direct => {
                    programmed_direct_peers = programmed_direct_peers.saturating_add(1);
                    if handshake_fresh {
                        live_direct_peers = live_direct_peers.saturating_add(1);
                        latest_live_handshake_unix = Some(
                            latest_live_handshake_unix
                                .unwrap_or(0)
                                .max(handshake_unix.expect(
                                "fresh direct handshake must carry a latest handshake timestamp",
                            )),
                        );
                        if let Some(status) = status {
                            direct_live_reasons.insert(status.reason.as_str());
                        }
                    }
                }
                PathMode::Relay => {
                    programmed_relay_peers = programmed_relay_peers.saturating_add(1);
                    let current_endpoint = self.controller.managed_peer_endpoint(&node_id);
                    let session = self
                        .relay_client
                        .as_ref()
                        .and_then(|client| client.session_for_peer(&node_id));
                    if let Some(session) = session {
                        relay_session_next_expiry_unix =
                            Some(match relay_session_next_expiry_unix {
                                Some(value) => value.min(session.token_expires_at_unix),
                                None => session.token_expires_at_unix,
                            });
                        if session.is_expired(now_unix) {
                            relay_session_expired_peers =
                                relay_session_expired_peers.saturating_add(1);
                            continue;
                        }

                        relay_session_established_peers =
                            relay_session_established_peers.saturating_add(1);
                        let selected_endpoint_matches = current_endpoint
                            .map(|endpoint| session.matches_selected_endpoint(endpoint))
                            .unwrap_or(false);
                        if selected_endpoint_matches {
                            relay_session_selected_endpoint_peers =
                                relay_session_selected_endpoint_peers.saturating_add(1);
                        }
                        if selected_endpoint_matches && handshake_fresh {
                            live_relay_peers = live_relay_peers.saturating_add(1);
                            latest_live_handshake_unix = Some(
                                latest_live_handshake_unix
                                    .unwrap_or(0)
                                    .max(handshake_unix.expect(
                                    "fresh relay handshake must carry a latest handshake timestamp",
                                )),
                            );
                        }
                    }
                }
            }
        }

        let programmed_mode = if programmed_relay_peers > 0 && programmed_direct_peers > 0 {
            "mixed_programmed"
        } else if programmed_relay_peers > 0 {
            "relay_programmed"
        } else {
            "direct_programmed"
        };
        let programmed_reason = if programmed_relay_peers > 0 {
            "relay_endpoint_programmed".to_string()
        } else if self.controller.has_armed_relay_path() {
            "relay_armed".to_string()
        } else if self.traversal_authority_mode().is_enforced() && self.traversal_hints.is_some() {
            "traversal_authority".to_string()
        } else {
            "static_assignment".to_string()
        };

        let live_peer_count = live_direct_peers.saturating_add(live_relay_peers);
        let live_mode = if live_peer_count == 0 {
            programmed_mode
        } else if live_peer_count < programmed_peer_count {
            "mixed_active"
        } else if live_relay_peers == programmed_peer_count {
            "relay_active"
        } else if live_direct_peers == programmed_peer_count {
            "direct_active"
        } else {
            "mixed_active"
        };
        let live_reason = match live_mode {
            "direct_active" => {
                if direct_live_reasons.len() == 1 {
                    direct_live_reasons
                        .iter()
                        .next()
                        .copied()
                        .unwrap_or("fresh_handshake_observed")
                        .to_string()
                } else {
                    "fresh_handshake_observed".to_string()
                }
            }
            "relay_active" => "relay_selected_endpoint_with_fresh_handshake".to_string(),
            "mixed_active" => {
                if live_peer_count < programmed_peer_count {
                    "partial_live_proof".to_string()
                } else {
                    "mixed_live_paths".to_string()
                }
            }
            _ => {
                if programmed_relay_peers > 0 {
                    if !relay_session_configured {
                        "relay_session_disabled".to_string()
                    } else if self.transport_socket_identity_blocker.is_some() {
                        "relay_transport_identity_blocked".to_string()
                    } else if self.controller.authoritative_transport_identity().is_none() {
                        "relay_transport_unavailable".to_string()
                    } else if relay_session_expired_peers > 0 {
                        "relay_session_expired".to_string()
                    } else if relay_session_established_peers == 0 {
                        "relay_session_missing".to_string()
                    } else if relay_session_selected_endpoint_peers < programmed_relay_peers {
                        "relay_endpoint_unselected".to_string()
                    } else {
                        "relay_handshake_unproven".to_string()
                    }
                } else if programmed_direct_peers > 0 {
                    "direct_handshake_unproven".to_string()
                } else {
                    programmed_reason.clone()
                }
            }
        };

        let relay_session_state = if !relay_session_configured {
            "disabled"
        } else if self.transport_socket_identity_blocker.is_some() {
            "blocked_transport_identity"
        } else if self.controller.authoritative_transport_identity().is_none() {
            "unavailable_authoritative_transport"
        } else if programmed_relay_peers == 0 {
            "unused"
        } else if relay_session_established_peers == 0 {
            "missing"
        } else if relay_session_expired_peers > 0 {
            "expired"
        } else if relay_session_established_peers < programmed_relay_peers {
            "partial"
        } else if live_relay_peers == programmed_relay_peers {
            "live"
        } else if relay_session_selected_endpoint_peers < programmed_relay_peers {
            "endpoint_unselected"
        } else {
            "established_unproven"
        };

        RuntimePathStateSummary {
            live_mode,
            live_reason,
            programmed_mode,
            programmed_reason,
            live_proven: live_peer_count == programmed_peer_count && programmed_peer_count > 0,
            programmed_peer_count,
            live_peer_count,
            programmed_direct_peers,
            programmed_relay_peers,
            live_direct_peers,
            live_relay_peers,
            latest_live_handshake_unix,
            relay_session_configured,
            relay_session_state,
            relay_session_established_peers,
            relay_session_expired_peers,
            relay_session_next_expiry_unix,
        }
    }

    fn traversal_remote_node_id(
        &self,
        source_node_id: &str,
        target_node_id: &str,
    ) -> Option<NodeId> {
        let remote_node = if source_node_id == self.local_node_id {
            target_node_id
        } else if target_node_id == self.local_node_id {
            source_node_id
        } else {
            return None;
        };
        NodeId::new(remote_node.to_string()).ok()
    }

    fn bootstrap(&mut self) {
        // Attempt remote pull of all signed state before disk loads.
        // Skipped = no URL configured or network unreachable: continue to disk load.
        // Err = bundle received but verification failed: fail permanently closed.
        match self.state_fetcher.fetch_trust() {
            Ok(FetchDecision::Applied) => {
                eprintln!("rustynetd: bootstrap: remote trust bundle applied");
            }
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote trust fetch verification failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_trust_fetch_verification_failed");
                return;
            }
        }
        match self.state_fetcher.fetch_traversal() {
            Ok(FetchDecision::Applied) => {
                eprintln!("rustynetd: bootstrap: remote traversal bundle applied");
            }
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote traversal fetch verification failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_traversal_fetch_verification_failed");
                return;
            }
        }
        if self.auto_tunnel_enforce {
            match self.state_fetcher.fetch_assignment() {
                Ok(FetchDecision::Applied) => {
                    eprintln!("rustynetd: bootstrap: remote assignment bundle applied");
                }
                Ok(FetchDecision::Skipped) => {}
                Err(e) => {
                    self.restrict_permanent(format!(
                        "remote assignment fetch verification failed: {e}"
                    ));
                    let _ = self
                        .controller
                        .force_fail_closed("remote_assignment_fetch_verification_failed");
                    return;
                }
            }
        }
        match self.state_fetcher.fetch_dns_zone(None) {
            // Pass None: we haven't loaded auto_bundle yet; auto_tunnel context not yet known.
            Ok(FetchDecision::Applied) => {
                eprintln!("rustynetd: bootstrap: remote dns zone bundle applied");
            }
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote dns zone fetch verification failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_dns_zone_fetch_verification_failed");
                return;
            }
        }

        match self.restore_state() {
            Ok(()) => {}
            Err(_err) => {
                self.restrict_permanent("state restore failed integrity checks".to_string());
                let _ = self
                    .controller
                    .force_fail_closed("state_restore_integrity_failed");
                return;
            }
        }
        if let Err(err) = self.enforce_blind_exit_invariants() {
            self.restrict_permanent(format!(
                "blind-exit role invariants failed during bootstrap: {err}"
            ));
            let _ = self
                .controller
                .force_fail_closed("blind_exit_invariants_failed");
            return;
        }

        match self.state_fetcher.fetch_trust() {
            Ok(FetchDecision::Applied) => eprintln!("statefetch: trust applied before bootstrap"),
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote trust fetch failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_trust_fetch_failed");
                return;
            }
        }
        match self.state_fetcher.fetch_traversal() {
            Ok(FetchDecision::Applied) => {
                eprintln!("statefetch: traversal applied before bootstrap")
            }
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote traversal fetch failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_traversal_fetch_failed");
                return;
            }
        }
        if self.auto_tunnel_enforce {
            match self.state_fetcher.fetch_assignment() {
                Ok(FetchDecision::Applied) => {
                    eprintln!("statefetch: assignment applied before bootstrap")
                }
                Ok(FetchDecision::Skipped) => {}
                Err(e) => {
                    self.restrict_permanent(format!("remote assignment fetch failed: {e}"));
                    let _ = self
                        .controller
                        .force_fail_closed("remote_assignment_fetch_failed");
                    return;
                }
            }
        }
        let dns_context = if self.auto_tunnel_enforce {
            if let Some(path) = &self.auto_tunnel_bundle_path {
                if let Some(verifier) = &self.auto_tunnel_verifier_key_path {
                    use crate::phase10::TrustPolicy;
                    let policy = TrustPolicy {
                        max_signed_data_age_secs: self.auto_tunnel_max_age_secs,
                        max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
                    };
                    load_auto_tunnel_bundle(
                        path,
                        verifier,
                        self.auto_tunnel_max_age_secs,
                        policy,
                        None,
                    )
                    .map(|b| b.bundle)
                    .ok()
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        match self.state_fetcher.fetch_dns_zone(dns_context.as_ref()) {
            Ok(FetchDecision::Applied) => {
                eprintln!("statefetch: dns zone applied before bootstrap")
            }
            Ok(FetchDecision::Skipped) => {}
            Err(e) => {
                self.restrict_permanent(format!("remote dns zone fetch failed: {e}"));
                let _ = self
                    .controller
                    .force_fail_closed("remote_dns_zone_fetch_failed");
                return;
            }
        }

        let trust = match self.load_verified_trust() {
            Ok(evidence) => evidence,
            Err(err) => {
                self.restrict_recoverable(err.to_string());
                let _ = self.controller.force_fail_closed("trust_bootstrap_failed");
                return;
            }
        };

        let membership_state = match self.load_verified_membership() {
            Ok(state) => state,
            Err(err) => {
                self.restrict_recoverable(err.to_string());
                let _ = self
                    .controller
                    .force_fail_closed("membership_bootstrap_failed");
                return;
            }
        };
        let membership_directory = membership_directory_from_state(&membership_state);

        let auto_bundle = if self.auto_tunnel_enforce {
            match self.load_verified_auto_tunnel(&membership_directory) {
                Ok(bundle) => Some(bundle),
                Err(err) => {
                    self.restrict_recoverable(err.to_string());
                    let _ = self
                        .controller
                        .force_fail_closed("auto_tunnel_bootstrap_failed");
                    return;
                }
            }
        } else {
            None
        };

        let (mesh_cidr, local_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
            if let Some(ref envelope) = auto_bundle {
                let lan_enabled = envelope
                    .bundle
                    .routes
                    .iter()
                    .any(|route| route.kind == RouteKind::ExitNodeLan);
                (
                    envelope.bundle.mesh_cidr.clone(),
                    envelope.bundle.assigned_cidr.clone(),
                    envelope.bundle.peers.clone(),
                    envelope.bundle.routes.clone(),
                    envelope.bundle.selected_exit_node.clone(),
                    lan_enabled,
                    Some(envelope.watermark),
                )
            } else {
                (
                    "100.64.0.0/10".to_string(),
                    "100.64.0.1/32".to_string(),
                    Vec::new(),
                    Vec::new(),
                    None,
                    false,
                    None,
                )
            };
        if let Err(err) = self.validate_blind_exit_assignment(auto_exit.as_deref(), auto_lan_access)
        {
            self.restrict_recoverable(err);
            let _ = self
                .controller
                .force_fail_closed("blind_exit_assignment_rejected");
            return;
        }

        self.refresh_traversal_hint_state(true);

        let local_node = match NodeId::new(self.local_node_id.clone()) {
            Ok(node_id) => node_id,
            Err(err) => {
                self.restrict_permanent(format!("invalid local node id in runtime: {err}"));
                let _ = self.controller.force_fail_closed("invalid_local_node_id");
                return;
            }
        };

        if let Err(err) = self.ensure_runtime_private_key_material() {
            self.restrict_recoverable(format!("runtime key preparation failed: {err}"));
            let _ = self
                .controller
                .force_fail_closed("runtime_key_prepare_failed");
            return;
        }

        let serve_exit_node = if self.node_role.is_blind_exit() {
            true
        } else if self.auto_tunnel_enforce {
            self.is_serving_exit_node(auto_exit.as_deref())
        } else {
            self.is_serving_exit_node(self.selected_exit_node.as_deref())
        };

        let peers = match self.apply_traversal_authority_to_peers(peers, &membership_directory) {
            Ok(peers) => peers,
            Err(err) => {
                self.restrict_recoverable(format!(
                    "traversal authority rejected bootstrap apply: {err}"
                ));
                let _ = self
                    .controller
                    .force_fail_closed("bootstrap_traversal_authority_rejected");
                return;
            }
        };

        let routes = sanitize_dataplane_routes_for_node_role(self.node_role, routes);
        let apply_result = self.controller.apply_dataplane_generation(
            trust,
            RuntimeContext {
                local_node,
                interface_name: self.wg_interface.clone(),
                mesh_cidr,
                local_cidr,
            },
            peers,
            routes,
            ApplyOptions {
                protected_dns: true,
                ipv6_parity_supported: false,
                serve_exit_node,
                exit_mode: if self.node_role.is_blind_exit() {
                    ExitMode::Off
                } else if self.auto_tunnel_enforce {
                    if auto_exit.is_some() {
                        ExitMode::FullTunnel
                    } else {
                        ExitMode::Off
                    }
                } else {
                    self.desired_exit_mode()
                },
            },
        );
        let cleanup_result = self.scrub_runtime_private_key_material();
        match (apply_result, cleanup_result) {
            (Ok(()), Ok(())) => {}
            (Err(err), Ok(())) => {
                self.restrict_recoverable(format!("dataplane bootstrap apply failed: {err}"));
                let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
                return;
            }
            (Err(err), Err(cleanup_err)) => {
                self.restrict_recoverable(format!(
                    "dataplane bootstrap apply failed: {err}; runtime key cleanup failed: {cleanup_err}"
                ));
                let _ = self.controller.force_fail_closed("bootstrap_apply_failed");
                return;
            }
            (Ok(()), Err(cleanup_err)) => {
                self.restrict_recoverable(format!(
                    "runtime key cleanup failed after bootstrap apply: {cleanup_err}"
                ));
                let _ = self
                    .controller
                    .force_fail_closed("runtime_key_cleanup_failed");
                return;
            }
        }
        self.membership_state = Some(membership_state);
        self.membership_directory = membership_directory;
        self.refresh_dns_zone_state(auto_bundle.as_ref());

        if self.auto_tunnel_enforce {
            if self.node_role.is_blind_exit() {
                self.selected_exit_node = None;
                self.lan_access_enabled = false;
                self.controller.set_lan_access(false);
            } else {
                self.selected_exit_node = auto_exit;
                self.lan_access_enabled = auto_lan_access;
                self.controller.set_lan_access(auto_lan_access);
            }
            self.last_applied_assignment = auto_watermark;
        } else if let Some(exit_node) = &self.selected_exit_node {
            if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                let _ = self
                    .controller
                    .set_exit_node(node_id, "user:local", Protocol::Any);
            }
        }

        self.restriction_mode = RestrictionMode::None;
        self.bootstrap_error = None;
        self.poll_endpoint_monitor_and_maybe_refresh();
        self.refresh_traversal_hint_state(false);
        self.maybe_preexpiry_refresh_dns_zone(unix_now(), auto_bundle.as_ref());
        self.maybe_trigger_endpoint_change_refresh();
        self.maintain_exit_port_forward(
            self.is_serving_exit_node(self.selected_exit_node.as_deref()),
        );
    }

    fn authorize_remote_command(
        &mut self,
        envelope: &RemoteCommandEnvelope,
        now_unix: u64,
    ) -> Result<IpcCommand, String> {
        if envelope.subject != self.remote_ops_expected_subject {
            return Err(format!("unexpected subject: {}", envelope.subject));
        }

        // Enforce strict freshness (nonce as timestamp)
        // Window: 60 seconds
        let age = now_unix.saturating_sub(envelope.nonce);
        if age > 60 {
            return Err(format!("nonce expired (age {age}s)"));
        }
        if envelope.nonce > now_unix + 60 {
            return Err(format!(
                "nonce in future ({nonce} > {now})",
                nonce = envelope.nonce,
                now = now_unix
            ));
        }

        if let Some(verifier) = &self.remote_ops_verifying_key {
            let payload = crate::ipc::remote_ops_signature_payload(
                &envelope.subject,
                envelope.nonce,
                &envelope.command,
            );
            use ed25519_dalek::Verifier;
            let signature = ed25519_dalek::Signature::from_bytes(
                &envelope
                    .signature
                    .clone()
                    .try_into()
                    .map_err(|_| "invalid signature length".to_string())?,
            );
            verifier
                .verify(&payload, &signature)
                .map_err(|e| format!("signature verification failed: {e}"))?;

            let active_window_floor = now_unix.saturating_sub(60);
            let seen_nonces = self
                .remote_ops_seen_nonces
                .entry(envelope.subject.clone())
                .or_default();
            seen_nonces.retain(|nonce| *nonce >= active_window_floor);
            if !seen_nonces.insert(envelope.nonce) {
                return Err("remote command replay detected".to_string());
            }

            Ok(envelope.command.clone())
        } else {
            Err("remote ops not configured".to_string())
        }
    }

    fn handle_command(&mut self, command: IpcCommand) -> IpcResponse {
        if !self.node_role.allows_command(&command) {
            return IpcResponse::err(
                "command denied: current node role does not permit this operation",
            );
        }
        if self.is_restricted()
            && command.is_mutating()
            && !matches!(command, IpcCommand::StateRefresh)
        {
            return IpcResponse::err("daemon is in restricted-safe mode");
        }
        let auto_tunnel_route_advertise_allowed = matches!(
            &command,
            IpcCommand::RouteAdvertise(cidr)
                if self.allow_auto_tunnel_exit_advertisement(cidr)
        );
        if self.auto_tunnel_enforce
            && matches!(
                &command,
                IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::RouteAdvertise(_)
            )
            && !auto_tunnel_route_advertise_allowed
        {
            return IpcResponse::err(
                "manual route and exit mutations are disabled while auto-tunnel is enforced (except route advertise 0.0.0.0/0 for exit-serving nodes)",
            );
        }

        match command {
            IpcCommand::Status => {
                self.refresh_traversal_hint_state(false);
                let last_assignment = self
                    .last_applied_assignment
                    .map(|watermark| format!("{}:{}", watermark.generated_at_unix, watermark.nonce))
                    .unwrap_or_else(|| "none".to_string());
                let membership_epoch = self
                    .membership_state
                    .as_ref()
                    .map(|state| state.epoch.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let membership_active_nodes = self
                    .membership_state
                    .as_ref()
                    .map(|state| state.active_nodes().len().to_string())
                    .unwrap_or_else(|| "none".to_string());
                let (dns_zone_state, dns_zone_record_count, dns_zone_error) =
                    self.dns_zone_status_summary();
                let port_forward_external_port = self
                    .exit_port_forward_external_port()
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let port_forward_error = self
                    .exit_port_forward_last_error
                    .as_deref()
                    .unwrap_or("none");
                let (
                    traversal_probe_result,
                    traversal_probe_reason,
                    traversal_probe_attempts,
                    traversal_probe_endpoint,
                    traversal_probe_handshake,
                    traversal_probe_next_reprobe,
                    traversal_probe_peer_count,
                    traversal_probe_direct_peers,
                    traversal_probe_relay_peers,
                ) = self.traversal_probe_summary();
                let serving_exit_node =
                    if self.is_serving_exit_node(self.selected_exit_node.as_deref()) {
                        "true"
                    } else {
                        "false"
                    };
                let traversal_peer_count = self
                    .traversal_hints
                    .as_ref()
                    .map(|envelope| envelope.bundles.len().to_string())
                    .unwrap_or_else(|| "0".to_string());
                let traversal_probe_max_candidates =
                    self.traversal_probe_config.max_candidates.to_string();
                let traversal_probe_max_pairs =
                    self.traversal_probe_config.max_probe_pairs.to_string();
                let traversal_probe_rounds = self
                    .traversal_probe_config
                    .simultaneous_open_rounds
                    .to_string();
                let traversal_probe_round_spacing_ms =
                    self.traversal_probe_config.round_spacing_ms.to_string();
                let traversal_probe_relay_switch_after_failures = self
                    .traversal_probe_config
                    .relay_switch_after_failures
                    .to_string();
                let traversal_probe_handshake_freshness_secs =
                    self.traversal_probe_handshake_freshness_secs.to_string();
                let traversal_probe_reprobe_interval_secs =
                    self.traversal_probe_reprobe_interval_secs.to_string();
                let traversal_preexpiry_refresh_events =
                    self.traversal_preexpiry_refresh_events.to_string();
                let traversal_last_preexpiry_refresh_unix = self
                    .traversal_last_preexpiry_refresh_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let traversal_stale_rejections = self.traversal_stale_rejections.to_string();
                let traversal_replay_rejections = self.traversal_replay_rejections.to_string();
                let traversal_future_dated_rejections =
                    self.traversal_future_dated_rejections.to_string();
                let traversal_endpoint_change_events =
                    self.traversal_endpoint_change_events.to_string();
                let traversal_endpoint_fingerprint = self
                    .traversal_last_endpoint_fingerprint
                    .as_deref()
                    .map(sanitize_netcheck_value)
                    .unwrap_or_else(|| "none".to_string());
                let (traversal_alarm_state, traversal_alarm_reason) =
                    self.traversal_alarm_state(unix_now());
                let (dns_alarm_state, dns_alarm_reason) = self.dns_zone_alarm_state(unix_now());
                let dns_preexpiry_refresh_events =
                    self.dns_zone_preexpiry_refresh_events.to_string();
                let dns_last_preexpiry_refresh_unix = self
                    .dns_zone_last_preexpiry_refresh_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let dns_stale_rejections = self.dns_zone_stale_rejections.to_string();
                let dns_replay_rejections = self.dns_zone_replay_rejections.to_string();
                let dns_future_dated_rejections = self.dns_zone_future_dated_rejections.to_string();
                let stun_candidate_local_addrs = self.stun_candidate_local_addrs();
                let stun_transport_port_binding = self.stun_transport_port_binding();
                let transport_socket_identity_state = self.transport_socket_identity_state();
                let transport_socket_identity_error = self.transport_socket_identity_error();
                let transport_socket_identity_label = self.transport_socket_identity_label();
                let transport_socket_identity_local_addr =
                    self.transport_socket_identity_local_addr();
                let (selected_exit_peer_endpoint, selected_exit_peer_endpoint_error) =
                    self.selected_exit_peer_endpoint_summary();
                let (managed_peer_endpoints, managed_peer_endpoints_error) =
                    self.managed_peer_endpoints_summary();
                let path_state = self.runtime_path_state_summary();
                let path_live_proven = if path_state.live_proven {
                    "true"
                } else {
                    "false"
                };
                let path_latest_live_handshake_unix = path_state
                    .latest_live_handshake_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string());
                let relay_session_configured = if path_state.relay_session_configured {
                    "true"
                } else {
                    "false"
                };
                let relay_session_next_expiry_unix = path_state
                    .relay_session_next_expiry_unix
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_string());
                IpcResponse::ok(format!(
                    "node_id={} node_role={} state={:?} generation={} exit_node={} selected_exit_peer_endpoint={} selected_exit_peer_endpoint_error={} managed_peer_endpoints={} managed_peer_endpoints_error={} serving_exit_node={} lan_access={} restricted_safe_mode={} restriction_mode={:?} bootstrap_error={} reconcile_attempts={} reconcile_failures={} last_reconcile_unix={} last_reconcile_error={} encrypted_key_store={} auto_tunnel_enforce={} path_mode={} path_reason={} path_programmed_mode={} path_programmed_reason={} path_live_proven={} path_programmed_peer_count={} path_live_peer_count={} path_programmed_direct_peers={} path_programmed_relay_peers={} path_live_direct_peers={} path_live_relay_peers={} path_latest_live_handshake_unix={} relay_session_configured={} relay_session_state={} relay_session_established_peers={} relay_session_expired_peers={} relay_session_next_expiry_unix={} transport_socket_identity_state={} transport_socket_identity_error={} transport_socket_identity_label={} transport_socket_identity_local_addr={} dns_zone_state={} dns_zone_record_count={} dns_zone_error={} traversal_authority={} traversal_peer_count={} traversal_probe_max_candidates={} traversal_probe_max_pairs={} traversal_probe_rounds={} traversal_probe_round_spacing_ms={} traversal_probe_relay_switch_after_failures={} traversal_probe_handshake_freshness_secs={} traversal_probe_reprobe_interval_secs={} traversal_probe_result={} traversal_probe_reason={} traversal_probe_attempts={} traversal_probe_endpoint={} traversal_probe_latest_handshake_unix={} traversal_probe_next_reprobe_unix={} traversal_probe_peer_count={} traversal_probe_direct_peers={} traversal_probe_relay_peers={} traversal_preexpiry_refresh_events={} traversal_last_preexpiry_refresh_unix={} traversal_stale_rejections={} traversal_replay_rejections={} traversal_future_dated_rejections={} traversal_endpoint_change_events={} traversal_endpoint_fingerprint={} traversal_alarm_state={} traversal_alarm_reason={} dns_alarm_state={} dns_alarm_reason={} dns_preexpiry_refresh_events={} dns_last_preexpiry_refresh_unix={} dns_stale_rejections={} dns_replay_rejections={} dns_future_dated_rejections={} stun_candidate_local_addrs={} stun_transport_port_binding={} auto_port_forward_exit={} port_forward_external_port={} port_forward_error={} last_assignment={} membership_epoch={} membership_active_nodes={}",
                    self.local_node_id,
                    self.node_role.as_str(),
                    self.controller.state(),
                    self.controller.generation(),
                    self.selected_exit_node.as_deref().unwrap_or("none"),
                    selected_exit_peer_endpoint,
                    selected_exit_peer_endpoint_error,
                    managed_peer_endpoints,
                    managed_peer_endpoints_error,
                    serving_exit_node,
                    if self.lan_access_enabled { "on" } else { "off" },
                    if self.is_restricted() {
                        "true"
                    } else {
                        "false"
                    },
                    self.restriction_mode,
                    self.bootstrap_error.as_deref().unwrap_or("none"),
                    self.reconcile_attempts,
                    self.reconcile_failures,
                    self.last_reconcile_unix
                        .map(|value| value.to_string())
                        .unwrap_or_else(|| "none".to_string()),
                    self.last_reconcile_error.as_deref().unwrap_or("none"),
                    if self.wg_encrypted_private_key_path.is_some() {
                        "true"
                    } else {
                        "false"
                    },
                    if self.auto_tunnel_enforce {
                        "true"
                    } else {
                        "false"
                    },
                    path_state.live_mode,
                    path_state.live_reason,
                    path_state.programmed_mode,
                    path_state.programmed_reason,
                    path_live_proven,
                    path_state.programmed_peer_count,
                    path_state.live_peer_count,
                    path_state.programmed_direct_peers,
                    path_state.programmed_relay_peers,
                    path_state.live_direct_peers,
                    path_state.live_relay_peers,
                    path_latest_live_handshake_unix,
                    relay_session_configured,
                    path_state.relay_session_state,
                    path_state.relay_session_established_peers,
                    path_state.relay_session_expired_peers,
                    relay_session_next_expiry_unix,
                    transport_socket_identity_state,
                    transport_socket_identity_error,
                    transport_socket_identity_label,
                    transport_socket_identity_local_addr,
                    dns_zone_state,
                    dns_zone_record_count,
                    dns_zone_error,
                    self.traversal_authority_mode().as_str(),
                    traversal_peer_count,
                    traversal_probe_max_candidates,
                    traversal_probe_max_pairs,
                    traversal_probe_rounds,
                    traversal_probe_round_spacing_ms,
                    traversal_probe_relay_switch_after_failures,
                    traversal_probe_handshake_freshness_secs,
                    traversal_probe_reprobe_interval_secs,
                    traversal_probe_result,
                    traversal_probe_reason,
                    traversal_probe_attempts,
                    traversal_probe_endpoint,
                    traversal_probe_handshake,
                    traversal_probe_next_reprobe,
                    traversal_probe_peer_count,
                    traversal_probe_direct_peers,
                    traversal_probe_relay_peers,
                    traversal_preexpiry_refresh_events,
                    traversal_last_preexpiry_refresh_unix,
                    traversal_stale_rejections,
                    traversal_replay_rejections,
                    traversal_future_dated_rejections,
                    traversal_endpoint_change_events,
                    traversal_endpoint_fingerprint,
                    traversal_alarm_state,
                    traversal_alarm_reason,
                    dns_alarm_state,
                    dns_alarm_reason,
                    dns_preexpiry_refresh_events,
                    dns_last_preexpiry_refresh_unix,
                    dns_stale_rejections,
                    dns_replay_rejections,
                    dns_future_dated_rejections,
                    stun_candidate_local_addrs,
                    stun_transport_port_binding,
                    if self.auto_port_forward_exit {
                        "true"
                    } else {
                        "false"
                    },
                    port_forward_external_port,
                    port_forward_error,
                    last_assignment,
                    membership_epoch,
                    membership_active_nodes
                ))
            }
            IpcCommand::Netcheck => {
                self.refresh_traversal_hint_state(true);
                IpcResponse::ok(self.netcheck_response_line())
            }
            IpcCommand::StateRefresh => {
                match self.refresh_signed_state_with_reason(true, SignedStateRefreshReason::Command)
                {
                    Ok(()) => IpcResponse::ok("signed state refresh completed"),
                    Err(err) => {
                        self.restrict_recoverable(err.clone());
                        let _ = self
                            .controller
                            .force_fail_closed("command_signed_state_refresh_failed");
                        IpcResponse::err(format!("signed state refresh failed: {err}"))
                    }
                }
            }
            IpcCommand::ExitNodeSelect(node) => {
                let node_id = match NodeId::new(node.clone()) {
                    Ok(value) => value,
                    Err(err) => return IpcResponse::err(format!("invalid node: {err}")),
                };
                if self.membership_directory.node_status(node.as_str()) != MembershipStatus::Active
                {
                    return IpcResponse::err(
                        "exit-node selection denied: node is not active in membership state",
                    );
                }
                match self
                    .controller
                    .set_exit_node(node_id, "user:local", Protocol::Any)
                {
                    Ok(()) => {
                        self.selected_exit_node = Some(node.clone());
                        if let Err(err) = self.persist_state() {
                            return IpcResponse::err(format!("persist failed: {err}"));
                        }
                        IpcResponse::ok(format!("exit-node selected: {node}"))
                    }
                    Err(err) => IpcResponse::err(err.to_string()),
                }
            }
            IpcCommand::ExitNodeOff => match self.controller.clear_exit_node() {
                Ok(()) => {
                    self.selected_exit_node = None;
                    if let Err(err) = self.persist_state() {
                        return IpcResponse::err(format!("persist failed: {err}"));
                    }
                    IpcResponse::ok("exit-node disabled")
                }
                Err(err) => IpcResponse::err(err.to_string()),
            },
            IpcCommand::LanAccessOn => {
                self.controller.set_lan_access(true);
                self.lan_access_enabled = true;
                if let Some(exit_node) = &self.selected_exit_node {
                    if self.membership_directory.node_status(exit_node.as_str())
                        != MembershipStatus::Active
                    {
                        return IpcResponse::err(
                            "lan-access denied: selected exit node is not active in membership state",
                        );
                    }
                    self.controller
                        .set_lan_route_acl("user:local", "192.168.1.0/24", true);
                    if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                        self.controller
                            .advertise_lan_route(node_id, "192.168.1.0/24");
                    }
                    let _ = self.controller.ensure_lan_route_allowed(RouteGrantRequest {
                        user: "user:local".to_string(),
                        cidr: "192.168.1.0/24".to_string(),
                        protocol: Protocol::Any,
                        context: TrafficContext::SharedExit,
                    });
                }
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                IpcResponse::ok("lan-access enabled")
            }
            IpcCommand::LanAccessOff => {
                self.controller.set_lan_access(false);
                self.lan_access_enabled = false;
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                IpcResponse::ok("lan-access disabled")
            }
            IpcCommand::DnsInspect => IpcResponse::ok(self.dns_inspect_message()),
            IpcCommand::RouteAdvertise(cidr) => {
                if self.auto_tunnel_enforce && !self.allow_auto_tunnel_exit_advertisement(&cidr) {
                    return IpcResponse::err(
                        "manual route and exit mutations are disabled while auto-tunnel is enforced (except route advertise 0.0.0.0/0 for exit-serving nodes)",
                    );
                }
                if !validate_cidr(&cidr) {
                    return IpcResponse::err("invalid cidr format");
                }
                if let Some(exit_node) = &self.selected_exit_node {
                    if let Ok(node_id) = NodeId::new(exit_node.clone()) {
                        if self.membership_directory.node_status(exit_node.as_str())
                            != MembershipStatus::Active
                        {
                            return IpcResponse::err(
                                "route advertise denied: selected exit node is not active in membership state",
                            );
                        }
                        self.controller.advertise_lan_route(node_id, &cidr);
                        self.controller.set_lan_route_acl("user:local", &cidr, true);
                    }
                }
                self.advertised_routes.insert(cidr.clone());
                self.local_route_reconcile_pending = true;
                if let Err(err) = self.persist_state() {
                    return IpcResponse::err(format!("persist failed: {err}"));
                }
                if self.auto_tunnel_enforce && cidr == "0.0.0.0/0" {
                    // Apply exit-serving dataplane/NAT immediately after advertised default route changes
                    // (including relay-with-upstream-exit mode) so status and forwarding reflect the
                    // requested fail-closed policy without waiting for the periodic reconcile interval.
                    self.reconcile();
                }
                IpcResponse::ok(format!("route advertised: {cidr}"))
            }
            IpcCommand::KeyRotate => match self.rotate_local_key_material() {
                Ok(message) => IpcResponse::ok(message),
                Err(err) => IpcResponse::err(err),
            },
            IpcCommand::KeyRevoke => match self.revoke_local_key_material() {
                Ok(message) => IpcResponse::ok(message),
                Err(err) => IpcResponse::err(err),
            },
            IpcCommand::Unknown(raw) => IpcResponse::err(format!("unknown command: {raw}")),
        }
    }

    fn apply_interface_private_key_runtime(&self, runtime_key_path: &Path) -> Result<(), String> {
        if let Some(client) = self.privileged_helper_client.as_ref() {
            let runtime_path = runtime_key_path
                .to_str()
                .ok_or_else(|| "runtime key path must be valid utf-8".to_string())?;
            let output = client.run_capture(
                PrivilegedCommandProgram::Wg,
                &[
                    "set",
                    self.wg_interface.as_str(),
                    "private-key",
                    runtime_path,
                ],
            )?;
            if output.success() {
                return Ok(());
            }
            return Err(format!(
                "wg set private-key failed for {}: status={} stderr={}",
                self.wg_interface, output.status, output.stderr
            ));
        }
        apply_interface_private_key(&self.wg_interface, runtime_key_path)
    }

    fn set_interface_down_runtime(&self) -> Result<(), String> {
        if let Some(client) = self.privileged_helper_client.as_ref() {
            let output = match self.backend_mode {
                DaemonBackendMode::LinuxWireguard => client.run_capture(
                    PrivilegedCommandProgram::Ip,
                    &["link", "set", "down", "dev", self.wg_interface.as_str()],
                )?,
                DaemonBackendMode::LinuxWireguardUserspaceShared => {
                    return Err(
                        "interface down is not supported for linux-wireguard-userspace-shared backend; use backend shutdown"
                            .to_string(),
                    );
                }
                DaemonBackendMode::MacosWireguard => client.run_capture(
                    PrivilegedCommandProgram::Ifconfig,
                    &[self.wg_interface.as_str(), "down"],
                )?,
                DaemonBackendMode::MacosWireguardUserspaceShared => {
                    return Err(DaemonBackendMode::MacosWireguardUserspaceShared
                        .userspace_shared_blocker()
                        .expect("macos shared backend blocker should exist")
                        .to_string());
                }
                DaemonBackendMode::WindowsUnsupported => {
                    return Err(
                        require_supported_windows_backend(WindowsBackendMode::Unsupported)
                            .expect_err("windows unsupported backend must fail closed"),
                    );
                }
                DaemonBackendMode::InMemory => {
                    return Err("interface down is not supported for in-memory backend".to_string());
                }
            };
            if output.success() {
                return Ok(());
            }
            let command_label = match self.backend_mode {
                DaemonBackendMode::LinuxWireguard => "ip link set down",
                DaemonBackendMode::LinuxWireguardUserspaceShared => "linux userspace-shared down",
                DaemonBackendMode::MacosWireguard => "ifconfig down",
                DaemonBackendMode::MacosWireguardUserspaceShared => {
                    "macos-wireguard-userspace-shared blocked"
                }
                DaemonBackendMode::WindowsUnsupported => "windows-unsupported blocked",
                DaemonBackendMode::InMemory => "interface down",
            };
            return Err(format!(
                "{command_label} failed for {}: status={} stderr={}",
                self.wg_interface, output.status, output.stderr
            ));
        }
        set_interface_down(&self.wg_interface)
    }

    fn rotate_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(
            self.backend_mode,
            DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
        ) {
            return Err(
                "key rotation is only supported for linux-wireguard or macos-wireguard backend"
                    .to_string(),
            );
        }
        let runtime_path = self
            .wg_private_key_path
            .clone()
            .ok_or_else(|| "wg private key path is not configured".to_string())?;

        let mut old_runtime = fs::read(&runtime_path).ok();
        let mut old_encrypted = self
            .wg_encrypted_private_key_path
            .as_ref()
            .and_then(|path| fs::read(path).ok());
        let old_public = self
            .wg_public_key_path
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());

        let result = (|| -> Result<String, String> {
            let (mut new_private, new_public) = generate_wireguard_keypair()?;

            if let Some(encrypted_path) = self.wg_encrypted_private_key_path.as_ref() {
                let passphrase_path = self.wg_key_passphrase_path.as_ref().ok_or_else(|| {
                    "wg key passphrase path is required when encrypted key storage is configured"
                        .to_string()
                })?;
                if let Err(err) = encrypt_private_key(&new_private, encrypted_path, passphrase_path)
                {
                    new_private.fill(0);
                    return Err(err);
                }
            }

            if let Err(err) = write_runtime_private_key(&runtime_path, &new_private) {
                new_private.fill(0);
                return Err(err);
            }
            if let Some(public_path) = self.wg_public_key_path.as_ref() {
                if let Err(err) = write_public_key(public_path, &new_public) {
                    new_private.fill(0);
                    return Err(err);
                }
            }

            if let Err(err) = self.apply_interface_private_key_runtime(&runtime_path) {
                let _ = self.restore_key_backups(
                    old_runtime.as_deref(),
                    old_encrypted.as_deref(),
                    old_public.as_deref(),
                );
                new_private.fill(0);
                return Err(format!("rotate apply failed and rollback attempted: {err}"));
            }

            new_private.fill(0);

            if let Err(err) = self.persist_state() {
                return Err(format!("persist failed after key rotation: {err}"));
            }
            if let Err(err) = self.scrub_runtime_private_key_file() {
                return Err(format!(
                    "key rotation completed but runtime key cleanup failed: {err}"
                ));
            }

            let bundle = format!("rotation:{}:{}", self.local_node_id, new_public);
            Ok(format!(
                "key rotated: node_id={} public_key={} rotation_bundle={}",
                self.local_node_id, new_public, bundle
            ))
        })();

        zeroize_optional_bytes(&mut old_runtime);
        zeroize_optional_bytes(&mut old_encrypted);
        result
    }

    fn restore_key_backups(
        &self,
        old_runtime: Option<&[u8]>,
        old_encrypted: Option<&[u8]>,
        old_public: Option<&str>,
    ) -> Result<(), String> {
        if let (Some(path), Some(bytes)) = (self.wg_private_key_path.as_ref(), old_runtime) {
            write_runtime_private_key(path, bytes)?;
            let _ = self.apply_interface_private_key_runtime(path);
        }
        if let (Some(path), Some(bytes)) =
            (self.wg_encrypted_private_key_path.as_ref(), old_encrypted)
        {
            write_runtime_private_key(path, bytes)?;
        }
        if let (Some(path), Some(value)) = (self.wg_public_key_path.as_ref(), old_public) {
            write_public_key(path, value.trim())?;
        }
        Ok(())
    }

    fn revoke_local_key_material(&mut self) -> Result<String, String> {
        if !matches!(
            self.backend_mode,
            DaemonBackendMode::LinuxWireguard | DaemonBackendMode::MacosWireguard
        ) {
            return Err(
                "key revoke is only supported for linux-wireguard or macos-wireguard backend"
                    .to_string(),
            );
        }
        self.restrict_permanent("local key revoked".to_string());
        let _ = self.controller.force_fail_closed("local_key_revoked");

        let mut failures = Vec::new();
        if let Err(err) = self.set_interface_down_runtime() {
            failures.push(format!("interface down failed: {err}"));
        }
        if let Some(path) = self.wg_private_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }
        if let Some(path) = self.wg_encrypted_private_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }
        if let Some(path) = self.wg_public_key_path.as_ref() {
            if let Err(err) = remove_file_if_present(path) {
                failures.push(err);
            }
        }

        self.selected_exit_node = None;
        self.lan_access_enabled = false;
        self.release_exit_port_forward();
        self.clear_exit_port_forward_state();

        if let Err(err) = self.persist_state() {
            failures.push(format!("persist failed after revoke: {err}"));
        }

        if failures.is_empty() {
            Ok("local key revoked: interface disabled and key material removed".to_string())
        } else {
            Err(format!(
                "key revoke completed with errors: {}",
                failures.join("; ")
            ))
        }
    }

    fn scrub_runtime_private_key_file(&self) -> Result<(), String> {
        if self.wg_encrypted_private_key_path.is_none() {
            return Ok(());
        }
        if let Some(path) = self.wg_private_key_path.as_ref() {
            remove_file_if_present(path)?;
        }
        Ok(())
    }

    fn ensure_runtime_private_key_material(&self) -> Result<(), String> {
        prepare_runtime_wireguard_key_material(
            self.backend_mode,
            self.wg_private_key_path.as_deref(),
            self.wg_encrypted_private_key_path.as_deref(),
            self.wg_key_passphrase_path.as_deref(),
        )
    }

    fn scrub_runtime_private_key_material(&self) -> Result<(), String> {
        scrub_runtime_wireguard_key_material(
            self.backend_mode,
            self.wg_private_key_path.as_deref(),
            self.wg_encrypted_private_key_path.as_deref(),
        )
    }

    fn persist_state(&mut self) -> Result<(), String> {
        let snapshot = SessionStateSnapshot {
            timestamp_unix: unix_now(),
            peer_ids: self.advertised_routes.iter().cloned().collect::<Vec<_>>(),
            selected_exit_node: self.selected_exit_node.clone(),
            lan_access_enabled: self.lan_access_enabled,
        };
        persist_session_snapshot(&snapshot, &self.state_path).map_err(|err| {
            self.restrict_permanent("state persist failure".to_string());
            let _ = self.controller.force_fail_closed("state_persist_failure");
            err.to_string()
        })
    }

    fn try_load_auto_tunnel_bundle_for_dns_context(&self) -> Result<AutoTunnelBundle, String> {
        let bundle_path = self
            .auto_tunnel_bundle_path
            .as_ref()
            .ok_or("no assignment path")?;
        if !bundle_path.exists() {
            return Err("assignment bundle not found".to_string());
        }
        let _content = std::fs::read_to_string(bundle_path).map_err(|e| e.to_string())?;

        // Use the existing private parser logic. Since load_auto_tunnel_bundle is what parses it,
        // and it returns AutoTunnelEnvelope, we can reuse it if we can construct the arguments.
        // But load_auto_tunnel_bundle requires verification. We just want to parse it for context.
        // However, we can use load_auto_tunnel_bundle with a relaxed policy OR just trust the file on disk
        // since we are about to re-verify everything in fetch_dns_zone anyway?
        // Actually, the prompt says: "Use a local load, not the full load_verified_auto_tunnel ... we just need the bundle content".
        // It implies we should duplicate the parsing logic or reuse a parser.
        // Since AutoTunnelBundle is likely a struct with a parse method (or internal parsing logic), let's check.
        // I don't see a public parse method for AutoTunnelBundle exposed.
        // However, I can call load_auto_tunnel_bundle and just ignore the policy error?
        // No, that enforces signatures.
        // Let's assume for now we call load_auto_tunnel_bundle with current watermark.

        // Wait, I should check if there is a 'parse_auto_tunnel_bundle_content' or similar.
        // If not, I'll have to rely on `load_auto_tunnel_bundle` being available.
        // I see `load_auto_tunnel_bundle` call in `fetch_assignment`.

        let verifier_path = self
            .auto_tunnel_verifier_key_path
            .as_ref()
            .ok_or("no verifier path")?;
        let watermark_path = self
            .auto_tunnel_watermark_path
            .as_ref()
            .ok_or("no watermark path")?;

        let previous_watermark =
            load_auto_tunnel_watermark(watermark_path).map_err(|e| e.to_string())?;

        // We use the real load function. This is safe (it verifies signature again).
        // If it fails, we return Err, and caller passes None.
        let envelope = load_auto_tunnel_bundle(
            bundle_path,
            verifier_path,
            self.auto_tunnel_bundle_path
                .as_deref()
                .map(|_| DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS)
                .unwrap_or(DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS),
            TrustPolicy {
                max_signed_data_age_secs: DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
                max_clock_skew_secs: DEFAULT_SIGNED_STATE_MAX_CLOCK_SKEW_SECS,
            },
            previous_watermark,
        )
        .map_err(|e| format!("{e:?}"))?;

        Ok(envelope.bundle)
    }

    fn restore_state(&mut self) -> Result<(), ResilienceError> {
        if !self.state_path.exists() {
            return Ok(());
        }

        let snapshot = load_session_snapshot(&self.state_path)?;
        self.selected_exit_node = snapshot.selected_exit_node;
        self.lan_access_enabled = snapshot.lan_access_enabled;
        self.advertised_routes = snapshot.peer_ids.into_iter().collect::<BTreeSet<_>>();
        self.controller.set_lan_access(self.lan_access_enabled);

        if let Some(selected) = &self.selected_exit_node {
            if let Ok(node_id) = NodeId::new(selected.clone()) {
                for route in &self.advertised_routes {
                    self.controller.advertise_lan_route(node_id.clone(), route);
                }
            }
        }

        Ok(())
    }

    fn reconcile(&mut self) {
        self.reconcile_attempts = self.reconcile_attempts.saturating_add(1);
        self.last_reconcile_unix = Some(unix_now());
        if let Err(err) = self.enforce_blind_exit_invariants() {
            self.reconcile_failures = self.reconcile_failures.saturating_add(1);
            let message = format!("blind-exit role invariants failed during reconcile: {err}");
            self.last_reconcile_error = Some(message.clone());
            self.restrict_permanent(message);
            let _ = self
                .controller
                .force_fail_closed("blind_exit_invariants_failed");
            return;
        }

        let trust = match self.load_verified_trust() {
            Ok(evidence) => evidence,
            Err(err) => {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("trust reconcile failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self.controller.force_fail_closed("trust_reconcile_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }
        };

        let membership_state = match self.load_verified_membership() {
            Ok(state) => state,
            Err(err) => {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("membership reconcile failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self
                    .controller
                    .force_fail_closed("membership_reconcile_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }
        };
        let membership_directory = membership_directory_from_state(&membership_state);

        let auto_bundle = if self.auto_tunnel_enforce {
            match self.load_verified_auto_tunnel(&membership_directory) {
                Ok(bundle) => Some(bundle),
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("auto-tunnel reconcile failed: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self
                        .controller
                        .force_fail_closed("auto_tunnel_reconcile_failed");
                    self.promote_to_permanent_if_over_limit();
                    return;
                }
            }
        } else {
            None
        };

        let assignment_changed = auto_bundle
            .as_ref()
            .map(|envelope| Some(envelope.watermark) != self.last_applied_assignment)
            .unwrap_or(false);
        let membership_changed = self
            .membership_state
            .as_ref()
            .map(|current| current.epoch != membership_state.epoch)
            .unwrap_or(true);

        self.last_reconcile_error = None;
        let now_unix = unix_now();
        self.maybe_preexpiry_refresh_traversal(now_unix);
        self.maybe_preexpiry_refresh_dns_zone(now_unix, auto_bundle.as_ref());
        self.maybe_trigger_endpoint_change_refresh();

        if self.controller.state() == DataplaneState::FailClosed
            || self.restriction_mode == RestrictionMode::Recoverable
            || assignment_changed
            || membership_changed
            || self.local_route_reconcile_pending
        {
            let (mesh_cidr, local_cidr, peers, routes, auto_exit, auto_lan_access, auto_watermark) =
                if let Some(ref envelope) = auto_bundle {
                    let lan_enabled = envelope
                        .bundle
                        .routes
                        .iter()
                        .any(|route| route.kind == RouteKind::ExitNodeLan);
                    (
                        envelope.bundle.mesh_cidr.clone(),
                        envelope.bundle.assigned_cidr.clone(),
                        envelope.bundle.peers.clone(),
                        envelope.bundle.routes.clone(),
                        envelope.bundle.selected_exit_node.clone(),
                        lan_enabled,
                        Some(envelope.watermark),
                    )
                } else {
                    (
                        "100.64.0.0/10".to_string(),
                        "100.64.0.1/32".to_string(),
                        Vec::new(),
                        Vec::new(),
                        None,
                        false,
                        None,
                    )
                };
            if let Err(err) =
                self.validate_blind_exit_assignment(auto_exit.as_deref(), auto_lan_access)
            {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                self.last_reconcile_error = Some(err.clone());
                self.restrict_recoverable(err);
                let _ = self
                    .controller
                    .force_fail_closed("blind_exit_assignment_rejected");
                self.promote_to_permanent_if_over_limit();
                return;
            }
            let local_node = match NodeId::new(self.local_node_id.clone()) {
                Ok(node_id) => node_id,
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("invalid local node id in runtime: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_permanent(message);
                    let _ = self.controller.force_fail_closed("invalid_local_node_id");
                    return;
                }
            };

            if let Err(err) = self.ensure_runtime_private_key_material() {
                self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                let message = format!("runtime key preparation failed: {err}");
                self.last_reconcile_error = Some(message.clone());
                self.restrict_recoverable(message);
                let _ = self
                    .controller
                    .force_fail_closed("runtime_key_prepare_failed");
                self.promote_to_permanent_if_over_limit();
                return;
            }

            let serve_exit_node = if self.node_role.is_blind_exit() {
                true
            } else if self.auto_tunnel_enforce {
                self.is_serving_exit_node(auto_exit.as_deref())
            } else {
                self.is_serving_exit_node(self.selected_exit_node.as_deref())
            };

            let peers = match self.apply_traversal_authority_to_peers(peers, &membership_directory)
            {
                Ok(peers) => peers,
                Err(err) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("traversal authority rejected reconcile apply: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self
                        .controller
                        .force_fail_closed("reconcile_traversal_authority_rejected");
                    self.promote_to_permanent_if_over_limit();
                    return;
                }
            };

            let routes = sanitize_dataplane_routes_for_node_role(self.node_role, routes);
            let apply_result = self.controller.apply_dataplane_generation(
                trust,
                RuntimeContext {
                    local_node,
                    interface_name: self.wg_interface.clone(),
                    mesh_cidr,
                    local_cidr,
                },
                peers,
                routes,
                ApplyOptions {
                    protected_dns: true,
                    ipv6_parity_supported: false,
                    serve_exit_node,
                    exit_mode: if self.node_role.is_blind_exit() {
                        ExitMode::Off
                    } else if self.auto_tunnel_enforce {
                        if auto_exit.is_some() {
                            ExitMode::FullTunnel
                        } else {
                            ExitMode::Off
                        }
                    } else {
                        self.desired_exit_mode()
                    },
                },
            );
            let cleanup_result = self.scrub_runtime_private_key_material();

            match (apply_result, cleanup_result) {
                (Ok(()), Ok(())) => {
                    self.membership_state = Some(membership_state);
                    self.membership_directory = membership_directory;
                    self.refresh_dns_zone_state(auto_bundle.as_ref());
                    if self.auto_tunnel_enforce {
                        if self.node_role.is_blind_exit() {
                            self.selected_exit_node = None;
                            self.lan_access_enabled = false;
                            self.controller.set_lan_access(false);
                        } else {
                            self.selected_exit_node = auto_exit;
                            self.lan_access_enabled = auto_lan_access;
                            self.controller.set_lan_access(auto_lan_access);
                        }
                        self.last_applied_assignment = auto_watermark;
                    }
                    self.restriction_mode = RestrictionMode::None;
                    self.bootstrap_error = None;
                    self.reconcile_failures = 0;
                    self.local_route_reconcile_pending = false;
                }
                (Err(err), Ok(())) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!("reconcile dataplane apply failed: {err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self.controller.force_fail_closed("reconcile_apply_failed");
                    self.promote_to_permanent_if_over_limit();
                }
                (Err(err), Err(cleanup_err)) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message = format!(
                        "reconcile dataplane apply failed: {err}; runtime key cleanup failed: {cleanup_err}"
                    );
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self.controller.force_fail_closed("reconcile_apply_failed");
                    self.promote_to_permanent_if_over_limit();
                }
                (Ok(()), Err(cleanup_err)) => {
                    self.reconcile_failures = self.reconcile_failures.saturating_add(1);
                    let message =
                        format!("runtime key cleanup failed after reconcile apply: {cleanup_err}");
                    self.last_reconcile_error = Some(message.clone());
                    self.restrict_recoverable(message);
                    let _ = self
                        .controller
                        .force_fail_closed("runtime_key_cleanup_failed");
                    self.promote_to_permanent_if_over_limit();
                }
            }
        }

        self.poll_endpoint_monitor_and_maybe_refresh();
        self.refresh_traversal_hint_state(false);
        self.maintain_exit_port_forward(
            self.is_serving_exit_node(self.selected_exit_node.as_deref()),
        );
    }

    fn enforce_blind_exit_invariants(&mut self) -> Result<(), String> {
        if !self.node_role.is_blind_exit() {
            return Ok(());
        }
        let mut changed = false;
        if self.selected_exit_node.take().is_some() {
            changed = true;
        }
        if self.lan_access_enabled {
            self.lan_access_enabled = false;
            self.controller.set_lan_access(false);
            changed = true;
        }
        if !self
            .advertised_routes
            .contains(BLIND_EXIT_DEFAULT_ROUTE_CIDR)
        {
            self.advertised_routes
                .insert(BLIND_EXIT_DEFAULT_ROUTE_CIDR.to_string());
            self.local_route_reconcile_pending = true;
            changed = true;
        }
        if changed {
            self.persist_state()?;
        }
        Ok(())
    }

    fn validate_blind_exit_assignment(
        &self,
        selected_exit_node: Option<&str>,
        lan_access_enabled: bool,
    ) -> Result<(), String> {
        if !self.node_role.is_blind_exit() {
            return Ok(());
        }
        if selected_exit_node.is_some() {
            eprintln!("rustynetd: ignoring selected_exit_node assignment for blind_exit role");
        }
        if lan_access_enabled {
            eprintln!("rustynetd: ignoring LAN route assignment for blind_exit role");
        }
        Ok(())
    }

    fn desired_exit_mode(&self) -> ExitMode {
        if self.selected_exit_node.is_some() {
            ExitMode::FullTunnel
        } else {
            ExitMode::Off
        }
    }

    fn is_serving_exit_node(&self, _selected_exit_node: Option<&str>) -> bool {
        self.node_role.is_blind_exit()
            || (self.node_role.is_admin()
                && self
                    .advertised_routes
                    .contains(BLIND_EXIT_DEFAULT_ROUTE_CIDR))
    }

    fn allow_auto_tunnel_exit_advertisement(&self, cidr: &str) -> bool {
        self.node_role.is_admin() && cidr == BLIND_EXIT_DEFAULT_ROUTE_CIDR
    }

    fn is_restricted(&self) -> bool {
        self.restriction_mode != RestrictionMode::None
    }

    fn restrict_recoverable(&mut self, message: String) {
        if self.restriction_mode == RestrictionMode::Permanent {
            return;
        }
        self.restriction_mode = RestrictionMode::Recoverable;
        self.bootstrap_error = Some(message);
    }

    fn restrict_permanent(&mut self, message: String) {
        self.restriction_mode = RestrictionMode::Permanent;
        self.bootstrap_error = Some(message);
    }

    fn promote_to_permanent_if_over_limit(&mut self) {
        if self.reconcile_failures >= u64::from(self.max_reconcile_failures) {
            self.restrict_permanent(format!(
                "reconcile failure threshold exceeded: {}",
                self.reconcile_failures
            ));
        }
    }

    fn maintain_exit_port_forward(&mut self, should_serve_exit: bool) {
        if !self.auto_port_forward_exit {
            self.release_exit_port_forward();
            self.clear_exit_port_forward_state();
            return;
        }

        #[cfg(target_os = "linux")]
        {
            if !should_serve_exit {
                self.release_exit_port_forward();
                self.clear_exit_port_forward_state();
                return;
            }

            let now_unix = unix_now();
            if let Some(current) = self.exit_port_forward_lease {
                let refresh_at = current
                    .renewed_at_unix
                    .saturating_add(u64::from(current.lease_secs.max(60) / 2));
                if now_unix < refresh_at {
                    return;
                }
            }

            let gateway =
                match detect_ipv4_default_gateway_for_interface(self.egress_interface.as_str()) {
                    Ok(value) => value,
                    Err(err) => {
                        self.exit_port_forward_last_error = Some(err);
                        self.exit_port_forward_lease = None;
                        return;
                    }
                };

            match nat_pmp_map_udp_port(
                gateway,
                self.wg_listen_port,
                self.wg_listen_port,
                self.auto_port_forward_lease_secs,
            ) {
                Ok((external_port, granted_lease_secs)) => {
                    if external_port != self.wg_listen_port {
                        let _ =
                            nat_pmp_delete_udp_port(gateway, self.wg_listen_port, external_port);
                        self.exit_port_forward_last_error = Some(format!(
                            "router mapped unexpected external port {external_port}; expected {}",
                            self.wg_listen_port
                        ));
                        self.exit_port_forward_lease = None;
                        return;
                    }
                    self.exit_port_forward_lease = Some(ExitPortForwardLease {
                        gateway,
                        internal_port: self.wg_listen_port,
                        external_port,
                        lease_secs: granted_lease_secs,
                        renewed_at_unix: now_unix,
                    });
                    self.exit_port_forward_last_error = None;
                }
                Err(err) => {
                    self.exit_port_forward_last_error = Some(err);
                    self.exit_port_forward_lease = None;
                }
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = should_serve_exit;
            self.exit_port_forward_last_error =
                Some("auto port forward is supported only on Linux".to_string());
        }
    }

    fn release_exit_port_forward(&mut self) {
        #[cfg(target_os = "linux")]
        {
            if let Some(lease) = self.exit_port_forward_lease {
                if let Err(err) =
                    nat_pmp_delete_udp_port(lease.gateway, lease.internal_port, lease.external_port)
                {
                    self.exit_port_forward_last_error =
                        Some(format!("auto port-forward release failed: {err}"));
                }
            }
        }
    }

    fn clear_exit_port_forward_state(&mut self) {
        #[cfg(target_os = "linux")]
        {
            self.exit_port_forward_lease = None;
        }
        self.exit_port_forward_last_error = None;
    }

    fn exit_port_forward_external_port(&self) -> Option<u16> {
        #[cfg(target_os = "linux")]
        {
            self.exit_port_forward_lease
                .map(|lease| lease.external_port)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_ipv4_default_gateway_for_interface(interface: &str) -> Result<Ipv4Addr, String> {
    let routes = fs::read_to_string("/proc/net/route")
        .map_err(|err| format!("read /proc/net/route failed: {err}"))?;
    for (index, line) in routes.lines().enumerate() {
        if index == 0 {
            continue;
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 {
            continue;
        }
        if fields[0] != interface {
            continue;
        }
        if fields[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(fields[3], 16)
            .map_err(|err| format!("parse route flags failed: {err}"))?;
        let route_is_up = (flags & 0x1) != 0;
        let has_gateway = (flags & 0x2) != 0;
        if !route_is_up || !has_gateway {
            continue;
        }
        let gateway_u32 = u32::from_str_radix(fields[2], 16)
            .map_err(|err| format!("parse default gateway failed: {err}"))?;
        let octets = gateway_u32.to_le_bytes();
        return Ok(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
    }
    Err(format!(
        "no IPv4 default gateway found for interface {interface}"
    ))
}

/// Collect current routable addresses per interface using `getifaddrs(2)`.
/// Returns a map of interface-name → Vec<IpAddr> for use with EndpointMonitor.
/// Loopback and link-local addresses are included as-is; EndpointMonitor
/// applies its own filtering via the `ignored_prefixes` list.
fn interface_name_is_usable_for_traversal_host_candidate(interface: &str) -> bool {
    interface != "lo" && !interface.starts_with(DEFAULT_WG_INTERFACE)
}

fn ip_is_usable_for_traversal_host_candidate(ip: IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(value) => !(value.is_link_local() || value.is_broadcast()),
        IpAddr::V6(value) => !value.is_unicast_link_local(),
    }
}

#[cfg(any(target_os = "linux", test))]
fn snapshot_has_usable_traversal_host_candidates(
    snapshot: &BTreeMap<String, Vec<std::net::IpAddr>>,
) -> bool {
    snapshot.iter().any(|(iface, addrs)| {
        interface_name_is_usable_for_traversal_host_candidate(iface.as_str())
            && addrs
                .iter()
                .copied()
                .any(ip_is_usable_for_traversal_host_candidate)
    })
}

#[cfg(any(target_os = "linux", test))]
fn collect_traversal_host_candidate_snapshot_with_retry<Collect, Wait>(
    mut collect: Collect,
    mut wait: Wait,
    attempts: usize,
) -> BTreeMap<String, Vec<std::net::IpAddr>>
where
    Collect: FnMut() -> BTreeMap<String, Vec<std::net::IpAddr>>,
    Wait: FnMut(Duration),
{
    let attempts = attempts.max(1);
    let mut last_snapshot = BTreeMap::new();
    for attempt in 0..attempts {
        let current = collect();
        let usable = snapshot_has_usable_traversal_host_candidates(&current);
        last_snapshot = current;
        if usable {
            return last_snapshot;
        }
        if attempt + 1 < attempts {
            wait(Duration::from_millis(
                TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_DELAY_MS,
            ));
        }
    }
    last_snapshot
}

#[cfg(target_os = "linux")]
fn collect_linux_interface_addrs_for_traversal() -> BTreeMap<String, Vec<std::net::IpAddr>> {
    collect_traversal_host_candidate_snapshot_with_retry(
        collect_linux_interface_addrs,
        sleep,
        TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_ATTEMPTS,
    )
}

#[cfg(target_os = "linux")]
fn collect_linux_interface_addrs() -> BTreeMap<String, Vec<std::net::IpAddr>> {
    use std::net::IpAddr;
    let mut result: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
    let Ok(iter) = ifaddrs::getifaddrs() else {
        return result;
    };
    for ifaddr in iter {
        let Some(addr) = ifaddr.address else {
            continue;
        };
        let ip: IpAddr = if let Some(inet) = addr.as_sockaddr_in() {
            IpAddr::V4(inet.ip())
        } else if let Some(inet6) = addr.as_sockaddr_in6() {
            IpAddr::V6(inet6.ip())
        } else {
            continue;
        };
        result.entry(ifaddr.interface_name).or_default().push(ip);
    }
    result
}

#[cfg(target_os = "linux")]
fn nat_pmp_map_udp_port(
    gateway: Ipv4Addr,
    internal_port: u16,
    requested_external_port: u16,
    requested_lease_secs: u32,
) -> Result<(u16, u32), String> {
    let mut request = [0u8; 12];
    request[0] = 0;
    request[1] = 1;
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&requested_external_port.to_be_bytes());
    request[8..12].copy_from_slice(&requested_lease_secs.to_be_bytes());
    let response = nat_pmp_round_trip(gateway, &request)?;
    if response.len() < 16 {
        return Err("nat-pmp mapping response too short".to_string());
    }
    if response[0] != 0 || response[1] != 129 {
        return Err("nat-pmp mapping response opcode mismatch".to_string());
    }
    let result_code = u16::from_be_bytes([response[2], response[3]]);
    if result_code != 0 {
        return Err(format!(
            "nat-pmp mapping rejected by gateway (code {result_code})"
        ));
    }
    let returned_internal = u16::from_be_bytes([response[8], response[9]]);
    if returned_internal != internal_port {
        return Err(format!(
            "nat-pmp internal port mismatch: expected {internal_port}, got {returned_internal}"
        ));
    }
    let mapped_external = u16::from_be_bytes([response[10], response[11]]);
    let granted_lease =
        u32::from_be_bytes([response[12], response[13], response[14], response[15]]);
    if mapped_external == 0 {
        return Err("nat-pmp gateway returned invalid external port".to_string());
    }
    if granted_lease == 0 {
        return Err("nat-pmp gateway returned zero lease".to_string());
    }
    Ok((mapped_external, granted_lease))
}

#[cfg(target_os = "linux")]
fn nat_pmp_delete_udp_port(
    gateway: Ipv4Addr,
    internal_port: u16,
    current_external_port: u16,
) -> Result<(), String> {
    let mut request = [0u8; 12];
    request[0] = 0;
    request[1] = 1;
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&current_external_port.to_be_bytes());
    request[8..12].copy_from_slice(&0u32.to_be_bytes());
    let response = nat_pmp_round_trip(gateway, &request)?;
    if response.len() < 16 {
        return Err("nat-pmp delete response too short".to_string());
    }
    if response[0] != 0 || response[1] != 129 {
        return Err("nat-pmp delete response opcode mismatch".to_string());
    }
    let result_code = u16::from_be_bytes([response[2], response[3]]);
    if result_code != 0 {
        return Err(format!(
            "nat-pmp delete rejected by gateway (code {result_code})"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn nat_pmp_round_trip(gateway: Ipv4Addr, request: &[u8]) -> Result<Vec<u8>, String> {
    let gateway_addr = SocketAddrV4::new(gateway, 5351);
    let socket = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
        .map_err(|err| format!("nat-pmp socket bind failed: {err}"))?;
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("nat-pmp read-timeout setup failed: {err}"))?;
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|err| format!("nat-pmp write-timeout setup failed: {err}"))?;
    socket
        .send_to(request, gateway_addr)
        .map_err(|err| format!("nat-pmp request send failed: {err}"))?;
    let mut response = [0u8; 64];
    let (len, from) = socket
        .recv_from(&mut response)
        .map_err(|err| format!("nat-pmp response receive failed: {err}"))?;
    if from.ip() != gateway {
        return Err(format!(
            "nat-pmp response source mismatch: expected {gateway}, got {}",
            from.ip()
        ));
    }
    if from.port() != 5351 {
        return Err(format!(
            "nat-pmp response source port mismatch: expected 5351, got {}",
            from.port()
        ));
    }
    Ok(response[..len].to_vec())
}

fn zeroize_optional_bytes(value: &mut Option<Vec<u8>>) {
    if let Some(bytes) = value.as_mut() {
        bytes.fill(0);
    }
}

fn daemon_system(config: &DaemonConfig) -> Result<RuntimeSystem, DaemonError> {
    #[cfg(target_os = "linux")]
    {
        // In test mode, the in-memory backend uses DryRunSystem to avoid modifying
        // host network state (nftables killswitch, ip rules, sysctl) which would sever
        // the network connection running the tests.
        #[cfg(test)]
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            return Ok(RuntimeSystem::DryRun(
                crate::phase10::DryRunSystem::default(),
            ));
        }

        let mode = match config.dataplane_mode {
            DaemonDataplaneMode::Shell => LinuxDataplaneMode::Shell,
            DaemonDataplaneMode::HybridNative => LinuxDataplaneMode::HybridNative,
        };
        let helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        let system = LinuxCommandSystem::new(
            config.wg_interface.clone(),
            config.egress_interface.clone(),
            mode,
            helper_client,
            config.fail_closed_ssh_allow,
            config.fail_closed_ssh_allow_cidrs.clone(),
        )
        .map(|system| {
            system.with_traversal_bootstrap_allow_endpoints(config.traversal_stun_servers.clone())
        })
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        Ok(RuntimeSystem::Linux(system))
    }
    #[cfg(target_os = "macos")]
    {
        #[cfg(test)]
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            return Ok(RuntimeSystem::DryRun(
                crate::phase10::DryRunSystem::default(),
            ));
        }

        let helper_client = config
            .privileged_helper_socket_path
            .as_ref()
            .map(|path| {
                PrivilegedCommandClient::new(
                    path.clone(),
                    Duration::from_millis(config.privileged_helper_timeout_ms.get()),
                )
            })
            .transpose()
            .map_err(DaemonError::InvalidConfig)?;
        let system = MacosCommandSystem::new(
            config.wg_interface.clone(),
            config.egress_interface.clone(),
            helper_client,
            config.fail_closed_ssh_allow,
            config.fail_closed_ssh_allow_cidrs.clone(),
        )
        .map(|system| {
            system.with_traversal_bootstrap_allow_endpoints(config.traversal_stun_servers.clone())
        })
        .map_err(|err| DaemonError::InvalidConfig(err.to_string()))?;
        Ok(RuntimeSystem::Macos(system))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
            #[cfg(test)]
            {
                return Ok(RuntimeSystem::DryRun(
                    crate::phase10::DryRunSystem::default(),
                ));
            }
        }
        Err(DaemonError::InvalidConfig(
            "daemon dataplane requires a linux or macos host with a supported wireguard backend"
                .to_string(),
        ))
    }
}

pub fn run_daemon(config: DaemonConfig) -> Result<(), DaemonError> {
    let mut config = config;
    if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
        return Err(DaemonError::InvalidConfig(
            "in-memory backend is disabled in production daemon paths".to_string(),
        ));
    }
    if config.socket_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "socket path must not be empty".to_string(),
        ));
    }
    resolve_configured_egress_interface(&mut config)?;
    validate_daemon_config(&config)?;
    prepare_runtime_wireguard_key(&config)?;
    if let Err(err) = run_preflight_checks(&config) {
        let _ = scrub_runtime_wireguard_key_after_bootstrap(&config);
        return Err(err);
    }

    let mut runtime = match DaemonRuntime::new(&config) {
        Ok(runtime) => runtime,
        Err(err) => {
            let _ = scrub_runtime_wireguard_key_after_bootstrap(&config);
            return Err(err);
        }
    };
    runtime.bootstrap();
    scrub_runtime_wireguard_key_after_bootstrap(&config)?;

    #[cfg(windows)]
    {
        drop(runtime);
        return Err(DaemonError::InvalidConfig(windows_ipc_blocker_reason(
            WindowsLocalIpcRole::DaemonControl,
        )));
    }

    #[cfg(not(windows))]
    {
        if let Some(parent) = config.socket_path.parent() {
            fs::create_dir_all(parent).map_err(|err| DaemonError::Io(err.to_string()))?;
            match fs::set_permissions(parent, fs::Permissions::from_mode(0o700)) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                    let metadata = fs::metadata(parent).map_err(|meta_err| {
                        DaemonError::Io(format!(
                            "inspect socket parent after chmod denial failed: {meta_err}"
                        ))
                    })?;
                    let mode = metadata.permissions().mode() & 0o777;
                    let owner_uid = metadata.uid();
                    let expected_uid = Uid::effective().as_raw();
                    let root_managed_shared_runtime = owner_uid == 0 && mode == 0o770;
                    if !root_managed_shared_runtime || owner_uid == expected_uid {
                        return Err(DaemonError::Io(err.to_string()));
                    }
                }
                Err(err) => {
                    return Err(DaemonError::Io(err.to_string()));
                }
            }
        }

        if config.socket_path.exists() {
            fs::remove_file(&config.socket_path).map_err(|err| DaemonError::Io(err.to_string()))?;
        }

        let listener = UnixListener::bind(&config.socket_path)
            .map_err(|err| DaemonError::Io(format!("bind failed: {err}")))?;
        fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o600))
            .map_err(|err| DaemonError::Io(err.to_string()))?;
        listener
            .set_nonblocking(true)
            .map_err(|err| DaemonError::Io(format!("socket nonblocking failed: {err}")))?;
        let dns_socket = UdpSocket::bind(config.dns_resolver_bind_addr)
            .map_err(|err| DaemonError::Io(format!("dns resolver bind failed: {err}")))?;
        dns_socket
            .set_nonblocking(true)
            .map_err(|err| DaemonError::Io(format!("dns resolver nonblocking failed: {err}")))?;

        let socket_owner_uid = socket_owner_uid(&config.socket_path)?;

        let mut processed = 0usize;
        let reconcile_interval = Duration::from_millis(config.reconcile_interval_ms.get().max(100));
        let mut next_reconcile = Instant::now() + reconcile_interval;
        let mut dns_buffer = [0u8; 1536];

        loop {
            let mut processed_io = false;
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .map_err(|err| {
                            DaemonError::Io(format!("socket read-timeout failed: {err}"))
                        })?;
                    let response = match read_command_envelope(&stream).map_err(DaemonError::Io)? {
                        CommandEnvelope::Local(parsed) => {
                            let authorized = if parsed.is_mutating() {
                                match (peer_uid(&stream), peer_gid(&stream)) {
                                    (Some(peer_uid), Some(peer_gid)) => {
                                        // allow root uid, socket owner uid, or socket owner gid (e.g., rustynet group)
                                        peer_uid == 0
                                            || peer_uid == socket_owner_uid
                                            || peer_gid
                                                == socket_owner_gid(&config.socket_path)
                                                    .unwrap_or(0)
                                    }
                                    (Some(peer_uid), None) => {
                                        peer_uid == 0 || peer_uid == socket_owner_uid
                                    }
                                    _ => false,
                                }
                            } else {
                                true
                            };

                            if authorized {
                                runtime.handle_command(parsed)
                            } else {
                                IpcResponse::err("unauthorized mutation request")
                            }
                        }
                        CommandEnvelope::Remote(remote_envelope) => {
                            let now_unix = unix_now();
                            match runtime.authorize_remote_command(&remote_envelope, now_unix) {
                                Ok(parsed) => runtime.handle_command(parsed),
                                Err(err) => IpcResponse::err(format!(
                                    "remote ops authorization failed: {err}"
                                )),
                            }
                        }
                    };

                    write_response(stream, response).map_err(DaemonError::Io)?;
                    processed = processed.saturating_add(1);
                    processed_io = true;
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                Err(err) => return Err(DaemonError::Io(format!("accept failed: {err}"))),
            }
            loop {
                match dns_socket.recv_from(&mut dns_buffer) {
                    Ok((length, peer_addr)) => {
                        if let Some(response) = build_dns_response(&runtime, &dns_buffer[..length])
                        {
                            dns_socket.send_to(&response, peer_addr).map_err(|err| {
                                DaemonError::Io(format!("dns resolver send failed: {err}"))
                            })?;
                        }
                        processed = processed.saturating_add(1);
                        processed_io = true;
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                    Err(err) => {
                        return Err(DaemonError::Io(format!("dns resolver recv failed: {err}")));
                    }
                }
            }

            let now = Instant::now();
            if now >= next_reconcile {
                runtime.reconcile();
                next_reconcile = now + reconcile_interval;
            }
            let now_unix = unix_now();
            runtime.poll_stun_results();
            runtime.maybe_preexpiry_refresh_traversal(now_unix);
            runtime.poll_endpoint_monitor_and_maybe_refresh();
            runtime.maybe_trigger_endpoint_change_refresh();

            if config
                .max_requests
                .map(|max| processed >= max.get())
                .unwrap_or(false)
            {
                break;
            }

            if !processed_io {
                let sleep_for = next_reconcile
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(25));
                if !sleep_for.is_zero() {
                    sleep(sleep_for);
                }
            }
        }

        scrub_runtime_wireguard_key_after_bootstrap(&config)?;
        Ok(())
    }
}

const DNS_HEADER_BYTES: usize = 12;
const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const DNS_CLASS_IN: u16 = 1;
const DNS_FLAG_QR: u16 = 0x8000;
const DNS_FLAG_AA: u16 = 0x0400;
const DNS_FLAG_RD: u16 = 0x0100;
const DNS_RCODE_NOERROR: u16 = 0;
const DNS_RCODE_FORMERR: u16 = 1;
const DNS_RCODE_SERVFAIL: u16 = 2;
const DNS_RCODE_NXDOMAIN: u16 = 3;
const DNS_RCODE_REFUSED: u16 = 5;

struct DnsQuestion {
    id: u16,
    flags: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
}

fn build_dns_response(runtime: &DaemonRuntime, request: &[u8]) -> Option<Vec<u8>> {
    let fallback_id = request
        .get(0..2)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0);
    let fallback_flags = request
        .get(2..4)
        .and_then(|value| value.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or(0);
    let query = match parse_dns_question(request) {
        Ok(query) => query,
        Err(_) => {
            return Some(render_dns_error_response(
                fallback_id,
                fallback_flags,
                DNS_RCODE_FORMERR,
            ));
        }
    };
    if !dns_name_in_managed_zone(&query.qname, &runtime.dns_zone_name) {
        return Some(render_dns_question_response(
            &query,
            DNS_RCODE_REFUSED,
            None,
        ));
    }
    if query.qclass != DNS_CLASS_IN {
        return Some(render_dns_question_response(
            &query,
            DNS_RCODE_REFUSED,
            None,
        ));
    }
    if runtime.dns_zone.is_none() || runtime.dns_zone_error.is_some() {
        return Some(render_dns_question_response(
            &query,
            DNS_RCODE_SERVFAIL,
            None,
        ));
    }
    if query.qtype == DNS_TYPE_A {
        let answer = runtime.resolve_dns_ipv4_record(&query.qname);
        return Some(match answer {
            Some((ip, ttl)) => {
                render_dns_question_response(&query, DNS_RCODE_NOERROR, Some((ip, ttl)))
            }
            None => render_dns_question_response(&query, DNS_RCODE_NXDOMAIN, None),
        });
    }
    if query.qtype == DNS_TYPE_AAAA {
        return Some(render_dns_question_response(
            &query,
            DNS_RCODE_NOERROR,
            None,
        ));
    }
    Some(render_dns_question_response(
        &query,
        DNS_RCODE_NOERROR,
        None,
    ))
}

fn parse_dns_question(request: &[u8]) -> Result<DnsQuestion, String> {
    if request.len() < DNS_HEADER_BYTES {
        return Err("dns request too short".to_string());
    }
    let id = u16::from_be_bytes([request[0], request[1]]);
    let flags = u16::from_be_bytes([request[2], request[3]]);
    if (flags & DNS_FLAG_QR) != 0 {
        return Err("dns request must be a query".to_string());
    }
    let qdcount = u16::from_be_bytes([request[4], request[5]]);
    if qdcount != 1 {
        return Err("dns request must contain exactly one question".to_string());
    }
    let mut offset = DNS_HEADER_BYTES;
    let mut labels = Vec::new();
    loop {
        let length = *request
            .get(offset)
            .ok_or_else(|| "dns qname is truncated".to_string())?;
        offset = offset.saturating_add(1);
        if length == 0 {
            break;
        }
        if (length & 0b1100_0000) != 0 {
            return Err("dns name compression is not supported in queries".to_string());
        }
        let label_len = usize::from(length);
        let end = offset.saturating_add(label_len);
        let label_bytes = request
            .get(offset..end)
            .ok_or_else(|| "dns qname label is truncated".to_string())?;
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| "dns qname contains invalid utf8".to_string())?;
        labels.push(label.to_ascii_lowercase());
        offset = end;
    }
    let qtype = u16::from_be_bytes([
        *request
            .get(offset)
            .ok_or_else(|| "dns qtype is truncated".to_string())?,
        *request
            .get(offset + 1)
            .ok_or_else(|| "dns qtype is truncated".to_string())?,
    ]);
    let qclass = u16::from_be_bytes([
        *request
            .get(offset + 2)
            .ok_or_else(|| "dns qclass is truncated".to_string())?,
        *request
            .get(offset + 3)
            .ok_or_else(|| "dns qclass is truncated".to_string())?,
    ]);
    Ok(DnsQuestion {
        id,
        flags,
        qname: labels.join("."),
        qtype,
        qclass,
    })
}

fn dns_name_in_managed_zone(qname: &str, zone_name: &str) -> bool {
    qname == zone_name
        || qname
            .strip_suffix(zone_name)
            .map(|prefix| prefix.ends_with('.'))
            .unwrap_or(false)
}

fn render_dns_error_response(id: u16, request_flags: u16, rcode: u16) -> Vec<u8> {
    let mut response = Vec::with_capacity(DNS_HEADER_BYTES);
    response.extend_from_slice(&id.to_be_bytes());
    let flags = DNS_FLAG_QR | DNS_FLAG_AA | (request_flags & DNS_FLAG_RD) | (rcode & 0x000f);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response
}

fn render_dns_question_response(
    question: &DnsQuestion,
    rcode: u16,
    answer: Option<(Ipv4Addr, u32)>,
) -> Vec<u8> {
    let question_section = question_bytes(question);
    let mut response = Vec::with_capacity(DNS_HEADER_BYTES + question_section.len() + 16);
    response.extend_from_slice(&question.id.to_be_bytes());
    let flags = DNS_FLAG_QR | DNS_FLAG_AA | (question.flags & DNS_FLAG_RD) | (rcode & 0x000f);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1u16.to_be_bytes());
    response.extend_from_slice(&(if answer.is_some() { 1u16 } else { 0u16 }).to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&0u16.to_be_bytes());
    response.extend_from_slice(&question_section);
    if let Some((ip, ttl)) = answer {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&DNS_TYPE_A.to_be_bytes());
        response.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        response.extend_from_slice(&ttl.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&ip.octets());
    }
    response
}

fn question_bytes(question: &DnsQuestion) -> Vec<u8> {
    let mut out = Vec::new();
    for label in question.qname.split('.').filter(|label| !label.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&question.qtype.to_be_bytes());
    out.extend_from_slice(&question.qclass.to_be_bytes());
    out
}

fn scrub_runtime_wireguard_key_after_bootstrap(config: &DaemonConfig) -> Result<(), DaemonError> {
    scrub_runtime_wireguard_key_material(
        config.backend_mode,
        config.wg_private_key_path.as_deref(),
        config.wg_encrypted_private_key_path.as_deref(),
    )
    .map_err(|err| DaemonError::InvalidConfig(format!("runtime private key cleanup failed: {err}")))
}

fn scrub_runtime_wireguard_key_material(
    backend_mode: DaemonBackendMode,
    runtime_path: Option<&Path>,
    encrypted_private_key_path: Option<&Path>,
) -> Result<(), String> {
    if !backend_mode.requires_runtime_wireguard_key_material() {
        return Ok(());
    }
    if encrypted_private_key_path.is_none() {
        return Ok(());
    }
    let Some(runtime_path) = runtime_path else {
        return Ok(());
    };
    if !runtime_path.exists() {
        return Ok(());
    }
    remove_file_if_present(runtime_path)
}

fn prepare_runtime_wireguard_key(config: &DaemonConfig) -> Result<(), DaemonError> {
    prepare_runtime_wireguard_key_material(
        config.backend_mode,
        config.wg_private_key_path.as_deref(),
        config.wg_encrypted_private_key_path.as_deref(),
        config.wg_key_passphrase_path.as_deref(),
    )
    .map_err(DaemonError::InvalidConfig)
}

fn prepare_runtime_wireguard_key_material(
    backend_mode: DaemonBackendMode,
    runtime_path: Option<&Path>,
    encrypted_private_key_path: Option<&Path>,
    passphrase_path: Option<&Path>,
) -> Result<(), String> {
    if !backend_mode.requires_runtime_wireguard_key_material() {
        return Ok(());
    }

    let runtime_path = runtime_path.ok_or_else(|| {
        "wg private key path is required for linux-wireguard or macos-wireguard backend".to_string()
    })?;

    if let Some(encrypted_path) = encrypted_private_key_path {
        let passphrase_path = passphrase_path.ok_or_else(|| {
            "wg key passphrase path is required when encrypted key path is configured".to_string()
        })?;
        let mut decrypted = decrypt_private_key(encrypted_path, passphrase_path)
            .map_err(|err| format!("wg key decrypt failed: {err}"))?;
        let write_result = write_runtime_private_key(runtime_path, &decrypted);
        decrypted.fill(0);
        if let Err(err) = write_result {
            let _ = remove_file_if_present(runtime_path);
            return Err(format!("wg runtime key write failed: {err}"));
        }
        return Ok(());
    }

    validate_private_key_permissions(runtime_path).map_err(|err| err.to_string())
}

fn validate_daemon_config(config: &DaemonConfig) -> Result<(), DaemonError> {
    if matches!(config.backend_mode, DaemonBackendMode::InMemory) {
        return Err(DaemonError::InvalidConfig(
            "in-memory backend is disabled in production daemon paths".to_string(),
        ));
    }
    if matches!(
        config.backend_mode,
        DaemonBackendMode::MacosWireguardUserspaceShared
    ) {
        let blocker = config
            .backend_mode
            .userspace_shared_blocker()
            .expect("macos userspace-shared blocker should exist");
        return Err(DaemonError::InvalidConfig(blocker.to_string()));
    }
    #[cfg(all(not(test), not(target_os = "linux")))]
    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguardUserspaceShared
    ) {
        return Err(DaemonError::InvalidConfig(
            "linux-wireguard-userspace-shared backend is only supported on linux".to_string(),
        ));
    }

    NodeId::new(config.node_id.clone())
        .map_err(|err| DaemonError::InvalidConfig(format!("node id is invalid: {err}")))?;

    if config.trust_url.is_some()
        || config.traversal_url.is_some()
        || config.assignment_url.is_some()
        || config.dns_zone_url.is_some()
    {
        return Err(DaemonError::InvalidConfig(
            "remote network state fetch is disabled in hardened daemon paths; use pinned local signed artifacts"
                .to_string(),
        ));
    }

    validate_control_socket_path(&config.socket_path)?;
    validate_runtime_file_path(&config.state_path, "state")?;
    if let Some(path) = config.privileged_helper_socket_path.as_ref() {
        validate_privileged_helper_control_path(path)?;
    }
    validate_runtime_file_path(&config.trust_evidence_path, "trust evidence")?;
    validate_runtime_file_path(&config.trust_verifier_key_path, "trust verifier key")?;
    validate_runtime_file_path(&config.trust_watermark_path, "trust watermark")?;
    validate_runtime_file_path(&config.membership_snapshot_path, "membership snapshot")?;
    validate_runtime_file_path(&config.membership_log_path, "membership log")?;
    validate_runtime_file_path(&config.membership_watermark_path, "membership watermark")?;
    if let Some(path) = config.remote_ops_token_verifier_key_path.as_ref() {
        validate_runtime_file_path(path, "remote ops token verifier key")?;
    }
    if let Some(path) = config.auto_tunnel_bundle_path.as_ref() {
        validate_runtime_file_path(path, "auto tunnel bundle")?;
    }
    if let Some(path) = config.auto_tunnel_verifier_key_path.as_ref() {
        validate_runtime_file_path(path, "auto tunnel verifier key")?;
    }
    if let Some(path) = config.auto_tunnel_watermark_path.as_ref() {
        validate_runtime_file_path(path, "auto tunnel watermark")?;
    }
    validate_runtime_file_path(&config.dns_zone_bundle_path, "dns zone bundle")?;
    validate_runtime_file_path(&config.dns_zone_verifier_key_path, "dns zone verifier key")?;
    validate_runtime_file_path(&config.dns_zone_watermark_path, "dns zone watermark")?;
    validate_runtime_file_path(&config.traversal_bundle_path, "traversal bundle")?;
    validate_runtime_file_path(
        &config.traversal_verifier_key_path,
        "traversal verifier key",
    )?;
    validate_runtime_file_path(&config.traversal_watermark_path, "traversal watermark")?;
    if config.traversal_probe_max_candidates.get() > MAX_TRAVERSAL_CANDIDATE_COUNT {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe max candidates must be at most {MAX_TRAVERSAL_CANDIDATE_COUNT}"
        )));
    }
    let max_probe_pairs_allowed = config
        .traversal_probe_max_candidates
        .get()
        .saturating_mul(config.traversal_probe_max_candidates.get());
    if config.traversal_probe_max_pairs.get() > max_probe_pairs_allowed {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe max pairs must be at most {max_probe_pairs_allowed} for max candidates {}",
            config.traversal_probe_max_candidates.get()
        )));
    }
    if config.traversal_probe_simultaneous_open_rounds.get()
        > MAX_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS
    {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe rounds must be at most {MAX_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS}"
        )));
    }
    if config.traversal_probe_round_spacing_ms.get() > MAX_TRAVERSAL_PROBE_ROUND_SPACING_MS {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe round spacing must be at most {MAX_TRAVERSAL_PROBE_ROUND_SPACING_MS} ms"
        )));
    }
    if config.traversal_probe_relay_switch_after_failures.get()
        > MAX_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES
    {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe relay switch threshold must be at most {MAX_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES}"
        )));
    }
    if config.traversal_probe_handshake_freshness_secs.get() > config.traversal_max_age_secs.get() {
        return Err(DaemonError::InvalidConfig(
            "traversal probe handshake freshness must not exceed traversal max age".to_string(),
        ));
    }
    if config.traversal_probe_reprobe_interval_secs.get()
        > MAX_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS
    {
        return Err(DaemonError::InvalidConfig(format!(
            "traversal probe reprobe interval must be at most {MAX_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS} seconds"
        )));
    }
    canonicalize_dns_zone_name(&config.dns_zone_name)
        .map_err(|err| DaemonError::InvalidConfig(format!("dns zone name is invalid: {err}")))?;
    if !config.dns_resolver_bind_addr.ip().is_loopback() {
        return Err(DaemonError::InvalidConfig(
            "dns resolver bind addr must be loopback".to_string(),
        ));
    }
    if config.wg_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "wireguard interface must not be empty".to_string(),
        ));
    }
    if config.wg_listen_port == 0 {
        return Err(DaemonError::InvalidConfig(
            "wireguard listen port must be in range 1-65535".to_string(),
        ));
    }
    if config.egress_interface.is_empty() {
        return Err(DaemonError::InvalidConfig(
            "egress interface must not be empty".to_string(),
        ));
    }
    if config.auto_port_forward_lease_secs.get() < 60 {
        return Err(DaemonError::InvalidConfig(
            "auto port-forward lease must be at least 60 seconds".to_string(),
        ));
    }
    if config.auto_port_forward_exit
        && !matches!(config.backend_mode, DaemonBackendMode::LinuxWireguard)
    {
        return Err(DaemonError::InvalidConfig(
            "auto port-forward exit is supported only with linux-wireguard backend".to_string(),
        ));
    }
    if config.trust_evidence_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust evidence path must not be empty".to_string(),
        ));
    }
    if config.trust_verifier_key_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust verifier key path must not be empty".to_string(),
        ));
    }
    if config.trust_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "trust watermark path must not be empty".to_string(),
        ));
    }
    if config.membership_snapshot_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership snapshot path must not be empty".to_string(),
        ));
    }
    if config.membership_log_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership log path must not be empty".to_string(),
        ));
    }
    if config.membership_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "membership watermark path must not be empty".to_string(),
        ));
    }
    if config.remote_ops_expected_subject.trim().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "remote ops expected subject must not be empty".to_string(),
        ));
    }
    if config.traversal_bundle_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal bundle path must not be empty".to_string(),
        ));
    }
    if config.traversal_verifier_key_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal verifier key path must not be empty".to_string(),
        ));
    }
    if config.traversal_watermark_path.as_os_str().is_empty() {
        return Err(DaemonError::InvalidConfig(
            "traversal watermark path must not be empty".to_string(),
        ));
    }
    if let Some(path) = config.relay_session_signing_secret_path.as_ref() {
        if path.as_os_str().is_empty() {
            return Err(DaemonError::InvalidConfig(
                "relay session signing secret path must not be empty".to_string(),
            ));
        }
        validate_runtime_file_path(path, "relay session signing secret")?;
    }
    if let Some(path) = config.relay_session_signing_secret_passphrase_path.as_ref() {
        if path.as_os_str().is_empty() {
            return Err(DaemonError::InvalidConfig(
                "relay session signing secret passphrase path must not be empty".to_string(),
            ));
        }
        validate_runtime_file_path(path, "relay session signing secret passphrase")?;
    }
    if config.relay_session_signing_secret_path.is_some()
        && config
            .relay_session_signing_secret_passphrase_path
            .is_none()
    {
        return Err(DaemonError::InvalidConfig(format!(
            "{ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV} is required when {ASSIGNMENT_SIGNING_SECRET_ENV} is set"
        )));
    }
    if config
        .relay_session_signing_secret_passphrase_path
        .is_some()
        && config.relay_session_signing_secret_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(format!(
            "{ASSIGNMENT_SIGNING_SECRET_ENV} is required when {ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_ENV} is set"
        )));
    }
    if config.relay_session_refresh_margin_secs.get() >= config.relay_session_token_ttl_secs.get() {
        return Err(DaemonError::InvalidConfig(
            "relay session refresh margin must be less than relay session token ttl".to_string(),
        ));
    }
    if config.auto_tunnel_enforce
        && (config.auto_tunnel_bundle_path.is_none()
            || config.auto_tunnel_verifier_key_path.is_none()
            || config.auto_tunnel_watermark_path.is_none())
    {
        return Err(DaemonError::InvalidConfig(
            "auto tunnel enforce requires bundle, verifier key, and watermark paths".to_string(),
        ));
    }
    if config
        .backend_mode
        .requires_runtime_wireguard_key_material()
    {
        if let Some(path) = config.wg_private_key_path.as_ref() {
            validate_runtime_file_path(path, "wg private key")?;
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref() {
            validate_runtime_file_path(path, "wg encrypted private key")?;
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref() {
            validate_runtime_file_path(path, "wg key passphrase")?;
        }
        if let Some(path) = config.wg_public_key_path.as_ref() {
            validate_runtime_file_path(path, "wg public key")?;
        }
        if config.wg_encrypted_private_key_path.is_some() && config.wg_key_passphrase_path.is_none()
        {
            return Err(DaemonError::InvalidConfig(
                "wg key passphrase path is required when encrypted key path is set".to_string(),
            ));
        }
        if config.wg_key_passphrase_path.is_some() && config.wg_encrypted_private_key_path.is_none()
        {
            return Err(DaemonError::InvalidConfig(
                "wg encrypted private key path is required when passphrase path is set".to_string(),
            ));
        }
    }

    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard
            | DaemonBackendMode::LinuxWireguardUserspaceShared
            | DaemonBackendMode::MacosWireguard
    ) && config.wg_private_key_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(
            "wg private key path is required for linux-wireguard, linux-wireguard-userspace-shared, or macos-wireguard backend"
                .to_string(),
        ));
    }
    if config.fail_closed_ssh_allow {
        if config.fail_closed_ssh_allow_cidrs.is_empty() {
            return Err(DaemonError::InvalidConfig(
                "fail-closed ssh allow requires at least one management cidr".to_string(),
            ));
        }
    }
    if matches!(
        config.backend_mode,
        DaemonBackendMode::LinuxWireguard
            | DaemonBackendMode::LinuxWireguardUserspaceShared
            | DaemonBackendMode::MacosWireguard
    ) && config.privileged_helper_socket_path.is_none()
    {
        return Err(DaemonError::InvalidConfig(
            "privileged helper socket path is required for linux-wireguard, linux-wireguard-userspace-shared, or macos-wireguard backend"
                .to_string(),
        ));
    }

    validate_backend_supported_on_current_host(config.backend_mode)?;

    Ok(())
}

fn resolve_configured_egress_interface(config: &mut DaemonConfig) -> Result<(), DaemonError> {
    config.egress_interface = resolve_egress_interface_value(
        config.egress_interface.as_str(),
        detect_default_egress_interface,
    )
    .map_err(DaemonError::InvalidConfig)?;
    Ok(())
}

fn resolve_egress_interface_value<F>(configured: &str, detect: F) -> Result<String, String>
where
    F: FnOnce() -> Result<String, String>,
{
    let value = configured.trim();
    if value.is_empty() {
        return Err("egress interface must not be empty".to_string());
    }
    if !value.eq_ignore_ascii_case(DEFAULT_EGRESS_INTERFACE) {
        return Ok(value.to_string());
    }
    detect()
}

#[cfg(target_os = "linux")]
fn detect_default_egress_interface() -> Result<String, String> {
    detect_route_interface("ip", &["-o", "route", "show", "to", "default"])
}

#[cfg(target_os = "macos")]
fn detect_default_egress_interface() -> Result<String, String> {
    detect_route_interface("route", &["-n", "get", "default"])
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn detect_default_egress_interface() -> Result<String, String> {
    Err("egress interface auto-detect is unsupported on this platform".to_string())
}

fn detect_route_interface(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| format!("spawn {program} for egress detection failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "{program} egress detection exited unsuccessfully: status={} stderr={stderr}",
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|_| format!("{program} egress detection returned non-utf8 output"))?;
    parse_first_route_interface(stdout.as_str())
        .ok_or_else(|| "unable to detect default egress interface from route output".to_string())
}

fn parse_first_route_interface(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(parse_route_interface_token)
        .map(str::to_string)
}

fn parse_route_interface_token(line: &str) -> Option<&str> {
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    for (idx, token) in tokens.iter().enumerate() {
        let normalized = token.trim_end_matches(':');
        if normalized == "dev" || normalized == "interface" {
            return tokens.get(idx + 1).copied();
        }
    }
    tokens.get(4).copied()
}

fn run_preflight_checks(config: &DaemonConfig) -> Result<(), DaemonError> {
    if let Some(parent) = config.state_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("state directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.trust_evidence_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("trust directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.trust_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("trust watermark directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.membership_snapshot_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "membership snapshot directory create failed: {err}"
            ))
        })?;
    }
    if let Some(parent) = config.membership_log_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("membership log directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.membership_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "membership watermark directory create failed: {err}"
            ))
        })?;
    }
    if config.auto_tunnel_enforce {
        if let Some(path) = config.auto_tunnel_bundle_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    DaemonError::InvalidConfig(format!(
                        "auto tunnel bundle directory create failed: {err}"
                    ))
                })?;
            }
        }
    }
    if config.auto_tunnel_enforce {
        if let Some(path) = config.auto_tunnel_watermark_path.as_ref() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).map_err(|err| {
                    DaemonError::InvalidConfig(format!(
                        "auto tunnel watermark directory create failed: {err}"
                    ))
                })?;
            }
        }
    }
    if let Some(parent) = config.traversal_bundle_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!("traversal bundle directory create failed: {err}"))
        })?;
    }
    if let Some(parent) = config.traversal_watermark_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            DaemonError::InvalidConfig(format!(
                "traversal watermark directory create failed: {err}"
            ))
        })?;
    }
    if let Some(path) = config.remote_ops_token_verifier_key_path.as_ref() {
        validate_remote_ops_token_verifier_key_permissions(path)?;
    }

    validate_trust_evidence_permissions(&config.trust_evidence_path)?;
    validate_trust_verifier_key_permissions(&config.trust_verifier_key_path)?;
    validate_membership_snapshot_permissions(&config.membership_snapshot_path)?;
    validate_membership_log_permissions(&config.membership_log_path)?;
    if config.traversal_bundle_path.exists() {
        validate_traversal_verifier_key_permissions(&config.traversal_verifier_key_path)?;
        validate_traversal_bundle_permissions(&config.traversal_bundle_path)?;
    }
    if config.dns_zone_bundle_path.exists() {
        validate_dns_zone_verifier_key_permissions(&config.dns_zone_verifier_key_path)?;
        validate_dns_zone_bundle_permissions(&config.dns_zone_bundle_path)?;
    }
    if config.auto_tunnel_enforce {
        let bundle_path = config.auto_tunnel_bundle_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires bundle path".to_string())
        })?;
        let verifier_key_path = config
            .auto_tunnel_verifier_key_path
            .as_ref()
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "auto tunnel enforce requires verifier key path".to_string(),
                )
            })?;
        validate_auto_tunnel_bundle_permissions(bundle_path)?;
        validate_auto_tunnel_verifier_key_permissions(verifier_key_path)?;
    }
    if config
        .backend_mode
        .requires_runtime_wireguard_key_material()
    {
        if let Some(path) = config.wg_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_encrypted_private_key_path.as_ref() {
            validate_private_key_permissions(path)?;
        }
        if let Some(path) = config.wg_key_passphrase_path.as_ref() {
            validate_passphrase_permissions(path)?;
        }
        if let Some(path) = config.wg_public_key_path.as_ref() {
            validate_public_key_permissions(path)?;
        }
    }

    let watermark = load_trust_watermark(&config.trust_watermark_path).map_err(|err| {
        DaemonError::InvalidConfig(format!("trust watermark preflight failed: {err}"))
    })?;
    let _ = load_trust_evidence(
        &config.trust_evidence_path,
        &config.trust_verifier_key_path,
        TrustPolicy::default(),
        watermark,
    )
    .map_err(|err| DaemonError::InvalidConfig(format!("trust preflight failed: {err}")))?;
    let membership_snapshot =
        load_membership_snapshot(&config.membership_snapshot_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("membership snapshot preflight failed: {err}"))
        })?;
    let membership_entries = load_membership_log(&config.membership_log_path).map_err(|err| {
        DaemonError::InvalidConfig(format!("membership log preflight failed: {err}"))
    })?;
    let _ =
        replay_membership_snapshot_and_log(&membership_snapshot, &membership_entries, unix_now())
            .map_err(|err| {
            DaemonError::InvalidConfig(format!("membership replay preflight failed: {err}"))
        })?;

    let auto_tunnel_preflight = if config.auto_tunnel_enforce {
        let bundle_path = config.auto_tunnel_bundle_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires bundle path".to_string())
        })?;
        let verifier_key_path = config
            .auto_tunnel_verifier_key_path
            .as_ref()
            .ok_or_else(|| {
                DaemonError::InvalidConfig(
                    "auto tunnel enforce requires verifier key path".to_string(),
                )
            })?;
        let watermark_path = config.auto_tunnel_watermark_path.as_ref().ok_or_else(|| {
            DaemonError::InvalidConfig("auto tunnel enforce requires watermark path".to_string())
        })?;
        let watermark = load_auto_tunnel_watermark(watermark_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel watermark preflight failed: {err}"))
        })?;
        let envelope = load_auto_tunnel_bundle(
            bundle_path,
            verifier_key_path,
            config.auto_tunnel_max_age_secs.get(),
            TrustPolicy::default(),
            watermark,
        )
        .map_err(|err| {
            DaemonError::InvalidConfig(format!("auto tunnel preflight failed: {err}"))
        })?;
        Some(envelope)
    } else {
        None
    };

    let dns_zone_watermark =
        load_dns_zone_watermark(&config.dns_zone_watermark_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("dns zone watermark preflight failed: {err}"))
        })?;
    if config.dns_zone_bundle_path.exists() {
        if let Some(auto_tunnel) = auto_tunnel_preflight.as_ref() {
            if let Err(err) = load_dns_zone_bundle(DnsZoneLoadContext {
                path: &config.dns_zone_bundle_path,
                verifier_key_path: &config.dns_zone_verifier_key_path,
                max_age_secs: config.dns_zone_max_age_secs.get(),
                trust_policy: TrustPolicy::default(),
                previous_watermark: dns_zone_watermark,
                expected_zone_name: &config.dns_zone_name,
                local_node_id: &config.node_id,
                auto_tunnel: &auto_tunnel.bundle,
            }) {
                // Managed DNS must fail closed for managed names, but stale/invalid bundles
                // should not prevent daemon startup or dataplane reconciliation.
                eprintln!(
                    "rustynetd startup warning: dns zone preflight skipped invalid managed DNS bundle: {err}"
                );
            }
        } else {
            eprintln!(
                "rustynetd startup warning: dns zone bundle present without signed assignment context; managed DNS remains fail-closed"
            );
        }
    }

    let traversal_watermark =
        load_traversal_watermark(&config.traversal_watermark_path).map_err(|err| {
            DaemonError::InvalidConfig(format!("traversal watermark preflight failed: {err}"))
        })?;
    if config.traversal_bundle_path.exists() {
        let _ = load_traversal_bundle_set(
            &config.traversal_bundle_path,
            &config.traversal_verifier_key_path,
            config.traversal_max_age_secs.get(),
            TrustPolicy::default(),
            traversal_watermark,
        )
        .map_err(|err| DaemonError::InvalidConfig(format!("traversal preflight failed: {err}")))?;
    }

    let mut system = daemon_system(config)?;
    system
        .check_prerequisites()
        .map_err(|err| DaemonError::InvalidConfig(format!("dataplane preflight failed: {err}")))?;

    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077, false)
}

#[cfg(not(target_os = "linux"))]
fn validate_private_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard private key", 0o077, false)
}

fn validate_passphrase_permissions(path: &Path) -> Result<(), DaemonError> {
    #[cfg(target_os = "macos")]
    {
        if std::env::var("RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT")
            .ok()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false)
        {
            read_passphrase_file(path).map_err(|err| {
                DaemonError::InvalidConfig(format!(
                    "wireguard key passphrase source invalid: {err}"
                ))
            })?;
            return Ok(());
        }
    }

    let allow_root_owner = is_systemd_runtime_credential_path(path);
    let disallowed_mode_mask = passphrase_disallowed_mode_mask(path);
    validate_file_security(
        path,
        "wireguard key passphrase credential",
        disallowed_mode_mask,
        allow_root_owner,
    )
}

fn is_systemd_runtime_credential_path(path: &Path) -> bool {
    path.starts_with("/run/credentials/")
}

fn passphrase_disallowed_mode_mask(path: &Path) -> u32 {
    if is_systemd_runtime_credential_path(path) {
        // systemd runtime credentials are typically provisioned as 0440 root:<service-group>
        // and should still reject any write/execute bit or any "other" access.
        0o337
    } else {
        0o077
    }
}

#[cfg(target_os = "linux")]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022, false)
}

#[cfg(not(target_os = "linux"))]
fn validate_public_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "wireguard public key", 0o022, false)
}

#[cfg(target_os = "linux")]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_snapshot_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership snapshot", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_membership_log_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "membership log", 0o037, true)
}

fn load_trust_evidence(
    path: &Path,
    verifier_key_path: &Path,
    trust_policy: TrustPolicy,
    previous_watermark: Option<TrustWatermark>,
) -> Result<TrustEvidenceEnvelope, TrustBootstrapError> {
    if !path.exists() {
        return Err(TrustBootstrapError::Missing);
    }

    let verifying_key = load_verifying_key(verifier_key_path)?;
    enforce_text_artifact_size_limit(path, "trust evidence", MAX_TRUST_EVIDENCE_BYTES)
        .map_err(TrustBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_TRUST_EVIDENCE_BYTES {
        return Err(TrustBootstrapError::InvalidFormat(format!(
            "trust evidence exceeds maximum size of {MAX_TRUST_EVIDENCE_BYTES} bytes"
        )));
    }
    let mut version: Option<u8> = None;
    let mut tls13_valid: Option<bool> = None;
    let mut signed_control_valid: Option<bool> = None;
    let mut signed_data_age_secs: Option<u64> = None;
    let mut clock_skew_secs: Option<u64> = None;
    let mut updated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut signature_hex: Option<String> = None;
    let mut line_count = 0usize;
    let mut seen_keys = std::collections::HashSet::new();

    for line in content.lines() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_TRUST_EVIDENCE_LINES {
            return Err(TrustBootstrapError::InvalidFormat(format!(
                "trust evidence exceeds maximum line count of {MAX_TRUST_EVIDENCE_LINES}"
            )));
        }
        let (key, value) = parse_limited_key_value_line(
            line,
            line_count,
            MAX_TRUST_EVIDENCE_LINE_BYTES,
            MAX_TRUST_EVIDENCE_KEY_BYTES,
            MAX_TRUST_EVIDENCE_VALUE_BYTES,
            MAX_TRUST_EVIDENCE_KEY_DEPTH,
        )
        .map_err(TrustBootstrapError::InvalidFormat)?;
        if !seen_keys.insert(key.to_string()) {
            return Err(TrustBootstrapError::InvalidFormat(format!(
                "duplicate key {key}"
            )));
        }
        if !matches!(
            key,
            "version"
                | "tls13_valid"
                | "signed_control_valid"
                | "signed_data_age_secs"
                | "clock_skew_secs"
                | "updated_at_unix"
                | "nonce"
                | "signature"
        ) {
            return Err(TrustBootstrapError::InvalidFormat(format!(
                "unknown key {key}"
            )));
        }

        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "tls13_valid" => {
                tls13_valid = parse_bool(value);
            }
            "signed_control_valid" => {
                signed_control_valid = parse_bool(value);
            }
            "signed_data_age_secs" => {
                signed_data_age_secs = value.parse::<u64>().ok();
            }
            "clock_skew_secs" => {
                clock_skew_secs = value.parse::<u64>().ok();
            }
            "updated_at_unix" => {
                updated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "signature" => {
                signature_hex = Some(value.to_string());
            }
            _ => {
                return Err(TrustBootstrapError::InvalidFormat(format!(
                    "unknown key {key}"
                )));
            }
        }
    }

    if version != Some(2) {
        return Err(TrustBootstrapError::InvalidFormat(
            "unsupported trust evidence version".to_string(),
        ));
    }

    let record = TrustEvidenceRecord {
        tls13_valid: tls13_valid
            .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing tls13_valid".to_string()))?,
        signed_control_valid: signed_control_valid.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing signed_control_valid".to_string())
        })?,
        signed_data_age_secs: signed_data_age_secs.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing signed_data_age_secs".to_string())
        })?,
        clock_skew_secs: clock_skew_secs.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing clock_skew_secs".to_string())
        })?,
        updated_at_unix: updated_at_unix.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing updated_at_unix".to_string())
        })?,
        nonce: nonce
            .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing nonce".to_string()))?,
    };

    let signature_hex = signature_hex.ok_or_else(|| {
        TrustBootstrapError::InvalidFormat("missing trust evidence signature".to_string())
    })?;
    let signature_bytes = decode_hex_to_fixed::<64>(&signature_hex).map_err(|_| {
        TrustBootstrapError::InvalidFormat("invalid signature encoding".to_string())
    })?;
    let signature = Signature::from_bytes(&signature_bytes);
    let payload = trust_evidence_payload(&record);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TrustBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if record.updated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(TrustBootstrapError::FutureDated);
    }

    let age = now.saturating_sub(record.updated_at_unix);
    if age > trust_policy.max_signed_data_age_secs {
        return Err(TrustBootstrapError::Stale);
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = TrustWatermark {
        updated_at_unix: record.updated_at_unix,
        nonce: record.nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match compare_trust_watermark_generation(&watermark, &existing) {
            std::cmp::Ordering::Less => return Err(TrustBootstrapError::ReplayDetected),
            std::cmp::Ordering::Equal => {
                if existing.payload_digest != Some(payload_digest) {
                    return Err(TrustBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    Ok(TrustEvidenceEnvelope {
        evidence: TrustEvidence {
            tls13_valid: record.tls13_valid,
            signed_control_valid: record.signed_control_valid,
            signed_data_age_secs: record.signed_data_age_secs,
            clock_skew_secs: record.clock_skew_secs,
        },
        watermark,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrustEvidenceRecord {
    tls13_valid: bool,
    signed_control_valid: bool,
    signed_data_age_secs: u64,
    clock_skew_secs: u64,
    updated_at_unix: u64,
    nonce: u64,
}

fn trust_evidence_payload(record: &TrustEvidenceRecord) -> String {
    format!(
        "version=2\ntls13_valid={}\nsigned_control_valid={}\nsigned_data_age_secs={}\nclock_skew_secs={}\nupdated_at_unix={}\nnonce={}\n",
        if record.tls13_valid { "true" } else { "false" },
        if record.signed_control_valid {
            "true"
        } else {
            "false"
        },
        record.signed_data_age_secs,
        record.clock_skew_secs,
        record.updated_at_unix,
        record.nonce
    )
}

fn enforce_text_artifact_size_limit(
    path: &Path,
    artifact_name: &str,
    max_bytes: usize,
) -> Result<(), String> {
    let metadata =
        fs::metadata(path).map_err(|err| format!("{artifact_name} metadata read failed: {err}"))?;
    if metadata.len() > max_bytes as u64 {
        return Err(format!(
            "{artifact_name} exceeds maximum size of {max_bytes} bytes"
        ));
    }
    Ok(())
}

fn parse_limited_key_value_line(
    line: &str,
    line_number: usize,
    max_line_bytes: usize,
    max_key_bytes: usize,
    max_value_bytes: usize,
    max_key_depth: usize,
) -> Result<(&str, &str), String> {
    if line.len() > max_line_bytes {
        return Err(format!(
            "line {line_number} exceeds maximum size of {max_line_bytes} bytes"
        ));
    }
    let Some((key, value)) = line.split_once('=') else {
        return Err("line missing key/value separator".to_string());
    };
    if key.is_empty() {
        return Err(format!("line {line_number} has empty key"));
    }
    if key.len() > max_key_bytes {
        return Err(format!(
            "line {line_number} key exceeds maximum size of {max_key_bytes} bytes"
        ));
    }
    if value.len() > max_value_bytes {
        return Err(format!(
            "line {line_number} value exceeds maximum size of {max_value_bytes} bytes"
        ));
    }
    let depth = key.split('.').count();
    if depth == 0 || depth > max_key_depth {
        return Err(format!(
            "line {line_number} key depth exceeds maximum of {max_key_depth}"
        ));
    }
    if !key
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!("line {line_number} has invalid key characters"));
    }
    Ok((key, value))
}

fn parse_indexed_key<'a>(key: &'a str, prefix: &str) -> Option<(usize, &'a str)> {
    let tail = key.strip_prefix(prefix)?;
    let (index_raw, suffix) = tail.split_once('.')?;
    let index = index_raw.parse::<usize>().ok()?;
    Some((index, suffix))
}

fn is_allowed_auto_tunnel_key(key: &str) -> bool {
    if matches!(
        key,
        "version"
            | "node_id"
            | "mesh_cidr"
            | "assigned_cidr"
            | "generated_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "peer_count"
            | "route_count"
            | "signature"
    ) {
        return true;
    }

    if let Some((_index, suffix)) = parse_indexed_key(key, "peer.") {
        return matches!(
            suffix,
            "node_id" | "endpoint" | "public_key_hex" | "allowed_ips"
        );
    }

    if let Some((_index, suffix)) = parse_indexed_key(key, "route.") {
        return matches!(suffix, "destination_cidr" | "via_node" | "kind");
    }

    false
}

fn is_allowed_traversal_key(key: &str) -> bool {
    if matches!(
        key,
        "version"
            | "type"
            | "path_policy"
            | "source_node_id"
            | "target_node_id"
            | "generated_at_unix"
            | "expires_at_unix"
            | "nonce"
            | "candidate_count"
            | "session_id"
            | "probe_start_unix"
            | "node_a"
            | "node_b"
            | "issued_at_unix"
            | "signature"
    ) {
        return true;
    }

    if let Some((_index, suffix)) = parse_indexed_key(key, "candidate.") {
        return matches!(
            suffix,
            "type" | "addr" | "port" | "family" | "relay_id" | "priority"
        );
    }

    false
}

fn traversal_coordination_pair_key(left: &str, right: &str) -> (String, String) {
    if left <= right {
        (left.to_string(), right.to_string())
    } else {
        (right.to_string(), left.to_string())
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn compare_trust_watermark_generation(
    incoming: &TrustWatermark,
    existing: &TrustWatermark,
) -> std::cmp::Ordering {
    (incoming.updated_at_unix, incoming.nonce).cmp(&(existing.updated_at_unix, existing.nonce))
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], TrustBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(TrustBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_hex_nibble(raw[index * 2])?;
        let lo = decode_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_hex_nibble(value: u8) -> Result<u8, TrustBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TrustBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn load_verifying_key(path: &Path) -> Result<VerifyingKey, TrustBootstrapError> {
    enforce_text_artifact_size_limit(path, "trust verifier key", MAX_BUNDLE_VERIFIER_KEY_BYTES)
        .map_err(TrustBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_BUNDLE_VERIFIER_KEY_BYTES {
        return Err(TrustBootstrapError::InvalidFormat(format!(
            "trust verifier key exceeds maximum size of {MAX_BUNDLE_VERIFIER_KEY_BYTES} bytes"
        )));
    }
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| TrustBootstrapError::InvalidFormat("missing verifier key".to_string()))?;
    let key_bytes = decode_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| TrustBootstrapError::KeyInvalid)
}

fn load_remote_ops_access_token_verifying_key(path: &Path) -> Result<VerifyingKey, DaemonError> {
    enforce_text_artifact_size_limit(
        path,
        "remote ops token verifier key",
        MAX_BUNDLE_VERIFIER_KEY_BYTES,
    )
    .map_err(DaemonError::InvalidConfig)?;
    let content = fs::read_to_string(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("read remote ops verifier key: {err}"))
    })?;
    if content.len() > MAX_BUNDLE_VERIFIER_KEY_BYTES {
        return Err(DaemonError::InvalidConfig(format!(
            "remote ops token verifier key exceeds maximum size of {MAX_BUNDLE_VERIFIER_KEY_BYTES} bytes"
        )));
    }
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            DaemonError::InvalidConfig("missing remote ops token verifier key".to_string())
        })?;
    let key_bytes = decode_hex_to_fixed::<32>(key_line).map_err(|_| {
        DaemonError::InvalidConfig("invalid remote ops verifier key hex".to_string())
    })?;
    VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| DaemonError::InvalidConfig("remote ops verifier key is invalid".to_string()))
}

fn load_trust_watermark(path: &Path) -> Result<Option<TrustWatermark>, TrustBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut updated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TrustBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "updated_at_unix" => {
                updated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "payload_digest_sha256" => {
                payload_digest = Some(decode_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(TrustBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let version = version.ok_or_else(|| {
        TrustBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(TrustBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    Ok(Some(TrustWatermark {
        updated_at_unix: updated_at_unix.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark updated_at_unix".to_string())
        })?,
        nonce: nonce.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat("missing watermark nonce".to_string())
        })?,
        payload_digest: Some(payload_digest.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat(
                "missing watermark payload_digest_sha256".to_string(),
            )
        })?),
    }))
}

fn persist_trust_watermark(
    path: &Path,
    watermark: TrustWatermark,
) -> Result<(), TrustBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload = format!(
        "version=2\nupdated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.updated_at_unix,
        watermark.nonce,
        encode_hex(&watermark.payload_digest.ok_or_else(|| {
            TrustBootstrapError::InvalidFormat(
                "watermark payload digest must be present".to_string(),
            )
        })?)
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
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(TrustBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| TrustBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn load_membership_watermark(path: &Path) -> Result<Option<MembershipWatermark>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|err| err.to_string())?;
    let mut version: Option<u8> = None;
    let mut epoch: Option<u64> = None;
    let mut state_root: Option<String> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err("membership watermark line missing key/value separator".to_string());
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "epoch" => {
                epoch = value.parse::<u64>().ok();
            }
            "state_root" => {
                state_root = Some(value.to_string());
            }
            _ => return Err(format!("unknown membership watermark key {key}")),
        }
    }
    if version != Some(1) {
        return Err("unsupported membership watermark version".to_string());
    }
    Ok(Some(MembershipWatermark {
        epoch: epoch.ok_or_else(|| "missing membership watermark epoch".to_string())?,
        state_root: state_root
            .ok_or_else(|| "missing membership watermark state_root".to_string())?,
    }))
}

fn persist_membership_watermark(
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
        options.mode(0o600);
    }
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
    if let Some(parent) = path.parent() {
        let parent_dir = fs::File::open(parent).map_err(|err| err.to_string())?;
        parent_dir.sync_all().map_err(|err| err.to_string())?;
    }
    Ok(())
}

fn load_auto_tunnel_bundle(
    path: &Path,
    verifier_key_path: &Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<AutoTunnelWatermark>,
) -> Result<AutoTunnelBundleEnvelope, AutoTunnelBootstrapError> {
    if !path.exists() {
        return Err(AutoTunnelBootstrapError::Missing);
    }

    let verifying_key = load_auto_tunnel_verifying_key(verifier_key_path)?;
    enforce_text_artifact_size_limit(path, "auto-tunnel bundle", MAX_AUTO_TUNNEL_BUNDLE_BYTES)
        .map_err(AutoTunnelBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_AUTO_TUNNEL_BUNDLE_BYTES {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "auto-tunnel bundle exceeds maximum size of {MAX_AUTO_TUNNEL_BUNDLE_BYTES} bytes"
        )));
    }

    let mut payload = String::new();
    let mut signature_hex: Option<String> = None;
    let mut fields = std::collections::HashMap::new();
    let mut line_count = 0usize;

    for line in content.lines() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_AUTO_TUNNEL_BUNDLE_LINES {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "auto-tunnel bundle exceeds maximum line count of {MAX_AUTO_TUNNEL_BUNDLE_LINES}"
            )));
        }
        let (key, value) = parse_limited_key_value_line(
            line,
            line_count,
            MAX_AUTO_TUNNEL_LINE_BYTES,
            MAX_AUTO_TUNNEL_KEY_BYTES,
            MAX_AUTO_TUNNEL_VALUE_BYTES,
            MAX_AUTO_TUNNEL_KEY_DEPTH,
        )
        .map_err(AutoTunnelBootstrapError::InvalidFormat)?;
        if !is_allowed_auto_tunnel_key(key) {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "unknown key {key}"
            )));
        }
        if key == "signature" {
            if signature_hex.is_some() {
                return Err(AutoTunnelBootstrapError::InvalidFormat(
                    "duplicate key signature".to_string(),
                ));
            }
            signature_hex = Some(value.to_string());
            continue;
        }
        payload.push_str(line);
        payload.push('\n');
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "duplicate key {key}"
            )));
        }
    }
    if fields.len() > MAX_AUTO_TUNNEL_FIELD_COUNT {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "auto-tunnel bundle exceeds maximum field count of {MAX_AUTO_TUNNEL_FIELD_COUNT}"
        )));
    }

    let version = fields
        .get("version")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing version".to_string()))?;
    if version != "1" {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unsupported bundle version".to_string(),
        ));
    }

    let node_id = fields
        .get("node_id")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing node_id".to_string()))?
        .to_string();
    NodeId::new(node_id.clone())
        .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;

    let mesh_cidr = fields
        .get("mesh_cidr")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing mesh_cidr".to_string()))?
        .to_string();
    if !is_valid_ipv4_or_ipv6_cidr(&mesh_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid mesh_cidr".to_string(),
        ));
    }

    let assigned_cidr = fields
        .get("assigned_cidr")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing assigned_cidr".to_string())
        })?
        .to_string();
    if !is_valid_ipv4_or_ipv6_cidr(&assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid assigned_cidr".to_string(),
        ));
    }
    if !is_host_cidr(&assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "assigned_cidr must be a host cidr".to_string(),
        ));
    }
    if !cidr_contains(&mesh_cidr, &assigned_cidr) {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "assigned_cidr is outside mesh_cidr".to_string(),
        ));
    }

    let generated_at_unix = fields
        .get("generated_at_unix")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing generated_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat("invalid generated_at_unix".to_string())
        })?;
    let expires_at_unix = fields
        .get("expires_at_unix")
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing expires_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat("invalid expires_at_unix".to_string())
        })?;
    if generated_at_unix >= expires_at_unix {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
        ));
    }

    let nonce = fields
        .get("nonce")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing nonce".to_string()))?
        .parse::<u64>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid nonce".to_string()))?;

    let signature_hex = signature_hex.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing bundle signature".to_string())
    })?;
    let signature_bytes = decode_auto_tunnel_hex_to_fixed::<64>(&signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| AutoTunnelBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if generated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(AutoTunnelBootstrapError::FutureDated);
    }
    if now > expires_at_unix || now.saturating_sub(generated_at_unix) > max_age_secs {
        return Err(AutoTunnelBootstrapError::Stale);
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = AutoTunnelWatermark {
        generated_at_unix,
        nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match auto_tunnel_watermark_ordering(&watermark, &existing) {
            std::cmp::Ordering::Less => {
                return Err(AutoTunnelBootstrapError::ReplayDetected);
            }
            std::cmp::Ordering::Equal => {
                let existing_digest = existing
                    .payload_digest
                    .ok_or(AutoTunnelBootstrapError::ReplayDetected)?;
                if existing_digest != payload_digest {
                    return Err(AutoTunnelBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    let peer_count = fields
        .get("peer_count")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing peer_count".to_string()))?
        .parse::<usize>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid peer_count".to_string()))?;
    if peer_count > MAX_AUTO_TUNNEL_PEER_COUNT {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "peer_count exceeds maximum of {MAX_AUTO_TUNNEL_PEER_COUNT}"
        )));
    }

    let mut peers = Vec::with_capacity(peer_count);
    for index in 0..peer_count {
        let node_id_key = format!("peer.{index}.node_id");
        let endpoint_key = format!("peer.{index}.endpoint");
        let public_key_key = format!("peer.{index}.public_key_hex");
        let allowed_ips_key = format!("peer.{index}.allowed_ips");

        let peer_node = fields.get(&node_id_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {node_id_key}"))
        })?;
        let peer_node_id = NodeId::new(peer_node.clone())
            .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;

        let endpoint_raw = fields.get(&endpoint_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {endpoint_key}"))
        })?;
        let endpoint = endpoint_raw.parse::<std::net::SocketAddr>().map_err(|_| {
            AutoTunnelBootstrapError::InvalidFormat(format!("invalid endpoint {endpoint_key}"))
        })?;

        let public_key_hex = fields.get(&public_key_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {public_key_key}"))
        })?;
        let public_key = decode_auto_tunnel_hex_to_fixed::<32>(public_key_hex)?;

        let allowed_ips_raw = fields.get(&allowed_ips_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {allowed_ips_key}"))
        })?;
        let allowed_ips = allowed_ips_raw
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if allowed_ips.is_empty()
            || allowed_ips
                .iter()
                .any(|cidr| !is_valid_ipv4_or_ipv6_cidr(cidr))
        {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "invalid allowed_ips for peer {index}"
            )));
        }

        peers.push(PeerConfig {
            node_id: peer_node_id,
            endpoint: rustynet_backend_api::SocketEndpoint {
                addr: endpoint.ip(),
                port: endpoint.port(),
            },
            public_key,
            allowed_ips,
        });
    }

    let route_count = fields
        .get("route_count")
        .ok_or_else(|| AutoTunnelBootstrapError::InvalidFormat("missing route_count".to_string()))?
        .parse::<usize>()
        .map_err(|_| AutoTunnelBootstrapError::InvalidFormat("invalid route_count".to_string()))?;
    if route_count > MAX_AUTO_TUNNEL_ROUTE_COUNT {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "route_count exceeds maximum of {MAX_AUTO_TUNNEL_ROUTE_COUNT}"
        )));
    }
    let expected_field_count = 9usize
        .checked_add(peer_count.checked_mul(4).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("peer field count overflow".to_string())
        })?)
        .and_then(|value| value.checked_add(route_count.checked_mul(3)?))
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("route field count overflow".to_string())
        })?;
    if fields.len() != expected_field_count {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "unexpected field count for auto-tunnel bundle: expected {expected_field_count}, got {}",
            fields.len()
        )));
    }

    let mut routes = Vec::with_capacity(route_count);
    let mut selected_exit_node: Option<String> = None;
    for index in 0..route_count {
        let destination_key = format!("route.{index}.destination_cidr");
        let via_node_key = format!("route.{index}.via_node");
        let kind_key = format!("route.{index}.kind");

        let destination_cidr = fields.get(&destination_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {destination_key}"))
        })?;
        if !is_valid_ipv4_or_ipv6_cidr(destination_cidr) {
            return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                "invalid destination cidr for route {index}"
            )));
        }
        let via_node_raw = fields.get(&via_node_key).ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(format!("missing {via_node_key}"))
        })?;
        let via_node = NodeId::new(via_node_raw.clone())
            .map_err(|err| AutoTunnelBootstrapError::InvalidFormat(err.to_string()))?;
        let kind = match fields.get(&kind_key).map(String::as_str) {
            Some("mesh") => RouteKind::Mesh,
            Some("exit_lan") => RouteKind::ExitNodeLan,
            Some("exit_default") => RouteKind::ExitNodeDefault,
            _ => {
                return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                    "invalid route kind for route {index}"
                )));
            }
        };
        if matches!(kind, RouteKind::ExitNodeDefault | RouteKind::ExitNodeLan) {
            let via = via_node.as_str().to_string();
            if let Some(existing) = selected_exit_node.as_deref() {
                if existing != via {
                    return Err(AutoTunnelBootstrapError::InvalidFormat(
                        "exit routes reference multiple exit nodes".to_string(),
                    ));
                }
            }
            selected_exit_node = Some(via);
        }

        routes.push(Route {
            destination_cidr: destination_cidr.clone(),
            via_node,
            kind,
        });
    }

    Ok(AutoTunnelBundleEnvelope {
        bundle: AutoTunnelBundle {
            node_id,
            mesh_cidr,
            assigned_cidr,
            peers,
            routes,
            selected_exit_node,
        },
        watermark,
    })
}

fn load_auto_tunnel_verifying_key(path: &Path) -> Result<VerifyingKey, AutoTunnelBootstrapError> {
    enforce_text_artifact_size_limit(
        path,
        "auto-tunnel verifier key",
        MAX_BUNDLE_VERIFIER_KEY_BYTES,
    )
    .map_err(AutoTunnelBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_BUNDLE_VERIFIER_KEY_BYTES {
        return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
            "auto-tunnel verifier key exceeds maximum size of {MAX_BUNDLE_VERIFIER_KEY_BYTES} bytes"
        )));
    }
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat("missing verifier key".to_string())
        })?;
    let key_bytes = decode_auto_tunnel_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| AutoTunnelBootstrapError::KeyInvalid)
}

fn decode_auto_tunnel_hex_to_fixed<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], AutoTunnelBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_auto_tunnel_hex_nibble(raw[index * 2])?;
        let lo = decode_auto_tunnel_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_auto_tunnel_hex_nibble(value: u8) -> Result<u8, AutoTunnelBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(AutoTunnelBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn auto_tunnel_watermark_ordering(
    current: &AutoTunnelWatermark,
    previous: &AutoTunnelWatermark,
) -> std::cmp::Ordering {
    current
        .generated_at_unix
        .cmp(&previous.generated_at_unix)
        .then(current.nonce.cmp(&previous.nonce))
}

fn load_auto_tunnel_watermark(
    path: &Path,
) -> Result<Option<AutoTunnelWatermark>, AutoTunnelBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut generated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(AutoTunnelBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => {
                version = value.parse::<u8>().ok();
            }
            "generated_at_unix" => {
                generated_at_unix = value.parse::<u64>().ok();
            }
            "nonce" => {
                nonce = value.parse::<u64>().ok();
            }
            "payload_digest_sha256" => {
                payload_digest = Some(decode_auto_tunnel_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(AutoTunnelBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let generated_at_unix = generated_at_unix.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark generated_at_unix".to_string())
    })?;
    let nonce = nonce.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark nonce".to_string())
    })?;
    let version = version.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(AutoTunnelBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    let payload_digest = Some(payload_digest.ok_or_else(|| {
        AutoTunnelBootstrapError::InvalidFormat(
            "missing watermark payload_digest_sha256".to_string(),
        )
    })?);
    Ok(Some(AutoTunnelWatermark {
        generated_at_unix,
        nonce,
        payload_digest,
    }))
}

fn persist_auto_tunnel_watermark(
    path: &Path,
    watermark: AutoTunnelWatermark,
) -> Result<(), AutoTunnelBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload_digest = watermark
        .payload_digest
        .ok_or_else(|| {
            AutoTunnelBootstrapError::InvalidFormat(
                "watermark payload digest is required".to_string(),
            )
        })
        .map(|digest| encode_hex(&digest))?;
    let payload = format!(
        "version=2\ngenerated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.generated_at_unix, watermark.nonce, payload_digest
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
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(AutoTunnelBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| AutoTunnelBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn load_dns_zone_bundle(
    context: DnsZoneLoadContext<'_>,
) -> Result<DnsZoneBundleEnvelope, DnsZoneBootstrapError> {
    let DnsZoneLoadContext {
        path,
        verifier_key_path,
        max_age_secs,
        trust_policy,
        previous_watermark,
        expected_zone_name,
        local_node_id,
        auto_tunnel,
    } = context;
    if !path.exists() {
        return Err(DnsZoneBootstrapError::Missing);
    }

    let verifying_key = load_dns_zone_verifying_key(verifier_key_path)?;
    enforce_text_artifact_size_limit(path, "dns zone bundle", MAX_DNS_ZONE_BUNDLE_BYTES)
        .map_err(DnsZoneBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
    let bundle = parse_signed_dns_zone_bundle_wire(&content).map_err(map_dns_zone_parse_error)?;
    verify_dns_zone_bundle(&bundle, &verifying_key).map_err(map_dns_zone_parse_error)?;
    if bundle.zone_name != expected_zone_name {
        return Err(DnsZoneBootstrapError::InvalidFormat(format!(
            "dns zone bundle zone_name mismatch: expected {expected_zone_name}, got {}",
            bundle.zone_name
        )));
    }
    NodeId::new(bundle.subject_node_id.clone())
        .map_err(|err| DnsZoneBootstrapError::InvalidFormat(err.to_string()))?;
    if bundle.subject_node_id != local_node_id {
        return Err(DnsZoneBootstrapError::WrongNode);
    }

    let now = unix_now();
    if bundle.generated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(DnsZoneBootstrapError::FutureDated);
    }
    if now > bundle.expires_at_unix || now.saturating_sub(bundle.generated_at_unix) > max_age_secs {
        return Err(DnsZoneBootstrapError::Stale);
    }

    let assignment_ip_map = collect_assignment_mesh_ip_map(auto_tunnel)?;
    for record in &bundle.records {
        NodeId::new(record.target_node_id.clone())
            .map_err(|err| DnsZoneBootstrapError::InvalidFormat(err.to_string()))?;
        let assigned_ip = assignment_ip_map
            .get(&record.target_node_id)
            .ok_or_else(|| {
                DnsZoneBootstrapError::AssignmentMismatch(format!(
                    "target node {} is not present in signed assignment state",
                    record.target_node_id
                ))
            })?;
        if assigned_ip != &record.expected_ip {
            return Err(DnsZoneBootstrapError::AssignmentMismatch(format!(
                "target node {} expected ip {} does not match signed assignment {}",
                record.target_node_id, record.expected_ip, assigned_ip
            )));
        }
    }

    let watermark = DnsZoneWatermark {
        version: 2,
        generated_at_unix: bundle.generated_at_unix,
        nonce: bundle.nonce,
        payload_digest: dns_zone_payload_digest(&bundle),
    };
    if let Some(existing) = previous_watermark {
        match dns_zone_watermark_ordering(&watermark, &existing) {
            std::cmp::Ordering::Less => return Err(DnsZoneBootstrapError::ReplayDetected),
            std::cmp::Ordering::Equal => {
                if existing.payload_digest != watermark.payload_digest {
                    return Err(DnsZoneBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    Ok(DnsZoneBundleEnvelope { bundle, watermark })
}

fn load_dns_zone_verifying_key(path: &Path) -> Result<VerifyingKey, DnsZoneBootstrapError> {
    enforce_text_artifact_size_limit(path, "dns zone verifier key", MAX_BUNDLE_VERIFIER_KEY_BYTES)
        .map_err(DnsZoneBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_BUNDLE_VERIFIER_KEY_BYTES {
        return Err(DnsZoneBootstrapError::InvalidFormat(format!(
            "dns zone verifier key exceeds maximum size of {MAX_BUNDLE_VERIFIER_KEY_BYTES} bytes"
        )));
    }
    parse_dns_zone_verifying_key(&content).map_err(map_dns_zone_parse_error)
}

fn load_dns_zone_watermark(path: &Path) -> Result<Option<DnsZoneWatermark>, DnsZoneBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }

    let content =
        fs::read_to_string(path).map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut generated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(DnsZoneBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => version = value.parse::<u8>().ok(),
            "generated_at_unix" => generated_at_unix = value.parse::<u64>().ok(),
            "nonce" => nonce = value.parse::<u64>().ok(),
            "payload_digest_sha256" => {
                payload_digest = Some(decode_hex_to_fixed::<32>(value).map_err(|err| {
                    DnsZoneBootstrapError::InvalidFormat(format!(
                        "invalid dns zone watermark payload digest: {err}"
                    ))
                })?);
            }
            _ => {
                return Err(DnsZoneBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let generated_at_unix = generated_at_unix.ok_or_else(|| {
        DnsZoneBootstrapError::InvalidFormat("missing watermark generated_at_unix".to_string())
    })?;
    let nonce = nonce.ok_or_else(|| {
        DnsZoneBootstrapError::InvalidFormat("missing watermark nonce".to_string())
    })?;
    let version = version.ok_or_else(|| {
        DnsZoneBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(DnsZoneBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    let payload_digest = payload_digest.ok_or_else(|| {
        DnsZoneBootstrapError::InvalidFormat("missing watermark payload_digest_sha256".to_string())
    })?;
    Ok(Some(DnsZoneWatermark {
        version,
        generated_at_unix,
        nonce,
        payload_digest,
    }))
}

fn persist_dns_zone_watermark(
    path: &Path,
    watermark: DnsZoneWatermark,
) -> Result<(), DnsZoneBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload = format!(
        "version=2\ngenerated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.generated_at_unix,
        watermark.nonce,
        encode_hex(&watermark.payload_digest)
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
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(DnsZoneBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(DnsZoneBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(DnsZoneBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| DnsZoneBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
fn load_traversal_bundle(
    path: &Path,
    verifier_key_path: &Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<TraversalWatermark>,
) -> Result<TraversalBundleEnvelope, TraversalBootstrapError> {
    let envelope = load_traversal_bundle_set(
        path,
        verifier_key_path,
        max_age_secs,
        trust_policy,
        previous_watermark,
    )?;
    if envelope.bundles.len() != 1 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "expected exactly one traversal bundle entry".to_string(),
        ));
    }
    envelope.bundles.into_iter().next().ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing traversal bundle".to_string())
    })
}

fn load_traversal_bundle_set(
    path: &Path,
    verifier_key_path: &Path,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
    previous_watermark: Option<TraversalWatermark>,
) -> Result<TraversalBundleSetEnvelope, TraversalBootstrapError> {
    if !path.exists() {
        return Err(TraversalBootstrapError::Missing);
    }

    let verifying_key = load_traversal_verifying_key(verifier_key_path)?;
    let verifier_key_bytes = verifying_key.to_bytes();
    let content = read_traversal_bundle_content(path)?;
    let sections = split_traversal_bundle_sections(&content)?;
    if sections.len() > MAX_TRAVERSAL_BUNDLE_ENTRY_COUNT {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "traversal bundle entry count exceeds maximum of {MAX_TRAVERSAL_BUNDLE_ENTRY_COUNT}"
        )));
    }

    let mut bundles = Vec::with_capacity(sections.len());
    let mut coordinations = Vec::new();
    for section in &sections {
        match parse_traversal_bundle_section(section, &verifying_key, max_age_secs, trust_policy)? {
            TraversalSectionEnvelope::Bundle(bundle) => bundles.push(bundle),
            TraversalSectionEnvelope::Coordination(coordination) => {
                coordinations.push(coordination)
            }
        }
    }
    let Some(first_bundle) = bundles.first() else {
        return Err(TraversalBootstrapError::InvalidFormat(
            "traversal bundle set contains no endpoint hint entries".to_string(),
        ));
    };
    for bundle in &bundles[1..] {
        if bundle.bundle.generated_at_unix != first_bundle.bundle.generated_at_unix
            || bundle.bundle.expires_at_unix != first_bundle.bundle.expires_at_unix
            || bundle.bundle.nonce != first_bundle.bundle.nonce
        {
            return Err(TraversalBootstrapError::InvalidFormat(
                "traversal bundle entries must share a single generated_at/expires_at/nonce snapshot"
                    .to_string(),
            ));
        }
    }

    let mut seen_coordination_pairs = BTreeSet::new();
    for coordination in &coordinations {
        let key = traversal_coordination_pair_key(
            coordination.record.node_a.as_str(),
            coordination.record.node_b.as_str(),
        );
        if !seen_coordination_pairs.insert(key) {
            return Err(TraversalBootstrapError::InvalidFormat(
                "traversal bundle contains duplicate coordination entries for a node pair"
                    .to_string(),
            ));
        }
    }

    let payload_digest = traversal_snapshot_payload_digest(&bundles, &coordinations)?;
    let watermark = TraversalWatermark {
        generated_at_unix: first_bundle.bundle.generated_at_unix,
        nonce: first_bundle.bundle.nonce,
        payload_digest: Some(payload_digest),
    };
    if let Some(existing) = previous_watermark {
        match traversal_watermark_ordering(&watermark, &existing) {
            std::cmp::Ordering::Less => {
                return Err(TraversalBootstrapError::ReplayDetected);
            }
            std::cmp::Ordering::Equal => {
                let existing_digest = existing
                    .payload_digest
                    .ok_or(TraversalBootstrapError::ReplayDetected)?;
                if existing_digest != payload_digest {
                    return Err(TraversalBootstrapError::ReplayDetected);
                }
            }
            std::cmp::Ordering::Greater => {}
        }
    }

    Ok(TraversalBundleSetEnvelope {
        bundles,
        coordinations,
        verifier_key_bytes,
        watermark,
    })
}

fn read_traversal_bundle_content(path: &Path) -> Result<String, TraversalBootstrapError> {
    enforce_text_artifact_size_limit(path, "traversal bundle", MAX_TRAVERSAL_BUNDLE_BYTES)
        .map_err(TraversalBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_TRAVERSAL_BUNDLE_BYTES {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "traversal bundle exceeds maximum size of {MAX_TRAVERSAL_BUNDLE_BYTES} bytes"
        )));
    }
    Ok(content)
}

fn split_traversal_bundle_sections(content: &str) -> Result<Vec<String>, TraversalBootstrapError> {
    let mut sections = Vec::new();
    let mut current = Vec::new();
    let mut saw_signature = false;
    let mut total_lines = 0usize;

    for line in content.lines() {
        total_lines = total_lines.saturating_add(1);
        if total_lines > MAX_TRAVERSAL_BUNDLE_LINES {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "traversal bundle exceeds maximum line count of {MAX_TRAVERSAL_BUNDLE_LINES}"
            )));
        }
        if line.trim().is_empty() {
            if current.is_empty() {
                continue;
            }
            if !saw_signature {
                return Err(TraversalBootstrapError::InvalidFormat(
                    "blank line before traversal bundle signature".to_string(),
                ));
            }
            sections.push(current.join("\n"));
            current.clear();
            saw_signature = false;
            continue;
        }
        if saw_signature {
            sections.push(current.join("\n"));
            current.clear();
            saw_signature = false;
        }
        current.push(line.to_string());
        if line.starts_with("signature=") {
            saw_signature = true;
        }
    }
    if !current.is_empty() {
        sections.push(current.join("\n"));
    }
    if sections.is_empty() {
        return Err(TraversalBootstrapError::InvalidFormat(
            "traversal bundle is empty".to_string(),
        ));
    }
    Ok(sections)
}

fn parse_traversal_bundle_section(
    content: &str,
    verifying_key: &VerifyingKey,
    max_age_secs: u64,
    trust_policy: TrustPolicy,
) -> Result<TraversalSectionEnvelope, TraversalBootstrapError> {
    let mut payload = String::new();
    let mut signature_hex: Option<String> = None;
    let mut fields = std::collections::HashMap::new();
    let mut line_count = 0usize;

    for line in content.lines() {
        line_count = line_count.saturating_add(1);
        if line_count > MAX_TRAVERSAL_BUNDLE_LINES {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "traversal bundle exceeds maximum line count of {MAX_TRAVERSAL_BUNDLE_LINES}"
            )));
        }
        let (key, value) = parse_limited_key_value_line(
            line,
            line_count,
            MAX_TRAVERSAL_LINE_BYTES,
            MAX_TRAVERSAL_KEY_BYTES,
            MAX_TRAVERSAL_VALUE_BYTES,
            MAX_TRAVERSAL_KEY_DEPTH,
        )
        .map_err(TraversalBootstrapError::InvalidFormat)?;
        if !is_allowed_traversal_key(key) {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "unknown key {key}"
            )));
        }
        if key == "signature" {
            if signature_hex.is_some() {
                return Err(TraversalBootstrapError::InvalidFormat(
                    "duplicate key signature".to_string(),
                ));
            }
            signature_hex = Some(value.to_string());
            continue;
        }
        payload.push_str(line);
        payload.push('\n');
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "duplicate key {key}"
            )));
        }
    }
    if fields.len() > MAX_TRAVERSAL_FIELD_COUNT {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "traversal bundle exceeds maximum field count of {MAX_TRAVERSAL_FIELD_COUNT}"
        )));
    }

    let version = fields
        .get("version")
        .ok_or_else(|| TraversalBootstrapError::InvalidFormat("missing version".to_string()))?;
    if version != "1" {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported traversal version".to_string(),
        ));
    }
    if fields.get("type").map(String::as_str) == Some("traversal_coordination") {
        return parse_traversal_coordination_section(
            &payload,
            &fields,
            signature_hex,
            verifying_key,
        );
    }
    if fields.get("path_policy").map(String::as_str) != Some("direct_preferred_relay_allowed") {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported traversal path_policy".to_string(),
        ));
    }

    let source_node_id = fields
        .get("source_node_id")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing source_node_id".to_string())
        })?
        .to_string();
    NodeId::new(source_node_id.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;
    let target_node_id = fields
        .get("target_node_id")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing target_node_id".to_string())
        })?
        .to_string();
    NodeId::new(target_node_id.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;

    let generated_at_unix = fields
        .get("generated_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing generated_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid generated_at_unix".to_string())
        })?;
    let expires_at_unix = fields
        .get("expires_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing expires_at_unix".to_string())
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid expires_at_unix".to_string())
        })?;
    if generated_at_unix >= expires_at_unix {
        return Err(TraversalBootstrapError::InvalidFormat(
            "invalid generated/expires ordering".to_string(),
        ));
    }
    let nonce = fields
        .get("nonce")
        .ok_or_else(|| TraversalBootstrapError::InvalidFormat("missing nonce".to_string()))?
        .parse::<u64>()
        .map_err(|_| TraversalBootstrapError::InvalidFormat("invalid nonce".to_string()))?;

    let signature_hex = signature_hex.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing traversal signature".to_string())
    })?;
    let signature_bytes = decode_traversal_hex_to_fixed::<64>(&signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TraversalBootstrapError::SignatureInvalid)?;

    let now = unix_now();
    if generated_at_unix > now.saturating_add(trust_policy.max_clock_skew_secs) {
        return Err(TraversalBootstrapError::FutureDated);
    }
    if now > expires_at_unix || now.saturating_sub(generated_at_unix) > max_age_secs {
        return Err(TraversalBootstrapError::Stale);
    }

    let candidate_count = fields
        .get("candidate_count")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing candidate_count".to_string())
        })?
        .parse::<usize>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat("invalid candidate_count".to_string())
        })?;
    if candidate_count == 0 || candidate_count > MAX_TRAVERSAL_CANDIDATE_COUNT {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "candidate_count must be between 1 and {MAX_TRAVERSAL_CANDIDATE_COUNT}"
        )));
    }
    let expected_field_count = 8usize
        .checked_add(candidate_count.checked_mul(6).ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("candidate field count overflow".to_string())
        })?)
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("candidate field count overflow".to_string())
        })?;
    if fields.len() != expected_field_count {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "unexpected field count for traversal bundle: expected {expected_field_count}, got {}",
            fields.len()
        )));
    }

    let mut candidates = Vec::with_capacity(candidate_count);
    let mut seen = std::collections::HashSet::new();
    for index in 0..candidate_count {
        let candidate_type_key = format!("candidate.{index}.type");
        let addr_key = format!("candidate.{index}.addr");
        let port_key = format!("candidate.{index}.port");
        let family_key = format!("candidate.{index}.family");
        let relay_id_key = format!("candidate.{index}.relay_id");
        let priority_key = format!("candidate.{index}.priority");

        let candidate_type = match fields.get(&candidate_type_key).map(String::as_str) {
            Some("host") => TraversalCandidateType::Host,
            Some("srflx") => TraversalCandidateType::ServerReflexive,
            Some("relay") => TraversalCandidateType::Relay,
            _ => {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate type for index {index}"
                )));
            }
        };

        let ip = fields
            .get(&addr_key)
            .ok_or_else(|| TraversalBootstrapError::InvalidFormat(format!("missing {addr_key}")))?
            .parse::<std::net::IpAddr>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate addr for index {index}"
                ))
            })?;
        validate_traversal_candidate_ip(candidate_type, ip, index)?;
        let family = fields.get(&family_key).ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(format!("missing {family_key}"))
        })?;
        if (ip.is_ipv4() && family != "ipv4") || (ip.is_ipv6() && family != "ipv6") {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "candidate family mismatch for index {index}"
            )));
        }
        let port = fields
            .get(&port_key)
            .ok_or_else(|| TraversalBootstrapError::InvalidFormat(format!("missing {port_key}")))?
            .parse::<u16>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate port for index {index}"
                ))
            })?;
        if port == 0 {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "candidate port must be non-zero for index {index}"
            )));
        }

        let relay_id_raw = fields.get(&relay_id_key).ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(format!("missing {relay_id_key}"))
        })?;
        let relay_id = if relay_id_raw.trim().is_empty() {
            None
        } else {
            Some(relay_id_raw.trim().to_string())
        };
        if matches!(candidate_type, TraversalCandidateType::Relay) && relay_id.is_none() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "relay candidate missing relay_id for index {index}"
            )));
        }
        if !matches!(candidate_type, TraversalCandidateType::Relay) && relay_id.is_some() {
            return Err(TraversalBootstrapError::InvalidFormat(format!(
                "relay_id is only allowed for relay candidates (index {index})"
            )));
        }

        let priority = fields
            .get(&priority_key)
            .ok_or_else(|| {
                TraversalBootstrapError::InvalidFormat(format!("missing {priority_key}"))
            })?
            .parse::<u32>()
            .map_err(|_| {
                TraversalBootstrapError::InvalidFormat(format!(
                    "invalid candidate priority for index {index}"
                ))
            })?;
        let dedupe = format!(
            "{}|{}|{}|{}",
            candidate_type.as_str(),
            ip,
            port,
            relay_id.as_deref().unwrap_or("")
        );
        if !seen.insert(dedupe) {
            return Err(TraversalBootstrapError::InvalidFormat(
                "duplicate traversal candidate tuple".to_string(),
            ));
        }

        candidates.push(TraversalCandidate {
            candidate_type,
            endpoint: std::net::SocketAddr::new(ip, port),
            relay_id,
            priority,
        });
    }

    let payload_digest = sha256_digest(payload.as_bytes());
    let watermark = TraversalWatermark {
        generated_at_unix,
        nonce,
        payload_digest: Some(payload_digest),
    };
    Ok(TraversalSectionEnvelope::Bundle(TraversalBundleEnvelope {
        bundle: TraversalBundle {
            source_node_id,
            target_node_id,
            generated_at_unix,
            expires_at_unix,
            nonce,
            candidates,
        },
        watermark,
    }))
}

fn parse_traversal_coordination_section(
    payload: &str,
    fields: &std::collections::HashMap<String, String>,
    signature_hex: Option<String>,
    verifying_key: &VerifyingKey,
) -> Result<TraversalSectionEnvelope, TraversalBootstrapError> {
    let expected_field_count = 9usize;
    if fields.len() != expected_field_count {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "unexpected field count for traversal coordination: expected {expected_field_count}, got {}",
            fields.len()
        )));
    }

    let session_id = decode_traversal_hex_to_fixed::<16>(
        fields
            .get("session_id")
            .ok_or_else(|| {
                TraversalBootstrapError::InvalidFormat(
                    "missing coordination session_id".to_string(),
                )
            })?
            .as_str(),
    )
    .map_err(|_| {
        TraversalBootstrapError::InvalidFormat("invalid coordination session_id".to_string())
    })?;
    if session_id.iter().all(|value| *value == 0) {
        return Err(TraversalBootstrapError::InvalidFormat(
            "coordination session_id must not be all zeros".to_string(),
        ));
    }
    let probe_start_unix = fields
        .get("probe_start_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(
                "missing coordination probe_start_unix".to_string(),
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat(
                "invalid coordination probe_start_unix".to_string(),
            )
        })?;
    let node_a = fields
        .get("node_a")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing coordination node_a".to_string())
        })?
        .trim()
        .to_string();
    let node_b = fields
        .get("node_b")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing coordination node_b".to_string())
        })?
        .trim()
        .to_string();
    NodeId::new(node_a.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;
    NodeId::new(node_b.clone())
        .map_err(|err| TraversalBootstrapError::InvalidFormat(err.to_string()))?;
    let issued_at_unix = fields
        .get("issued_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(
                "missing coordination issued_at_unix".to_string(),
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat(
                "invalid coordination issued_at_unix".to_string(),
            )
        })?;
    let expires_at_unix = fields
        .get("expires_at_unix")
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(
                "missing coordination expires_at_unix".to_string(),
            )
        })?
        .parse::<u64>()
        .map_err(|_| {
            TraversalBootstrapError::InvalidFormat(
                "invalid coordination expires_at_unix".to_string(),
            )
        })?;
    let nonce = decode_traversal_hex_to_fixed::<16>(
        fields
            .get("nonce")
            .ok_or_else(|| {
                TraversalBootstrapError::InvalidFormat("missing coordination nonce".to_string())
            })?
            .as_str(),
    )
    .map_err(|_| {
        TraversalBootstrapError::InvalidFormat("invalid coordination nonce".to_string())
    })?;
    if nonce.iter().all(|value| *value == 0) {
        return Err(TraversalBootstrapError::InvalidFormat(
            "coordination nonce must not be all zeros".to_string(),
        ));
    }

    let signature_hex = signature_hex.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing traversal signature".to_string())
    })?;
    let signature_bytes = decode_traversal_hex_to_fixed::<64>(&signature_hex)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify(payload.as_bytes(), &signature)
        .map_err(|_| TraversalBootstrapError::SignatureInvalid)?;

    Ok(TraversalSectionEnvelope::Coordination(
        TraversalCoordinationEnvelope {
            record: SignedTraversalCoordinationRecord {
                payload: payload.to_string(),
                signature_hex,
                session_id,
                probe_start_unix,
                node_a,
                node_b,
                issued_at_unix,
                expires_at_unix,
                nonce,
            },
            payload_digest: sha256_digest(payload.as_bytes()),
        },
    ))
}

fn traversal_snapshot_payload_digest(
    bundles: &[TraversalBundleEnvelope],
    coordinations: &[TraversalCoordinationEnvelope],
) -> Result<[u8; 32], TraversalBootstrapError> {
    if coordinations.is_empty() && bundles.len() == 1 {
        return bundles[0]
            .watermark
            .payload_digest
            .ok_or(TraversalBootstrapError::ReplayDetected);
    }

    let mut ordered_digests = bundles
        .iter()
        .map(|bundle| {
            let digest = bundle
                .watermark
                .payload_digest
                .ok_or(TraversalBootstrapError::ReplayDetected)?;
            Ok((
                bundle.bundle.source_node_id.clone(),
                bundle.bundle.target_node_id.clone(),
                digest,
            ))
        })
        .collect::<Result<Vec<_>, TraversalBootstrapError>>()?;
    ordered_digests.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut hasher = Sha256::new();
    for (_source_node_id, _target_node_id, digest) in ordered_digests {
        hasher.update(digest);
    }
    if !coordinations.is_empty() {
        let mut ordered_coordination_digests = coordinations
            .iter()
            .map(|coordination| {
                Ok((
                    traversal_coordination_pair_key(
                        coordination.record.node_a.as_str(),
                        coordination.record.node_b.as_str(),
                    ),
                    coordination.record.probe_start_unix,
                    coordination.payload_digest,
                ))
            })
            .collect::<Result<Vec<_>, TraversalBootstrapError>>()?;
        ordered_coordination_digests.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.cmp(&right.1))
                .then(left.2.cmp(&right.2))
        });
        for ((node_a, node_b), probe_start_unix, digest) in ordered_coordination_digests {
            hasher.update(b"coordination");
            hasher.update(node_a.as_bytes());
            hasher.update(node_b.as_bytes());
            hasher.update(probe_start_unix.to_be_bytes());
            hasher.update(digest);
        }
    }
    Ok(hasher.finalize().into())
}

fn validate_traversal_candidate_ip(
    candidate_type: TraversalCandidateType,
    ip: std::net::IpAddr,
    index: usize,
) -> Result<(), TraversalBootstrapError> {
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "candidate index {index} uses disallowed special address"
        )));
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_link_local() || v4.is_broadcast() {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "candidate index {index} uses disallowed special address"
                )));
            }
            if matches!(candidate_type, TraversalCandidateType::Relay)
                && (v4.is_private() || is_shared_carrier_grade_nat_ipv4(v4))
            {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "relay candidate index {index} must not use private transport address"
                )));
            }
            if matches!(candidate_type, TraversalCandidateType::ServerReflexive)
                && !is_global_unicast_ipv4(v4)
            {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "srflx candidate index {index} must use global unicast address"
                )));
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() || v6.is_unique_local() {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "candidate index {index} uses disallowed special address"
                )));
            }
            if matches!(candidate_type, TraversalCandidateType::ServerReflexive)
                && !is_global_unicast_ipv6(v6)
            {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "srflx candidate index {index} must use global unicast address"
                )));
            }
        }
    }
    Ok(())
}

fn select_runtime_traversal_endpoints(
    candidates: &[TraversalCandidate],
) -> (Option<SocketEndpoint>, Option<SocketEndpoint>) {
    let direct = candidates
        .iter()
        .filter(|candidate| !matches!(candidate.candidate_type, TraversalCandidateType::Relay))
        .max_by_key(|candidate| candidate.priority)
        .map(|candidate| SocketEndpoint {
            addr: candidate.endpoint.ip(),
            port: candidate.endpoint.port(),
        });
    let relay = candidates
        .iter()
        .filter(|candidate| matches!(candidate.candidate_type, TraversalCandidateType::Relay))
        .max_by_key(|candidate| candidate.priority)
        .map(|candidate| SocketEndpoint {
            addr: candidate.endpoint.ip(),
            port: candidate.endpoint.port(),
        });
    (direct, relay)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeRelayCandidate {
    endpoint: SocketAddr,
    relay_id: [u8; 16],
}

fn relay_transport_id_from_label(label: &str) -> Result<[u8; 16], String> {
    let trimmed = label.trim();
    if trimmed.is_empty() {
        return Err("relay candidate relay_id must not be empty".to_string());
    }
    if !trimmed.is_ascii() {
        return Err("relay candidate relay_id must be ASCII".to_string());
    }
    if trimmed.len() > 16 {
        return Err("relay candidate relay_id must be at most 16 ASCII bytes".to_string());
    }
    let mut relay_id = [0u8; 16];
    relay_id[..trimmed.len()].copy_from_slice(trimmed.as_bytes());
    Ok(relay_id)
}

fn select_runtime_relay_candidate(
    candidates: &[TraversalCandidate],
) -> Result<Option<RuntimeRelayCandidate>, String> {
    let Some(candidate) = candidates
        .iter()
        .filter(|candidate| matches!(candidate.candidate_type, TraversalCandidateType::Relay))
        .max_by_key(|candidate| candidate.priority)
    else {
        return Ok(None);
    };
    let relay_id_label = candidate
        .relay_id
        .as_deref()
        .ok_or_else(|| "relay candidate missing relay_id".to_string())?;
    if let std::net::IpAddr::V4(v4) = candidate.endpoint.ip()
        && (v4.is_private() || is_shared_carrier_grade_nat_ipv4(v4))
    {
        return Err("relay candidate must not use private transport address".to_string());
    }
    Ok(Some(RuntimeRelayCandidate {
        endpoint: candidate.endpoint,
        relay_id: relay_transport_id_from_label(relay_id_label)?,
    }))
}

fn traversal_direct_probe_candidates(
    candidates: &[TraversalCandidate],
    observed_at_unix: u64,
) -> Vec<ProbeTraversalCandidate> {
    candidates
        .iter()
        .filter_map(|candidate| {
            let source = match candidate.candidate_type {
                TraversalCandidateType::Host => ProbeCandidateSource::Host,
                TraversalCandidateType::ServerReflexive => ProbeCandidateSource::ServerReflexive,
                TraversalCandidateType::Relay => return None,
            };
            Some(ProbeTraversalCandidate {
                endpoint: SocketEndpoint {
                    addr: candidate.endpoint.ip(),
                    port: candidate.endpoint.port(),
                },
                source,
                priority: candidate.priority,
                observed_at_unix,
            })
        })
        .collect()
}

fn host_ip_from_host_cidr_daemon(value: &str) -> Option<String> {
    let (ip, prefix) = value.split_once('/')?;
    if prefix != "32" && prefix != "128" {
        return None;
    }
    Some(ip.to_string())
}

fn collect_assignment_mesh_ip_map(
    auto_tunnel: &AutoTunnelBundle,
) -> Result<BTreeMap<String, String>, DnsZoneBootstrapError> {
    if !cidr_contains(&auto_tunnel.mesh_cidr, &auto_tunnel.assigned_cidr)
        || !is_host_cidr(&auto_tunnel.assigned_cidr)
    {
        return Err(DnsZoneBootstrapError::AssignmentMismatch(
            "local assigned_cidr must be a host cidr inside mesh_cidr".to_string(),
        ));
    }
    let mut ip_map = BTreeMap::new();
    let mut seen_ips = BTreeSet::new();
    let local_ip = host_ip_from_host_cidr_daemon(&auto_tunnel.assigned_cidr).ok_or_else(|| {
        DnsZoneBootstrapError::AssignmentMismatch(
            "local assigned_cidr must be a host cidr".to_string(),
        )
    })?;
    seen_ips.insert(local_ip.clone());
    ip_map.insert(auto_tunnel.node_id.clone(), local_ip);

    for peer in &auto_tunnel.peers {
        let mut mesh_host_ips = peer
            .allowed_ips
            .iter()
            .filter(|cidr| cidr_contains(&auto_tunnel.mesh_cidr, cidr) && is_host_cidr(cidr))
            .filter_map(|cidr| host_ip_from_host_cidr_daemon(cidr))
            .collect::<Vec<_>>();
        mesh_host_ips.sort();
        mesh_host_ips.dedup();
        if mesh_host_ips.len() != 1 {
            return Err(DnsZoneBootstrapError::AssignmentMismatch(format!(
                "peer {} must expose exactly one mesh host cidr in allowed_ips",
                peer.node_id
            )));
        }
        let mesh_ip = mesh_host_ips
            .pop()
            .expect("exactly one deduped mesh host ip should remain");
        if !seen_ips.insert(mesh_ip.clone()) {
            return Err(DnsZoneBootstrapError::AssignmentMismatch(format!(
                "duplicate mesh ip {mesh_ip} in signed assignment state",
            )));
        }
        ip_map.insert(peer.node_id.to_string(), mesh_ip);
    }

    Ok(ip_map)
}

fn is_global_unicast_ipv4(value: std::net::Ipv4Addr) -> bool {
    if value.is_private()
        || value.is_loopback()
        || value.is_link_local()
        || value.is_multicast()
        || value.is_broadcast()
        || value.is_unspecified()
        || value.is_documentation()
    {
        return false;
    }
    let octets = value.octets();
    // Shared Address Space (100.64.0.0/10) and benchmarking space (198.18.0.0/15).
    if octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000 {
        return false;
    }
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return false;
    }
    true
}

fn is_shared_carrier_grade_nat_ipv4(value: std::net::Ipv4Addr) -> bool {
    let octets = value.octets();
    octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000
}

fn is_global_unicast_ipv6(value: std::net::Ipv6Addr) -> bool {
    if value.is_unspecified()
        || value.is_loopback()
        || value.is_multicast()
        || value.is_unicast_link_local()
        || value.is_unique_local()
    {
        return false;
    }
    // Documentation range 2001:db8::/32.
    let segments = value.segments();
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }
    true
}

fn load_traversal_verifying_key(path: &Path) -> Result<VerifyingKey, TraversalBootstrapError> {
    enforce_text_artifact_size_limit(
        path,
        "traversal verifier key",
        MAX_BUNDLE_VERIFIER_KEY_BYTES,
    )
    .map_err(TraversalBootstrapError::InvalidFormat)?;
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    if content.len() > MAX_BUNDLE_VERIFIER_KEY_BYTES {
        return Err(TraversalBootstrapError::InvalidFormat(format!(
            "traversal verifier key exceeds maximum size of {MAX_BUNDLE_VERIFIER_KEY_BYTES} bytes"
        )));
    }
    let key_line = content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat("missing verifier key".to_string())
        })?;
    let key_bytes = decode_traversal_hex_to_fixed::<32>(key_line)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| TraversalBootstrapError::KeyInvalid)
}

fn decode_traversal_hex_to_fixed<const N: usize>(
    encoded: &str,
) -> Result<[u8; N], TraversalBootstrapError> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unexpected hex length".to_string(),
        ));
    }
    let raw = trimmed.as_bytes();
    let mut index = 0usize;
    while index < N {
        let hi = decode_traversal_hex_nibble(raw[index * 2])?;
        let lo = decode_traversal_hex_nibble(raw[index * 2 + 1])?;
        bytes[index] = (hi << 4) | lo;
        index += 1;
    }
    Ok(bytes)
}

fn decode_traversal_hex_nibble(value: u8) -> Result<u8, TraversalBootstrapError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(TraversalBootstrapError::InvalidFormat(
            "invalid hex character".to_string(),
        )),
    }
}

fn traversal_watermark_ordering(
    current: &TraversalWatermark,
    previous: &TraversalWatermark,
) -> std::cmp::Ordering {
    current
        .generated_at_unix
        .cmp(&previous.generated_at_unix)
        .then(current.nonce.cmp(&previous.nonce))
}

fn load_traversal_watermark(
    path: &Path,
) -> Result<Option<TraversalWatermark>, TraversalBootstrapError> {
    if !path.exists() {
        return Ok(None);
    }
    let content =
        fs::read_to_string(path).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    let mut version: Option<u8> = None;
    let mut generated_at_unix: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut payload_digest: Option<[u8; 32]> = None;
    for line in content.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(TraversalBootstrapError::InvalidFormat(
                "watermark line missing key/value separator".to_string(),
            ));
        };
        match key {
            "version" => version = value.parse::<u8>().ok(),
            "generated_at_unix" => generated_at_unix = value.parse::<u64>().ok(),
            "nonce" => nonce = value.parse::<u64>().ok(),
            "payload_digest_sha256" => {
                payload_digest = Some(decode_traversal_hex_to_fixed::<32>(value)?);
            }
            _ => {
                return Err(TraversalBootstrapError::InvalidFormat(format!(
                    "unknown watermark key {key}"
                )));
            }
        }
    }
    let generated_at_unix = generated_at_unix.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark generated_at_unix".to_string())
    })?;
    let nonce = nonce.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark nonce".to_string())
    })?;
    let version = version.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat("missing watermark version".to_string())
    })?;
    if version != 2 {
        return Err(TraversalBootstrapError::InvalidFormat(
            "unsupported watermark version; expected version=2".to_string(),
        ));
    }
    let payload_digest = Some(payload_digest.ok_or_else(|| {
        TraversalBootstrapError::InvalidFormat(
            "missing watermark payload_digest_sha256".to_string(),
        )
    })?);
    Ok(Some(TraversalWatermark {
        generated_at_unix,
        nonce,
        payload_digest,
    }))
}

fn persist_traversal_watermark(
    path: &Path,
    watermark: TraversalWatermark,
) -> Result<(), TraversalBootstrapError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        }
    }
    let payload_digest = watermark
        .payload_digest
        .ok_or_else(|| {
            TraversalBootstrapError::InvalidFormat(
                "watermark payload digest is required".to_string(),
            )
        })
        .map(|digest| encode_hex(&digest))?;
    let payload = format!(
        "version=2\ngenerated_at_unix={}\nnonce={}\npayload_digest_sha256={}\n",
        watermark.generated_at_unix, watermark.nonce, payload_digest
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
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(TraversalBootstrapError::Io(err.to_string()));
    }
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| TraversalBootstrapError::Io(err.to_string()))?;
    }
    Ok(())
}

fn is_valid_ipv4_or_ipv6_cidr(value: &str) -> bool {
    parse_cidr(value).is_some()
}

fn is_host_cidr(value: &str) -> bool {
    match parse_cidr(value) {
        Some((std::net::IpAddr::V4(_), prefix)) => prefix == 32,
        Some((std::net::IpAddr::V6(_), prefix)) => prefix == 128,
        None => false,
    }
}

fn cidr_contains(container: &str, candidate: &str) -> bool {
    let Some((container_ip, container_prefix)) = parse_cidr(container) else {
        return false;
    };
    let Some((candidate_ip, candidate_prefix)) = parse_cidr(candidate) else {
        return false;
    };
    if candidate_prefix < container_prefix {
        return false;
    }
    match (container_ip, candidate_ip) {
        (std::net::IpAddr::V4(container_v4), std::net::IpAddr::V4(candidate_v4)) => {
            let mask = if container_prefix == 0 {
                0
            } else {
                u32::MAX << (32 - container_prefix)
            };
            (u32::from(container_v4) & mask) == (u32::from(candidate_v4) & mask)
        }
        (std::net::IpAddr::V6(container_v6), std::net::IpAddr::V6(candidate_v6)) => {
            let container_raw = u128::from_be_bytes(container_v6.octets());
            let candidate_raw = u128::from_be_bytes(candidate_v6.octets());
            let mask = if container_prefix == 0 {
                0
            } else {
                u128::MAX << (128 - container_prefix)
            };
            (container_raw & mask) == (candidate_raw & mask)
        }
        _ => false,
    }
}

fn parse_cidr(value: &str) -> Option<(std::net::IpAddr, u8)> {
    let (ip_part, prefix_part) = value.split_once('/')?;
    let ip = ip_part.parse::<std::net::IpAddr>().ok()?;
    let prefix = prefix_part.parse::<u8>().ok()?;
    let valid = match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    };
    if valid { Some((ip, prefix)) } else { None }
}

#[cfg(target_os = "linux")]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_evidence_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust evidence", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel bundle", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_dns_zone_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "dns zone bundle", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_dns_zone_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "dns zone bundle", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_dns_zone_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "dns zone verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_dns_zone_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "dns zone verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_auto_tunnel_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "auto tunnel verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_traversal_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal bundle", 0o037, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_traversal_bundle_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal bundle", 0o037, true)
}

#[cfg(target_os = "linux")]
fn validate_traversal_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_traversal_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "traversal verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022, true)
}

#[cfg(target_os = "linux")]
fn validate_remote_ops_token_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "remote ops token verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_remote_ops_token_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "remote ops token verifier key", 0o022, true)
}

#[cfg(not(target_os = "linux"))]
fn validate_trust_verifier_key_permissions(path: &Path) -> Result<(), DaemonError> {
    validate_file_security(path, "trust verifier key", 0o022, true)
}

#[cfg(not(windows))]
fn validate_file_security(
    path: &Path,
    label: &str,
    disallowed_mode_mask: u32,
    allow_root_owner: bool,
) -> Result<(), DaemonError> {
    validate_parent_directory_security(path, label, allow_root_owner)?;

    let link_metadata = fs::symlink_metadata(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("{label} metadata read failed: {err}"))
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must not be a symlink"
        )));
    }
    if !link_metadata.file_type().is_file() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must be a regular file"
        )));
    }

    let metadata = fs::metadata(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("{label} metadata read failed: {err}"))
    })?;
    let mode = metadata.permissions().mode();
    if mode & disallowed_mode_mask != 0 {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} has insecure permissions: mode {:o}",
            mode & 0o777
        )));
    }

    let owner_uid = metadata.uid();
    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid && !(allow_root_owner && owner_uid == 0) {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} owner uid mismatch: expected {expected_uid}, got {owner_uid}"
        )));
    }
    fs::File::open(path).map_err(|err| {
        DaemonError::InvalidConfig(format!(
            "{label} is not readable by runtime user (uid {expected_uid}): {err}"
        ))
    })?;
    Ok(())
}

#[cfg(windows)]
fn validate_file_security(
    path: &Path,
    label: &str,
    _disallowed_mode_mask: u32,
    _allow_root_owner: bool,
) -> Result<(), DaemonError> {
    validate_windows_runtime_file_path(path, label).map_err(DaemonError::InvalidConfig)?;
    let link_metadata = fs::symlink_metadata(path).map_err(|err| {
        DaemonError::InvalidConfig(format!("{label} metadata read failed: {err}"))
    })?;
    if link_metadata.file_type().is_symlink() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must not be a symlink"
        )));
    }
    if !link_metadata.file_type().is_file() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} must be a regular file"
        )));
    }
    fs::File::open(path).map_err(|err| {
        DaemonError::InvalidConfig(format!(
            "{label} is not readable by the current service identity: {err}"
        ))
    })?;
    Err(DaemonError::InvalidConfig(format!(
        "{label} Windows ACL validation is not yet implemented; refusing to treat filesystem presence as a secure authorization check"
    )))
}

#[cfg(not(windows))]
fn validate_parent_directory_security(
    path: &Path,
    label: &str,
    allow_root_owner: bool,
) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::InvalidConfig(format!(
            "{label} path must include a parent directory: {}",
            path.display()
        ))
    })?;
    let metadata = fs::symlink_metadata(parent).map_err(|err| {
        DaemonError::InvalidConfig(format!(
            "{label} parent directory metadata read failed for {}: {err}",
            parent.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} parent directory must be a non-symlink directory: {}",
            parent.display()
        )));
    }

    let mode = metadata.permissions().mode() & 0o777;
    let owner_uid = metadata.uid();
    let owner_gid = metadata.gid();
    let expected_gid = Gid::effective().as_raw();
    let root_managed_shared_runtime =
        is_root_managed_shared_runtime_parent(parent, mode, owner_uid, owner_gid, expected_gid);

    if mode & 0o022 != 0 && !root_managed_shared_runtime {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} parent directory has insecure permissions: mode {mode:o}"
        )));
    }

    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid
        && !(allow_root_owner && owner_uid == 0)
        && !root_managed_shared_runtime
    {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} parent directory owner uid mismatch: expected {expected_uid}, got {owner_uid}"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_parent_directory_security(
    path: &Path,
    label: &str,
    _allow_root_owner: bool,
) -> Result<(), DaemonError> {
    let parent = path.parent().ok_or_else(|| {
        DaemonError::InvalidConfig(format!(
            "{label} path must include a parent directory: {}",
            path.display()
        ))
    })?;
    validate_windows_runtime_file_path(parent, label).map_err(DaemonError::InvalidConfig)?;
    let metadata = fs::symlink_metadata(parent).map_err(|err| {
        DaemonError::InvalidConfig(format!(
            "{label} parent directory metadata read failed for {}: {err}",
            parent.display()
        ))
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(DaemonError::InvalidConfig(format!(
            "{label} parent directory must be a non-symlink directory: {}",
            parent.display()
        )));
    }
    Err(DaemonError::InvalidConfig(format!(
        "{label} parent directory ACL validation is not yet implemented for Windows runtime paths"
    )))
}

#[cfg(target_os = "linux")]
fn is_root_managed_shared_runtime_parent(
    parent: &Path,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    expected_gid: u32,
) -> bool {
    parent == Path::new("/run/rustynet")
        && owner_uid == 0
        && mode == 0o770
        && (owner_gid == expected_gid || owner_gid == 0)
}

#[cfg(not(target_os = "linux"))]
fn is_root_managed_shared_runtime_parent(
    _parent: &Path,
    _mode: u32,
    _owner_uid: u32,
    _owner_gid: u32,
    _expected_gid: u32,
) -> bool {
    false
}

#[cfg(not(windows))]
fn read_command_envelope(stream: &UnixStream) -> Result<CommandEnvelope, String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let reader = std::io::BufReader::new(stream);
    ipc_read_command_envelope(reader).map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn write_response(mut stream: UnixStream, response: IpcResponse) -> Result<(), String> {
    stream
        .write_all(format!("{}\n", response.to_wire()).as_bytes())
        .map_err(|err| format!("write failed: {err}"))
}

#[cfg(not(windows))]
fn socket_owner_uid(path: &Path) -> Result<u32, DaemonError> {
    let metadata = fs::metadata(path).map_err(|err| DaemonError::Io(err.to_string()))?;
    Ok(metadata.uid())
}

#[cfg(not(windows))]
fn socket_owner_gid(path: &Path) -> Result<u32, DaemonError> {
    let metadata = fs::metadata(path).map_err(|err| DaemonError::Io(err.to_string()))?;
    Ok(metadata.gid())
}

#[cfg(not(windows))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return getsockopt(stream, PeerCredentials)
            .ok()
            .map(|cred| cred.uid());
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))]
    {
        return getsockopt(stream, LocalPeerCred)
            .ok()
            .map(|cred| cred.uid());
    }

    #[allow(unreachable_code)]
    None
}

#[cfg(not(windows))]
fn peer_gid(_stream: &UnixStream) -> Option<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return getsockopt(_stream, PeerCredentials)
            .ok()
            .map(|cred| cred.gid());
    }

    #[allow(unreachable_code)]
    None
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn sanitize_netcheck_value(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '-' | ':' | '.' | '/' | '+' => ch,
            _ => '_',
        })
        .collect()
}

fn membership_directory_from_state(state: &MembershipState) -> MembershipDirectory {
    let mut directory = MembershipDirectory::default();
    for node in &state.nodes {
        let status = match node.status {
            MembershipNodeStatus::Active => MembershipStatus::Active,
            MembershipNodeStatus::Revoked | MembershipNodeStatus::Quarantined => {
                MembershipStatus::Revoked
            }
        };
        directory.set_node_status(node.node_id.clone(), status);
    }
    directory
}

#[cfg(all(test, not(windows)))]
mod tests {
    use std::collections::BTreeMap;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::net::{IpAddr, SocketAddr, UdpSocket};
    use std::num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize};
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::daemon::RestrictionMode;
    use crate::ipc::{
        CommandEnvelope, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, IpcCommand, IpcResponse,
        REMOTE_OPS_WIRE_PREFIX, RemoteCommandEnvelope, RemoteOpsEnvelopeParseError,
        read_command_envelope, remote_ops_signature_payload,
    };
    #[cfg(not(target_os = "macos"))]
    use crate::key_material::encrypt_private_key;
    use crate::relay_client::{RelayClient, RelayClientConfig, RelayClientError};

    use ed25519_dalek::{Signer, SigningKey};
    use rustynet_backend_api::{
        NodeId, Route, RouteKind, RuntimeContext, SocketEndpoint, TunnelBackend,
    };
    use rustynet_backend_wireguard::RecordedAuthoritativeTransportOperationKind;
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
        persist_membership_snapshot,
    };

    use super::{
        AutoTunnelWatermark, DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS, DEFAULT_DNS_ZONE_MAX_AGE_SECS,
        DEFAULT_EGRESS_INTERFACE, DEFAULT_TRAVERSAL_MAX_AGE_SECS, DNS_RCODE_NOERROR,
        DNS_RCODE_REFUSED, DNS_RCODE_SERVFAIL, DaemonBackendMode, DaemonConfig, DaemonRuntime,
        DnsZoneBootstrapError, DnsZoneLoadContext, MAX_AUTO_TUNNEL_BUNDLE_BYTES,
        MAX_AUTO_TUNNEL_PEER_COUNT, MAX_AUTO_TUNNEL_ROUTE_COUNT, MAX_TRAVERSAL_BUNDLE_BYTES,
        MAX_TRAVERSAL_CANDIDATE_COUNT, MAX_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS,
        MAX_TRUST_EVIDENCE_BYTES, MIN_TRAVERSAL_REFRESH_COOLDOWN_SECS, NodeRole, StateFetcher,
        TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_DELAY_MS, TrustEvidenceRecord, TrustPolicy,
        TrustWatermark, build_dns_response, collect_traversal_host_candidate_snapshot_with_retry,
        is_root_managed_shared_runtime_parent, load_auto_tunnel_bundle, load_auto_tunnel_watermark,
        load_dns_zone_bundle, load_traversal_bundle, load_traversal_bundle_set,
        load_traversal_watermark, load_trust_evidence, load_trust_watermark,
        parse_route_interface_token, passphrase_disallowed_mode_mask,
        persist_auto_tunnel_watermark, persist_traversal_watermark, persist_trust_watermark,
        prepare_runtime_wireguard_key_material, resolve_egress_interface_value, run_daemon,
        run_preflight_checks, sanitize_dataplane_routes_for_node_role,
        scrub_runtime_wireguard_key_material, sha256_digest,
        snapshot_has_usable_traversal_host_candidates, trust_evidence_payload, unix_now,
        validate_daemon_config, validate_file_security, zeroize_optional_bytes,
    };
    use crate::phase10::{DataplaneState, PathMode, TraversalProbeDecision, TraversalProbeReason};
    use crate::stun_client::StunResult;

    fn hex_encode(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn format_stun_local_addrs_reports_none_when_empty() {
        assert_eq!(super::format_stun_local_addrs(&[]), "none");
    }

    #[test]
    fn stun_local_port_match_state_reports_mismatch_when_observed_port_differs() {
        let observations = vec![StunResult {
            mapped_endpoint: "198.51.100.20:61000"
                .parse()
                .expect("endpoint should parse"),
            server: "198.51.100.1:3478".parse().expect("server should parse"),
            local_addr: "0.0.0.0:49152".parse().expect("local addr should parse"),
        }];
        assert_eq!(
            super::stun_local_port_match_state(&observations, 51820),
            "all_mismatch_wg_listen_port"
        );
        assert_eq!(
            super::format_stun_local_addrs(&observations),
            "0.0.0.0:49152"
        );
    }

    #[test]
    fn stun_local_port_match_state_reports_mixed_when_ports_do_not_agree() {
        let observations = vec![
            StunResult {
                mapped_endpoint: "198.51.100.20:61000"
                    .parse()
                    .expect("endpoint should parse"),
                server: "198.51.100.1:3478".parse().expect("server should parse"),
                local_addr: "0.0.0.0:51820".parse().expect("local addr should parse"),
            },
            StunResult {
                mapped_endpoint: "198.51.100.21:61001"
                    .parse()
                    .expect("endpoint should parse"),
                server: "198.51.100.2:3478".parse().expect("server should parse"),
                local_addr: "0.0.0.0:49152".parse().expect("local addr should parse"),
            },
        ];
        assert_eq!(
            super::stun_local_port_match_state(&observations, 51820),
            "mixed"
        );
    }

    fn write_signed_kv_artifact(path: &Path, verifier_path: &Path, seed: [u8; 32], payload: &str) {
        let signing_key = SigningKey::from_bytes(&seed);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("verifier key should be written");
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("signed artifact should be written");
    }

    fn write_signed_kv_artifact_with_verifier_seed(
        path: &Path,
        verifier_path: &Path,
        signer_seed: [u8; 32],
        verifier_seed: [u8; 32],
        payload: &str,
    ) {
        let signing_key = SigningKey::from_bytes(&signer_seed);
        let verifier_signing_key = SigningKey::from_bytes(&verifier_seed);
        std::fs::write(
            verifier_path,
            format!(
                "{}\n",
                hex_encode(verifier_signing_key.verifying_key().as_bytes())
            ),
        )
        .expect("verifier key should be written");
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("signed artifact should be written");
    }

    fn write_signed_kv_sections(
        path: &Path,
        verifier_path: &Path,
        seed: [u8; 32],
        payloads: &[String],
    ) {
        write_signed_kv_sections_with_verifier_seed(path, verifier_path, seed, seed, payloads);
    }

    fn write_signed_kv_sections_with_verifier_seed(
        path: &Path,
        verifier_path: &Path,
        signer_seed: [u8; 32],
        verifier_seed: [u8; 32],
        payloads: &[String],
    ) {
        let signing_key = SigningKey::from_bytes(&signer_seed);
        let verifier_signing_key = SigningKey::from_bytes(&verifier_seed);
        std::fs::write(
            verifier_path,
            format!(
                "{}\n",
                hex_encode(verifier_signing_key.verifying_key().as_bytes())
            ),
        )
        .expect("verifier key should be written");

        let mut body = String::new();
        for (index, payload) in payloads.iter().enumerate() {
            if index > 0 {
                body.push('\n');
            }
            let signature = signing_key.sign(payload.as_bytes());
            body.push_str(payload);
            body.push_str(&format!(
                "signature={}\n",
                hex_encode(&signature.to_bytes())
            ));
        }
        std::fs::write(path, body).expect("signed sections should be written");
    }

    fn traversal_bundle_payload(
        source_node: &str,
        target_node: &str,
        nonce: u64,
        relay_addr: SocketAddr,
        relay_label: &str,
        generated: u64,
        expires: u64,
    ) -> String {
        format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr={}\ncandidate.1.port={}\ncandidate.1.family=ipv4\ncandidate.1.relay_id={relay_label}\ncandidate.1.priority=20\n",
            relay_addr.ip(),
            relay_addr.port(),
        )
    }

    fn traversal_coordination_payload(
        session_id: [u8; 16],
        probe_start_unix: u64,
        node_a: &str,
        node_b: &str,
        issued_at_unix: u64,
        expires_at_unix: u64,
        nonce: [u8; 16],
    ) -> String {
        format!(
            "version=1\ntype=traversal_coordination\nsession_id={}\nprobe_start_unix={probe_start_unix}\nnode_a={node_a}\nnode_b={node_b}\nissued_at_unix={issued_at_unix}\nexpires_at_unix={expires_at_unix}\nnonce={}\n",
            hex_encode(&session_id),
            hex_encode(&nonce),
        )
    }

    #[allow(dead_code)]
    fn percent_encode_test(value: &str) -> String {
        let mut encoded = String::new();
        for byte in value.bytes() {
            if byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b':' | b'.' | b'-' | b'_' | b'/' | b' ' | b',' | b'=' | b'+' | b'@'
                )
            {
                encoded.push(byte as char);
            } else {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
        encoded
    }

    fn render_remote_command_wire(
        subject: &str,
        nonce: u64,
        command: IpcCommand,
        signing_seed: [u8; 32],
    ) -> String {
        let signing_key = SigningKey::from_bytes(&signing_seed);
        let _envelope = RemoteCommandEnvelope {
            subject: subject.to_string(),
            nonce,
            command: command.clone(),
            signature: Vec::new(),
        };
        let payload = remote_ops_signature_payload(subject, nonce, &command);
        let signature = signing_key.sign(&payload);
        format!(
            "{REMOTE_OPS_WIRE_PREFIX}subject={} nonce={} command={} signature={}",
            subject,
            nonce,
            command.as_wire(),
            hex_encode(&signature.to_bytes())
        )
    }

    #[test]
    fn passphrase_permission_mask_accepts_systemd_runtime_credential_mode() {
        assert_eq!(
            passphrase_disallowed_mode_mask(Path::new(
                "/run/credentials/rustynetd.service/wg_key_passphrase"
            )),
            0o337
        );
        assert_eq!(
            passphrase_disallowed_mode_mask(Path::new(
                "/var/lib/rustynet/keys/wireguard.passphrase"
            )),
            0o077
        );
    }

    #[test]
    fn read_command_envelope_rejects_null_byte_payload() {
        let (mut writer, reader) = UnixStream::pair().expect("unix stream pair should initialize");
        writer
            .write_all(b"status\0\n")
            .expect("null-byte payload write should succeed");

        let err = read_command_envelope(&reader).expect_err("null-byte payload must be rejected");
        assert!(err.to_string().contains("command contains null byte"));
    }

    #[test]
    fn read_command_envelope_parses_remote_wire_command() {
        let nonce = unix_now();
        let wire = render_remote_command_wire(
            DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT,
            nonce,
            IpcCommand::Status,
            [44u8; 32],
        );
        let (mut writer, reader) = UnixStream::pair().expect("unix stream pair should initialize");
        writer
            .write_all(format!("{wire}\n").as_bytes())
            .expect("remote command wire should write");
        let envelope = read_command_envelope(&reader).expect("remote envelope should parse");
        match envelope {
            CommandEnvelope::Remote(remote) => {
                assert_eq!(remote.subject, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT);
                assert_eq!(remote.command, IpcCommand::Status);
                assert_eq!(remote.nonce, nonce);
            }
            CommandEnvelope::Local(_) => panic!("expected remote envelope"),
        }
    }

    #[test]
    fn read_command_envelope_rejects_invalid_remote_wire_command() {
        let (mut writer, reader) = UnixStream::pair().expect("unix stream pair should initialize");
        writer
            .write_all(
                format!("{REMOTE_OPS_WIRE_PREFIX}subject=user:local nonce=123 command=status\n")
                    .as_bytes(),
            )
            .expect("invalid remote command wire should write");
        let err = read_command_envelope(&reader)
            .expect_err("remote envelope missing signature must be rejected");
        assert!(matches!(err, RemoteOpsEnvelopeParseError::MissingSignature));
    }

    #[test]
    fn authorize_remote_command_rejects_replay_and_invalid_signature() {
        let test_dir = secure_test_dir("rustynetd-remote-ops-replay");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");

        // Setup remote ops keys
        let remote_seed = [55u8; 32];
        let remote_signing_key = SigningKey::from_bytes(&remote_seed);
        let remote_verifier_key = remote_signing_key.verifying_key();
        let remote_ops_verifier_path = test_dir.join("remote-ops.pub");
        std::fs::write(
            &remote_ops_verifier_path,
            hex_encode(remote_verifier_key.as_bytes()),
        )
        .expect("verifier key should be written");

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            remote_ops_token_verifier_key_path: Some(remote_ops_verifier_path),
            remote_ops_expected_subject: DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT.to_string(),
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();

        let now = unix_now();
        let nonce = now;
        let command = IpcCommand::Status;
        let payload =
            remote_ops_signature_payload(DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, nonce, &command);
        let signature = remote_signing_key.sign(&payload);

        let envelope = RemoteCommandEnvelope {
            subject: DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT.to_string(),
            nonce,
            command: command.clone(),
            signature: signature.to_bytes().to_vec(),
        };

        let first = runtime.authorize_remote_command(&envelope, now);
        assert!(first.is_ok(), "fresh remote command should authorize");

        let replay = runtime
            .authorize_remote_command(&envelope, now)
            .expect_err("fresh remote command replay must be rejected");
        assert!(replay.contains("replay detected"));

        let expired_nonce = now.saturating_sub(61);
        let expired_payload = remote_ops_signature_payload(
            DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT,
            expired_nonce,
            &command,
        );
        let expired_signature = remote_signing_key.sign(&expired_payload);
        let expired_envelope = RemoteCommandEnvelope {
            subject: DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT.to_string(),
            nonce: expired_nonce,
            command: command.clone(),
            signature: expired_signature.to_bytes().to_vec(),
        };

        let expired = runtime
            .authorize_remote_command(&expired_envelope, now)
            .expect_err("expired remote command must be rejected");
        assert!(expired.contains("nonce expired"));

        // Tampered check
        let mut tampered = envelope.clone();
        tampered.command = IpcCommand::Netcheck;
        let tampered_err = runtime
            .authorize_remote_command(&tampered, now)
            .expect_err("tampered remote command must fail signature validation");
        assert!(tampered_err.contains("signature verification failed"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn authorize_remote_command_rejects_wrong_subject() {
        let test_dir = secure_test_dir("rustynetd-remote-ops-subject");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let remote_ops_verifier_path = test_dir.join("remote_ops_access_token.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let remote_signing_key = SigningKey::from_bytes(&[56u8; 32]);
        std::fs::write(
            &remote_ops_verifier_path,
            format!(
                "{}\n",
                hex_encode(remote_signing_key.verifying_key().as_bytes())
            ),
        )
        .expect("remote ops verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                &remote_ops_verifier_path,
                std::fs::Permissions::from_mode(0o644),
            )
            .expect("remote ops verifier key permissions should be secure");
        }

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            remote_ops_token_verifier_key_path: Some(remote_ops_verifier_path),
            remote_ops_expected_subject: DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT.to_string(),
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let now = unix_now();
        let nonce = now;
        let command = IpcCommand::Status;

        // Signed by correct key but WRONG subject
        let wrong_subject = "user:attacker";
        let payload = remote_ops_signature_payload(wrong_subject, nonce, &command);
        let signature = remote_signing_key.sign(&payload);

        let envelope = RemoteCommandEnvelope {
            subject: wrong_subject.to_string(),
            nonce,
            command: command.clone(),
            signature: signature.to_bytes().to_vec(),
        };

        let err = runtime
            .authorize_remote_command(&envelope, now)
            .expect_err("subject mismatch must be rejected");
        assert!(err.contains("unexpected subject"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn node_role_command_matrix_is_fail_closed() {
        let command_matrix = vec![
            (IpcCommand::Status, true, true, true),
            (IpcCommand::Netcheck, true, true, true),
            (IpcCommand::StateRefresh, true, true, true),
            (
                IpcCommand::ExitNodeSelect("node-exit".to_string()),
                true,
                true,
                false,
            ),
            (IpcCommand::ExitNodeOff, true, true, false),
            (IpcCommand::LanAccessOn, true, true, false),
            (IpcCommand::LanAccessOff, true, true, false),
            (IpcCommand::DnsInspect, true, true, true),
            (
                IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()),
                true,
                false,
                false,
            ),
            (
                IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()),
                true,
                false,
                false,
            ),
            (IpcCommand::KeyRotate, true, false, false),
            (IpcCommand::KeyRevoke, true, false, false),
            (
                IpcCommand::Unknown("unknown".to_string()),
                true,
                false,
                false,
            ),
        ];

        for (command, admin_expected, client_expected, blind_exit_expected) in &command_matrix {
            assert_eq!(
                NodeRole::Admin.allows_command(command),
                *admin_expected,
                "admin role command mismatch for {}",
                command.as_wire()
            );
            assert_eq!(
                NodeRole::Client.allows_command(command),
                *client_expected,
                "client role command mismatch for {}",
                command.as_wire()
            );
            assert_eq!(
                NodeRole::BlindExit.allows_command(command),
                *blind_exit_expected,
                "blind_exit role command mismatch for {}",
                command.as_wire()
            );
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum RoleAuthMatrixMode {
        Manual,
        AutoTunnel,
        Restricted,
        AutoTunnelRestricted,
    }

    impl RoleAuthMatrixMode {
        fn as_str(self) -> &'static str {
            match self {
                RoleAuthMatrixMode::Manual => "manual",
                RoleAuthMatrixMode::AutoTunnel => "auto_tunnel",
                RoleAuthMatrixMode::Restricted => "restricted",
                RoleAuthMatrixMode::AutoTunnelRestricted => "auto_tunnel_restricted",
            }
        }

        fn auto_tunnel_enforced(self) -> bool {
            matches!(
                self,
                RoleAuthMatrixMode::AutoTunnel | RoleAuthMatrixMode::AutoTunnelRestricted
            )
        }

        fn restricted_safe(self) -> bool {
            matches!(
                self,
                RoleAuthMatrixMode::Restricted | RoleAuthMatrixMode::AutoTunnelRestricted
            )
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum RoleAuthMatrixHop {
        OneHop,
        TwoHop,
    }

    impl RoleAuthMatrixHop {
        fn as_str(self) -> &'static str {
            match self {
                RoleAuthMatrixHop::OneHop => "one_hop",
                RoleAuthMatrixHop::TwoHop => "two_hop",
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum RoleAuthDecision {
        Allowed,
        DeniedByRole,
        DeniedByRestrictedSafeMode,
        DeniedByAutoTunnelEnforcement,
    }

    fn role_auth_matrix_commands() -> Vec<IpcCommand> {
        vec![
            IpcCommand::Status,
            IpcCommand::Netcheck,
            IpcCommand::StateRefresh,
            IpcCommand::DnsInspect,
            IpcCommand::ExitNodeSelect("node-exit".to_string()),
            IpcCommand::ExitNodeOff,
            IpcCommand::LanAccessOn,
            IpcCommand::LanAccessOff,
            IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()),
            IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()),
            IpcCommand::KeyRotate,
            IpcCommand::KeyRevoke,
            IpcCommand::Unknown("unknown".to_string()),
        ]
    }

    fn classify_role_auth_decision(response: &IpcResponse) -> RoleAuthDecision {
        if response
            .message
            .contains("current node role does not permit this operation")
        {
            return RoleAuthDecision::DeniedByRole;
        }
        if response.message.contains("restricted-safe mode") {
            return RoleAuthDecision::DeniedByRestrictedSafeMode;
        }
        if response
            .message
            .contains("disabled while auto-tunnel is enforced")
        {
            return RoleAuthDecision::DeniedByAutoTunnelEnforcement;
        }
        RoleAuthDecision::Allowed
    }

    fn expected_role_auth_decision(
        role: NodeRole,
        mode: RoleAuthMatrixMode,
        command: &IpcCommand,
    ) -> RoleAuthDecision {
        if !role.allows_command(command) {
            return RoleAuthDecision::DeniedByRole;
        }
        if mode.restricted_safe()
            && command.is_mutating()
            && !matches!(command, IpcCommand::StateRefresh)
        {
            return RoleAuthDecision::DeniedByRestrictedSafeMode;
        }
        if mode.auto_tunnel_enforced()
            && matches!(
                command,
                IpcCommand::ExitNodeSelect(_)
                    | IpcCommand::ExitNodeOff
                    | IpcCommand::LanAccessOn
                    | IpcCommand::LanAccessOff
                    | IpcCommand::RouteAdvertise(_)
            )
        {
            let auto_tunnel_exception = matches!(
                command,
                IpcCommand::RouteAdvertise(cidr)
                    if role == NodeRole::Admin && cidr == "0.0.0.0/0"
            );
            if !auto_tunnel_exception {
                return RoleAuthDecision::DeniedByAutoTunnelEnforcement;
            }
        }
        RoleAuthDecision::Allowed
    }

    fn build_role_auth_matrix_runtime(
        role: NodeRole,
        mode: RoleAuthMatrixMode,
        hop: RoleAuthMatrixHop,
    ) -> (DaemonRuntime, std::path::PathBuf) {
        let test_dir = secure_test_dir(&format!(
            "rustynetd-role-auth-{}-{}-{}",
            role.as_str(),
            mode.as_str(),
            hop.as_str()
        ));
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: role,
            ..DaemonConfig::default()
        };

        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        runtime.auto_tunnel_enforce = mode.auto_tunnel_enforced();
        runtime.advertised_routes.clear();
        runtime.local_route_reconcile_pending = false;

        if !role.is_blind_exit() {
            runtime.selected_exit_node = Some("node-exit".to_string());
        } else {
            // Start from an intentionally over-privileged state and force invariant cleanup.
            runtime.selected_exit_node = Some("node-exit".to_string());
            runtime.lan_access_enabled = true;
            runtime.controller.set_lan_access(true);
            runtime
                .enforce_blind_exit_invariants()
                .expect("blind_exit invariants should enforce least-knowledge state");
        }

        if matches!(hop, RoleAuthMatrixHop::TwoHop) {
            runtime.advertised_routes.insert("0.0.0.0/0".to_string());
        }

        if mode.restricted_safe() {
            runtime.restrict_recoverable("matrix-forced-restricted".to_string());
        }

        (runtime, test_dir)
    }

    fn assert_role_auth_status_invariants(
        runtime: &mut DaemonRuntime,
        role: NodeRole,
        mode: RoleAuthMatrixMode,
        hop: RoleAuthMatrixHop,
    ) {
        let status = runtime.handle_command(IpcCommand::Status);
        assert!(
            status.ok,
            "status must succeed in matrix scenario role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );
        assert!(
            status
                .message
                .contains(format!("node_role={}", role.as_str()).as_str()),
            "status role marker mismatch for role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );
        assert!(
            status.message.contains(
                format!(
                    "auto_tunnel_enforce={}",
                    if mode.auto_tunnel_enforced() {
                        "true"
                    } else {
                        "false"
                    }
                )
                .as_str()
            ),
            "status auto_tunnel marker mismatch for role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );
        assert!(
            status.message.contains(
                format!(
                    "restricted_safe_mode={}",
                    if mode.restricted_safe() {
                        "true"
                    } else {
                        "false"
                    }
                )
                .as_str()
            ),
            "status restricted marker mismatch for role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );

        if role.is_blind_exit() {
            assert!(
                status.message.contains("exit_node=none"),
                "blind_exit must never report selected exit: {}",
                status.message
            );
            assert!(
                status.message.contains("serving_exit_node=true"),
                "blind_exit must always serve as exit: {}",
                status.message
            );
            assert!(
                status.message.contains("lan_access=off"),
                "blind_exit must never enable LAN access: {}",
                status.message
            );
            return;
        }

        assert!(
            status.message.contains("exit_node=node-exit"),
            "non-blind role must preserve selected exit for matrix scenario role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );

        let serving_expected = role.is_admin() && matches!(hop, RoleAuthMatrixHop::TwoHop);
        assert!(
            status.message.contains(
                format!(
                    "serving_exit_node={}",
                    if serving_expected { "true" } else { "false" }
                )
                .as_str()
            ),
            "serving_exit_node mismatch for role={} mode={} hop={}: {}",
            role.as_str(),
            mode.as_str(),
            hop.as_str(),
            status.message
        );
    }

    #[test]
    fn role_auth_matrix_runtime_is_exhaustive_and_fail_closed() {
        let roles = [NodeRole::Admin, NodeRole::Client, NodeRole::BlindExit];
        let modes = [
            RoleAuthMatrixMode::Manual,
            RoleAuthMatrixMode::AutoTunnel,
            RoleAuthMatrixMode::Restricted,
            RoleAuthMatrixMode::AutoTunnelRestricted,
        ];
        let hops = [RoleAuthMatrixHop::OneHop, RoleAuthMatrixHop::TwoHop];
        let commands = role_auth_matrix_commands();

        for role in roles {
            for mode in modes {
                for hop in hops {
                    let (mut status_runtime, status_test_dir) =
                        build_role_auth_matrix_runtime(role, mode, hop);
                    assert_role_auth_status_invariants(&mut status_runtime, role, mode, hop);
                    let _ = std::fs::remove_dir_all(status_test_dir);

                    for command in &commands {
                        let (mut runtime, test_dir) =
                            build_role_auth_matrix_runtime(role, mode, hop);
                        let response = runtime.handle_command(command.clone());
                        let observed = classify_role_auth_decision(&response);
                        let expected = expected_role_auth_decision(role, mode, command);
                        assert_eq!(
                            observed,
                            expected,
                            "role/auth matrix mismatch role={} mode={} hop={} command={} expected={:?} observed={:?} ok={} message={}",
                            role.as_str(),
                            mode.as_str(),
                            hop.as_str(),
                            command.as_wire(),
                            expected,
                            observed,
                            response.ok,
                            response.message
                        );

                        if expected == RoleAuthDecision::Allowed
                            && !matches!(
                                command,
                                IpcCommand::Unknown(_)
                                    | IpcCommand::KeyRotate
                                    | IpcCommand::KeyRevoke
                                    | IpcCommand::StateRefresh
                            )
                        {
                            assert!(
                                response.ok,
                                "allowed command should complete successfully role={} mode={} hop={} command={} message={}",
                                role.as_str(),
                                mode.as_str(),
                                hop.as_str(),
                                command.as_wire(),
                                response.message
                            );
                        }

                        let _ = std::fs::remove_dir_all(test_dir);
                    }
                }
            }
        }
    }

    #[test]
    fn validate_file_security_rejects_group_writable_parent_directory() {
        let test_dir = secure_test_dir("rustynetd-parent-mode-reject");
        let insecure_parent = test_dir.join("insecure-parent");
        std::fs::create_dir_all(&insecure_parent).expect("insecure parent should be created");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&insecure_parent, std::fs::Permissions::from_mode(0o770))
                .expect("insecure parent permissions should be set");
        }

        let secret_path = insecure_parent.join("secret.key");
        std::fs::write(&secret_path, b"secret\n").expect("secret file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .expect("secret file permissions should be set");
        }

        let err = validate_file_security(&secret_path, "test secret", 0o077, false)
            .expect_err("group-writable parent directory must be rejected");
        assert!(
            err.to_string()
                .contains("parent directory has insecure permissions"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn validate_file_security_rejects_symlink_parent_directory() {
        let test_dir = secure_test_dir("rustynetd-parent-symlink-reject");
        let real_parent = test_dir.join("real-parent");
        std::fs::create_dir_all(&real_parent).expect("real parent should be created");
        let symlink_parent = test_dir.join("symlink-parent");
        std::os::unix::fs::symlink(&real_parent, &symlink_parent)
            .expect("symlink parent should be creatable");

        let secret_path = symlink_parent.join("secret.key");
        std::fs::write(&secret_path, b"secret\n")
            .expect("secret file through symlink should write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
                .expect("secret file permissions should be set");
        }

        let err = validate_file_security(&secret_path, "test secret", 0o077, false)
            .expect_err("symlink parent directory must be rejected");
        assert!(
            err.to_string()
                .contains("parent directory must be a non-symlink directory"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn root_managed_shared_runtime_parent_policy_allows_expected_shape() {
        let expected_gid = nix::unistd::Gid::effective().as_raw();
        #[cfg(target_os = "linux")]
        assert!(is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet"),
            0o770,
            0,
            expected_gid,
            expected_gid
        ));
        #[cfg(not(target_os = "linux"))]
        assert!(!is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet"),
            0o770,
            0,
            expected_gid,
            expected_gid
        ));
        #[cfg(target_os = "linux")]
        assert!(is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet"),
            0o770,
            0,
            0,
            expected_gid
        ));
        assert!(!is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet"),
            0o775,
            0,
            expected_gid,
            expected_gid
        ));
        assert!(!is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet"),
            0o770,
            1000,
            expected_gid,
            expected_gid
        ));
        assert!(!is_root_managed_shared_runtime_parent(
            Path::new("/run/other"),
            0o770,
            0,
            expected_gid,
            expected_gid
        ));
        assert!(!is_root_managed_shared_runtime_parent(
            Path::new("/run/rustynet/wireguard.key"),
            0o770,
            0,
            expected_gid,
            expected_gid
        ));
    }

    fn write_trust_file(path: &Path, verifier_path: &Path, nonce: u64) {
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce,
        };
        write_trust_file_with_record(path, verifier_path, record);
    }

    fn write_trust_file_with_record(
        path: &Path,
        verifier_path: &Path,
        record: TrustEvidenceRecord,
    ) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("verifier key permissions should be secure");
        }
        let body = trust_evidence_payload(&record);
        let signature = signing_key.sign(body.as_bytes());
        std::fs::write(
            path,
            format!("{body}signature={}\n", hex_encode(&signature.to_bytes())),
        )
        .expect("trust file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("trust evidence permissions should be secure");
        }
    }

    fn write_auto_tunnel_file(
        path: &Path,
        verifier_path: &Path,
        node_id: &str,
        nonce: u64,
        tamper_after_sign: bool,
    ) {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("auto tunnel verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("auto tunnel verifier key permissions should be secure");
        }

        let generated = unix_now();
        let expires = generated.saturating_add(300);
        let peer_public = hex_encode(&[9u8; 32]);
        let payload = format!(
            "version=1\nnode_id={node_id}\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npeer_count=1\npeer.0.node_id=node-exit\npeer.0.endpoint=203.0.113.20:51820\npeer.0.public_key_hex={peer_public}\npeer.0.allowed_ips=100.64.0.2/32\nroute_count=1\nroute.0.destination_cidr=0.0.0.0/0\nroute.0.via_node=node-exit\nroute.0.kind=exit_default\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if tamper_after_sign {
            body = body.replace("route_count=1", "route_count=2");
        }
        std::fs::write(path, body).expect("auto tunnel file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
                .expect("auto tunnel bundle permissions should be secure");
        }
    }

    fn write_auto_tunnel_file_exitless(
        path: &Path,
        verifier_path: &Path,
        node_id: &str,
        nonce: u64,
    ) {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("auto tunnel verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("auto tunnel verifier key permissions should be secure");
        }

        let generated = unix_now();
        let expires = generated.saturating_add(300);
        let peer_public = hex_encode(&[9u8; 32]);
        let payload = format!(
            "version=1\nnode_id={node_id}\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npeer_count=1\npeer.0.node_id=node-exit\npeer.0.endpoint=203.0.113.21:51820\npeer.0.public_key_hex={peer_public}\npeer.0.allowed_ips=100.64.0.2/32\nroute_count=0\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("auto tunnel file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
                .expect("auto tunnel bundle permissions should be secure");
        }
    }

    fn write_auto_tunnel_file_two_peers(
        path: &Path,
        verifier_path: &Path,
        node_id: &str,
        nonce: u64,
    ) {
        let signing_key = SigningKey::from_bytes(&[19u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("auto tunnel verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("auto tunnel verifier key permissions should be secure");
        }

        let generated = unix_now();
        let expires = generated.saturating_add(300);
        let peer_public = hex_encode(&[9u8; 32]);
        let second_peer_public = hex_encode(&[10u8; 32]);
        let payload = format!(
            "version=1\nnode_id={node_id}\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npeer_count=2\npeer.0.node_id=node-exit\npeer.0.endpoint=203.0.113.20:51820\npeer.0.public_key_hex={peer_public}\npeer.0.allowed_ips=100.64.0.2/32,0.0.0.0/0\npeer.1.node_id=node-relay\npeer.1.endpoint=203.0.113.21:51820\npeer.1.public_key_hex={second_peer_public}\npeer.1.allowed_ips=100.64.0.3/32\nroute_count=1\nroute.0.destination_cidr=0.0.0.0/0\nroute.0.via_node=node-exit\nroute.0.kind=exit_default\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("auto tunnel file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
                .expect("auto tunnel bundle permissions should be secure");
        }
    }

    #[derive(Clone, Copy)]
    struct DnsZoneFixtureTiming {
        generated_at_unix: u64,
        ttl_secs: u64,
        tamper_after_sign: bool,
    }

    impl DnsZoneFixtureTiming {
        fn fresh(ttl_secs: u64, tamper_after_sign: bool) -> Self {
            Self {
                generated_at_unix: unix_now(),
                ttl_secs,
                tamper_after_sign,
            }
        }
    }

    #[derive(Clone, Copy)]
    struct TraversalFixtureTiming {
        generated_at_unix: u64,
        ttl_secs: u64,
        tamper_after_sign: bool,
    }

    impl TraversalFixtureTiming {
        fn fresh(ttl_secs: u64, tamper_after_sign: bool) -> Self {
            Self {
                generated_at_unix: unix_now(),
                ttl_secs,
                tamper_after_sign,
            }
        }
    }

    fn write_dns_zone_file_with_timing(
        path: &Path,
        verifier_path: &Path,
        subject_node_id: &str,
        record: (&str, &str, &[&str]),
        nonce: u64,
        timing: DnsZoneFixtureTiming,
    ) {
        let (target_node_id, expected_ip, aliases) = record;
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("dns zone verifier key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(verifier_path, std::fs::Permissions::from_mode(0o644))
                .expect("dns zone verifier key permissions should be secure");
        }

        let bundle = rustynet_dns_zone::build_signed_dns_zone_bundle(
            &signing_key,
            "rustynet",
            subject_node_id,
            timing.generated_at_unix,
            timing.ttl_secs,
            nonce,
            &[rustynet_dns_zone::DnsZoneRecordInput {
                label: "app".to_string(),
                target_node_id: target_node_id.to_string(),
                rr_type: rustynet_dns_zone::DnsRecordType::A,
                target_addr_kind: rustynet_dns_zone::DnsTargetAddrKind::MeshIpv4,
                expected_ip: expected_ip.to_string(),
                ttl_secs: timing.ttl_secs,
                aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            }],
        )
        .expect("dns zone bundle should be built");
        let mut body = rustynet_dns_zone::render_signed_dns_zone_bundle_wire(&bundle);
        if timing.tamper_after_sign {
            body = body.replace("record.0.ttl_secs=60", "record.0.ttl_secs=61");
        }
        std::fs::write(path, body).expect("dns zone file should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o640))
                .expect("dns zone bundle permissions should be secure");
        }
    }

    fn write_dns_zone_file(
        path: &Path,
        verifier_path: &Path,
        subject_node_id: &str,
        record: (&str, &str, &[&str]),
        nonce: u64,
        tamper_after_sign: bool,
    ) {
        write_dns_zone_file_with_timing(
            path,
            verifier_path,
            subject_node_id,
            record,
            nonce,
            DnsZoneFixtureTiming::fresh(60, tamper_after_sign),
        );
    }

    fn build_dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x1234_u16.to_be_bytes());
        out.extend_from_slice(&0x0100_u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        for label in name.split('.').filter(|label| !label.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    fn dns_response_rcode(response: &[u8]) -> u16 {
        u16::from_be_bytes([response[2], response[3]]) & 0x000f
    }

    fn dns_response_ancount(response: &[u8]) -> u16 {
        u16::from_be_bytes([response[6], response[7]])
    }

    fn write_traversal_file_with_srflx(
        path: &Path,
        verifier_path: &Path,
        nonce: u64,
        srflx_addr: &str,
        tamper_after_sign: bool,
    ) {
        let signing_key = SigningKey::from_bytes(&[29u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(DEFAULT_TRAVERSAL_MAX_AGE_SECS);
        let payload = format!(
            "version=1\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\npath_policy=direct_preferred_relay_allowed\ncandidate_count=3\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.10\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=900\ncandidate.1.type=srflx\ncandidate.1.addr={srflx_addr}\ncandidate.1.port=62000\ncandidate.1.family=ipv4\ncandidate.1.relay_id=\ncandidate.1.priority=850\ncandidate.2.type=relay\ncandidate.2.addr=198.51.100.40\ncandidate.2.port=51820\ncandidate.2.family=ipv4\ncandidate.2.relay_id=relay-eu-1\ncandidate.2.priority=700\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if tamper_after_sign {
            body = body.replace("candidate.2.priority=700", "candidate.2.priority=701");
        }
        std::fs::write(path, body).expect("traversal file should be written");
    }

    fn write_traversal_file_with_timing(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        timing: TraversalFixtureTiming,
    ) {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = timing.generated_at_unix;
        let expires = generated.saturating_add(timing.ttl_secs);
        let payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.77\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-1\ncandidate.1.priority=20\n"
        );
        let signature = signing_key.sign(payload.as_bytes());
        let mut body = format!(
            "{}signature={}\n",
            payload,
            hex_encode(&signature.to_bytes())
        );
        if timing.tamper_after_sign {
            body = body.replace("candidate_count=2", "candidate_count=3");
        }
        std::fs::write(path, body).expect("traversal file should be written");
    }

    fn write_traversal_file(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        tamper_after_sign: bool,
    ) {
        write_traversal_file_with_timing(
            path,
            verifier_path,
            source_node,
            target_node,
            nonce,
            TraversalFixtureTiming::fresh(60, tamper_after_sign),
        );
    }

    fn write_traversal_file_with_coordination(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        coordination_payload: &str,
    ) {
        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let bundle_payload = traversal_bundle_payload(
            source_node,
            target_node,
            nonce,
            "203.0.113.77:443".parse().expect("relay addr should parse"),
            "relay-eu-1",
            generated,
            expires,
        );
        write_signed_kv_sections(
            path,
            verifier_path,
            [23u8; 32],
            &[bundle_payload, coordination_payload.to_string()],
        );
    }

    fn write_host_only_traversal_file_with_coordination(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        coordination_payload: &str,
    ) {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let bundle_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        let bundle_signature = signing_key.sign(bundle_payload.as_bytes());
        let coordination_signature = signing_key.sign(coordination_payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n\n{}signature={}\n",
                bundle_payload,
                hex_encode(&bundle_signature.to_bytes()),
                coordination_payload,
                hex_encode(&coordination_signature.to_bytes()),
            ),
        )
        .expect("host-only traversal file should be written");
    }

    fn write_traversal_file_with_custom_relay(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        target_node: &str,
        nonce: u64,
        relay_addr: SocketAddr,
        relay_label: &str,
    ) {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr={}\ncandidate.1.port={}\ncandidate.1.family=ipv4\ncandidate.1.relay_id={relay_label}\ncandidate.1.priority=20\n",
            relay_addr.ip(),
            relay_addr.port(),
        );
        let signature = signing_key.sign(payload.as_bytes());
        std::fs::write(
            path,
            format!(
                "{}signature={}\n",
                payload,
                hex_encode(&signature.to_bytes())
            ),
        )
        .expect("custom relay traversal file should be written");
    }

    fn valid_coordination_payload_for_peer(
        local_node_id: &str,
        remote_node_id: &str,
        now_unix: u64,
        marker: u8,
    ) -> String {
        traversal_coordination_payload(
            [marker; 16],
            now_unix,
            local_node_id,
            remote_node_id,
            now_unix.saturating_sub(1),
            now_unix.saturating_add(20),
            [marker.saturating_add(1); 16],
        )
    }

    fn build_test_relay_client(
        local_node_id: &str,
        session_timeout: Duration,
        recv_timeout: Duration,
        scripted_establishments: Vec<Result<u16, RelayClientError>>,
    ) -> RelayClient {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let mut relay_client = RelayClient::new(
            NodeId::new(local_node_id.to_string()).expect("local node id should parse"),
            Arc::new(signing_key),
            RelayClientConfig {
                session_timeout,
                keepalive_interval: Duration::from_secs(25),
                max_sessions_per_peer: 2,
                recv_timeout,
                local_port: None,
            },
        );
        for result in scripted_establishments {
            relay_client.script_establish_session_result(result);
        }
        relay_client
    }

    fn relay_hello_ack_bytes(session_id: [u8; 16], allocated_port: u16) -> Vec<u8> {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&session_id);
        bytes.extend_from_slice(&allocated_port.to_be_bytes());
        bytes
    }

    fn configure_runtime_authoritative_transport(
        runtime: &mut DaemonRuntime,
        local_addr: SocketAddr,
    ) {
        runtime
            .controller
            .backend_mut_for_test()
            .configure_authoritative_shared_transport_for_test(
                local_addr,
                "daemon-test-authoritative-shared-transport",
            )
            .expect("authoritative transport should be configurable for in-memory backend");
    }

    fn script_runtime_authoritative_relay_ack(
        runtime: &mut DaemonRuntime,
        relay_addr: SocketAddr,
        local_addr: SocketAddr,
        session_id: [u8; 16],
        allocated_port: u16,
    ) {
        runtime
            .controller
            .backend_mut_for_test()
            .script_authoritative_round_trip_for_test(Ok(
                rustynet_backend_api::AuthoritativeTransportResponse {
                    local_addr,
                    remote_addr: relay_addr,
                    payload: relay_hello_ack_bytes(session_id, allocated_port),
                },
            ))
            .expect("relay authoritative round trip should be scriptable");
    }

    fn build_runtime_with_custom_relay(
        test_name: &str,
        relay_addr: SocketAddr,
        relay_label: &str,
    ) -> (DaemonRuntime, std::path::PathBuf) {
        let test_dir = secure_test_dir(test_name);
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file_with_custom_relay(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            relay_addr,
            relay_label,
        );

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path),
            auto_tunnel_watermark_path: Some(assignment_watermark_path),
            traversal_bundle_path: traversal_path,
            traversal_verifier_key_path: traversal_verifier_path,
            traversal_watermark_path,
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(15)
                .expect("test traversal handshake freshness should be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        (runtime, test_dir)
    }

    fn free_udp_port() -> u16 {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .expect("ephemeral udp port should be available");
        socket.local_addr().expect("local addr").port()
    }

    fn write_valid_userspace_shared_private_key(path: &Path) {
        std::fs::write(path, b"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n")
            .expect("valid userspace-shared private key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("userspace-shared private key permissions should be restrictive");
        }
    }

    fn build_runtime_with_linux_userspace_shared_backend(
        test_name: &str,
    ) -> (DaemonRuntime, std::path::PathBuf) {
        let relay_addr: SocketAddr = "203.0.113.33:40023".parse().expect("relay addr");
        let test_dir = secure_test_dir(test_name);
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        let private_key_path = test_dir.join("wireguard.key");

        write_trust_file(&trust_path, &trust_verifier_path, 11);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            11,
            false,
        );
        write_traversal_file_with_custom_relay(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            12,
            relay_addr,
            "relay-eu-1",
        );
        write_valid_userspace_shared_private_key(&private_key_path);

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path),
            auto_tunnel_watermark_path: Some(assignment_watermark_path),
            traversal_bundle_path: traversal_path,
            traversal_verifier_key_path: traversal_verifier_path,
            traversal_watermark_path,
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(15)
                .expect("test traversal handshake freshness should be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            traversal_stun_servers: vec![
                "127.0.0.1:3478"
                    .parse()
                    .expect("test stun server should parse"),
            ],
            backend_mode: DaemonBackendMode::LinuxWireguardUserspaceShared,
            wg_private_key_path: Some(private_key_path),
            privileged_helper_socket_path: Some(test_dir.join("privileged-helper.sock")),
            wg_listen_port: free_udp_port(),
            ..DaemonConfig::default()
        };
        let runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        (runtime, test_dir)
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn current_platform_production_backend_mode() -> DaemonBackendMode {
        #[cfg(target_os = "linux")]
        {
            DaemonBackendMode::LinuxWireguard
        }
        #[cfg(target_os = "macos")]
        {
            DaemonBackendMode::MacosWireguard
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn build_runtime_with_blocked_production_backend(
        test_name: &str,
    ) -> (DaemonRuntime, std::path::PathBuf) {
        let test_dir = secure_test_dir(test_name);
        let private_key_path = test_dir.join("wireguard.key");
        std::fs::write(&private_key_path, b"wireguard-private-key\n")
            .expect("test private key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .expect("test private key permissions should be restrictive");
        }

        let mut config = DaemonConfig {
            backend_mode: current_platform_production_backend_mode(),
            traversal_stun_servers: vec![
                "127.0.0.1:3478"
                    .parse()
                    .expect("test stun server should parse"),
            ],
            wg_private_key_path: Some(private_key_path),
            privileged_helper_socket_path: Some(test_dir.join("privileged-helper.sock")),
            ..DaemonConfig::default()
        };
        #[cfg(target_os = "macos")]
        {
            config.wg_interface = "utun9".to_string();
            config.egress_interface = "en0".to_string();
        }

        let runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        (runtime, test_dir)
    }

    fn seed_local_probe_candidate(runtime: &mut DaemonRuntime) {
        runtime.local_host_candidates.insert(
            "eth-test".to_string(),
            vec![
                "192.0.2.10"
                    .parse()
                    .expect("probe candidate ip should parse"),
            ],
        );
    }

    fn seed_local_probe_candidate_snapshot(runtime: &mut DaemonRuntime) {
        let mut snapshot = std::collections::BTreeMap::new();
        snapshot.insert(
            "eth-test".to_string(),
            vec![
                "192.0.2.10"
                    .parse()
                    .expect("probe candidate ip should parse"),
            ],
        );
        runtime.test_local_host_candidates_snapshot = Some(snapshot);
    }

    fn transient_loopback_only_candidate_snapshot() -> BTreeMap<String, Vec<IpAddr>> {
        BTreeMap::from([
            (
                "lo".to_string(),
                vec!["127.0.0.1".parse().expect("ipv4 should parse")],
            ),
            (
                "rustynet0".to_string(),
                vec!["100.109.33.213".parse().expect("ipv4 should parse")],
            ),
        ])
    }

    fn usable_probe_candidate_snapshot() -> BTreeMap<String, Vec<IpAddr>> {
        BTreeMap::from([(
            "enp0s1".to_string(),
            vec!["192.168.64.22".parse().expect("ipv4 should parse")],
        )])
    }

    #[test]
    fn traversal_host_candidate_retry_waits_for_usable_snapshot() {
        let mut snapshots = vec![
            transient_loopback_only_candidate_snapshot(),
            usable_probe_candidate_snapshot(),
        ]
        .into_iter();
        let mut waited = Vec::new();

        let collected = collect_traversal_host_candidate_snapshot_with_retry(
            || {
                snapshots
                    .next()
                    .unwrap_or_else(usable_probe_candidate_snapshot)
            },
            |duration| waited.push(duration),
            3,
        );

        assert!(snapshot_has_usable_traversal_host_candidates(&collected));
        assert_eq!(waited.len(), 1);
        assert_eq!(
            waited[0],
            Duration::from_millis(TRAVERSAL_LOCAL_HOST_CANDIDATE_RETRY_DELAY_MS)
        );
        assert_eq!(collected, usable_probe_candidate_snapshot());
    }

    #[test]
    fn traversal_host_candidate_retry_returns_last_unusable_snapshot_when_exhausted() {
        let mut snapshots = vec![
            transient_loopback_only_candidate_snapshot(),
            transient_loopback_only_candidate_snapshot(),
        ]
        .into_iter();
        let mut waited = Vec::new();

        let collected = collect_traversal_host_candidate_snapshot_with_retry(
            || {
                snapshots
                    .next()
                    .unwrap_or_else(transient_loopback_only_candidate_snapshot)
            },
            |duration| waited.push(duration),
            2,
        );

        assert!(!snapshot_has_usable_traversal_host_candidates(&collected));
        assert_eq!(waited.len(), 1);
        assert_eq!(collected, transient_loopback_only_candidate_snapshot());
    }

    fn write_traversal_file_set(
        path: &Path,
        verifier_path: &Path,
        source_node: &str,
        peers: &[(&str, &str, u16)],
        nonce: u64,
    ) {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let mut body = String::new();
        for (index, (target_node, direct_addr, direct_port)) in peers.iter().enumerate() {
            let relay_octet = 77u8.saturating_add(index as u8);
            let payload = format!(
                "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id={source_node}\ntarget_node_id={target_node}\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr={direct_addr}\ncandidate.0.port={direct_port}\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.{relay_octet}\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-{}\ncandidate.1.priority=20\n",
                index + 1
            );
            let signature = signing_key.sign(payload.as_bytes());
            body.push_str(&payload);
            body.push_str(&format!(
                "signature={}\n",
                hex_encode(&signature.to_bytes())
            ));
            if index + 1 != peers.len() {
                body.push('\n');
            }
        }
        std::fs::write(path, body).expect("traversal file set should be written");
    }

    fn write_membership_files(snapshot_path: &Path, log_path: &Path, local_node_id: &str) {
        write_membership_files_with_exit_status(
            snapshot_path,
            log_path,
            local_node_id,
            MembershipNodeStatus::Active,
        );
    }

    fn write_membership_files_with_exit_status(
        snapshot_path: &Path,
        log_path: &Path,
        local_node_id: &str,
        exit_status: MembershipNodeStatus,
    ) {
        let owner_signing = SigningKey::from_bytes(&[7; 32]);
        write_membership_files_with_nodes(
            snapshot_path,
            log_path,
            local_node_id,
            &[("node-exit", exit_status)],
            &owner_signing,
        );
    }

    fn write_membership_files_with_additional_nodes(
        snapshot_path: &Path,
        log_path: &Path,
        local_node_id: &str,
        nodes: &[(&str, MembershipNodeStatus)],
    ) {
        let owner_signing = SigningKey::from_bytes(&[7; 32]);
        write_membership_files_with_nodes(
            snapshot_path,
            log_path,
            local_node_id,
            nodes,
            &owner_signing,
        );
    }

    fn write_membership_files_with_nodes(
        snapshot_path: &Path,
        log_path: &Path,
        local_node_id: &str,
        nodes: &[(&str, MembershipNodeStatus)],
        owner_signing: &SigningKey,
    ) {
        let mut state_nodes = vec![MembershipNode {
            node_id: local_node_id.to_string(),
            node_pubkey_hex: hex_encode(&[9; 32]),
            owner: "owner@example.local".to_string(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_string()],
            joined_at_unix: 100,
            updated_at_unix: 100,
        }];
        for (index, (node_id, status)) in nodes.iter().enumerate() {
            let pubkey_byte = 11u8.saturating_add(index as u8);
            state_nodes.push(MembershipNode {
                node_id: (*node_id).to_string(),
                node_pubkey_hex: hex_encode(&[pubkey_byte; 32]),
                owner: "owner@example.local".to_string(),
                status: *status,
                roles: vec!["tag:exit".to_string()],
                joined_at_unix: 100,
                updated_at_unix: 100,
            });
        }
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-test".to_string(),
            epoch: 1,
            nodes: state_nodes,
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_string(),
                approver_pubkey_hex: hex_encode(owner_signing.verifying_key().as_bytes()),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        persist_membership_snapshot(snapshot_path, &state)
            .expect("membership snapshot should be written");
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent).expect("membership log parent should exist");
        }
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(log_path)
            .expect("membership log should be opened");
        file.write_all(b"version=1\n")
            .expect("membership log should be written");
    }

    fn secure_test_dir(prefix: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("{prefix}-{unique}"));
        std::fs::create_dir_all(&dir).expect("secure test directory should be creatable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .expect("secure test directory permissions should be set");
        }
        dir
    }

    #[test]
    fn run_daemon_rejects_in_memory_backend_mode() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let err = run_daemon(config).expect_err("in-memory backend must be rejected");
        assert!(err.to_string().contains("in-memory backend is disabled"));
    }

    #[test]
    fn validate_daemon_config_rejects_fail_closed_ssh_allow_without_cidrs() {
        let config = DaemonConfig {
            fail_closed_ssh_allow: true,
            fail_closed_ssh_allow_cidrs: Vec::new(),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("fail-closed ssh allow must require management cidrs");
        assert!(err.to_string().contains("at least one management cidr"));
    }

    #[test]
    fn validate_daemon_config_rejects_auto_port_forward_short_lease() {
        let config = DaemonConfig {
            auto_port_forward_lease_secs: NonZeroU32::new(59)
                .expect("non-zero auto port-forward lease for test"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("short auto port-forward lease should be rejected");
        assert!(err.to_string().contains("at least 60 seconds"));
    }

    #[test]
    fn validate_daemon_config_rejects_auto_port_forward_on_non_linux_backend() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::MacosWireguard,
            auto_port_forward_exit: true,
            auto_port_forward_lease_secs: NonZeroU32::new(1200)
                .expect("non-zero auto port-forward lease for test"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("auto port-forward should be linux-wireguard only");
        assert!(
            err.to_string()
                .contains("supported only with linux-wireguard backend")
        );
    }

    #[test]
    fn validate_daemon_config_accepts_linux_userspace_shared_backend() {
        let test_dir = secure_test_dir("rustynetd-validate-linux-userspace-shared");
        let private_key_path = test_dir.join("wireguard.key");
        std::fs::write(&private_key_path, b"valid-wireguard-private-key\n")
            .expect("test private key should be written");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&private_key_path, std::fs::Permissions::from_mode(0o600))
                .expect("test private key permissions should be restrictive");
        }
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::LinuxWireguardUserspaceShared,
            wg_private_key_path: Some(private_key_path),
            privileged_helper_socket_path: Some(test_dir.join("privileged-helper.sock")),
            ..DaemonConfig::default()
        };
        validate_daemon_config(&config)
            .expect("linux userspace-shared backend config should now validate");
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn validate_daemon_config_rejects_macos_userspace_shared_backend_with_precise_blocker() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::MacosWireguardUserspaceShared,
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("unimplemented macos userspace-shared backend must fail closed");
        let message = err.to_string();
        assert!(message.contains("macos-wireguard-userspace-shared backend is not implemented"));
        assert!(message.contains("backend-owned Rust userspace WireGuard engine"));
        assert!(message.contains("authoritative peer UDP socket"));
    }

    #[cfg(not(windows))]
    #[test]
    fn validate_daemon_config_rejects_windows_explicit_unsupported_backend_on_non_windows_hosts() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::WindowsUnsupported,
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("windows-unsupported backend must fail closed on non-windows hosts");
        assert!(
            err.to_string()
                .contains("backend 'windows-unsupported' is only valid on Windows daemon hosts")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_relative_traversal_paths() {
        let config = DaemonConfig {
            traversal_bundle_path: std::path::PathBuf::from("relative.traversal"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("relative traversal bundle path must be rejected");
        assert!(
            err.to_string()
                .contains("traversal bundle path must be absolute")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_relative_relay_session_signing_paths() {
        let config = DaemonConfig {
            relay_session_signing_secret_path: Some(std::path::PathBuf::from("relative.secret")),
            relay_session_signing_secret_passphrase_path: Some(std::path::PathBuf::from(
                "/tmp/relay.passphrase",
            )),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("relative relay signing secret path must be rejected");
        assert!(
            err.to_string()
                .contains("relay session signing secret path must be absolute")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_relay_session_refresh_margin_not_less_than_ttl() {
        let config = DaemonConfig {
            relay_session_token_ttl_secs: NonZeroU64::new(30)
                .expect("relay token ttl should be non-zero"),
            relay_session_refresh_margin_secs: NonZeroU64::new(30)
                .expect("relay refresh margin should be non-zero"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("relay refresh margin >= ttl must be rejected");
        assert!(
            err.to_string()
                .contains("relay session refresh margin must be less than relay session token ttl")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_remote_fetch_urls() {
        let config = DaemonConfig {
            trust_url: Some("http://127.0.0.1:8080/trust".to_string()),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("remote fetch URLs must be rejected in hardened daemon paths");
        assert!(
            err.to_string()
                .contains("remote network state fetch is disabled in hardened daemon paths")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_excessive_traversal_probe_max_candidates() {
        let config = DaemonConfig {
            traversal_probe_max_candidates: NonZeroUsize::new(MAX_TRAVERSAL_CANDIDATE_COUNT + 1)
                .expect("test value should be non-zero"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("excessive traversal probe max candidates must be rejected");
        assert!(
            err.to_string()
                .contains("traversal probe max candidates must be at most")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_excessive_traversal_probe_pair_fanout() {
        let config = DaemonConfig {
            traversal_probe_max_candidates: NonZeroUsize::new(2)
                .expect("test candidate count should be non-zero"),
            traversal_probe_max_pairs: NonZeroUsize::new(5)
                .expect("test pair count should be non-zero"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("excessive traversal probe pairs must be rejected");
        assert!(
            err.to_string()
                .contains("traversal probe max pairs must be at most 4")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_traversal_probe_freshness_above_bundle_age() {
        let config = DaemonConfig {
            traversal_max_age_secs: NonZeroU64::new(30).expect("test max age should be non-zero"),
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(31)
                .expect("test handshake freshness should be non-zero"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("traversal handshake freshness above bundle age must be rejected");
        assert!(
            err.to_string()
                .contains("traversal probe handshake freshness must not exceed traversal max age")
        );
    }

    #[test]
    fn validate_daemon_config_rejects_excessive_traversal_probe_reprobe_interval() {
        let config = DaemonConfig {
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(
                MAX_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS + 1,
            )
            .expect("test reprobe interval should be non-zero"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config)
            .expect_err("excessive traversal probe reprobe interval must be rejected");
        assert!(
            err.to_string()
                .contains("traversal probe reprobe interval must be at most")
        );
    }

    #[test]
    fn zeroize_optional_bytes_scrubs_sensitive_buffer() {
        let mut value = Some(vec![7u8, 9u8, 13u8, 17u8]);
        zeroize_optional_bytes(&mut value);
        assert_eq!(value, Some(vec![0u8, 0u8, 0u8, 0u8]));
    }

    #[test]
    fn runtime_key_prepare_requires_plaintext_key_when_encrypted_store_disabled() {
        for backend_mode in [
            DaemonBackendMode::LinuxWireguard,
            DaemonBackendMode::LinuxWireguardUserspaceShared,
        ] {
            let test_dir = secure_test_dir("rustynetd-runtime-key-prepare-plaintext");
            let runtime_key_path = test_dir.join("wireguard.key");

            let err = prepare_runtime_wireguard_key_material(
                backend_mode,
                Some(runtime_key_path.as_path()),
                None,
                None,
            )
            .expect_err("missing plaintext runtime key must be rejected");
            assert!(err.contains("wireguard private key"));

            std::fs::write(&runtime_key_path, b"private-key\n")
                .expect("runtime key should be writable");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&runtime_key_path, std::fs::Permissions::from_mode(0o600))
                    .expect("runtime key permissions should be restrictive");
            }

            prepare_runtime_wireguard_key_material(
                backend_mode,
                Some(runtime_key_path.as_path()),
                None,
                None,
            )
            .expect("existing plaintext runtime key should be accepted");

            let _ = std::fs::remove_dir_all(test_dir);
        }
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn runtime_key_prepare_decrypts_encrypted_store_for_linux_userspace_shared_backend() {
        let test_dir = secure_test_dir("rustynetd-runtime-key-prepare-userspace-encrypted");
        let runtime_key_path = test_dir.join("wireguard.key");
        let encrypted_key_path = test_dir.join("wireguard.key.enc");
        let passphrase_path = test_dir.join("wireguard.passphrase");
        let expected_runtime_key = b"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\n";

        std::fs::write(&passphrase_path, b"phase7-test-passphrase\n")
            .expect("passphrase should be writable");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&passphrase_path, std::fs::Permissions::from_mode(0o600))
                .expect("passphrase permissions should be restrictive");
        }
        encrypt_private_key(
            expected_runtime_key,
            encrypted_key_path.as_path(),
            passphrase_path.as_path(),
        )
        .expect("encrypted key should be created");

        prepare_runtime_wireguard_key_material(
            DaemonBackendMode::LinuxWireguardUserspaceShared,
            Some(runtime_key_path.as_path()),
            Some(encrypted_key_path.as_path()),
            Some(passphrase_path.as_path()),
        )
        .expect(
            "userspace-shared backend should materialize the runtime key from encrypted storage",
        );

        let actual_runtime_key =
            std::fs::read(&runtime_key_path).expect("runtime key should have been written");
        assert_eq!(actual_runtime_key, expected_runtime_key);

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn runtime_key_scrub_only_removes_ephemeral_file_when_encrypted_store_is_used() {
        for backend_mode in [
            DaemonBackendMode::LinuxWireguard,
            DaemonBackendMode::LinuxWireguardUserspaceShared,
        ] {
            let test_dir = secure_test_dir("rustynetd-runtime-key-scrub");
            let runtime_key_path = test_dir.join("wireguard.key");
            let encrypted_key_path = test_dir.join("wireguard.key.enc");
            std::fs::write(&runtime_key_path, b"private-key\n")
                .expect("runtime key should be writable");

            scrub_runtime_wireguard_key_material(
                backend_mode,
                Some(runtime_key_path.as_path()),
                None,
            )
            .expect("plaintext key mode should not scrub runtime key");
            assert!(runtime_key_path.exists());

            scrub_runtime_wireguard_key_material(
                backend_mode,
                Some(runtime_key_path.as_path()),
                Some(encrypted_key_path.as_path()),
            )
            .expect("encrypted key mode should scrub runtime key");
            assert!(!runtime_key_path.exists());

            let _ = std::fs::remove_dir_all(test_dir);
        }
    }

    #[test]
    fn trust_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-trust-watermark-round-trip");
        let watermark_path = test_dir.join("trust.watermark");
        let expected = TrustWatermark {
            updated_at_unix: 123,
            nonce: 9,
            payload_digest: Some([0x5au8; 32]),
        };
        persist_trust_watermark(&watermark_path, expected).expect("watermark should persist");
        let loaded = load_trust_watermark(&watermark_path)
            .expect("watermark should load")
            .expect("watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path).expect("watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_watermark_rejects_legacy_version_without_digest() {
        let test_dir = secure_test_dir("rustynetd-trust-watermark-v1");
        let watermark_path = test_dir.join("trust.watermark");
        std::fs::write(&watermark_path, "version=1\nupdated_at_unix=100\nnonce=7\n")
            .expect("legacy watermark should be written");
        let err = load_trust_watermark(&watermark_path)
            .expect_err("legacy watermark format must fail closed");
        assert!(matches!(err, super::TrustBootstrapError::InvalidFormat(_)));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_allows_equal_watermark_when_payload_digest_matches() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-match");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 41,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: Some(sha256_digest(trust_evidence_payload(&record).as_bytes())),
        };
        let envelope = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect("matching digest for equal watermark should be accepted");
        assert_eq!(envelope.watermark, previous);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_rejects_equal_watermark_when_payload_digest_differs() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-mismatch");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 42,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let tampered_record = TrustEvidenceRecord {
            signed_control_valid: false,
            ..record
        };
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: Some(sha256_digest(
                trust_evidence_payload(&tampered_record).as_bytes(),
            )),
        };
        let err = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect_err("mismatched digest for equal watermark must be rejected");
        assert!(matches!(err, super::TrustBootstrapError::ReplayDetected));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_trust_evidence_rejects_equal_watermark_when_legacy_digest_missing() {
        let test_dir = secure_test_dir("rustynetd-trust-evidence-equal-legacy");
        let trust_path = test_dir.join("trust.evidence");
        let verifier_path = test_dir.join("trust.verifier.pub");
        let record = TrustEvidenceRecord {
            tls13_valid: true,
            signed_control_valid: true,
            signed_data_age_secs: 0,
            clock_skew_secs: 0,
            updated_at_unix: unix_now(),
            nonce: 43,
        };
        write_trust_file_with_record(&trust_path, &verifier_path, record);
        let previous = TrustWatermark {
            updated_at_unix: record.updated_at_unix,
            nonce: record.nonce,
            payload_digest: None,
        };
        let err = load_trust_evidence(
            &trust_path,
            &verifier_path,
            TrustPolicy::default(),
            Some(previous),
        )
        .expect_err("legacy equal watermark without digest must fail closed");
        assert!(matches!(err, super::TrustBootstrapError::ReplayDetected));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn auto_tunnel_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-round-trip");
        let watermark_path = test_dir.join("assignment.watermark");
        let expected = AutoTunnelWatermark {
            generated_at_unix: 100,
            nonce: 9,
            payload_digest: Some([0x33u8; 32]),
        };
        persist_auto_tunnel_watermark(&watermark_path, expected)
            .expect("auto tunnel watermark should persist");
        let loaded = load_auto_tunnel_watermark(&watermark_path)
            .expect("auto tunnel watermark should load")
            .expect("auto tunnel watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path)
            .expect("auto tunnel watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_watermark_rejects_legacy_version_without_digest() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-v1");
        let watermark_path = test_dir.join("assignment.watermark");
        std::fs::write(
            &watermark_path,
            "version=1\ngenerated_at_unix=10\nnonce=2\n",
        )
        .expect("legacy auto tunnel watermark should be written");
        let err = load_auto_tunnel_watermark(&watermark_path)
            .expect_err("legacy auto tunnel watermark format must fail closed");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_allows_equal_watermark_when_payload_digest_matches() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-equal-match");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            7,
            false,
        );
        let first = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect("first auto tunnel load should succeed");
        let second = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            Some(first.watermark),
        )
        .expect("equal watermark should be accepted when digest matches");
        assert_eq!(second.watermark, first.watermark);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_equal_watermark_when_payload_digest_differs() {
        let test_dir = secure_test_dir("rustynetd-auto-watermark-equal-mismatch");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            8,
            false,
        );
        let envelope = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect("first auto tunnel load should succeed");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            Some(AutoTunnelWatermark {
                generated_at_unix: envelope.watermark.generated_at_unix,
                nonce: envelope.watermark.nonce,
                payload_digest: Some([0x44u8; 32]),
            }),
        )
        .expect_err("equal watermark with mismatched payload digest must fail");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::ReplayDetected
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn traversal_watermark_round_trip_persists_payload_digest() {
        let test_dir = secure_test_dir("rustynetd-traversal-watermark-round-trip");
        let watermark_path = test_dir.join("traversal.watermark");
        let expected = super::TraversalWatermark {
            generated_at_unix: 200,
            nonce: 13,
            payload_digest: Some([0x55u8; 32]),
        };
        persist_traversal_watermark(&watermark_path, expected)
            .expect("traversal watermark should persist");
        let loaded = load_traversal_watermark(&watermark_path)
            .expect("traversal watermark should load")
            .expect("traversal watermark should exist");
        assert_eq!(loaded, expected);
        let raw = std::fs::read_to_string(&watermark_path)
            .expect("traversal watermark file should exist");
        assert!(raw.contains("version=2"));
        assert!(raw.contains("payload_digest_sha256="));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_rejects_tampered_signature_and_replay() {
        let test_dir = secure_test_dir("rustynetd-traversal-tamper-replay");
        let traversal_path = test_dir.join("traversal.bundle");
        let verifier_path = test_dir.join("traversal.verifier.pub");

        write_traversal_file(&traversal_path, &verifier_path, "node-a", "node-b", 1, true);
        let tampered = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("tampered traversal bundle must fail signature verification");
        assert!(matches!(
            tampered,
            super::TraversalBootstrapError::SignatureInvalid
        ));

        write_traversal_file(
            &traversal_path,
            &verifier_path,
            "node-a",
            "node-b",
            2,
            false,
        );
        let first = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("first traversal bundle load should succeed");
        let replay = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            Some(super::TraversalWatermark {
                generated_at_unix: first.watermark.generated_at_unix,
                nonce: first.watermark.nonce,
                payload_digest: Some([0x42u8; 32]),
            }),
        )
        .expect_err("equal traversal watermark with mismatched digest must fail");
        assert!(matches!(
            replay,
            super::TraversalBootstrapError::ReplayDetected
        ));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn artifact_limitgate_rejects_oversized_bundle_files() {
        let test_dir = secure_test_dir("rustynetd-artifact-limit-oversized");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 17);
        std::fs::write(&trust_path, vec![b'a'; MAX_TRUST_EVIDENCE_BYTES + 1])
            .expect("oversized trust evidence should be writable");
        let trust_err = load_trust_evidence(
            &trust_path,
            &trust_verifier_path,
            TrustPolicy::default(),
            None,
        )
        .expect_err("oversized trust evidence must fail closed");
        assert!(matches!(
            trust_err,
            super::TrustBootstrapError::InvalidFormat(_)
        ));
        assert!(trust_err.to_string().contains("exceeds maximum size"));

        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            18,
            false,
        );
        std::fs::write(
            &assignment_path,
            vec![b'b'; MAX_AUTO_TUNNEL_BUNDLE_BYTES + 1],
        )
        .expect("oversized auto-tunnel bundle should be writable");
        let assignment_err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("oversized auto-tunnel bundle must fail closed");
        assert!(matches!(
            assignment_err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(assignment_err.to_string().contains("exceeds maximum size"));

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            19,
            false,
        );
        std::fs::write(&traversal_path, vec![b'c'; MAX_TRAVERSAL_BUNDLE_BYTES + 1])
            .expect("oversized traversal bundle should be writable");
        let traversal_err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("oversized traversal bundle must fail closed");
        assert!(matches!(
            traversal_err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(traversal_err.to_string().contains("exceeds maximum size"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay() {
        let test_dir = secure_test_dir("rustynetd-traversal-adversarial-gate");
        let traversal_path = test_dir.join("traversal.bundle");
        let verifier_path = test_dir.join("traversal.verifier.pub");

        write_traversal_file(
            &traversal_path,
            &verifier_path,
            "node-a",
            "node-b",
            100,
            true,
        );
        let forged_err = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("forged traversal hint must be rejected");
        assert!(matches!(
            forged_err,
            super::TraversalBootstrapError::SignatureInvalid
        ));

        let wrong_signer_generated = unix_now();
        let wrong_signer_expires = wrong_signer_generated.saturating_add(60);
        let wrong_signer_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={wrong_signer_generated}\nexpires_at_unix={wrong_signer_expires}\nnonce=101\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.77\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-1\ncandidate.1.priority=20\n"
        );
        write_signed_kv_artifact_with_verifier_seed(
            &traversal_path,
            &verifier_path,
            [31u8; 32],
            [32u8; 32],
            wrong_signer_payload.as_str(),
        );
        let wrong_signer_err = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("wrong-signer traversal hint must be rejected");
        assert!(matches!(
            wrong_signer_err,
            super::TraversalBootstrapError::SignatureInvalid
        ));

        let stale_generated = unix_now().saturating_sub(DEFAULT_TRAVERSAL_MAX_AGE_SECS + 15);
        let stale_expires = stale_generated.saturating_add(1);
        let stale_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={stale_generated}\nexpires_at_unix={stale_expires}\nnonce=102\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &verifier_path,
            [33u8; 32],
            stale_payload.as_str(),
        );
        let stale_err = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("stale traversal hint must be rejected");
        assert!(matches!(stale_err, super::TraversalBootstrapError::Stale));

        let replay_generated = unix_now();
        let replay_expires = replay_generated.saturating_add(60);
        let replay_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={replay_generated}\nexpires_at_unix={replay_expires}\nnonce=200\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &verifier_path,
            [34u8; 32],
            replay_payload.as_str(),
        );
        let baseline = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("baseline traversal hint should be accepted");

        let replay_nonce_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={replay_generated}\nexpires_at_unix={replay_expires}\nnonce=199\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &verifier_path,
            [34u8; 32],
            replay_nonce_payload.as_str(),
        );
        let replay_err = load_traversal_bundle(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            Some(baseline.watermark),
        )
        .expect_err("nonce replay traversal hint must be rejected");
        assert!(matches!(
            replay_err,
            super::TraversalBootstrapError::ReplayDetected
        ));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn traversal_bundle_set_accepts_signed_coordination_and_rejects_malformed_section() {
        let test_dir = secure_test_dir("rustynetd-traversal-coordination-ingestion");
        let traversal_path = test_dir.join("traversal.bundle");
        let verifier_path = test_dir.join("traversal.verifier.pub");

        let valid_coordination =
            valid_coordination_payload_for_peer("node-a", "node-b", unix_now(), 0x31);
        write_traversal_file_with_coordination(
            &traversal_path,
            &verifier_path,
            "node-a",
            "node-b",
            300,
            &valid_coordination,
        );
        let envelope = load_traversal_bundle_set(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("mixed traversal bundle should load");
        assert_eq!(envelope.bundles.len(), 1);
        assert_eq!(envelope.coordinations.len(), 1);
        assert_eq!(envelope.coordinations[0].record.node_a, "node-a");
        assert_eq!(envelope.coordinations[0].record.node_b, "node-b");

        let malformed_coordination = format!(
            "version=1\ntype=traversal_coordination\nsession_id={}\nprobe_start_unix={}\nnode_a=node-a\nissued_at_unix={}\nexpires_at_unix={}\nnonce={}\n",
            hex_encode(&[0x33; 16]),
            unix_now(),
            unix_now(),
            unix_now().saturating_add(20),
            hex_encode(&[0x44; 16]),
        );
        write_traversal_file_with_coordination(
            &traversal_path,
            &verifier_path,
            "node-a",
            "node-b",
            301,
            &malformed_coordination,
        );
        let err = load_traversal_bundle_set(
            &traversal_path,
            &verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("malformed coordination section must fail closed");
        assert!(matches!(
            err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn artifact_limitgate_rejects_count_overflow_for_assignment_and_traversal() {
        let test_dir = secure_test_dir("rustynetd-artifact-limit-count-overflow");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let now = unix_now();
        let expires = now.saturating_add(300);

        let oversized_peer_payload = format!(
            "version=1\nnode_id=daemon-local\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=21\npeer_count={}\nroute_count=0\n",
            MAX_AUTO_TUNNEL_PEER_COUNT + 1
        );
        write_signed_kv_artifact(
            &assignment_path,
            &assignment_verifier_path,
            [61u8; 32],
            &oversized_peer_payload,
        );
        let peer_err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("peer_count overflow must fail closed");
        assert!(matches!(
            peer_err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(peer_err.to_string().contains("peer_count exceeds maximum"));

        let oversized_route_payload = format!(
            "version=1\nnode_id=daemon-local\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=22\npeer_count=0\nroute_count={}\n",
            MAX_AUTO_TUNNEL_ROUTE_COUNT + 1
        );
        write_signed_kv_artifact(
            &assignment_path,
            &assignment_verifier_path,
            [62u8; 32],
            &oversized_route_payload,
        );
        let route_err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("route_count overflow must fail closed");
        assert!(matches!(
            route_err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(
            route_err
                .to_string()
                .contains("route_count exceeds maximum")
        );

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=23\ncandidate_count={}\n",
            MAX_TRAVERSAL_CANDIDATE_COUNT + 1
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [63u8; 32],
            &traversal_payload,
        );
        let candidate_err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("candidate_count overflow must fail closed");
        assert!(matches!(
            candidate_err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(
            candidate_err
                .to_string()
                .contains("candidate_count must be between")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn artifact_limitgate_rejects_excessive_key_depth() {
        let test_dir = secure_test_dir("rustynetd-artifact-limit-key-depth");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let now = unix_now();
        let expires = now.saturating_add(300);
        let assignment_payload = format!(
            "version=1\nnode_id=daemon-local\nmesh_cidr=100.64.0.0/10\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=24\npeer_count=0\nroute_count=0\npeer.0.extra.deep=value\n"
        );
        write_signed_kv_artifact(
            &assignment_path,
            &assignment_verifier_path,
            [64u8; 32],
            &assignment_payload,
        );
        let assignment_err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("auto-tunnel key depth overflow must fail closed");
        assert!(matches!(
            assignment_err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(
            assignment_err
                .to_string()
                .contains("key depth exceeds maximum")
        );

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce=25\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.3\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=20\ncandidate.0.extra.deep=value\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [65u8; 32],
            &traversal_payload,
        );
        let traversal_err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("traversal key depth overflow must fail closed");
        assert!(matches!(
            traversal_err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(
            traversal_err
                .to_string()
                .contains("key depth exceeds maximum")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn artifact_fuzzgate_rejects_rollback_generations_fail_closed() {
        let test_dir = secure_test_dir("rustynetd-artifact-fuzzgate-rollback");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 31);
        let trust_envelope = load_trust_evidence(
            &trust_path,
            &trust_verifier_path,
            TrustPolicy::default(),
            None,
        )
        .expect("first trust load should succeed");
        let trust_rollback = load_trust_evidence(
            &trust_path,
            &trust_verifier_path,
            TrustPolicy::default(),
            Some(TrustWatermark {
                updated_at_unix: trust_envelope.watermark.updated_at_unix.saturating_add(1),
                nonce: trust_envelope.watermark.nonce.saturating_add(1),
                payload_digest: Some([0x11u8; 32]),
            }),
        )
        .expect_err("trust rollback must fail closed");
        assert!(matches!(
            trust_rollback,
            super::TrustBootstrapError::ReplayDetected
        ));

        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            32,
            false,
        );
        let assignment_envelope = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect("first assignment load should succeed");
        let assignment_rollback = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            Some(AutoTunnelWatermark {
                generated_at_unix: assignment_envelope
                    .watermark
                    .generated_at_unix
                    .saturating_add(1),
                nonce: assignment_envelope.watermark.nonce.saturating_add(1),
                payload_digest: Some([0x22u8; 32]),
            }),
        )
        .expect_err("assignment rollback must fail closed");
        assert!(matches!(
            assignment_rollback,
            super::AutoTunnelBootstrapError::ReplayDetected
        ));

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            33,
            false,
        );
        let traversal_envelope = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("first traversal load should succeed");
        let traversal_rollback = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            Some(super::TraversalWatermark {
                generated_at_unix: traversal_envelope
                    .watermark
                    .generated_at_unix
                    .saturating_add(1),
                nonce: traversal_envelope.watermark.nonce.saturating_add(1),
                payload_digest: Some([0x33u8; 32]),
            }),
        )
        .expect_err("traversal rollback must fail closed");
        assert!(matches!(
            traversal_rollback,
            super::TraversalBootstrapError::ReplayDetected
        ));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn artifact_fuzzgate_bundle_parsers_never_panic_and_fail_closed() {
        let test_dir = secure_test_dir("rustynetd-artifact-fuzzgate-no-panic");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 41);
        let trust_cases = vec![
            Vec::new(),
            b"version=2\n".to_vec(),
            b"version=2\nnonce=abc\n".to_vec(),
            b"version=2\ntls13_valid=true\nsigned_control_valid=true\nsigned_data_age_secs=0\nclock_skew_secs=0\nupdated_at_unix=1\nnonce=1\nsignature=zz\n".to_vec(),
            vec![0xff, 0xfe, 0xfd],
        ];
        for payload in trust_cases {
            std::fs::write(&trust_path, payload).expect("trust fuzz payload should be writable");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                load_trust_evidence(
                    &trust_path,
                    &trust_verifier_path,
                    TrustPolicy::default(),
                    None,
                )
            }));
            assert!(outcome.is_ok(), "trust parser must never panic");
            assert!(
                outcome.expect("panic already asserted absent").is_err(),
                "trust parser must fail closed on malformed input"
            );
        }

        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            42,
            false,
        );
        let assignment_cases = vec![
            Vec::new(),
            b"version=1\nnode_id=daemon-local\n".to_vec(),
            b"version=1\nnode_id=daemon-local\nmesh_cidr=bad\nassigned_cidr=100.64.0.1/32\ngenerated_at_unix=1\nexpires_at_unix=2\nnonce=1\npeer_count=0\nroute_count=0\nsignature=abcd\n".to_vec(),
            vec![0x80, 0x81, 0x82],
        ];
        for payload in assignment_cases {
            std::fs::write(&assignment_path, payload)
                .expect("assignment fuzz payload should be writable");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                load_auto_tunnel_bundle(
                    &assignment_path,
                    &assignment_verifier_path,
                    300,
                    TrustPolicy::default(),
                    None,
                )
            }));
            assert!(outcome.is_ok(), "auto-tunnel parser must never panic");
            assert!(
                outcome.expect("panic already asserted absent").is_err(),
                "auto-tunnel parser must fail closed on malformed input"
            );
        }

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            43,
            false,
        );
        let traversal_cases = vec![
            Vec::new(),
            b"version=1\npath_policy=direct_preferred_relay_allowed\n".to_vec(),
            b"version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix=1\nexpires_at_unix=2\nnonce=1\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=0.0.0.0\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=1\nsignature=abcd\n".to_vec(),
            vec![0x90, 0x91, 0x92],
        ];
        for payload in traversal_cases {
            std::fs::write(&traversal_path, payload)
                .expect("traversal fuzz payload should be writable");
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                load_traversal_bundle(
                    &traversal_path,
                    &traversal_verifier_path,
                    DEFAULT_TRAVERSAL_MAX_AGE_SECS,
                    TrustPolicy::default(),
                    None,
                )
            }));
            assert!(outcome.is_ok(), "traversal parser must never panic");
            assert!(
                outcome.expect("panic already asserted absent").is_err(),
                "traversal parser must fail closed on malformed input"
            );
        }

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn netcheck_reports_structured_traversal_diagnostics() {
        let test_dir = secure_test_dir("rustynetd-netcheck-traversal-diagnostics");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.pub");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            5,
            false,
        );

        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::InMemory,
            node_id: "daemon-local".to_string(),
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            membership_snapshot_path,
            membership_log_path,
            auto_tunnel_enforce: false,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should initialize");
        runtime.traversal_bundle_path = traversal_path;
        runtime.traversal_verifier_key_path = traversal_verifier_path;
        runtime.traversal_watermark_path = traversal_watermark_path;
        runtime.refresh_traversal_hint_state(true);
        let output = runtime.netcheck_response_line();
        assert!(output.contains("path_mode=initializing"));
        assert!(output.contains("traversal_status=valid"));
        assert!(output.contains("candidate_count=2"));
        assert!(output.contains("host_candidates=1"));
        assert!(output.contains("relay_candidates=1"));
        assert!(output.contains("srflx_candidates=0"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn parse_route_interface_token_handles_linux_and_macos_output() {
        assert_eq!(
            parse_route_interface_token(
                "default via 192.168.1.1 dev enp0s3 proto dhcp src 192.168.1.10"
            ),
            Some("enp0s3")
        );
        assert_eq!(parse_route_interface_token("interface: en0"), Some("en0"));
    }

    #[test]
    fn resolve_egress_interface_value_uses_detector_only_for_auto() {
        let explicit =
            resolve_egress_interface_value("wlp2s0", || Err("detector should not run".to_string()))
                .expect("explicit interface should be preserved");
        assert_eq!(explicit, "wlp2s0");

        let detected =
            resolve_egress_interface_value(DEFAULT_EGRESS_INTERFACE, || Ok("enp0s8".to_string()))
                .expect("auto interface should use detector");
        assert_eq!(detected, "enp0s8");
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_probe_falls_back_to_relay_without_handshake_evidence() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-authority-override");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x41);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            traversal_probe_max_candidates: NonZeroUsize::new(4)
                .expect("test traversal probe max candidates should be non-zero"),
            traversal_probe_max_pairs: NonZeroUsize::new(4)
                .expect("test traversal probe max pairs should be non-zero"),
            traversal_probe_simultaneous_open_rounds: NonZeroU8::new(2)
                .expect("test traversal probe rounds should be non-zero"),
            traversal_probe_round_spacing_ms: NonZeroU64::new(40)
                .expect("test traversal probe round spacing should be non-zero"),
            traversal_probe_relay_switch_after_failures: NonZeroU8::new(2)
                .expect("test traversal relay switch threshold should be non-zero"),
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(15)
                .expect("test traversal handshake freshness should be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();
        runtime.controller.set_stability_windows(0, 0);
        runtime.local_stun_observations = vec![StunResult {
            mapped_endpoint: "198.51.100.20:61000"
                .parse()
                .expect("mapped endpoint should parse"),
            server: "198.51.100.1:3478".parse().expect("server should parse"),
            local_addr: "0.0.0.0:49152".parse().expect("local addr should parse"),
        }];
        runtime.local_stun_candidates = runtime
            .local_stun_observations
            .iter()
            .map(|result| result.mapped_endpoint)
            .collect();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(SocketEndpoint {
                addr: "203.0.113.77".parse().expect("ipv4 should parse"),
                port: 443,
            })
        );
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(crate::phase10::PathMode::Relay)
        );

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("path_mode=relay_programmed"));
        assert!(
            status
                .message
                .contains("path_reason=relay_session_disabled")
        );
        assert!(
            status
                .message
                .contains("path_programmed_mode=relay_programmed")
        );
        assert!(
            status
                .message
                .contains("path_programmed_reason=relay_endpoint_programmed")
        );
        assert!(status.message.contains("path_live_proven=false"));
        assert!(status.message.contains("relay_session_state=disabled"));
        assert!(
            status
                .message
                .contains("stun_candidate_local_addrs=0.0.0.0:49152")
        );
        assert!(
            status
                .message
                .contains("stun_transport_port_binding=all_mismatch_wg_listen_port")
        );
        assert!(status.message.contains("traversal_authority=enforced_v1"));
        assert!(status.message.contains("traversal_probe_max_candidates=4"));
        assert!(status.message.contains("traversal_probe_max_pairs=4"));
        assert!(status.message.contains("traversal_probe_rounds=2"));
        assert!(
            status
                .message
                .contains("traversal_probe_round_spacing_ms=40")
        );
        assert!(
            status
                .message
                .contains("traversal_probe_relay_switch_after_failures=2")
        );
        assert!(
            status
                .message
                .contains("traversal_probe_handshake_freshness_secs=15")
        );
        assert!(
            status
                .message
                .contains("traversal_probe_reprobe_interval_secs=60")
        );
        assert!(status.message.contains("traversal_probe_result=relay"));
        assert!(
            status
                .message
                .contains("traversal_probe_reason=direct_probe_exhausted_relay_armed")
        );
        assert!(
            !status
                .message
                .contains("traversal_probe_next_reprobe_unix=none")
        );
        assert!(status.message.contains("exit_node=node-exit"));
        assert!(
            status
                .message
                .contains("selected_exit_peer_endpoint=203.0.113.77:443")
        );
        assert!(
            status
                .message
                .contains("selected_exit_peer_endpoint_error=none")
        );

        let refreshed_coordination =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x42);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            &refreshed_coordination,
        );
        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=relay_programmed"));
        assert!(
            netcheck
                .message
                .contains("path_reason=relay_session_disabled")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_mode=relay_programmed")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_reason=relay_endpoint_programmed")
        );
        assert!(netcheck.message.contains("path_live_proven=false"));
        assert!(netcheck.message.contains("relay_session_state=disabled"));
        assert!(
            netcheck
                .message
                .contains("stun_candidate_local_addrs=0.0.0.0:49152")
        );
        assert!(
            netcheck
                .message
                .contains("stun_transport_port_binding=all_mismatch_wg_listen_port")
        );
        assert!(netcheck.message.contains("traversal_authority=enforced_v1"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_max_candidates=4")
        );
        assert!(netcheck.message.contains("traversal_probe_max_pairs=4"));
        assert!(netcheck.message.contains("traversal_probe_rounds=2"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_round_spacing_ms=40")
        );
        assert!(
            netcheck
                .message
                .contains("traversal_probe_relay_switch_after_failures=2")
        );
        assert!(
            netcheck
                .message
                .contains("traversal_probe_handshake_freshness_secs=15")
        );
        assert!(
            netcheck
                .message
                .contains("traversal_probe_reprobe_interval_secs=60")
        );
        assert!(netcheck.message.contains("traversal_probe_result=relay"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_reason=direct_probe_exhausted_relay_armed")
        );
        assert!(
            !netcheck
                .message
                .contains("traversal_probe_next_reprobe_unix=none")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_client_upgrades_relay_candidate_endpoint() {
        let relay_addr: SocketAddr = "203.0.113.10:40000".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-client-upgrade",
            relay_addr,
            "relay-eu-1",
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            vec![Ok(61_001)],
        ));

        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let expected_endpoint = SocketEndpoint {
            addr: relay_addr.ip(),
            port: 61_001,
        };
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay),
            "controller_state={:?} traversal_hint_error={:?} bootstrap_error={:?}",
            runtime.controller.state(),
            runtime.traversal_hint_error,
            runtime.bootstrap_error
        );
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(expected_endpoint)
        );
        assert_eq!(
            runtime
                .traversal_probe_statuses
                .get(&exit_node)
                .expect("relay traversal status should exist")
                .selected_endpoint,
            expected_endpoint
        );
        assert!(
            runtime
                .relay_client
                .as_ref()
                .expect("relay client should be configured")
                .has_session(&exit_node)
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap() {
        let relay_addr: SocketAddr = "203.0.113.16:40006".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-transport-identity-blocked",
            relay_addr,
            "relay-eu-1",
        );
        runtime.transport_socket_identity_blocker =
            Some("authoritative backend udp socket unavailable".to_string());
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            vec![Ok(61_013)],
        ));

        runtime.bootstrap();

        assert_eq!(runtime.controller.state(), DataplaneState::FailClosed);
        assert!(
            runtime
                .traversal_hint_error
                .as_deref()
                .expect("blocked relay bootstrap should record traversal error")
                .contains("validated signed traversal coordination required for direct probe")
        );

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("relay_session_configured=true"));
        assert!(
            status
                .message
                .contains("relay_session_state=blocked_transport_identity")
        );
        assert!(
            status
                .message
                .contains("transport_socket_identity_state=blocked_backend_opaque_socket")
        );
        assert!(status.message.contains(
            "transport_socket_identity_error=authoritative_backend_udp_socket_unavailable"
        ));
        assert!(
            !runtime
                .relay_client
                .as_ref()
                .expect("relay client should remain configured")
                .has_session(&NodeId::new("node-exit").expect("test node id should parse"))
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_transport_socket_identity_blocker_rejects_bound_relay_side_socket() {
        let relay_addr: SocketAddr = "203.0.113.26:40016".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-transport-bound-side-socket-blocked",
            relay_addr,
            "relay-eu-1",
        );
        runtime.transport_socket_identity_blocker =
            Some("authoritative backend udp socket unavailable".to_string());
        let mut relay_client = build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            vec![Ok(61_023)],
        );
        relay_client.set_bound_for_test(true);
        assert!(relay_client.is_bound());
        runtime.relay_client = Some(relay_client);

        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(
            status
                .message
                .contains("relay_session_state=blocked_transport_identity")
        );
        assert!(
            !runtime
                .relay_client
                .as_ref()
                .expect("relay client should remain configured")
                .has_session(&NodeId::new("node-exit").expect("test node id should parse"))
        );

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(
            netcheck
                .message
                .contains("relay_session_state=blocked_transport_identity")
        );
        assert!(
            netcheck
                .message
                .contains("transport_socket_identity_state=blocked_backend_opaque_socket")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker() {
        let (runtime, test_dir) = build_runtime_with_blocked_production_backend(
            "rustynetd-runtime-production-backend-transport-identity-blocked",
        );

        assert!(
            runtime.transport_socket_identity_blocker.is_some(),
            "production backend should report an authoritative transport blocker"
        );
        assert!(
            runtime.next_stun_refresh_at.is_none(),
            "daemon must not schedule authoritative STUN refresh when backend transport is opaque"
        );
        assert_eq!(
            runtime.transport_socket_identity_state(),
            "blocked_backend_opaque_socket"
        );
        assert_eq!(runtime.local_stun_candidates.len(), 0);
        assert_eq!(runtime.stun_candidate_local_addrs(), "none");

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state() {
        let (mut runtime, test_dir) = build_runtime_with_linux_userspace_shared_backend(
            "rustynetd-runtime-linux-userspace-shared-authoritative-transport",
        );

        runtime
            .controller
            .backend_mut_for_test()
            .start(RuntimeContext {
                local_node: NodeId::new("daemon-local").expect("test node id should parse"),
                interface_name: runtime.wg_interface.clone(),
                mesh_cidr: "100.64.0.0/10".to_string(),
                local_cidr: "100.64.0.1/32".to_string(),
            })
            .expect("linux userspace-shared backend should start");

        assert_eq!(
            runtime.transport_socket_identity_state(),
            "authoritative_backend_shared_transport"
        );
        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(
            status
                .message
                .contains("transport_socket_identity_state=authoritative_backend_shared_transport")
        );
        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(
            netcheck
                .message
                .contains("transport_socket_identity_state=authoritative_backend_shared_transport")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_authoritative_stun_refresh_uses_backend_shared_transport_identity() {
        let relay_addr: SocketAddr = "203.0.113.31:40021".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-authoritative-stun-shared-transport",
            relay_addr,
            "relay-eu-1",
        );
        let authoritative_local_addr: SocketAddr =
            "0.0.0.0:51820".parse().expect("local addr should parse");
        let stun_server: SocketAddr = "198.51.100.1:3478"
            .parse()
            .expect("stun server should parse");
        let mapped_endpoint: SocketAddr = "198.51.100.24:62000"
            .parse()
            .expect("mapped endpoint should parse");

        configure_runtime_authoritative_transport(&mut runtime, authoritative_local_addr);
        runtime.traversal_probe_config.stun_servers = vec![stun_server];
        runtime.next_stun_refresh_at = Some(Instant::now());
        runtime
            .controller
            .backend_mut_for_test()
            .script_authoritative_stun_round_trip_for_test(stun_server, mapped_endpoint)
            .expect("stun authoritative round trip should be scriptable");

        runtime.bootstrap();
        runtime.poll_stun_results();

        assert_eq!(runtime.local_stun_candidates, vec![mapped_endpoint]);
        assert_eq!(runtime.stun_candidate_local_addrs(), "0.0.0.0:51820");
        assert_eq!(
            runtime.transport_socket_identity_state(),
            "authoritative_backend_shared_transport"
        );
        let operations = runtime
            .controller
            .backend_mut_for_test()
            .authoritative_transport_operations_for_test();
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].local_addr, authoritative_local_addr);
        assert_eq!(operations[0].remote_addr, stun_server);

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(
            netcheck
                .message
                .contains("transport_socket_identity_state=authoritative_backend_shared_transport")
        );
        assert!(
            netcheck
                .message
                .contains("transport_socket_identity_local_addr=0.0.0.0:51820")
        );
        assert!(
            netcheck
                .message
                .contains("stun_candidates=198.51.100.24:62000")
        );
        assert!(
            netcheck
                .message
                .contains("stun_candidate_local_addrs=0.0.0.0:51820")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_establish_and_keepalive_use_backend_shared_transport_identity() {
        let relay_addr: SocketAddr = "203.0.113.32:40022".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-authoritative-relay-shared-transport",
            relay_addr,
            "relay-eu-1",
        );
        let authoritative_local_addr: SocketAddr =
            "0.0.0.0:51820".parse().expect("local addr should parse");
        let allocated_port = 61_044;
        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");

        configure_runtime_authoritative_transport(&mut runtime, authoritative_local_addr);
        script_runtime_authoritative_relay_ack(
            &mut runtime,
            relay_addr,
            authoritative_local_addr,
            [0x44; 16],
            allocated_port,
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            Vec::new(),
        ));

        runtime.bootstrap();
        runtime
            .relay_client
            .as_mut()
            .expect("relay client should be configured")
            .set_session_last_activity_for_test(
                &exit_node,
                Instant::now() - Duration::from_secs(60),
            );
        runtime
            .controller
            .backend_mut_for_test()
            .script_authoritative_send_result_for_test(Ok(()))
            .expect("relay authoritative keepalive send should be scriptable");

        runtime
            .sync_traversal_runtime_state(false)
            .expect("relay runtime sync should succeed");

        let operations = runtime
            .controller
            .backend_mut_for_test()
            .authoritative_transport_operations_for_test();
        assert_eq!(operations.len(), 2);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].local_addr, authoritative_local_addr);
        assert_eq!(operations[0].remote_addr, relay_addr);
        assert_eq!(
            operations[1].kind,
            RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(operations[1].local_addr, authoritative_local_addr);
        assert_eq!(
            operations[1].remote_addr,
            SocketAddr::new(relay_addr.ip(), allocated_port)
        );
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(SocketEndpoint {
                addr: relay_addr.ip(),
                port: allocated_port,
            })
        );

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(
            status
                .message
                .contains("transport_socket_identity_state=authoritative_backend_shared_transport")
        );
        assert!(
            status
                .message
                .contains("transport_socket_identity_local_addr=0.0.0.0:51820")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_session_is_programmed_but_not_live_without_fresh_handshake() {
        let relay_addr: SocketAddr = "203.0.113.13:40003".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-session-unproven",
            relay_addr,
            "relay-eu-1",
        );
        let authoritative_local_addr: SocketAddr =
            "0.0.0.0:51820".parse().expect("local addr should parse");
        configure_runtime_authoritative_transport(&mut runtime, authoritative_local_addr);
        script_runtime_authoritative_relay_ack(
            &mut runtime,
            relay_addr,
            authoritative_local_addr,
            [0x10; 16],
            61_010,
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            Vec::new(),
        ));

        runtime.bootstrap();

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=relay_programmed"));
        assert!(
            netcheck
                .message
                .contains("path_reason=relay_handshake_unproven")
        );
        assert!(netcheck.message.contains("path_live_proven=false"));
        assert!(
            netcheck
                .message
                .contains("relay_session_state=established_unproven")
        );
        assert!(
            netcheck
                .message
                .contains("relay_session_established_peers=1")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake() {
        let relay_addr: SocketAddr = "203.0.113.14:40004".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-session-live",
            relay_addr,
            "relay-eu-1",
        );
        let authoritative_local_addr: SocketAddr =
            "0.0.0.0:51820".parse().expect("local addr should parse");
        configure_runtime_authoritative_transport(&mut runtime, authoritative_local_addr);
        script_runtime_authoritative_relay_ack(
            &mut runtime,
            relay_addr,
            authoritative_local_addr,
            [0x11; 16],
            61_011,
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            Vec::new(),
        ));

        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let relay_endpoint = SocketEndpoint {
            addr: relay_addr.ip(),
            port: 61_011,
        };
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(relay_endpoint, Some(unix_now()))
            .expect("relay handshake injection should succeed");

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay)
        );
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(relay_endpoint)
        );
        assert!(netcheck.message.contains("path_mode=relay_active"));
        assert!(
            netcheck
                .message
                .contains("path_reason=relay_selected_endpoint_with_fresh_handshake")
        );
        assert!(netcheck.message.contains("path_live_proven=true"));
        assert!(netcheck.message.contains("relay_session_state=live"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_session_endpoint_mismatch_is_not_live() {
        let relay_addr: SocketAddr = "203.0.113.15:40005".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-endpoint-mismatch",
            relay_addr,
            "relay-eu-1",
        );
        let authoritative_local_addr: SocketAddr =
            "0.0.0.0:51820".parse().expect("local addr should parse");
        configure_runtime_authoritative_transport(&mut runtime, authoritative_local_addr);
        script_runtime_authoritative_relay_ack(
            &mut runtime,
            relay_addr,
            authoritative_local_addr,
            [0x12; 16],
            61_012,
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            vec![Ok(61_012)],
        ));

        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let established_relay_endpoint = SocketEndpoint {
            addr: relay_addr.ip(),
            port: 61_012,
        };
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(established_relay_endpoint, Some(unix_now()))
            .expect("relay handshake injection should succeed");
        runtime
            .controller
            .configure_traversal_paths(
                &exit_node,
                None,
                Some(SocketEndpoint {
                    addr: relay_addr.ip(),
                    port: 61_013,
                }),
            )
            .expect("controller relay endpoint should be reconfigurable");

        let path_state = runtime.runtime_path_state_summary();
        assert_eq!(path_state.live_mode, "relay_programmed");
        assert_eq!(path_state.live_reason, "relay_endpoint_unselected");
        assert!(!path_state.live_proven);
        assert_eq!(path_state.relay_session_state, "endpoint_unselected");

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_client_refreshes_expiring_session_without_forced_reprobe() {
        let relay_addr: SocketAddr = "203.0.113.11:40001".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-client-refresh",
            relay_addr,
            "relay-eu-1",
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(200),
            Duration::from_millis(50),
            vec![Ok(61_001), Ok(61_002)],
        ));
        runtime.relay_session_token_ttl_secs = 60;
        runtime.relay_session_refresh_margin_secs = 20;

        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let initial_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .cloned()
            .expect("initial relay traversal status should exist");
        assert_eq!(initial_status.selected_endpoint.port, 61_001);
        assert!(
            initial_status
                .next_reprobe_unix
                .expect("relay status should schedule reprobe")
                > initial_status.evaluated_at_unix
        );

        runtime
            .relay_client
            .as_mut()
            .expect("relay client should be configured")
            .set_session_token_expiry_for_test(
                &exit_node,
                unix_now() + runtime.relay_session_refresh_margin_secs - 1,
            );

        runtime
            .sync_traversal_runtime_state(false)
            .expect("expiring relay session should refresh without reprobe failure");

        let refreshed_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .cloned()
            .expect("refreshed relay traversal status should exist");
        let expected_endpoint = SocketEndpoint {
            addr: relay_addr.ip(),
            port: 61_002,
        };
        assert_eq!(refreshed_status.selected_endpoint, expected_endpoint);
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(expected_endpoint)
        );
        assert_eq!(
            refreshed_status.evaluated_at_unix,
            initial_status.evaluated_at_unix
        );
        assert_eq!(
            refreshed_status.next_reprobe_unix,
            initial_status.next_reprobe_unix
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_relay_client_failure_fail_closes_when_configured() {
        let relay_addr: SocketAddr = "203.0.113.12:40002".parse().expect("relay addr");
        let (mut runtime, test_dir) = build_runtime_with_custom_relay(
            "rustynetd-runtime-relay-client-fail-closed",
            relay_addr,
            "relay-eu-1",
        );
        runtime.relay_client = Some(build_test_relay_client(
            "daemon-local",
            Duration::from_millis(120),
            Duration::from_millis(40),
            vec![Err(RelayClientError::Timeout)],
        ));

        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        assert_eq!(runtime.controller.state(), DataplaneState::FailClosed);
        assert!(
            runtime
                .traversal_hint_error
                .as_deref()
                .expect("relay establishment failure should be recorded")
                .contains("relay session establishment failed")
        );
        assert!(
            runtime.traversal_probe_statuses.is_empty(),
            "relay establishment failure must not retain a relay endpoint"
        );
        assert!(
            !runtime
                .relay_client
                .as_ref()
                .expect("relay client should be configured")
                .has_session(&exit_node)
        );
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_requires_signed_coordination_for_direct_probe_attempts() {
        let test_dir = secure_test_dir("rustynetd-runtime-requires-coordination");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path),
            auto_tunnel_watermark_path: Some(assignment_watermark_path),
            traversal_bundle_path: traversal_path,
            traversal_verifier_key_path: traversal_verifier_path,
            traversal_watermark_path,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("relay status should exist");
        assert_eq!(status.decision, TraversalProbeDecision::Relay);
        assert_eq!(
            status.reason,
            TraversalProbeReason::CoordinationRequiredRelayArmed
        );
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay)
        );
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(SocketEndpoint {
                addr: "203.0.113.77".parse().expect("ipv4 should parse"),
                port: 443,
            })
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_refresh_reuses_loaded_coordination_without_replay_restriction() {
        let test_dir = secure_test_dir("rustynetd-runtime-refresh-coordination");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x53);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();
        assert_eq!(runtime.restriction_mode, RestrictionMode::None);
        assert!(runtime.traversal_hint_error.is_none());

        runtime.refresh_traversal_hint_state(false);
        assert_eq!(runtime.restriction_mode, RestrictionMode::None);
        assert!(runtime.traversal_hint_error.is_none());
        assert!(
            !runtime
                .last_reconcile_error
                .as_deref()
                .unwrap_or("none")
                .contains("coordination nonce replay detected")
        );
        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        assert!(
            runtime.traversal_probe_statuses.contains_key(&exit_node),
            "probe status should remain available after refresh"
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_host_only_signed_direct_probe_exhaustion_stays_programmed_without_restricting()
     {
        let test_dir = secure_test_dir("rustynetd-runtime-host-only-direct-exhaustion");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x61);
        write_host_only_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path,
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path,
            membership_log_path,
            membership_watermark_path,
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path),
            auto_tunnel_watermark_path: Some(assignment_watermark_path),
            traversal_bundle_path: traversal_path,
            traversal_verifier_key_path: traversal_verifier_path,
            traversal_watermark_path,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("direct programmed status should exist");
        assert_eq!(status.decision, TraversalProbeDecision::Direct);
        assert_eq!(
            status.reason,
            TraversalProbeReason::DirectProbeExhaustedUnprovenDirect
        );
        assert!(status.latest_handshake_unix.is_none());
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Direct)
        );
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(SocketEndpoint {
                addr: "10.0.0.2".parse().expect("ipv4 should parse"),
                port: 51820,
            })
        );
        assert!(runtime.traversal_hint_error.is_none());
        assert_eq!(runtime.restriction_mode, RestrictionMode::None);

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=direct_programmed"));
        assert!(netcheck.message.contains("path_live_proven=false"));
        assert!(netcheck.message.contains("traversal_probe_result=direct"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_reason=direct_probe_exhausted_unproven_direct")
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_periodic_reprobe_recovers_direct_after_relay() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-periodic-reprobe");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x51);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay)
        );
        let initial_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .cloned()
            .expect("initial traversal probe status should exist");
        assert_eq!(initial_status.decision, TraversalProbeDecision::Relay);
        assert!(
            initial_status
                .next_reprobe_unix
                .expect("relay status should schedule a reprobe")
                > initial_status.evaluated_at_unix
        );

        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(
                SocketEndpoint {
                    addr: "10.0.0.2".parse().expect("ipv4 should parse"),
                    port: 51820,
                },
                Some(unix_now()),
            )
            .expect("test handshake injection should succeed");

        runtime
            .sync_traversal_runtime_state(false)
            .expect("reprobe before interval should not fail");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay)
        );

        let refreshed_coordination =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x52);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            &refreshed_coordination,
        );
        runtime.refresh_traversal_hint_state(false);
        runtime
            .traversal_probe_statuses
            .get_mut(&exit_node)
            .expect("relay status should still exist")
            .next_reprobe_unix = Some(unix_now());
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(
                SocketEndpoint {
                    addr: "10.0.0.2".parse().expect("ipv4 should parse"),
                    port: 51820,
                },
                Some(unix_now()),
            )
            .expect("fresh direct handshake should be visible for due reprobe");

        runtime
            .sync_traversal_runtime_state(false)
            .expect("due reprobe should not fail");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Direct)
        );
        let recovered_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("direct recovery status should exist");
        assert_eq!(recovered_status.decision, TraversalProbeDecision::Direct);
        assert_eq!(
            recovered_status.reason,
            TraversalProbeReason::FreshHandshakeObserved
        );
        assert_eq!(recovered_status.next_reprobe_unix, None);

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-direct-health");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x61);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(60)
                .expect("test traversal handshake freshness should be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();
        seed_local_probe_candidate(&mut runtime);
        runtime.controller.set_stability_windows(0, 0);

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let direct_endpoint = SocketEndpoint {
            addr: "10.0.0.2".parse().expect("ipv4 should parse"),
            port: 51820,
        };
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(direct_endpoint, Some(unix_now()))
            .expect("test handshake injection should succeed");
        let refreshed_coordination =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x62);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            &refreshed_coordination,
        );
        runtime.refresh_traversal_hint_state(false);
        runtime
            .traversal_probe_statuses
            .get_mut(&exit_node)
            .expect("relay probe status should exist")
            .next_reprobe_unix = Some(unix_now());
        runtime
            .sync_traversal_runtime_state(false)
            .expect("due reprobe should promote direct path");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Direct)
        );

        let stale_probe_status = runtime
            .traversal_probe_statuses
            .get_mut(&exit_node)
            .expect("direct traversal probe status should exist");
        let prior_evaluated_at_unix = stale_probe_status.evaluated_at_unix;
        stale_probe_status.latest_handshake_unix =
            Some(unix_now().saturating_sub(runtime.traversal_probe_handshake_freshness_secs + 1));

        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(direct_endpoint, Some(unix_now()))
            .expect("fresh direct handshake should remain visible");

        runtime
            .sync_traversal_runtime_state(false)
            .expect("live handshake refresh should not fail");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Direct)
        );
        let retained_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("direct traversal probe status should still exist");
        assert_eq!(retained_status.decision, TraversalProbeDecision::Direct);
        assert_eq!(retained_status.evaluated_at_unix, prior_evaluated_at_unix);
        assert!(
            retained_status
                .latest_handshake_unix
                .expect("live handshake should be reflected in retained status")
                >= prior_evaluated_at_unix
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-direct-expiry-failover");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let coordination_payload =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x81);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            &coordination_payload,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            traversal_probe_handshake_freshness_secs: NonZeroU64::new(60)
                .expect("test traversal handshake freshness should be non-zero"),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();
        runtime.controller.set_stability_windows(0, 0);

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        let direct_endpoint = SocketEndpoint {
            addr: "10.0.0.2".parse().expect("ipv4 should parse"),
            port: 51820,
        };
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(direct_endpoint, Some(unix_now()))
            .expect("test handshake injection should succeed");
        let refreshed_coordination =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x82);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            &refreshed_coordination,
        );
        runtime.refresh_traversal_hint_state(false);
        runtime
            .traversal_probe_statuses
            .get_mut(&exit_node)
            .expect("relay probe status should exist")
            .next_reprobe_unix = Some(unix_now());
        runtime
            .sync_traversal_runtime_state(false)
            .expect("due reprobe should promote direct path");
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Direct)
        );

        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(
                direct_endpoint,
                Some(
                    unix_now().saturating_sub(runtime.traversal_probe_handshake_freshness_secs + 1),
                ),
            )
            .expect("stale handshake injection should succeed");
        runtime
            .sync_traversal_runtime_state(false)
            .expect("stale direct liveness should reprobe and fall back to relay");

        let failover_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("relay failover status should exist");
        assert_eq!(failover_status.decision, TraversalProbeDecision::Relay);
        assert_eq!(
            failover_status.reason,
            TraversalProbeReason::CoordinationRequiredRelayArmed
        );
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(PathMode::Relay)
        );
        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=relay_programmed"));
        assert!(netcheck.message.contains("path_live_proven=false"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_probe_recovers_direct_when_handshake_arrives() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-probe-direct-recovery");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();
        seed_local_probe_candidate_snapshot(&mut runtime);
        runtime.controller.set_stability_windows(0, 0);

        let exit_node = NodeId::new("node-exit".to_string()).expect("node id should parse");
        runtime
            .controller
            .backend_mut_for_test()
            .set_test_endpoint_latest_handshake_unix(
                SocketEndpoint {
                    addr: "10.0.0.2".parse().expect("ipv4 should parse"),
                    port: 51820,
                },
                Some(unix_now()),
            )
            .expect("test handshake injection should succeed");
        let refreshed_coordination =
            valid_coordination_payload_for_peer("daemon-local", "node-exit", unix_now(), 0x72);
        write_traversal_file_with_coordination(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            &refreshed_coordination,
        );
        runtime.refresh_traversal_hint_state(false);
        runtime
            .traversal_probe_statuses
            .get_mut(&exit_node)
            .expect("relay probe status should exist")
            .next_reprobe_unix = Some(unix_now());

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=direct_active"));
        assert!(
            netcheck
                .message
                .contains("path_reason=fresh_handshake_observed")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_mode=direct_programmed")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_reason=relay_armed")
        );
        assert!(netcheck.message.contains("path_live_proven=true"));
        assert!(netcheck.message.contains("traversal_probe_result=direct"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_reason=fresh_handshake_observed")
        );
        let direct_status = runtime
            .traversal_probe_statuses
            .get(&exit_node)
            .expect("direct traversal probe status should exist");
        assert!(direct_status.attempts > 0);
        assert!(runtime.local_host_candidates.contains_key("eth-test"));
        assert_eq!(
            runtime.controller.managed_peer_endpoint(&exit_node),
            Some(SocketEndpoint {
                addr: "10.0.0.2".parse().expect("ipv4 should parse"),
                port: 51820,
            })
        );
        assert_eq!(
            runtime.controller.peer_path(&exit_node),
            Some(crate::phase10::PathMode::Direct)
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_traversal_preexpiry_refresh_emits_metrics_and_alarm() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-preexpiry-refresh");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );
        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            traversal_probe_reprobe_interval_secs: NonZeroU64::new(60)
                .expect("test traversal reprobe interval should be non-zero"),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();
        let refresh_generated = unix_now();
        let refresh_expires = refresh_generated
            .saturating_add(super::MIN_TRAVERSAL_REFRESH_MARGIN_SECS.saturating_sub(1));
        let refresh_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={refresh_generated}\nexpires_at_unix={refresh_expires}\nnonce=10\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.77\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-1\ncandidate.1.priority=20\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [23u8; 32],
            refresh_payload.as_str(),
        );
        let refresh_envelope = load_traversal_bundle_set(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed traversal bundle set should load");
        persist_traversal_watermark(&traversal_watermark_path, refresh_envelope.watermark)
            .expect("traversal watermark should persist");
        runtime.traversal_hints = Some(refresh_envelope);
        runtime.traversal_hint_error = None;

        let previous_refresh_events = runtime.traversal_preexpiry_refresh_events;
        runtime.traversal_last_preexpiry_refresh_unix =
            Some(unix_now().saturating_sub(MIN_TRAVERSAL_REFRESH_COOLDOWN_SECS.saturating_add(1)));
        runtime.maybe_preexpiry_refresh_traversal(unix_now());

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert_eq!(
            runtime.traversal_preexpiry_refresh_events,
            previous_refresh_events + 1
        );
        assert!(status.message.contains(&format!(
            "traversal_preexpiry_refresh_events={}",
            runtime.traversal_preexpiry_refresh_events
        )));
        assert!(
            !status
                .message
                .contains("traversal_last_preexpiry_refresh_unix=none")
        );
        assert!(status.message.contains("traversal_alarm_state=warning"));
        assert!(
            status
                .message
                .contains("traversal_alarm_reason=signed_traversal_state_near_expiry")
        );
        assert!(status.message.contains("traversal_stale_rejections=0"));
        assert!(status.message.contains("traversal_replay_rejections=0"));
        assert!(
            status
                .message
                .contains("traversal_future_dated_rejections=0")
        );

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("traversal_alarm_state=warning"));
        assert!(
            netcheck
                .message
                .contains("traversal_alarm_reason=signed_traversal_state_near_expiry")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_dns_preexpiry_refresh_emits_metrics_and_alarm() {
        let test_dir = secure_test_dir("rustynetd-runtime-dns-preexpiry-refresh");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let near_expiry_generated_at = unix_now().saturating_sub(280);
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            2,
            DnsZoneFixtureTiming {
                generated_at_unix: near_expiry_generated_at,
                ttl_secs: 300,
                tamper_after_sign: false,
            },
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            dns_zone_bundle_path: dns_zone_path.clone(),
            dns_zone_verifier_key_path: dns_zone_verifier_path.clone(),
            dns_zone_watermark_path: dns_zone_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(runtime.dns_zone.is_some());

        let previous_refresh_events = runtime.dns_zone_preexpiry_refresh_events;
        runtime.dns_zone_last_preexpiry_refresh_unix = Some(unix_now().saturating_sub(11));
        runtime.maybe_preexpiry_refresh_dns_zone(unix_now(), Some(&assignment));

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains(&format!(
            "dns_preexpiry_refresh_events={}",
            previous_refresh_events + 1
        )));
        assert!(
            !status
                .message
                .contains("dns_last_preexpiry_refresh_unix=none")
        );
        assert!(status.message.contains("dns_alarm_state=warning"));
        assert!(
            status
                .message
                .contains("dns_alarm_reason=signed_dns_zone_state_near_expiry")
        );
        assert!(status.message.contains("dns_stale_rejections=0"));
        assert!(status.message.contains("dns_replay_rejections=0"));
        assert!(status.message.contains("dns_future_dated_rejections=0"));

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("dns_alarm_state=warning"));
        assert!(
            netcheck
                .message
                .contains("dns_alarm_reason=signed_dns_zone_state_near_expiry")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_traversal_rejection_counters_increment_for_stale_replay_and_future_dated() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-rejection-counters");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let stale_generated = unix_now().saturating_sub(DEFAULT_TRAVERSAL_MAX_AGE_SECS + 20);
        let stale_expires = stale_generated.saturating_add(1);
        let stale_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={stale_generated}\nexpires_at_unix={stale_expires}\nnonce=41\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [23u8; 32],
            stale_payload.as_str(),
        );
        runtime.refresh_traversal_hint_state(true);

        let valid_generated = unix_now();
        write_traversal_file_with_timing(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            42,
            TraversalFixtureTiming {
                generated_at_unix: valid_generated,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        runtime.refresh_traversal_hint_state(true);

        let replay_generated = valid_generated;
        let replay_expires = replay_generated.saturating_add(60);
        let replay_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={replay_generated}\nexpires_at_unix={replay_expires}\nnonce=41\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [23u8; 32],
            replay_payload.as_str(),
        );
        runtime.refresh_traversal_hint_state(true);

        let future_generated =
            unix_now().saturating_add(runtime.trust_policy.max_clock_skew_secs + 20);
        let future_expires = future_generated.saturating_add(60);
        let future_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={future_generated}\nexpires_at_unix={future_expires}\nnonce=43\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [23u8; 32],
            future_payload.as_str(),
        );
        runtime.refresh_traversal_hint_state(true);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert_eq!(runtime.traversal_stale_rejections, 1);
        assert_eq!(runtime.traversal_replay_rejections, 1);
        assert_eq!(runtime.traversal_future_dated_rejections, 2);
        assert!(status.message.contains(&format!(
            "traversal_stale_rejections={}",
            runtime.traversal_stale_rejections
        )));
        assert!(status.message.contains(&format!(
            "traversal_replay_rejections={}",
            runtime.traversal_replay_rejections
        )));
        assert!(status.message.contains(&format!(
            "traversal_future_dated_rejections={}",
            runtime.traversal_future_dated_rejections
        )));
        assert!(status.message.contains("traversal_alarm_state=error"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_dns_rejection_counters_increment_for_stale_replay_and_future_dated() {
        let test_dir = secure_test_dir("rustynetd-runtime-dns-rejection-counters");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            dns_zone_bundle_path: dns_zone_path.clone(),
            dns_zone_verifier_key_path: dns_zone_verifier_path.clone(),
            dns_zone_watermark_path: dns_zone_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let stale_generated_at = unix_now().saturating_sub(DEFAULT_DNS_ZONE_MAX_AGE_SECS + 20);
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &[]),
            41,
            DnsZoneFixtureTiming {
                generated_at_unix: stale_generated_at,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(matches!(
            runtime.dns_zone_error.as_deref(),
            Some("dns zone bundle is stale")
        ));
        assert!(runtime.dns_zone.is_none());

        let replay_generated_at = unix_now();
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &[]),
            42,
            DnsZoneFixtureTiming {
                generated_at_unix: replay_generated_at,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(runtime.dns_zone.is_some());
        assert!(runtime.dns_zone_error.is_none());

        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            42,
            DnsZoneFixtureTiming {
                generated_at_unix: replay_generated_at,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(matches!(
            runtime.dns_zone_error.as_deref(),
            Some("dns zone bundle replay detected")
        ));
        assert!(runtime.dns_zone.is_none());

        let future_generated_at =
            unix_now().saturating_add(runtime.trust_policy.max_clock_skew_secs + 20);
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &[]),
            43,
            DnsZoneFixtureTiming {
                generated_at_unix: future_generated_at,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(matches!(
            runtime.dns_zone_error.as_deref(),
            Some("dns zone bundle is future dated")
        ));
        assert!(runtime.dns_zone.is_none());

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert_eq!(runtime.dns_zone_stale_rejections, 1);
        assert!(runtime.dns_zone_replay_rejections >= 1);
        assert_eq!(runtime.dns_zone_future_dated_rejections, 1);
        assert!(status.message.contains(&format!(
            "dns_stale_rejections={}",
            runtime.dns_zone_stale_rejections
        )));
        assert!(status.message.contains(&format!(
            "dns_replay_rejections={}",
            runtime.dns_zone_replay_rejections
        )));
        assert!(status.message.contains(&format!(
            "dns_future_dated_rejections={}",
            runtime.dns_zone_future_dated_rejections
        )));
        assert!(status.message.contains("dns_alarm_state=error"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_endpoint_change_refresh_triggers_event_counter() {
        let test_dir = secure_test_dir("rustynetd-runtime-endpoint-change-refresh");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            1,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        runtime.maybe_trigger_endpoint_change_refresh();
        let baseline_events = runtime.traversal_endpoint_change_events;

        let updated_payload = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={}\nexpires_at_unix={}\nnonce=2\ncandidate_count=2\ncandidate.0.type=host\ncandidate.0.addr=10.0.1.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\ncandidate.1.type=relay\ncandidate.1.addr=203.0.113.88\ncandidate.1.port=443\ncandidate.1.family=ipv4\ncandidate.1.relay_id=relay-eu-2\ncandidate.1.priority=20\n",
            unix_now(),
            unix_now().saturating_add(60)
        );
        write_signed_kv_artifact(
            &traversal_path,
            &traversal_verifier_path,
            [23u8; 32],
            updated_payload.as_str(),
        );
        runtime.refresh_traversal_hint_state(false);
        runtime.maybe_trigger_endpoint_change_refresh();

        assert_eq!(
            runtime.traversal_endpoint_change_events,
            baseline_events + 1
        );
        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains(&format!(
            "traversal_endpoint_change_events={}",
            baseline_events + 1
        )));
        assert!(
            !status
                .message
                .contains("traversal_endpoint_fingerprint=none")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_authority_rejects_unmanaged_peer_bundle() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-authority-unmanaged");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-ghost",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));
        assert!(
            status
                .message
                .contains("bootstrap_error=traversal authority rejected bootstrap apply")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_unmanaged_peer() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-authority-sync");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-ghost",
            3,
            false,
        );
        runtime.refresh_traversal_hint_state(true);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));
        assert!(
            status
                .message
                .contains("bootstrap_error=traversal runtime sync failed")
        );
        assert_eq!(
            runtime.controller.state(),
            crate::phase10::DataplaneState::FailClosed
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_set_rejects_mixed_snapshot_batches() {
        let test_dir = secure_test_dir("rustynetd-traversal-mixed-snapshot");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        std::fs::write(
            &traversal_verifier_path,
            format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
        )
        .expect("traversal verifier key should be written");

        let generated = unix_now();
        let expires = generated.saturating_add(60);
        let payload_a = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-exit\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce=11\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.2\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        let payload_b = format!(
            "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=daemon-local\ntarget_node_id=node-relay\ngenerated_at_unix={generated}\nexpires_at_unix={expires}\nnonce=12\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=10.0.0.3\ncandidate.0.port=51820\ncandidate.0.family=ipv4\ncandidate.0.relay_id=\ncandidate.0.priority=10\n"
        );
        let body = format!(
            "{payload_a}signature={}\n\n{payload_b}signature={}\n",
            hex_encode(&signing_key.sign(payload_a.as_bytes()).to_bytes()),
            hex_encode(&signing_key.sign(payload_b.as_bytes()).to_bytes())
        );
        std::fs::write(&traversal_path, body).expect("mixed traversal snapshot should be written");

        let err = load_traversal_bundle_set(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("mixed snapshot batches must fail closed");
        assert!(
            err.to_string()
                .contains("must share a single generated_at/expires_at/nonce snapshot"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_authority_requires_full_peer_coverage() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-full-coverage-required");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files_with_additional_nodes(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
            &[
                ("node-exit", MembershipNodeStatus::Active),
                ("node-relay", MembershipNodeStatus::Active),
            ],
        );
        write_auto_tunnel_file_two_peers(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));
        assert!(
            runtime
                .bootstrap_error
                .as_deref()
                .unwrap_or("none")
                .contains("missing signed traversal state for managed peers: node-relay")
        );
        assert_eq!(
            runtime.controller.state(),
            crate::phase10::DataplaneState::FailClosed
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_authority_accepts_multi_peer_snapshot() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-multi-peer");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files_with_additional_nodes(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
            &[
                ("node-exit", MembershipNodeStatus::Active),
                ("node-relay", MembershipNodeStatus::Active),
            ],
        );
        write_auto_tunnel_file_two_peers(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
        );
        write_traversal_file_set(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            &[
                ("node-exit", "10.0.0.2", 51820),
                ("node-relay", "10.0.0.3", 51820),
            ],
            2,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=false"));
        assert!(status.message.contains("managed_peer_endpoints_error=none"));
        assert!(status.message.contains(
            "managed_peer_endpoints=node-exit/203.0.113.77:443+node-relay/203.0.113.78:443"
        ));
        assert!(status.message.contains("traversal_peer_count=2"));
        assert!(status.message.contains("traversal_probe_peer_count=2"));
        assert!(status.message.contains("traversal_probe_relay_peers=2"));
        assert_eq!(
            runtime
                .controller
                .peer_path(&NodeId::new("node-exit".to_string()).unwrap()),
            Some(crate::phase10::PathMode::Relay)
        );
        assert_eq!(
            runtime
                .controller
                .peer_path(&NodeId::new("node-relay".to_string()).unwrap()),
            Some(crate::phase10::PathMode::Relay)
        );
        assert_eq!(
            runtime
                .controller
                .managed_peer_endpoint(&NodeId::new("node-exit".to_string()).unwrap()),
            Some(SocketEndpoint {
                addr: "203.0.113.77".parse().expect("ipv4 should parse"),
                port: 443,
            })
        );
        assert_eq!(
            runtime
                .controller
                .managed_peer_endpoint(&NodeId::new("node-relay".to_string()).unwrap()),
            Some(SocketEndpoint {
                addr: "203.0.113.78".parse().expect("ipv4 should parse"),
                port: 443,
            })
        );

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("traversal_peer_count=2"));
        assert!(netcheck.message.contains("candidate_count=4"));
        assert!(netcheck.message.contains("traversal_probe_result=relay"));
        assert!(netcheck.message.contains("traversal_probe_peer_count=2"));

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_traversal_runtime_sync_fail_closes_on_missing_peer_coverage() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-sync-missing-peer");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files_with_additional_nodes(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
            &[
                ("node-exit", MembershipNodeStatus::Active),
                ("node-relay", MembershipNodeStatus::Active),
            ],
        );
        write_auto_tunnel_file_two_peers(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
        );
        write_traversal_file_set(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            &[
                ("node-exit", "10.0.0.2", 51820),
                ("node-relay", "10.0.0.3", 51820),
            ],
            2,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            3,
            false,
        );
        runtime.refresh_traversal_hint_state(true);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));
        assert!(
            runtime
                .bootstrap_error
                .as_deref()
                .unwrap_or("none")
                .contains("missing signed traversal state for managed peer node-relay")
        );
        assert_eq!(
            runtime.controller.state(),
            crate::phase10::DataplaneState::FailClosed
        );

        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_assigned_cidr_outside_mesh() {
        let test_dir = secure_test_dir("rustynetd-auto-assigned-outside-mesh");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            9,
            false,
        );
        let body = std::fs::read_to_string(&assignment_path)
            .expect("auto tunnel bundle should be readable");
        let tampered = body.replace("assigned_cidr=100.64.0.1/32", "assigned_cidr=10.0.0.1/32");
        std::fs::write(&assignment_path, tampered).expect("tampered bundle should be writable");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("assigned cidr outside mesh must be rejected");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("outside mesh"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_auto_tunnel_bundle_rejects_non_host_assigned_cidr() {
        let test_dir = secure_test_dir("rustynetd-auto-assigned-not-host");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            10,
            false,
        );
        let body = std::fs::read_to_string(&assignment_path)
            .expect("auto tunnel bundle should be readable");
        let tampered = body.replace("assigned_cidr=100.64.0.1/32", "assigned_cidr=100.64.0.0/10");
        std::fs::write(&assignment_path, tampered).expect("tampered bundle should be writable");
        let err = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            300,
            TrustPolicy::default(),
            None,
        )
        .expect_err("non-host assigned cidr must be rejected");
        assert!(matches!(
            err,
            super::AutoTunnelBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("host cidr"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_rejects_private_srflx_candidate() {
        let test_dir = secure_test_dir("rustynetd-traversal-private-srflx");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file_with_srflx(
            &traversal_path,
            &traversal_verifier_path,
            1,
            "10.10.10.10",
            false,
        );

        let err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("private srflx candidate must be rejected");
        assert!(matches!(
            err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("srflx candidate"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_traversal_bundle_rejects_private_relay_candidate() {
        let test_dir = secure_test_dir("rustynetd-traversal-private-relay");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        write_traversal_file_with_custom_relay(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            1,
            "192.168.100.10:443"
                .parse()
                .expect("relay addr should parse"),
            "relay-lan-1",
        );

        let err = load_traversal_bundle(
            &traversal_path,
            &traversal_verifier_path,
            DEFAULT_TRAVERSAL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect_err("private relay candidate must be rejected");
        assert!(matches!(
            err,
            super::TraversalBootstrapError::InvalidFormat(_)
        ));
        assert!(err.to_string().contains("relay candidate"));
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn preflight_allows_missing_traversal_bundle_without_verifier_key() {
        let test_dir = secure_test_dir("rustynetd-preflight-traversal-optional");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_bundle_path = test_dir.join("missing.traversal.bundle");
        let traversal_verifier_path = test_dir.join("missing.traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_bundle_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        run_preflight_checks(&config)
            .expect("preflight should pass when traversal bundle is absent");

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn preflight_rejects_present_traversal_bundle_when_verifier_key_missing() {
        let test_dir = secure_test_dir("rustynetd-preflight-traversal-requires-verifier");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_bundle_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("missing.traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        std::fs::write(&traversal_bundle_path, "version=1\n")
            .expect("traversal bundle marker should be writable");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_bundle_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let err = run_preflight_checks(&config)
            .expect_err("preflight must fail when traversal bundle exists without verifier key");
        assert!(
            err.to_string()
                .contains("traversal verifier key metadata read failed"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_bundle_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn preflight_allows_stale_dns_zone_bundle_without_failing_daemon_start() {
        let test_dir = secure_test_dir("rustynetd-preflight-dns-zone-stale-optional");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");
        let traversal_bundle_path = test_dir.join("missing.traversal.bundle");
        let traversal_verifier_path = test_dir.join("missing.traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            41,
            false,
        );
        let stale_generated_at = unix_now().saturating_sub(7_200);
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &[]),
            42,
            DnsZoneFixtureTiming {
                generated_at_unix: stale_generated_at,
                ttl_secs: 300,
                tamper_after_sign: false,
            },
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            dns_zone_bundle_path: dns_zone_path.clone(),
            dns_zone_verifier_key_path: dns_zone_verifier_path.clone(),
            dns_zone_watermark_path: dns_zone_watermark_path.clone(),
            traversal_bundle_path: traversal_bundle_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };

        run_preflight_checks(&config)
            .expect("preflight should pass with stale dns zone bundle and fail-closed DNS state");

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_netcheck_reports_runtime_programmed_traversal_paths() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-netcheck");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            8,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            9,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        seed_local_probe_candidate(&mut runtime);
        runtime.bootstrap();

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("path_mode=relay_programmed"));
        assert!(
            netcheck
                .message
                .contains("path_reason=relay_session_disabled")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_mode=relay_programmed")
        );
        assert!(
            netcheck
                .message
                .contains("path_programmed_reason=relay_endpoint_programmed")
        );
        assert!(netcheck.message.contains("path_live_proven=false"));
        assert!(netcheck.message.contains("relay_session_configured=false"));
        assert!(netcheck.message.contains("relay_session_state=disabled"));
        assert!(netcheck.message.contains("traversal_status=valid"));
        assert!(netcheck.message.contains("candidate_count=2"));
        assert!(netcheck.message.contains("host_candidates=1"));
        assert!(netcheck.message.contains("relay_candidates=1"));
        assert!(netcheck.message.contains("traversal_probe_result=relay"));
        assert!(
            netcheck
                .message
                .contains("traversal_probe_reason=coordination_required_relay_armed")
        );
        assert!(runtime.controller.has_armed_relay_path());

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed() {
        let test_dir = secure_test_dir("rustynetd-runtime-traversal-forged");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "node-a",
            "node-b",
            53,
            true,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let netcheck = runtime.handle_command(IpcCommand::Netcheck);
        assert!(netcheck.ok);
        assert!(netcheck.message.contains("traversal_status=invalid"));
        assert!(netcheck.message.contains("candidate_count=0"));
        assert!(netcheck.message.contains("host_candidates=0"));
        assert!(netcheck.message.contains("srflx_candidates=0"));
        assert!(netcheck.message.contains("relay_candidates=0"));
        assert!(
            netcheck
                .message
                .contains("traversal_error=traversal_bundle_invalid_format")
                || netcheck
                    .message
                    .contains("traversal_error=traversal_signature_verification_failed")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_handles_status_and_mutating_commands() {
        let test_dir = secure_test_dir("rustynetd-runtime-test");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("state="));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(select.ok);
        assert!(select.message.contains("exit-node selected"));

        let route =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(route.ok);
        assert!(route.message.contains("route advertised"));

        let invalid_route =
            runtime.handle_command(IpcCommand::RouteAdvertise("bad-route".to_string()));
        assert!(!invalid_route.ok);

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_dns_zone_bundle_rejects_record_ip_outside_assignment() {
        let test_dir = secure_test_dir("rustynetd-dns-zone-assignment-mismatch");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_dns_zone_file(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.99", &[]),
            2,
            false,
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");
        let err = load_dns_zone_bundle(DnsZoneLoadContext {
            path: &dns_zone_path,
            verifier_key_path: &dns_zone_verifier_path,
            max_age_secs: DEFAULT_DNS_ZONE_MAX_AGE_SECS,
            trust_policy: TrustPolicy::default(),
            previous_watermark: None,
            expected_zone_name: "rustynet",
            local_node_id: "daemon-local",
            auto_tunnel: &assignment.bundle,
        })
        .expect_err("dns zone with assignment mismatch must be rejected");
        assert!(
            matches!(err, DnsZoneBootstrapError::AssignmentMismatch(_)),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn load_dns_zone_bundle_rejects_equal_watermark_when_payload_digest_differs() {
        let test_dir = secure_test_dir("rustynetd-dns-zone-replay-digest-mismatch");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let generated_at_unix = unix_now();
        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &[]),
            2,
            DnsZoneFixtureTiming {
                generated_at_unix,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        let valid = load_dns_zone_bundle(DnsZoneLoadContext {
            path: &dns_zone_path,
            verifier_key_path: &dns_zone_verifier_path,
            max_age_secs: DEFAULT_DNS_ZONE_MAX_AGE_SECS,
            trust_policy: TrustPolicy::default(),
            previous_watermark: None,
            expected_zone_name: "rustynet",
            local_node_id: "daemon-local",
            auto_tunnel: &assignment.bundle,
        })
        .expect("fresh dns zone bundle should load");

        write_dns_zone_file_with_timing(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            2,
            DnsZoneFixtureTiming {
                generated_at_unix,
                ttl_secs: 60,
                tamper_after_sign: false,
            },
        );
        let err = load_dns_zone_bundle(DnsZoneLoadContext {
            path: &dns_zone_path,
            verifier_key_path: &dns_zone_verifier_path,
            max_age_secs: DEFAULT_DNS_ZONE_MAX_AGE_SECS,
            trust_policy: TrustPolicy::default(),
            previous_watermark: Some(valid.watermark),
            expected_zone_name: "rustynet",
            local_node_id: "daemon-local",
            auto_tunnel: &assignment.bundle,
        })
        .expect_err("equal watermark with mismatched payload digest must fail");
        assert!(matches!(err, DnsZoneBootstrapError::ReplayDetected));

        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_dns_inspect_reports_signed_zone_state() {
        let test_dir = secure_test_dir("rustynetd-dns-inspect");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_dns_zone_file(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            2,
            false,
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let config = DaemonConfig {
            node_id: "daemon-local".to_string(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.dns_zone_bundle_path = dns_zone_path.clone();
        runtime.dns_zone_verifier_key_path = dns_zone_verifier_path.clone();
        runtime.dns_zone_watermark_path = dns_zone_watermark_path.clone();
        runtime.refresh_dns_zone_state(Some(&assignment));

        let inspect = runtime.handle_command(IpcCommand::DnsInspect);
        assert!(inspect.ok);
        assert!(inspect.message.contains("dns inspect: state=valid"));
        assert!(inspect.message.contains("zone_name=rustynet"));
        assert!(inspect.message.contains("record_count=1"));
        assert!(inspect.message.contains("record.0.fqdn=app.rustynet"));
        assert!(inspect.message.contains("target_node_id=node-exit"));
        assert!(inspect.message.contains("expected_ip=100.64.0.2"));
        assert!(inspect.message.contains("aliases=ssh.rustynet"));

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("dns_zone_state=valid"));
        assert!(status.message.contains("dns_zone_record_count=1"));
        assert!(status.message.contains("dns_zone_error=none"));

        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn dns_resolver_answers_managed_a_record_from_signed_zone() {
        let test_dir = secure_test_dir("rustynetd-dns-resolver-answer");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_dns_zone_file(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            2,
            false,
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let config = DaemonConfig {
            node_id: "daemon-local".to_string(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.dns_zone_bundle_path = dns_zone_path.clone();
        runtime.dns_zone_verifier_key_path = dns_zone_verifier_path.clone();
        runtime.dns_zone_watermark_path = dns_zone_watermark_path.clone();
        runtime.refresh_dns_zone_state(Some(&assignment));

        let response = build_dns_response(&runtime, &build_dns_query("app.rustynet", 1))
            .expect("resolver should answer");
        assert_eq!(dns_response_rcode(&response), DNS_RCODE_NOERROR);
        assert_eq!(dns_response_ancount(&response), 1);
        assert_eq!(&response[response.len() - 4..], &[100, 64, 0, 2]);

        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn dns_resolver_servfails_managed_name_when_zone_is_missing() {
        let config = DaemonConfig {
            node_id: "daemon-local".to_string(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let runtime = DaemonRuntime::new(&config).expect("runtime should be created");

        let response = build_dns_response(&runtime, &build_dns_query("app.rustynet", 1))
            .expect("resolver should answer");
        assert_eq!(dns_response_rcode(&response), DNS_RCODE_SERVFAIL);
        assert_eq!(dns_response_ancount(&response), 0);
    }

    #[test]
    fn dns_resolver_servfails_managed_name_when_zone_is_marked_invalid() {
        let test_dir = secure_test_dir("rustynetd-dns-zone-servfail-invalid");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let dns_zone_path = test_dir.join("dns-zone.bundle");
        let dns_zone_verifier_path = test_dir.join("dns-zone.verifier.pub");
        let dns_zone_watermark_path = test_dir.join("dns-zone.watermark");

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_dns_zone_file(
            &dns_zone_path,
            &dns_zone_verifier_path,
            "daemon-local",
            ("node-exit", "100.64.0.2", &["ssh"]),
            2,
            false,
        );

        let assignment = load_auto_tunnel_bundle(
            &assignment_path,
            &assignment_verifier_path,
            DEFAULT_AUTO_TUNNEL_MAX_AGE_SECS,
            TrustPolicy::default(),
            None,
        )
        .expect("signed assignment should load");

        let config = DaemonConfig {
            node_id: "daemon-local".to_string(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.dns_zone_bundle_path = dns_zone_path.clone();
        runtime.dns_zone_verifier_key_path = dns_zone_verifier_path.clone();
        runtime.dns_zone_watermark_path = dns_zone_watermark_path.clone();
        runtime.refresh_dns_zone_state(Some(&assignment));
        assert!(runtime.dns_zone.is_some());
        runtime.dns_zone_error = Some("dns zone bundle replay detected".to_string());

        let response = build_dns_response(&runtime, &build_dns_query("app.rustynet", 1))
            .expect("resolver should answer");
        assert_eq!(dns_response_rcode(&response), DNS_RCODE_SERVFAIL);
        assert_eq!(dns_response_ancount(&response), 0);

        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(dns_zone_path);
        let _ = std::fs::remove_file(dns_zone_verifier_path);
        let _ = std::fs::remove_file(dns_zone_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn dns_resolver_refuses_non_managed_name() {
        let config = DaemonConfig {
            node_id: "daemon-local".to_string(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let runtime = DaemonRuntime::new(&config).expect("runtime should be created");

        let response = build_dns_response(&runtime, &build_dns_query("example.com", 1))
            .expect("resolver should answer");
        assert_eq!(dns_response_rcode(&response), DNS_RCODE_REFUSED);
        assert_eq!(dns_response_ancount(&response), 0);
    }

    #[test]
    fn validate_daemon_config_rejects_non_loopback_dns_resolver_bind_addr() {
        let config = DaemonConfig {
            backend_mode: DaemonBackendMode::LinuxWireguard,
            dns_resolver_bind_addr: "192.0.2.10:53535".parse().expect("test addr"),
            ..DaemonConfig::default()
        };
        let err = validate_daemon_config(&config).expect_err("non-loopback bind must fail");
        assert!(format!("{err}").contains("dns resolver bind addr must be loopback"));
    }

    #[test]
    fn daemon_runtime_client_role_blocks_admin_mutations() {
        let test_dir = secure_test_dir("rustynetd-runtime-client-role");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Client,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=client"));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(select.ok);

        let route =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(!route.ok);
        assert!(route.message.contains("node role"));

        let key_rotate = runtime.handle_command(IpcCommand::KeyRotate);
        assert!(!key_rotate.ok);
        assert!(key_rotate.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_client_role_never_reports_exit_serving() {
        let test_dir = secure_test_dir("rustynetd-runtime-client-no-exit-serving");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Client,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        runtime.advertised_routes.insert("0.0.0.0/0".to_string());
        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=client"));
        assert!(status.message.contains("serving_exit_node=false"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_blind_exit_role_is_least_privilege() {
        let test_dir = secure_test_dir("rustynetd-runtime-blind-exit-role");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::BlindExit,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=blind_exit"));
        assert!(status.message.contains("serving_exit_node=true"));

        let select = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!select.ok);
        assert!(select.message.contains("node role"));

        let exit_off = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!exit_off.ok);
        assert!(exit_off.message.contains("node role"));

        let lan_on = runtime.handle_command(IpcCommand::LanAccessOn);
        assert!(!lan_on.ok);
        assert!(lan_on.message.contains("node role"));

        let route = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(!route.ok);
        assert!(route.message.contains("node role"));

        let key_rotate = runtime.handle_command(IpcCommand::KeyRotate);
        assert!(!key_rotate.ok);
        assert!(key_rotate.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_blind_exit_ignores_client_assignment_fields() {
        let test_dir = secure_test_dir("rustynetd-runtime-blind-exit-assignment");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        // Includes an exit-default route that would map to selected_exit_node for clients.
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            9,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            10,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::BlindExit,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("node_role=blind_exit"));
        assert!(status.message.contains("serving_exit_node=true"));
        assert!(status.message.contains("exit_node=none"));
        assert!(status.message.contains("restricted_safe_mode=false"));

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(denied.message.contains("node role"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn sanitize_dataplane_routes_for_blind_exit_drops_exit_scoped_routes_only() {
        let routes = vec![
            Route {
                destination_cidr: "100.64.0.0/10".to_string(),
                via_node: NodeId::new("mesh-peer".to_string()).expect("mesh peer node id"),
                kind: RouteKind::Mesh,
            },
            Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("exit-peer".to_string()).expect("exit peer node id"),
                kind: RouteKind::ExitNodeDefault,
            },
            Route {
                destination_cidr: "192.168.1.0/24".to_string(),
                via_node: NodeId::new("exit-peer".to_string()).expect("exit peer node id"),
                kind: RouteKind::ExitNodeLan,
            },
        ];

        let sanitized = sanitize_dataplane_routes_for_node_role(NodeRole::BlindExit, routes);
        assert_eq!(sanitized.len(), 1);
        assert_eq!(sanitized[0].destination_cidr, "100.64.0.0/10");
        assert_eq!(sanitized[0].kind, RouteKind::Mesh);
    }

    #[test]
    fn sanitize_dataplane_routes_for_non_blind_exit_preserves_routes() {
        let routes = vec![Route {
            destination_cidr: "0.0.0.0/0".to_string(),
            via_node: NodeId::new("exit-peer".to_string()).expect("exit peer node id"),
            kind: RouteKind::ExitNodeDefault,
        }];

        let client_routes =
            sanitize_dataplane_routes_for_node_role(NodeRole::Client, routes.clone());
        let admin_routes = sanitize_dataplane_routes_for_node_role(NodeRole::Admin, routes);

        assert_eq!(client_routes.len(), 1);
        assert_eq!(client_routes[0].kind, RouteKind::ExitNodeDefault);
        assert_eq!(admin_routes.len(), 1);
        assert_eq!(admin_routes[0].kind, RouteKind::ExitNodeDefault);
    }

    #[test]
    fn daemon_runtime_enters_restricted_safe_mode_without_trust_evidence() {
        let test_dir = secure_test_dir("rustynetd-runtime-restricted");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("missing.trust");
        let trust_verifier_path = test_dir.join("missing.trust.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path,
            trust_verifier_key_path: trust_verifier_path,
            trust_watermark_path,
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let response = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!response.ok);
        assert!(response.message.contains("restricted-safe"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_denies_exit_selection_for_revoked_membership_node() {
        let test_dir = secure_test_dir("rustynetd-runtime-membership-revoked");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files_with_exit_status(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
            MembershipNodeStatus::Revoked,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: false,
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(denied.message.contains("not active in membership state"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_rejects_replayed_trust_evidence() {
        let test_dir = secure_test_dir("rustynetd-runtime-replay");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        write_trust_file(&trust_path, &trust_verifier_path, 2);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        persist_trust_watermark(
            &trust_watermark_path,
            TrustWatermark {
                updated_at_unix: unix_now(),
                nonce: 3,
                payload_digest: Some([0u8; 32]),
            },
        )
        .expect("watermark should be persisted");

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let response = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!response.ok);
        assert!(response.message.contains("restricted-safe"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_enforcement_applies_and_blocks_manual_mutations() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("auto_tunnel_enforce=true"));
        assert!(status.message.contains("last_assignment="));

        let denied = runtime.handle_command(IpcCommand::ExitNodeSelect("node-exit".to_string()));
        assert!(!denied.ok);
        assert!(
            denied
                .message
                .contains("disabled while auto-tunnel is enforced")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_allows_exit_service_advertise_only() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-exit-service");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file_exitless(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            2,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let allowed = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(allowed.ok);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("serving_exit_node=true"));

        let denied =
            runtime.handle_command(IpcCommand::RouteAdvertise("192.168.1.0/24".to_string()));
        assert!(!denied.ok);
        assert!(
            denied
                .message
                .contains("disabled while auto-tunnel is enforced")
        );

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_allows_relay_exit_with_upstream_exit() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-relay-with-upstream");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");
        let traversal_path = test_dir.join("traversal.bundle");
        let traversal_verifier_path = test_dir.join("traversal.verifier.pub");
        let traversal_watermark_path = test_dir.join("traversal.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        // Includes an exit-default route, so selected_exit_node is present in assignment state.
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            5,
            false,
        );
        write_traversal_file(
            &traversal_path,
            &traversal_verifier_path,
            "daemon-local",
            "node-exit",
            6,
            false,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            traversal_bundle_path: traversal_path.clone(),
            traversal_verifier_key_path: traversal_verifier_path.clone(),
            traversal_watermark_path: traversal_watermark_path.clone(),
            backend_mode: DaemonBackendMode::InMemory,
            node_role: NodeRole::Admin,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let enabled = runtime.handle_command(IpcCommand::RouteAdvertise("0.0.0.0/0".to_string()));
        assert!(enabled.ok);

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("exit_node=node-exit"));
        assert!(status.message.contains("serving_exit_node=true"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_file(traversal_path);
        let _ = std::fs::remove_file(traversal_verifier_path);
        let _ = std::fs::remove_file(traversal_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn daemon_runtime_auto_tunnel_tamper_and_replay_fail_closed() {
        let test_dir = secure_test_dir("rustynetd-runtime-auto-tunnel-reject");
        let state_path = test_dir.join("daemon.state");
        let trust_path = test_dir.join("trust.evidence");
        let trust_verifier_path = test_dir.join("trust.verifier.pub");
        let trust_watermark_path = test_dir.join("trust.watermark");
        let membership_snapshot_path = test_dir.join("membership.snapshot");
        let membership_log_path = test_dir.join("membership.log");
        let membership_watermark_path = test_dir.join("membership.watermark");
        let assignment_path = test_dir.join("assignment.bundle");
        let assignment_verifier_path = test_dir.join("assignment.verifier.pub");
        let assignment_watermark_path = test_dir.join("assignment.watermark");

        write_trust_file(&trust_path, &trust_verifier_path, 1);
        write_membership_files(
            &membership_snapshot_path,
            &membership_log_path,
            "daemon-local",
        );
        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            1,
            true,
        );

        let config = DaemonConfig {
            state_path: state_path.clone(),
            trust_evidence_path: trust_path.clone(),
            trust_verifier_key_path: trust_verifier_path.clone(),
            trust_watermark_path: trust_watermark_path.clone(),
            membership_snapshot_path: membership_snapshot_path.clone(),
            membership_log_path: membership_log_path.clone(),
            membership_watermark_path: membership_watermark_path.clone(),
            auto_tunnel_enforce: true,
            auto_tunnel_bundle_path: Some(assignment_path.clone()),
            auto_tunnel_verifier_key_path: Some(assignment_verifier_path.clone()),
            auto_tunnel_watermark_path: Some(assignment_watermark_path.clone()),
            backend_mode: DaemonBackendMode::InMemory,
            ..DaemonConfig::default()
        };
        let mut runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        runtime.bootstrap();

        let status = runtime.handle_command(IpcCommand::Status);
        assert!(status.ok);
        assert!(status.message.contains("restricted_safe_mode=true"));

        let denied = runtime.handle_command(IpcCommand::ExitNodeOff);
        assert!(!denied.ok);
        assert!(denied.message.contains("restricted-safe"));

        write_auto_tunnel_file(
            &assignment_path,
            &assignment_verifier_path,
            "daemon-local",
            2,
            false,
        );
        persist_auto_tunnel_watermark(
            &assignment_watermark_path,
            AutoTunnelWatermark {
                generated_at_unix: unix_now().saturating_add(10),
                nonce: 99,
                payload_digest: Some([0xabu8; 32]),
            },
        )
        .expect("assignment watermark should be persisted");
        let mut replay_runtime = DaemonRuntime::new(&config).expect("runtime should be created");
        replay_runtime.bootstrap();

        let replay_status = replay_runtime.handle_command(IpcCommand::Status);
        assert!(replay_status.ok);
        assert!(replay_status.message.contains("restricted_safe_mode=true"));

        let _ = std::fs::remove_file(state_path);
        let _ = std::fs::remove_file(trust_path);
        let _ = std::fs::remove_file(trust_verifier_path);
        let _ = std::fs::remove_file(trust_watermark_path);
        let _ = std::fs::remove_file(membership_snapshot_path);
        let _ = std::fs::remove_file(membership_log_path);
        let _ = std::fs::remove_file(membership_watermark_path);
        let _ = std::fs::remove_file(assignment_path);
        let _ = std::fs::remove_file(assignment_verifier_path);
        let _ = std::fs::remove_file(assignment_watermark_path);
        let _ = std::fs::remove_dir_all(test_dir);
    }

    #[test]
    fn state_fetcher_new_from_daemon_discards_remote_fetch_urls() {
        let config = DaemonConfig {
            trust_url: Some("http://127.0.0.1:8080/trust".to_string()),
            traversal_url: Some("http://127.0.0.1:8080/traversal".to_string()),
            assignment_url: Some("http://127.0.0.1:8080/assignment".to_string()),
            dns_zone_url: Some("http://127.0.0.1:8080/dns".to_string()),
            ..DaemonConfig::default()
        };

        let fetcher = StateFetcher::new_from_daemon(&config);

        assert!(fetcher.trust_url.is_none());
        assert!(fetcher.traversal_url.is_none());
        assert!(fetcher.assignment_url.is_none());
        assert!(fetcher.dns_zone_url.is_none());
    }
}
