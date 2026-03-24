#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::RngCore;
use rustynet_backend_api::{NodeId, SocketEndpoint};
use rustynet_control::SignedTraversalCoordinationRecord;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateSource {
    Host,
    ServerReflexive,
    Relay,
}

impl CandidateSource {
    fn direct_eligible(self) -> bool {
        !matches!(self, CandidateSource::Relay)
    }

    fn preference_score(self) -> u64 {
        match self {
            CandidateSource::Host => 300,
            CandidateSource::ServerReflexive => 200,
            CandidateSource::Relay => 100,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalCandidate {
    pub endpoint: SocketEndpoint,
    pub source: CandidateSource,
    pub priority: u32,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalEngineConfig {
    pub max_candidates: usize,
    pub max_probe_pairs: usize,
    pub simultaneous_open_rounds: u8,
    pub round_spacing_ms: u64,
    pub relay_switch_after_failures: u8,
    pub stun_servers: Vec<SocketAddr>,
    pub stun_gather_timeout_ms: u64,
    /// How many seconds before expiry to fire a proactive refresh (B3-a).
    pub pre_expiry_refresh_margin_secs: u64,
    /// Maximum jitter added to the proactive refresh window (B3-a).
    pub pre_expiry_jitter_max_secs: u64,
}

pub const DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES: usize = 8;
pub const DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS: usize = 24;
pub const DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS: u8 = 3;
pub const DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS: u64 = 80;
pub const DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES: u8 = 3;
pub const DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS: u64 = 2_000;
/// Default: refresh traversal hints 60 s before expiry (B3-a).
pub const DEFAULT_PRE_EXPIRY_REFRESH_MARGIN_SECS: u64 = 60;
/// Default: up to 15 s of random jitter on the proactive refresh timer (B3-a).
pub const DEFAULT_PRE_EXPIRY_JITTER_MAX_SECS: u64 = 15;

impl Default for TraversalEngineConfig {
    fn default() -> Self {
        Self {
            max_candidates: DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES,
            max_probe_pairs: DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS,
            simultaneous_open_rounds: DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS,
            round_spacing_ms: DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS,
            relay_switch_after_failures: DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES,
            stun_servers: Vec::new(),
            stun_gather_timeout_ms: DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS,
            pre_expiry_refresh_margin_secs: DEFAULT_PRE_EXPIRY_REFRESH_MARGIN_SECS,
            pre_expiry_jitter_max_secs: DEFAULT_PRE_EXPIRY_JITTER_MAX_SECS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraversalError {
    CandidateCountExceeded {
        side: &'static str,
        count: usize,
        max: usize,
    },
    DuplicateCandidate {
        side: &'static str,
        addr: IpAddr,
        port: u16,
        source: CandidateSource,
    },
    InvalidCandidatePort {
        side: &'static str,
    },
    NoDirectCandidates,
    InvalidConfig(&'static str),
    Stun(String),
    Coordination(String),
    CoordinationSignatureInvalid,
    CoordinationReplayDetected,
    CoordinationExpired,
    CoordinationFutureRejected,
    CoordinationNodeMismatch,
}

impl fmt::Display for TraversalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraversalError::CandidateCountExceeded { side, count, max } => {
                write!(
                    f,
                    "candidate count exceeded on {side}: count={count} max={max}"
                )
            }
            TraversalError::DuplicateCandidate {
                side,
                addr,
                port,
                source,
            } => write!(
                f,
                "duplicate candidate on {side}: addr={addr} port={port} source={source:?}"
            ),
            TraversalError::InvalidCandidatePort { side } => {
                write!(f, "invalid candidate port on {side}: port must be non-zero")
            }
            TraversalError::NoDirectCandidates => {
                f.write_str("no direct-eligible candidates available")
            }
            TraversalError::InvalidConfig(message) => {
                write!(f, "invalid traversal config: {message}")
            }
            TraversalError::Stun(message) => write!(f, "stun error: {message}"),
            TraversalError::Coordination(message) => write!(f, "coordination error: {message}"),
            TraversalError::CoordinationSignatureInvalid => {
                f.write_str("coordination signature verification failed")
            }
            TraversalError::CoordinationReplayDetected => {
                f.write_str("coordination nonce replay detected")
            }
            TraversalError::CoordinationExpired => f.write_str("coordination record is expired"),
            TraversalError::CoordinationFutureRejected => {
                f.write_str("coordination probe start exceeds max future skew")
            }
            TraversalError::CoordinationNodeMismatch => {
                f.write_str("coordination record does not include local and remote nodes")
            }
        }
    }
}

impl std::error::Error for TraversalError {}

const STUN_BINDING_REQUEST_TYPE: u16 = 0x0001;
const STUN_BINDING_RESPONSE_TYPE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub type CandidateType = CandidateSource;

#[derive(Debug)]
pub struct CandidateGatherer {
    local_socket: UdpSocket,
    stun_servers: Vec<SocketAddr>,
    timeout: Duration,
    host_candidates: Vec<SocketEndpoint>,
    rustynet_interface_addrs: BTreeSet<IpAddr>,
}

impl CandidateGatherer {
    pub fn new(
        local_socket: UdpSocket,
        stun_servers: Vec<SocketAddr>,
        timeout: Duration,
        host_candidates: Vec<SocketEndpoint>,
        rustynet_interface_addrs: Vec<IpAddr>,
    ) -> Result<Self, TraversalError> {
        if timeout.is_zero() {
            return Err(TraversalError::InvalidConfig(
                "stun_gather_timeout_ms must be greater than zero",
            ));
        }
        local_socket.set_nonblocking(false).map_err(|err| {
            TraversalError::Stun(format!("failed to configure stun socket: {err}"))
        })?;
        Ok(Self {
            local_socket,
            stun_servers,
            timeout,
            host_candidates,
            rustynet_interface_addrs: rustynet_interface_addrs.into_iter().collect(),
        })
    }

    pub fn gather(&self) -> Vec<TraversalCandidate> {
        self.gather_with_observed_at(now_unix_secs())
    }

    fn gather_with_observed_at(&self, observed_at_unix: u64) -> Vec<TraversalCandidate> {
        let mut candidates = Vec::new();
        let host_priority = 900;
        let srflx_priority = 850;

        if let Ok(bound_addr) = self.local_socket.local_addr() {
            let endpoint = SocketEndpoint {
                addr: bound_addr.ip(),
                port: bound_addr.port(),
            };
            if is_candidate_endpoint_allowed(endpoint, &self.rustynet_interface_addrs) {
                candidates.push(TraversalCandidate {
                    endpoint,
                    source: CandidateSource::Host,
                    priority: host_priority,
                    observed_at_unix,
                });
            }
        }

        for endpoint in &self.host_candidates {
            if is_candidate_endpoint_allowed(*endpoint, &self.rustynet_interface_addrs) {
                candidates.push(TraversalCandidate {
                    endpoint: *endpoint,
                    source: CandidateSource::Host,
                    priority: host_priority,
                    observed_at_unix,
                });
            }
        }

        let deadline = Instant::now() + self.timeout;
        for server in &self.stun_servers {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                break;
            }
            if let Ok(endpoint) = self.query_stun_server(*server, remaining)
                && is_candidate_endpoint_allowed(endpoint, &self.rustynet_interface_addrs)
            {
                candidates.push(TraversalCandidate {
                    endpoint,
                    source: CandidateSource::ServerReflexive,
                    priority: srflx_priority,
                    observed_at_unix,
                });
            }
        }

        dedup_candidates(candidates)
    }

    fn query_stun_server(
        &self,
        server: SocketAddr,
        timeout: Duration,
    ) -> Result<SocketEndpoint, TraversalError> {
        let mut transaction_id = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(transaction_id.as_mut_slice());
        let request = build_stun_binding_request(transaction_id);
        self.local_socket
            .set_read_timeout(Some(timeout))
            .map_err(|err| {
                TraversalError::Stun(format!("failed to set stun read timeout: {err}"))
            })?;
        self.local_socket
            .set_write_timeout(Some(timeout))
            .map_err(|err| {
                TraversalError::Stun(format!("failed to set stun write timeout: {err}"))
            })?;
        self.local_socket
            .send_to(request.as_slice(), server)
            .map_err(|err| TraversalError::Stun(format!("failed to send stun request: {err}")))?;

        let mut buffer = [0u8; 1500];
        let receive_started = Instant::now();
        loop {
            match self.local_socket.recv_from(&mut buffer) {
                Ok((received, _source)) => {
                    return parse_stun_xor_mapped_address(
                        buffer[..received].as_ref(),
                        transaction_id,
                    )
                    .map(|addr| SocketEndpoint {
                        addr: addr.ip(),
                        port: addr.port(),
                    });
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(TraversalError::Stun("stun response timed out".to_string()));
                }
                Err(err) => {
                    if receive_started.elapsed() >= timeout {
                        return Err(TraversalError::Stun("stun response timed out".to_string()));
                    }
                    return Err(TraversalError::Stun(format!(
                        "failed to receive stun response: {err}"
                    )));
                }
            }
        }
    }
}

fn is_candidate_endpoint_allowed(
    endpoint: SocketEndpoint,
    rustynet_interface_addrs: &BTreeSet<IpAddr>,
) -> bool {
    if endpoint.port == 0 {
        return false;
    }
    let ip = endpoint.addr;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(value) => {
            if value.is_link_local() || value.is_broadcast() {
                return false;
            }
        }
        IpAddr::V6(value) => {
            if value.is_unicast_link_local() {
                return false;
            }
        }
    }
    !rustynet_interface_addrs.contains(&ip)
}

fn dedup_candidates(mut candidates: Vec<TraversalCandidate>) -> Vec<TraversalCandidate> {
    candidates.sort_by(|left, right| {
        left.endpoint
            .addr
            .cmp(&right.endpoint.addr)
            .then(left.endpoint.port.cmp(&right.endpoint.port))
            .then(left.source.cmp(&right.source))
            .then(right.priority.cmp(&left.priority))
            .then(right.observed_at_unix.cmp(&left.observed_at_unix))
    });

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in candidates {
        let key = (
            candidate.endpoint.addr,
            candidate.endpoint.port,
            candidate.source,
        );
        if seen.insert(key) {
            deduped.push(candidate);
        }
    }
    deduped
}

fn build_stun_binding_request(transaction_id: [u8; 12]) -> [u8; 20] {
    let mut request = [0u8; 20];
    request[0..2].copy_from_slice(&STUN_BINDING_REQUEST_TYPE.to_be_bytes());
    request[2..4].copy_from_slice(&0u16.to_be_bytes());
    request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    request[8..20].copy_from_slice(transaction_id.as_slice());
    request
}

fn parse_stun_xor_mapped_address(
    message: &[u8],
    transaction_id: [u8; 12],
) -> Result<SocketAddr, TraversalError> {
    if message.len() < 20 {
        return Err(TraversalError::Stun(
            "stun message is shorter than header".to_string(),
        ));
    }
    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type != STUN_BINDING_RESPONSE_TYPE {
        return Err(TraversalError::Stun(
            "stun message is not a binding response".to_string(),
        ));
    }
    let declared_len = usize::from(u16::from_be_bytes([message[2], message[3]]));
    let expected_len = 20usize.saturating_add(declared_len);
    if expected_len > message.len() {
        return Err(TraversalError::Stun(
            "stun message is truncated".to_string(),
        ));
    }
    let cookie = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(TraversalError::Stun(
            "stun magic cookie mismatch".to_string(),
        ));
    }
    if message[8..20] != transaction_id {
        return Err(TraversalError::Stun(
            "stun transaction id mismatch".to_string(),
        ));
    }

    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
    let mut offset = 20usize;
    while offset.saturating_add(4) <= expected_len {
        let attr_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([
            message[offset + 2],
            message[offset + 3],
        ]));
        offset = offset.saturating_add(4);
        let attr_end = offset.saturating_add(attr_len);
        if attr_end > expected_len {
            return Err(TraversalError::Stun(
                "stun attribute exceeds message boundary".to_string(),
            ));
        }
        let value = &message[offset..attr_end];
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            if attr_len < 8 {
                return Err(TraversalError::Stun(
                    "xor-mapped-address attribute too short".to_string(),
                ));
            }
            let family = value[1];
            let x_port = u16::from_be_bytes([value[2], value[3]]);
            let port_mask = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);
            let port = x_port ^ port_mask;
            let endpoint = match family {
                0x01 => {
                    if attr_len < 8 {
                        return Err(TraversalError::Stun(
                            "xor-mapped-address ipv4 attribute too short".to_string(),
                        ));
                    }
                    let mut addr = [0u8; 4];
                    for (index, slot) in addr.iter_mut().enumerate() {
                        *slot = value[4 + index] ^ cookie_bytes[index];
                    }
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::from(addr)), port)
                }
                0x02 => {
                    if attr_len < 20 {
                        return Err(TraversalError::Stun(
                            "xor-mapped-address ipv6 attribute too short".to_string(),
                        ));
                    }
                    let mut addr = [0u8; 16];
                    for (index, slot) in addr.iter_mut().enumerate() {
                        let mask = if index < 4 {
                            cookie_bytes[index]
                        } else {
                            transaction_id[index - 4]
                        };
                        *slot = value[4 + index] ^ mask;
                    }
                    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(addr)), port)
                }
                _ => {
                    return Err(TraversalError::Stun(
                        "xor-mapped-address has unsupported address family".to_string(),
                    ));
                }
            };
            return Ok(endpoint);
        }
        let padded_len = (attr_len + 3) & !3;
        offset = offset.saturating_add(padded_len);
    }

    Err(TraversalError::Stun(
        "stun response does not contain xor-mapped-address".to_string(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCoordinationPayload {
    session_id: [u8; 16],
    probe_start_unix: u64,
    node_a: String,
    node_b: String,
    issued_at_unix: u64,
    expires_at_unix: u64,
    nonce: [u8; 16],
}

fn verify_coordination_record_signature(
    record: &SignedTraversalCoordinationRecord,
    endpoint_hint_verifier_key: &[u8; 32],
) -> Result<(), TraversalError> {
    let parsed = parse_coordination_payload(record.payload.as_str())?;
    if parsed.session_id != record.session_id
        || parsed.probe_start_unix != record.probe_start_unix
        || parsed.node_a != record.node_a
        || parsed.node_b != record.node_b
        || parsed.issued_at_unix != record.issued_at_unix
        || parsed.expires_at_unix != record.expires_at_unix
        || parsed.nonce != record.nonce
    {
        return Err(TraversalError::Coordination(
            "coordination payload/header mismatch".to_string(),
        ));
    }
    let canonical_payload = serialize_coordination_payload(&parsed);
    if canonical_payload != record.payload {
        return Err(TraversalError::Coordination(
            "coordination payload canonicalization mismatch".to_string(),
        ));
    }

    let signature_bytes = decode_hex_to_fixed::<64>(record.signature_hex.as_str())
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(endpoint_hint_verifier_key)
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)?;
    verifying_key
        .verify(record.payload.as_bytes(), &signature)
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)
}

fn parse_coordination_payload(payload: &str) -> Result<ParsedCoordinationPayload, TraversalError> {
    let mut fields = BTreeMap::<String, String>::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            TraversalError::Coordination("coordination payload line missing '='".to_string())
        })?;
        if key.trim().is_empty() {
            return Err(TraversalError::Coordination(
                "coordination payload key is empty".to_string(),
            ));
        }
        if fields.insert(key.to_string(), value.to_string()).is_some() {
            return Err(TraversalError::Coordination(format!(
                "coordination payload duplicate key: {key}"
            )));
        }
    }
    if fields.len() != 9 {
        return Err(TraversalError::Coordination(
            "coordination payload has unexpected field count".to_string(),
        ));
    }

    let version = fields.get("version").ok_or_else(|| {
        TraversalError::Coordination("coordination payload missing version".to_string())
    })?;
    if version != "1" {
        return Err(TraversalError::Coordination(
            "coordination payload version is unsupported".to_string(),
        ));
    }
    let payload_type = fields.get("type").ok_or_else(|| {
        TraversalError::Coordination("coordination payload missing type".to_string())
    })?;
    if payload_type != "traversal_coordination" {
        return Err(TraversalError::Coordination(
            "coordination payload type is unsupported".to_string(),
        ));
    }

    let session_id = decode_hex_to_fixed::<16>(
        fields
            .get("session_id")
            .ok_or_else(|| {
                TraversalError::Coordination("coordination payload missing session_id".to_string())
            })?
            .as_str(),
    )
    .map_err(|_| TraversalError::Coordination("coordination session_id is invalid".to_string()))?;
    let nonce = decode_hex_to_fixed::<16>(
        fields
            .get("nonce")
            .ok_or_else(|| {
                TraversalError::Coordination("coordination payload missing nonce".to_string())
            })?
            .as_str(),
    )
    .map_err(|_| TraversalError::Coordination("coordination nonce is invalid".to_string()))?;
    let probe_start_unix = parse_u64_field(&fields, "probe_start_unix")?;
    let issued_at_unix = parse_u64_field(&fields, "issued_at_unix")?;
    let expires_at_unix = parse_u64_field(&fields, "expires_at_unix")?;
    let node_a = fields
        .get("node_a")
        .ok_or_else(|| {
            TraversalError::Coordination("coordination payload missing node_a".to_string())
        })?
        .trim()
        .to_string();
    let node_b = fields
        .get("node_b")
        .ok_or_else(|| {
            TraversalError::Coordination("coordination payload missing node_b".to_string())
        })?
        .trim()
        .to_string();
    if node_a.is_empty() || node_b.is_empty() {
        return Err(TraversalError::Coordination(
            "coordination payload node ids must not be empty".to_string(),
        ));
    }
    Ok(ParsedCoordinationPayload {
        session_id,
        probe_start_unix,
        node_a,
        node_b,
        issued_at_unix,
        expires_at_unix,
        nonce,
    })
}

fn parse_u64_field(fields: &BTreeMap<String, String>, name: &str) -> Result<u64, TraversalError> {
    fields
        .get(name)
        .ok_or_else(|| {
            TraversalError::Coordination(format!("coordination payload missing {name}"))
        })?
        .parse::<u64>()
        .map_err(|_| TraversalError::Coordination(format!("coordination payload invalid {name}")))
}

fn serialize_coordination_payload(payload: &ParsedCoordinationPayload) -> String {
    let mut out = String::new();
    out.push_str("version=1\n");
    out.push_str("type=traversal_coordination\n");
    out.push_str(&format!(
        "session_id={}\n",
        encode_hex(payload.session_id.as_slice())
    ));
    out.push_str(&format!("probe_start_unix={}\n", payload.probe_start_unix));
    out.push_str(&format!("node_a={}\n", payload.node_a.trim()));
    out.push_str(&format!("node_b={}\n", payload.node_b.trim()));
    out.push_str(&format!("issued_at_unix={}\n", payload.issued_at_unix));
    out.push_str(&format!("expires_at_unix={}\n", payload.expires_at_unix));
    out.push_str(&format!("nonce={}\n", encode_hex(payload.nonce.as_slice())));
    out
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex_to_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], ()> {
    let mut bytes = [0u8; N];
    let trimmed = encoded.trim();
    if trimmed.len() != N * 2 {
        return Err(());
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

fn decode_hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}

pub const MAX_COORDINATION_TTL_SECS: u64 = 30;
pub const MAX_COORDINATION_FUTURE_START_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDecisionReason {
    SimultaneousOpenHandshakeObserved,
    NoDirectCandidatesRelayArmed,
    DirectProbeExhaustedRelayArmed,
    DirectProbeExhaustedFailClosed,
}

impl TraversalDecisionReason {
    pub fn as_str(self) -> &'static str {
        match self {
            TraversalDecisionReason::SimultaneousOpenHandshakeObserved => {
                "simultaneous_open_handshake_observed"
            }
            TraversalDecisionReason::NoDirectCandidatesRelayArmed => {
                "no_direct_candidates_relay_armed"
            }
            TraversalDecisionReason::DirectProbeExhaustedRelayArmed => {
                "direct_probe_exhausted_relay_armed"
            }
            TraversalDecisionReason::DirectProbeExhaustedFailClosed => {
                "direct_probe_exhausted_fail_closed"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDecision {
    Direct {
        endpoint: SocketEndpoint,
        reason: TraversalDecisionReason,
    },
    Relay {
        endpoint: SocketEndpoint,
        reason: TraversalDecisionReason,
        rounds: u8,
    },
    FailClosed {
        reason: TraversalDecisionReason,
        rounds: u8,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimultaneousOpenResult {
    pub decision: TraversalDecision,
    pub attempts: usize,
    pub latest_handshake_unix: Option<u64>,
    pub waited_for_start: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinationSchedule {
    pub session_id: [u8; 16],
    pub nonce: [u8; 16],
    pub probe_start_unix: u64,
    pub wait_duration: Duration,
}

#[derive(Debug, Clone, Default)]
pub struct CoordinationReplayWindow {
    seen_nonces: BTreeMap<[u8; 16], u64>,
}

impl CoordinationReplayWindow {
    pub fn verify_and_record(
        &mut self,
        nonce: [u8; 16],
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<(), TraversalError> {
        self.seen_nonces.retain(|_, expires| *expires >= now_unix);
        if self.seen_nonces.contains_key(&nonce) {
            return Err(TraversalError::CoordinationReplayDetected);
        }
        self.seen_nonces.insert(nonce, expires_at_unix);
        Ok(())
    }
}

pub trait SimultaneousOpenRuntime {
    fn send_probe(&mut self, endpoint: SocketEndpoint, round: u8) -> Result<(), TraversalError>;
    fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError>;
}

pub trait SimultaneousOpenWaiter {
    fn wait(&mut self, duration: Duration);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleepWaiter;

impl SimultaneousOpenWaiter for ThreadSleepWaiter {
    fn wait(&mut self, duration: Duration) {
        if !duration.is_zero() {
            std::thread::sleep(duration);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMappingBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatFilteringBehavior {
    EndpointIndependent,
    AddressDependent,
    AddressAndPortDependent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatProfile {
    pub mapping: NatMappingBehavior,
    pub filtering: NatFilteringBehavior,
    pub preserves_port: bool,
}

impl NatProfile {
    pub fn is_symmetric(self) -> bool {
        matches!(self.mapping, NatMappingBehavior::AddressAndPortDependent)
    }

    fn is_hard_nat(self) -> bool {
        matches!(
            self.filtering,
            NatFilteringBehavior::AddressAndPortDependent
        ) || self.is_symmetric()
    }
}

pub fn direct_udp_viable(local: NatProfile, remote: NatProfile) -> bool {
    if local.is_symmetric() && remote.is_symmetric() {
        return false;
    }
    if local.is_hard_nat() && remote.is_hard_nat() {
        return false;
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePair {
    pub local: TraversalCandidate,
    pub remote: TraversalCandidate,
    pub round: u8,
    pub delay_ms: u64,
    pub score: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbePlan {
    pub pairs: Vec<ProbePair>,
}

impl ProbePlan {
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProbe {
    pub remote: TraversalCandidate,
    pub round: u8,
    pub delay_ms: u64,
    pub score: u64,
    pub attempt_ordinal: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteProbePlan {
    pub attempts: Vec<RemoteProbe>,
}

impl RemoteProbePlan {
    pub fn is_empty(&self) -> bool {
        self.attempts.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMode {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    SessionBoot,
    DirectProbeSuccess,
    DirectProbeTimeout,
    EndpointRoamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionEvent {
    pub from: PathMode,
    pub to: PathMode,
    pub reason: TransitionReason,
    pub at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalSession {
    pub peer_node_id: NodeId,
    pub path: PathMode,
    pub active_endpoint: Option<SocketEndpoint>,
    pub consecutive_direct_failures: u8,
    pub last_transition: TransitionEvent,
    pub last_keepalive_unix: Option<u64>,
}

impl TraversalSession {
    pub fn new(peer_node_id: NodeId, now_unix: u64) -> Self {
        Self {
            peer_node_id,
            path: PathMode::Relay,
            active_endpoint: None,
            consecutive_direct_failures: 0,
            last_transition: TransitionEvent {
                from: PathMode::Relay,
                to: PathMode::Relay,
                reason: TransitionReason::SessionBoot,
                at_unix: now_unix,
            },
            last_keepalive_unix: None,
        }
    }

    pub fn on_direct_probe_success(
        &mut self,
        endpoint: SocketEndpoint,
        now_unix: u64,
    ) -> TransitionEvent {
        let previous = self.path;
        self.path = PathMode::Direct;
        self.active_endpoint = Some(endpoint);
        self.consecutive_direct_failures = 0;
        let event = TransitionEvent {
            from: previous,
            to: PathMode::Direct,
            reason: TransitionReason::DirectProbeSuccess,
            at_unix: now_unix,
        };
        self.last_transition = event;
        event
    }

    pub fn on_direct_probe_timeout(
        &mut self,
        now_unix: u64,
        config: TraversalEngineConfig,
    ) -> Option<TransitionEvent> {
        self.consecutive_direct_failures = self.consecutive_direct_failures.saturating_add(1);
        if self.consecutive_direct_failures < config.relay_switch_after_failures {
            return None;
        }
        let previous = self.path;
        self.path = PathMode::Relay;
        let event = TransitionEvent {
            from: previous,
            to: PathMode::Relay,
            reason: TransitionReason::DirectProbeTimeout,
            at_unix: now_unix,
        };
        self.last_transition = event;
        Some(event)
    }

    pub fn on_endpoint_roamed(
        &mut self,
        new_endpoint: SocketEndpoint,
        now_unix: u64,
    ) -> Option<TransitionEvent> {
        let existing = self.active_endpoint;
        self.active_endpoint = Some(new_endpoint);
        if self.path != PathMode::Direct || existing == Some(new_endpoint) {
            return None;
        }
        let event = TransitionEvent {
            from: PathMode::Direct,
            to: PathMode::Direct,
            reason: TransitionReason::EndpointRoamed,
            at_unix: now_unix,
        };
        self.last_transition = event;
        Some(event)
    }

    pub fn recommended_keepalive_secs(nat_profile: NatProfile) -> u64 {
        if nat_profile.is_hard_nat() || !nat_profile.preserves_port {
            15
        } else {
            25
        }
    }

    pub fn should_send_keepalive(&self, now_unix: u64, nat_profile: NatProfile) -> bool {
        let interval = Self::recommended_keepalive_secs(nat_profile);
        let Some(last) = self.last_keepalive_unix else {
            return true;
        };
        now_unix.saturating_sub(last) >= interval
    }

    pub fn mark_keepalive_sent(&mut self, now_unix: u64) {
        self.last_keepalive_unix = Some(now_unix);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraversalEngine {
    pub config: TraversalEngineConfig,
}

impl TraversalEngine {
    pub fn new(config: TraversalEngineConfig) -> Result<Self, TraversalError> {
        if config.max_candidates == 0 {
            return Err(TraversalError::InvalidConfig(
                "max_candidates must be greater than zero",
            ));
        }
        if config.max_probe_pairs == 0 {
            return Err(TraversalError::InvalidConfig(
                "max_probe_pairs must be greater than zero",
            ));
        }
        if config.simultaneous_open_rounds == 0 {
            return Err(TraversalError::InvalidConfig(
                "simultaneous_open_rounds must be greater than zero",
            ));
        }
        if config.round_spacing_ms == 0 {
            return Err(TraversalError::InvalidConfig(
                "round_spacing_ms must be greater than zero",
            ));
        }
        if config.relay_switch_after_failures == 0 {
            return Err(TraversalError::InvalidConfig(
                "relay_switch_after_failures must be greater than zero",
            ));
        }
        Ok(Self { config })
    }

    pub fn plan_direct_probes(
        &self,
        local_candidates: &[TraversalCandidate],
        remote_candidates: &[TraversalCandidate],
    ) -> Result<ProbePlan, TraversalError> {
        validate_candidates("local", local_candidates, self.config)?;
        validate_candidates("remote", remote_candidates, self.config)?;

        let local_direct = local_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect::<Vec<_>>();
        let remote_direct = remote_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect::<Vec<_>>();

        if local_direct.is_empty() || remote_direct.is_empty() {
            return Err(TraversalError::NoDirectCandidates);
        }

        let mut base_pairs = Vec::new();
        for local in &local_direct {
            for remote in &remote_direct {
                let score = score_pair(*local, *remote);
                base_pairs.push((*local, *remote, score));
            }
        }
        base_pairs.sort_by(|left, right| right.2.cmp(&left.2));
        base_pairs.truncate(self.config.max_probe_pairs);

        let mut plan_pairs = Vec::new();
        for round in 0..self.config.simultaneous_open_rounds {
            let delay_ms = self
                .config
                .round_spacing_ms
                .saturating_mul(u64::from(round));
            for (local, remote, score) in &base_pairs {
                plan_pairs.push(ProbePair {
                    local: *local,
                    remote: *remote,
                    round,
                    delay_ms,
                    score: *score,
                });
            }
        }

        Ok(ProbePlan { pairs: plan_pairs })
    }

    pub fn plan_remote_probes(
        &self,
        remote_candidates: &[TraversalCandidate],
    ) -> Result<RemoteProbePlan, TraversalError> {
        validate_candidates("remote", remote_candidates, self.config)?;

        let mut direct_candidates = remote_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect::<Vec<_>>();
        if direct_candidates.is_empty() {
            return Err(TraversalError::NoDirectCandidates);
        }
        direct_candidates.sort_by(|left, right| {
            score_candidate(*right)
                .cmp(&score_candidate(*left))
                .then_with(|| right.priority.cmp(&left.priority))
        });
        direct_candidates.truncate(self.config.max_probe_pairs);

        let mut attempts = Vec::new();
        for round in 0..self.config.simultaneous_open_rounds {
            let delay_ms = self
                .config
                .round_spacing_ms
                .saturating_mul(u64::from(round));
            for candidate in &direct_candidates {
                attempts.push(RemoteProbe {
                    remote: *candidate,
                    round,
                    delay_ms,
                    score: score_candidate(*candidate),
                    attempt_ordinal: attempts.len().saturating_add(1),
                });
            }
        }

        Ok(RemoteProbePlan { attempts })
    }

    pub fn validate_signed_coordination_record(
        &self,
        record: &SignedTraversalCoordinationRecord,
        local_node_id: &NodeId,
        remote_node_id: &NodeId,
        endpoint_hint_verifier_key: &[u8; 32],
        replay_window: &mut CoordinationReplayWindow,
        now_unix: u64,
    ) -> Result<CoordinationSchedule, TraversalError> {
        if record.issued_at_unix >= record.expires_at_unix {
            return Err(TraversalError::Coordination(
                "coordination expires_at_unix must be greater than issued_at_unix".to_string(),
            ));
        }
        if record.expires_at_unix.saturating_sub(record.issued_at_unix) > MAX_COORDINATION_TTL_SECS
        {
            return Err(TraversalError::Coordination(
                "coordination ttl exceeds max supported value".to_string(),
            ));
        }
        if now_unix > record.expires_at_unix {
            return Err(TraversalError::CoordinationExpired);
        }

        let wait_secs = record.probe_start_unix.saturating_sub(now_unix);
        if wait_secs > MAX_COORDINATION_FUTURE_START_SECS {
            return Err(TraversalError::CoordinationFutureRejected);
        }

        let local = local_node_id.as_str();
        let remote = remote_node_id.as_str();
        let direct_match = record.node_a.trim() == local && record.node_b.trim() == remote;
        let reverse_match = record.node_a.trim() == remote && record.node_b.trim() == local;
        if !(direct_match || reverse_match) {
            return Err(TraversalError::CoordinationNodeMismatch);
        }

        verify_coordination_record_signature(record, endpoint_hint_verifier_key)?;
        replay_window.verify_and_record(record.nonce, record.expires_at_unix, now_unix)?;
        Ok(CoordinationSchedule {
            session_id: record.session_id,
            nonce: record.nonce,
            probe_start_unix: record.probe_start_unix,
            wait_duration: Duration::from_secs(wait_secs),
        })
    }

    pub fn execute_simultaneous_open<R: SimultaneousOpenRuntime, W: SimultaneousOpenWaiter>(
        &self,
        runtime: &mut R,
        waiter: &mut W,
        schedule: CoordinationSchedule,
        direct_candidates: &[TraversalCandidate],
        relay_endpoint: Option<SocketEndpoint>,
        now_unix: u64,
        handshake_freshness_secs: u64,
    ) -> Result<SimultaneousOpenResult, TraversalError> {
        if handshake_freshness_secs == 0 {
            return Err(TraversalError::InvalidConfig(
                "handshake freshness window must be greater than zero",
            ));
        }
        waiter.wait(schedule.wait_duration);

        let plan = match self.plan_remote_probes(direct_candidates) {
            Ok(plan) => plan,
            Err(TraversalError::NoDirectCandidates) => {
                if let Some(endpoint) = relay_endpoint {
                    return Ok(SimultaneousOpenResult {
                        decision: TraversalDecision::Relay {
                            endpoint,
                            reason: TraversalDecisionReason::NoDirectCandidatesRelayArmed,
                            rounds: 0,
                        },
                        attempts: 0,
                        latest_handshake_unix: runtime.latest_handshake_unix()?,
                        waited_for_start: schedule.wait_duration,
                    });
                }
                return Ok(SimultaneousOpenResult {
                    decision: TraversalDecision::FailClosed {
                        reason: TraversalDecisionReason::DirectProbeExhaustedFailClosed,
                        rounds: 0,
                    },
                    attempts: 0,
                    latest_handshake_unix: runtime.latest_handshake_unix()?,
                    waited_for_start: schedule.wait_duration,
                });
            }
            Err(err) => return Err(err),
        };

        let mut observed_latest = runtime.latest_handshake_unix()?;
        for attempt in &plan.attempts {
            runtime.send_probe(attempt.remote.endpoint, attempt.round)?;
            let latest = runtime.latest_handshake_unix()?;
            if handshake_advanced(observed_latest, latest)
                && handshake_is_fresh(latest, now_unix, handshake_freshness_secs)
            {
                return Ok(SimultaneousOpenResult {
                    decision: TraversalDecision::Direct {
                        endpoint: attempt.remote.endpoint,
                        reason: TraversalDecisionReason::SimultaneousOpenHandshakeObserved,
                    },
                    attempts: attempt.attempt_ordinal,
                    latest_handshake_unix: latest,
                    waited_for_start: schedule.wait_duration,
                });
            }
            observed_latest = match (observed_latest, latest) {
                (Some(left), Some(right)) => Some(left.max(right)),
                (Some(value), None) => Some(value),
                (None, Some(value)) => Some(value),
                (None, None) => None,
            };
        }

        if let Some(endpoint) = relay_endpoint {
            return Ok(SimultaneousOpenResult {
                decision: TraversalDecision::Relay {
                    endpoint,
                    reason: TraversalDecisionReason::DirectProbeExhaustedRelayArmed,
                    rounds: self.config.simultaneous_open_rounds,
                },
                attempts: plan.attempts.len(),
                latest_handshake_unix: observed_latest,
                waited_for_start: schedule.wait_duration,
            });
        }

        Ok(SimultaneousOpenResult {
            decision: TraversalDecision::FailClosed {
                reason: TraversalDecisionReason::DirectProbeExhaustedFailClosed,
                rounds: self.config.simultaneous_open_rounds,
            },
            attempts: plan.attempts.len(),
            latest_handshake_unix: observed_latest,
            waited_for_start: schedule.wait_duration,
        })
    }
}

fn validate_candidates(
    side: &'static str,
    candidates: &[TraversalCandidate],
    config: TraversalEngineConfig,
) -> Result<(), TraversalError> {
    if candidates.len() > config.max_candidates {
        return Err(TraversalError::CandidateCountExceeded {
            side,
            count: candidates.len(),
            max: config.max_candidates,
        });
    }

    let mut seen = BTreeSet::new();
    for candidate in candidates {
        if candidate.endpoint.port == 0 {
            return Err(TraversalError::InvalidCandidatePort { side });
        }
        let key = (
            candidate.endpoint.addr,
            candidate.endpoint.port,
            candidate.source,
        );
        if !seen.insert(key) {
            return Err(TraversalError::DuplicateCandidate {
                side,
                addr: candidate.endpoint.addr,
                port: candidate.endpoint.port,
                source: candidate.source,
            });
        }
    }

    Ok(())
}

fn score_pair(local: TraversalCandidate, remote: TraversalCandidate) -> u64 {
    u64::from(local.priority)
        .saturating_add(u64::from(remote.priority))
        .saturating_add(local.source.preference_score())
        .saturating_add(remote.source.preference_score())
}

fn score_candidate(candidate: TraversalCandidate) -> u64 {
    u64::from(candidate.priority).saturating_add(candidate.source.preference_score())
}

fn handshake_is_fresh(value: Option<u64>, now_unix: u64, freshness_secs: u64) -> bool {
    value
        .map(|timestamp| now_unix.saturating_sub(timestamp) <= freshness_secs)
        .unwrap_or(false)
}

fn handshake_advanced(previous: Option<u64>, current: Option<u64>) -> bool {
    match (previous, current) {
        (None, Some(_)) => true,
        (Some(before), Some(after)) => after > before,
        _ => false,
    }
}

// ─── B3-a: Proactive traversal refresh scheduling ────────────────────────────

/// Compute the `Instant` at which a proactive traversal refresh should fire.
///
/// The refresh is scheduled at `expires_at − margin + random_jitter`, where
/// `jitter ∈ [0, jitter_max_secs)`.  If that instant is already in the past
/// (or within 5 s of now) the function returns `Instant::now() + 5 s` so
/// the caller fires promptly without a negative-duration panic.
///
/// # Arguments
/// * `expires_at` – the expiry timestamp of the current traversal bundle.
/// * `margin_secs` – how many seconds before expiry to begin the refresh.
/// * `jitter_max_secs` – upper bound (exclusive) on random jitter seconds.
pub fn schedule_proactive_refresh(
    expires_at: SystemTime,
    margin_secs: u64,
    jitter_max_secs: u64,
) -> Instant {
    let jitter_secs = if jitter_max_secs > 0 {
        let mut buf = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        u64::from_le_bytes(buf) % jitter_max_secs
    } else {
        0
    };

    let margin = Duration::from_secs(margin_secs);
    let jitter = Duration::from_secs(jitter_secs);

    match expires_at.duration_since(SystemTime::now()) {
        Ok(remaining) if remaining > margin => {
            // Schedule `remaining − margin + jitter` from now (before expiry).
            Instant::now() + (remaining - margin) + jitter
        }
        _ => {
            // Already past the margin window — fire very soon.
            Instant::now() + Duration::from_secs(5)
        }
    }
}

// ─── B2-a: Endpoint mobility monitoring ──────────────────────────────────────

/// An address change detected on an underlay (non-tunnel) interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointChangeEvent {
    /// The interface whose routable addresses changed.
    pub interface: String,
    /// Previous routable addresses (empty if the interface just appeared).
    pub old_addrs: Vec<IpAddr>,
    /// Current routable addresses (empty if the interface disappeared).
    pub new_addrs: Vec<IpAddr>,
}

/// Poll-based endpoint change detector.
///
/// Tracks routable (non-loopback, non-link-local) addresses per underlay
/// interface.  Interfaces whose names start with a prefix listed in
/// `ignored_prefixes` are excluded — set this to `["rustynet"]` to prevent
/// the WireGuard tunnel address from triggering spurious events.
pub struct EndpointMonitor {
    last_seen_addrs: BTreeMap<String, Vec<IpAddr>>,
    ignored_prefixes: Vec<String>,
}

impl EndpointMonitor {
    /// Create a new monitor.
    pub fn new(ignored_prefixes: Vec<String>) -> Self {
        Self {
            last_seen_addrs: BTreeMap::new(),
            ignored_prefixes,
        }
    }

    /// Core change-detection logic given the *current* address snapshot.
    ///
    /// This method is intentionally `pub` so that tests can inject address
    /// maps directly without requiring OS calls.  Addresses that are
    /// loopback, link-local, or unspecified are filtered out.  Returns the
    /// first change found (one event per call) or `None` if nothing changed.
    pub fn poll_with_addrs(
        &mut self,
        current: BTreeMap<String, Vec<IpAddr>>,
    ) -> Option<EndpointChangeEvent> {
        // Apply interface prefix filter and drop non-routable addresses.
        let current_filtered: BTreeMap<String, Vec<IpAddr>> = current
            .into_iter()
            .filter(|(iface, _)| {
                !self
                    .ignored_prefixes
                    .iter()
                    .any(|pfx| iface.starts_with(pfx.as_str()))
            })
            .map(|(iface, addrs)| {
                let routable: Vec<IpAddr> = addrs
                    .into_iter()
                    .filter(|a| is_routable_address(*a))
                    .collect();
                (iface, routable)
            })
            .filter(|(_, addrs)| !addrs.is_empty())
            .collect();

        // Detect added or changed interfaces.
        for (iface, new_addrs) in &current_filtered {
            let old_addrs = self.last_seen_addrs.get(iface).cloned().unwrap_or_default();
            if &old_addrs != new_addrs {
                let event = EndpointChangeEvent {
                    interface: iface.clone(),
                    old_addrs,
                    new_addrs: new_addrs.clone(),
                };
                self.last_seen_addrs = current_filtered;
                return Some(event);
            }
        }

        // Detect removed interfaces.
        let removed: Vec<String> = self
            .last_seen_addrs
            .keys()
            .filter(|k| !current_filtered.contains_key(*k))
            .cloned()
            .collect();
        if let Some(iface) = removed.into_iter().next() {
            let old_addrs = self.last_seen_addrs.remove(&iface).unwrap_or_default();
            let event = EndpointChangeEvent {
                interface: iface,
                old_addrs,
                new_addrs: Vec::new(),
            };
            self.last_seen_addrs = current_filtered;
            return Some(event);
        }

        self.last_seen_addrs = current_filtered;
        None
    }
}

/// Returns `true` for addresses that are globally routable: not loopback,
/// not link-local, and not unspecified.
fn is_routable_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => !v4.is_loopback() && !v4.is_link_local() && !v4.is_unspecified(),
        IpAddr::V6(v6) => {
            !v6.is_loopback()
                && !v6.is_unspecified()
                // Reject link-local (fe80::/10).
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CandidateGatherer, CandidateSource, CoordinationReplayWindow, CoordinationSchedule,
        EndpointChangeEvent, EndpointMonitor, NatFilteringBehavior, NatMappingBehavior, NatProfile,
        PathMode, SimultaneousOpenResult, SimultaneousOpenRuntime, SimultaneousOpenWaiter,
        TraversalCandidate, TraversalDecision, TraversalDecisionReason, TraversalEngine,
        TraversalEngineConfig, TraversalError, TraversalSession, build_stun_binding_request,
        direct_udp_viable, parse_stun_xor_mapped_address, schedule_proactive_refresh,
    };
    use rustynet_backend_api::{NodeId, SocketEndpoint};
    use rustynet_control::{
        ControlPlaneCore, EndpointHintBundleRequest, EndpointHintCandidate,
        EndpointHintCandidateType, EnrollmentRequest, TraversalCoordinationRecord,
    };
    use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};
    use std::collections::BTreeMap;
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::sync::Mutex;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    fn endpoint(octets: [u8; 4], port: u16) -> SocketEndpoint {
        SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::from(octets)),
            port,
        }
    }

    fn candidate(
        octets: [u8; 4],
        port: u16,
        source: CandidateSource,
        priority: u32,
    ) -> TraversalCandidate {
        TraversalCandidate {
            endpoint: endpoint(octets, port),
            source,
            priority,
            observed_at_unix: 1_717_171_717,
        }
    }

    #[test]
    fn direct_plan_builds_simultaneous_rounds() {
        let engine = TraversalEngine::new(TraversalEngineConfig {
            max_candidates: 8,
            max_probe_pairs: 4,
            simultaneous_open_rounds: 3,
            round_spacing_ms: 100,
            relay_switch_after_failures: 3,
            ..TraversalEngineConfig::default()
        })
        .expect("engine config should be valid");

        let local = vec![
            candidate([10, 0, 0, 10], 51820, CandidateSource::Host, 900),
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                700,
            ),
        ];
        let remote = vec![
            candidate([10, 0, 0, 20], 51820, CandidateSource::Host, 950),
            candidate(
                [203, 0, 113, 20],
                63000,
                CandidateSource::ServerReflexive,
                650,
            ),
        ];

        let plan = engine
            .plan_direct_probes(local.as_slice(), remote.as_slice())
            .expect("probe plan should be generated");
        assert_eq!(plan.pairs.len(), 12);
        assert_eq!(plan.pairs[0].round, 0);
        assert_eq!(plan.pairs[0].delay_ms, 0);
        assert_eq!(plan.pairs[4].round, 1);
        assert_eq!(plan.pairs[4].delay_ms, 100);
        assert_eq!(plan.pairs[8].round, 2);
        assert_eq!(plan.pairs[8].delay_ms, 200);
    }

    #[test]
    fn direct_viability_rejects_double_symmetric_nat() {
        let symmetric = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        assert!(!direct_udp_viable(symmetric, symmetric));

        let easier = NatProfile {
            mapping: NatMappingBehavior::EndpointIndependent,
            filtering: NatFilteringBehavior::AddressDependent,
            preserves_port: true,
        };
        assert!(direct_udp_viable(symmetric, easier));
    }

    #[test]
    fn direct_session_survives_endpoint_roam() {
        let peer = NodeId::new("peer-1").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let first_endpoint = endpoint([198, 51, 100, 5], 55123);
        let second_endpoint = endpoint([198, 51, 100, 6], 55124);

        let event = session.on_direct_probe_success(first_endpoint, 120);
        assert_eq!(event.to, PathMode::Direct);
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(first_endpoint));

        let roam = session
            .on_endpoint_roamed(second_endpoint, 150)
            .expect("roam transition should be recorded");
        assert_eq!(roam.from, PathMode::Direct);
        assert_eq!(roam.to, PathMode::Direct);
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(second_endpoint));
    }

    #[test]
    fn keepalive_interval_is_tighter_for_hard_nat() {
        let hard_nat = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        let easy_nat = NatProfile {
            mapping: NatMappingBehavior::EndpointIndependent,
            filtering: NatFilteringBehavior::EndpointIndependent,
            preserves_port: true,
        };

        assert_eq!(TraversalSession::recommended_keepalive_secs(hard_nat), 15);
        assert_eq!(TraversalSession::recommended_keepalive_secs(easy_nat), 25);
    }

    #[test]
    fn candidate_validation_rejects_duplicates() {
        let engine =
            TraversalEngine::new(TraversalEngineConfig::default()).expect("config should be valid");
        let local = vec![
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                900,
            ),
            candidate(
                [198, 51, 100, 10],
                62000,
                CandidateSource::ServerReflexive,
                800,
            ),
        ];
        let remote = vec![candidate(
            [203, 0, 113, 20],
            63000,
            CandidateSource::ServerReflexive,
            900,
        )];

        let err = engine
            .plan_direct_probes(local.as_slice(), remote.as_slice())
            .expect_err("duplicate candidate should fail validation");
        assert!(err.to_string().contains("duplicate candidate"));
    }

    #[test]
    fn adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback() {
        let engine =
            TraversalEngine::new(TraversalEngineConfig::default()).expect("config should be valid");
        let relay_only_local = vec![candidate(
            [198, 51, 100, 10],
            62000,
            CandidateSource::Relay,
            900,
        )];
        let relay_only_remote = vec![candidate(
            [203, 0, 113, 20],
            63000,
            CandidateSource::Relay,
            900,
        )];
        let no_direct = engine
            .plan_direct_probes(relay_only_local.as_slice(), relay_only_remote.as_slice())
            .expect_err("relay-only candidate sets must never authorize direct path planning");
        assert!(matches!(no_direct, TraversalError::NoDirectCandidates));

        let hard_nat = NatProfile {
            mapping: NatMappingBehavior::AddressAndPortDependent,
            filtering: NatFilteringBehavior::AddressAndPortDependent,
            preserves_port: false,
        };
        assert!(
            !direct_udp_viable(hard_nat, hard_nat),
            "hard NAT mismatch must deny direct viability and require relay fallback"
        );

        let peer = NodeId::new("peer-nat-hard").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let fallback_config = TraversalEngineConfig {
            relay_switch_after_failures: 2,
            ..TraversalEngineConfig::default()
        };
        assert_eq!(session.path, PathMode::Relay);
        assert!(
            session
                .on_direct_probe_timeout(101, fallback_config)
                .is_none()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert!(
            session
                .on_direct_probe_timeout(102, fallback_config)
                .is_some()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert_eq!(session.active_endpoint, None);

        let direct_endpoint = endpoint([203, 0, 113, 21], 51820);
        session.on_direct_probe_success(direct_endpoint, 103);
        assert_eq!(session.path, PathMode::Direct);
        session.on_direct_probe_timeout(104, fallback_config);
        let failback = session
            .on_direct_probe_timeout(105, fallback_config)
            .expect("relay failback should trigger after configured direct probe failures");
        assert_eq!(failback.to, PathMode::Relay);
        assert_eq!(session.path, PathMode::Relay);
    }

    #[test]
    fn remote_probe_plan_prefers_higher_priority_direct_candidates() {
        let engine = TraversalEngine::new(TraversalEngineConfig {
            max_candidates: 8,
            max_probe_pairs: 2,
            simultaneous_open_rounds: 2,
            round_spacing_ms: 50,
            relay_switch_after_failures: 3,
            ..TraversalEngineConfig::default()
        })
        .expect("config should be valid");
        let candidates = vec![
            candidate(
                [203, 0, 113, 20],
                62000,
                CandidateSource::ServerReflexive,
                750,
            ),
            candidate([10, 0, 0, 20], 51820, CandidateSource::Host, 950),
            candidate(
                [203, 0, 113, 30],
                62001,
                CandidateSource::ServerReflexive,
                600,
            ),
        ];

        let plan = engine
            .plan_remote_probes(&candidates)
            .expect("remote probe plan should build");
        assert_eq!(plan.attempts.len(), 4);
        assert_eq!(
            plan.attempts[0].remote.endpoint,
            endpoint([10, 0, 0, 20], 51820)
        );
        assert_eq!(
            plan.attempts[1].remote.endpoint,
            endpoint([203, 0, 113, 20], 62000)
        );
        assert_eq!(plan.attempts[2].round, 1);
        assert_eq!(plan.attempts[2].delay_ms, 50);
        assert_eq!(plan.attempts[0].attempt_ordinal, 1);
        assert_eq!(plan.attempts[3].attempt_ordinal, 4);
    }

    #[test]
    fn remote_probe_plan_rejects_relay_only_candidates() {
        let engine =
            TraversalEngine::new(TraversalEngineConfig::default()).expect("config should be valid");
        let candidates = vec![candidate(
            [198, 51, 100, 10],
            62000,
            CandidateSource::Relay,
            900,
        )];

        let err = engine
            .plan_remote_probes(&candidates)
            .expect_err("relay-only candidates must not authorize direct probes");
        assert!(matches!(err, TraversalError::NoDirectCandidates));
    }

    // Additional tests for STUN parsing and gather behavior
    #[test]
    fn parse_stun_xor_mapped_address_ipv4_valid() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let port: u16 = 51820;
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        message.extend_from_slice(&transaction_id);
        let attr_type = 0x0020u16.to_be_bytes();
        let attr_len = 8u16.to_be_bytes();
        message.extend_from_slice(&attr_type);
        message.extend_from_slice(&attr_len);
        message.push(0x00);
        message.push(0x01);
        let cookie_bytes = 0x2112_A442u32.to_be_bytes();
        let port_mask = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);
        let x_port = port ^ port_mask;
        message.extend_from_slice(&x_port.to_be_bytes());
        let ip_bytes = ip.octets();
        for i in 0..4 {
            message.push(ip_bytes[i] ^ cookie_bytes[i]);
        }
        let declared_len = (message.len() - 20) as u16;
        message[2..4].copy_from_slice(&declared_len.to_be_bytes());
        let parsed =
            parse_stun_xor_mapped_address(message.as_slice(), transaction_id).expect("parse");
        assert_eq!(parsed.port(), port);
        assert_eq!(parsed.ip(), IpAddr::V4(ip));
    }

    #[test]
    fn parse_stun_xor_mapped_address_malformed_rejected() {
        let bad = vec![0u8; 10];
        let tid = [0u8; 12];
        let err = parse_stun_xor_mapped_address(bad.as_slice(), tid).expect_err("malformed");
        assert!(matches!(err, TraversalError::Stun(_)));
    }

    #[test]
    fn candidate_gatherer_query_and_timeout_and_filter_and_dedup() {
        let local = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind local");
        local.set_nonblocking(false).unwrap();
        let server = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind server");
        let server_addr = server.local_addr().expect("server addr");
        let server_handle = std::thread::spawn(move || {
            let mut buf = [0u8; 1500];
            let (n, src) = server.recv_from(&mut buf).expect("recv");
            let tx = &buf[8..20];
            let mut txid = [0u8; 12];
            txid.copy_from_slice(tx);
            let port = src.port();
            let ip = match src.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => Ipv4Addr::LOCALHOST,
            };
            let mut resp = Vec::new();
            resp.extend_from_slice(&0x0101u16.to_be_bytes());
            resp.extend_from_slice(&0u16.to_be_bytes());
            resp.extend_from_slice(&0x2112_A442u32.to_be_bytes());
            resp.extend_from_slice(&txid);
            resp.extend_from_slice(&0x0020u16.to_be_bytes());
            resp.extend_from_slice(&8u16.to_be_bytes());
            resp.push(0x00);
            resp.push(0x01);
            let cookie_bytes = 0x2112_A442u32.to_be_bytes();
            let port_mask = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);
            let x_port = port ^ port_mask;
            resp.extend_from_slice(&x_port.to_be_bytes());
            let ip_bytes = ip.octets();
            for i in 0..4 {
                resp.push(ip_bytes[i] ^ cookie_bytes[i]);
            }
            let declared_len = (resp.len() - 20) as u16;
            resp[2..4].copy_from_slice(&declared_len.to_be_bytes());
            server.send_to(&resp, src).expect("send resp");
        });

        let rustynet_if_ips = vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))];
        let host_candidates = vec![SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 0,
        }];
        let gatherer = CandidateGatherer::new(
            local.try_clone().unwrap(),
            vec![server_addr],
            Duration::from_millis(500),
            host_candidates.clone(),
            rustynet_if_ips.clone(),
        )
        .expect("gatherer");
        let candidates = gatherer.gather();
        assert!(candidates.iter().any(|c| c.source == CandidateSource::Host));
        assert!(
            candidates
                .iter()
                .any(|c| c.source == CandidateSource::ServerReflexive)
        );
        server_handle.join().expect("join");

        let local2 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind2");
        let gatherer_timeout = CandidateGatherer::new(
            local2.try_clone().unwrap(),
            vec![(Ipv4Addr::LOCALHOST, 9).into()],
            Duration::from_millis(10),
            host_candidates,
            rustynet_if_ips,
        )
        .expect("gatherer2");
        let results = gatherer_timeout.gather();
        assert!(results.iter().all(|c| c.source == CandidateSource::Host));
    }

    #[test]
    fn coordination_record_validation_and_execute_simultaneous_open_behaviour() {
        let policy = PolicySet::default();
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        let node_a = rustynet_control::NodeMetadata {
            node_id: "node-a".to_string(),
            hostname: "a".to_string(),
            os: "linux".to_string(),
            tags: vec![],
            owner: "owner-a".to_string(),
            endpoint: "127.0.0.1:51820".to_string(),
            last_seen_unix: 1,
            public_key: [1u8; 32],
        };
        let node_b = rustynet_control::NodeMetadata {
            node_id: "node-b".to_string(),
            hostname: "b".to_string(),
            os: "linux".to_string(),
            tags: vec![],
            owner: "owner-b".to_string(),
            endpoint: "127.0.0.1:51821".to_string(),
            last_seen_unix: 1,
            public_key: [2u8; 32],
        };
        core.nodes.upsert(node_a).expect("upsert a");
        core.nodes.upsert(node_b).expect("upsert b");

        let mut session_id = [0u8; 16];
        session_id[0] = 1;
        let mut nonce = [0u8; 16];
        nonce[0] = 7;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = TraversalCoordinationRecord {
            session_id,
            probe_start_unix: now.saturating_add(1),
            node_a: "node-a".to_string(),
            node_b: "node-b".to_string(),
            issued_at_unix: now,
            expires_at_unix: now.saturating_add(20),
            nonce,
        };
        let signed = core
            .signed_traversal_coordination_record(record.clone())
            .expect("sign");

        let engine = TraversalEngine::new(TraversalEngineConfig::default()).expect("engine");
        let mut replay = CoordinationReplayWindow::default();

        let schedule = engine
            .validate_signed_coordination_record(
                &signed,
                &NodeId::new("node-a").unwrap(),
                &NodeId::new("node-b").unwrap(),
                &core.endpoint_hint_verifying_key,
                &mut replay,
                now,
            )
            .expect("validate");
        assert!(schedule.wait_duration.as_secs() <= 10);

        let mut replay2 = CoordinationReplayWindow::default();
        engine
            .validate_signed_coordination_record(
                &signed,
                &NodeId::new("node-a").unwrap(),
                &NodeId::new("node-b").unwrap(),
                &core.endpoint_hint_verifying_key,
                &mut replay2,
                now,
            )
            .expect("first");
        let replay_err = engine.validate_signed_coordination_record(
            &signed,
            &NodeId::new("node-a").unwrap(),
            &NodeId::new("node-b").unwrap(),
            &core.endpoint_hint_verifying_key,
            &mut replay2,
            now + 1,
        );
        assert!(matches!(
            replay_err,
            Err(TraversalError::CoordinationReplayDetected)
        ));

        struct NoHandshakeRuntime {
            latest: Option<u64>,
            sent: Vec<SocketEndpoint>,
        }
        impl SimultaneousOpenRuntime for NoHandshakeRuntime {
            fn send_probe(
                &mut self,
                endpoint: SocketEndpoint,
                _round: u8,
            ) -> Result<(), TraversalError> {
                self.sent.push(endpoint);
                Ok(())
            }
            fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
                Ok(self.latest)
            }
        }
        struct ImmediateWaiter;
        impl SimultaneousOpenWaiter for ImmediateWaiter {
            fn wait(&mut self, _d: Duration) {}
        }

        let direct_candidates = vec![candidate([10, 0, 0, 1], 51820, CandidateSource::Host, 900)];
        let mut runtime = NoHandshakeRuntime {
            latest: None,
            sent: Vec::new(),
        };
        let mut waiter = ImmediateWaiter;
        let schedule2 = CoordinationSchedule {
            session_id,
            nonce,
            probe_start_unix: now,
            wait_duration: Duration::from_secs(0),
        };
        let result = engine
            .execute_simultaneous_open(
                &mut runtime,
                &mut waiter,
                schedule2,
                direct_candidates.as_slice(),
                Some(SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                    port: 60000,
                }),
                now,
                120,
            )
            .expect("exec");
        match result.decision {
            TraversalDecision::Relay {
                endpoint: _,
                reason,
                rounds,
            } => {
                assert_eq!(
                    reason,
                    TraversalDecisionReason::DirectProbeExhaustedRelayArmed
                );
                assert_eq!(rounds, engine.config.simultaneous_open_rounds);
            }
            _ => panic!("expected relay"),
        }
    }

    // ── A4: Adversarial traversal hardening tests ─────────────────────────

    /// A4: A coordination record with an invalid (forged) signature must be
    /// rejected.  The daemon must not switch paths based on forged records.
    #[test]
    fn test_a4_forged_signature_coordination_record_rejected() {
        use rustynet_control::{ControlPlaneCore, PolicySet};
        let policy = PolicySet::default();
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = TraversalCoordinationRecord {
            session_id: [1u8; 16],
            probe_start_unix: now + 2,
            node_a: "node-a".to_string(),
            node_b: "node-b".to_string(),
            issued_at_unix: now,
            expires_at_unix: now + 20,
            nonce: [9u8; 16],
        };
        let mut signed = core
            .signed_traversal_coordination_record(record)
            .expect("sign");
        // Corrupt the signature bytes.
        signed.signature[0] ^= 0xff;

        let engine = TraversalEngine::new(TraversalEngineConfig::default()).expect("engine");
        let mut replay = CoordinationReplayWindow::default();
        let err = engine.validate_signed_coordination_record(
            &signed,
            &NodeId::new("node-a").unwrap(),
            &NodeId::new("node-b").unwrap(),
            &core.endpoint_hint_verifying_key,
            &mut replay,
            now,
        );
        assert!(
            matches!(err, Err(TraversalError::CoordinationSignatureInvalid)),
            "forged signature must be rejected: {err:?}"
        );
    }

    /// A4: A replayed coordination record (nonce already seen) must be
    /// rejected even when the signature is valid.
    #[test]
    fn test_a4_replayed_coordination_record_rejected() {
        use rustynet_control::{ControlPlaneCore, PolicySet};
        let policy = PolicySet::default();
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = TraversalCoordinationRecord {
            session_id: [2u8; 16],
            probe_start_unix: now + 1,
            node_a: "node-a".to_string(),
            node_b: "node-b".to_string(),
            issued_at_unix: now,
            expires_at_unix: now + 20,
            nonce: [0xab; 16],
        };
        let signed = core
            .signed_traversal_coordination_record(record)
            .expect("sign");

        let engine = TraversalEngine::new(TraversalEngineConfig::default()).expect("engine");
        let mut replay = CoordinationReplayWindow::default();

        // First use: valid.
        engine
            .validate_signed_coordination_record(
                &signed,
                &NodeId::new("node-a").unwrap(),
                &NodeId::new("node-b").unwrap(),
                &core.endpoint_hint_verifying_key,
                &mut replay,
                now,
            )
            .expect("first use should succeed");

        // Second use with the same nonce: replay must be detected.
        let err = engine.validate_signed_coordination_record(
            &signed,
            &NodeId::new("node-a").unwrap(),
            &NodeId::new("node-b").unwrap(),
            &core.endpoint_hint_verifying_key,
            &mut replay,
            now + 1,
        );
        assert!(
            matches!(err, Err(TraversalError::CoordinationReplayDetected)),
            "replayed nonce must be rejected: {err:?}"
        );
    }

    /// A4: Candidate count exceeding `max_candidates` must be rejected; the
    /// engine must never panic or allocate unboundedly on a flooded input.
    #[test]
    fn test_a4_candidate_flooding_rejected_no_panic() {
        let engine = TraversalEngine::new(TraversalEngineConfig {
            max_candidates: 4,
            ..TraversalEngineConfig::default()
        })
        .expect("engine");

        // Build MAX_CANDIDATES + 2 candidates (a flood).
        let flooded: Vec<TraversalCandidate> = (0u16..6)
            .map(|i| candidate([10, 0, 0, i as u8 + 1], 51820, CandidateSource::Host, 900))
            .collect();
        let remote = vec![candidate([10, 0, 1, 1], 51820, CandidateSource::Host, 900)];

        let err = engine.plan_direct_probes(flooded.as_slice(), remote.as_slice());
        assert!(
            matches!(
                err,
                Err(TraversalError::CandidateCountExceeded { side: "local", .. })
            ),
            "flooded candidates must be rejected: {err:?}"
        );
    }

    // ── B3-a: Proactive refresh scheduling tests ──────────────────────────

    /// B3-a: The proactive refresh instant must be *before* `expires_at`.
    #[test]
    fn test_b3a_schedule_proactive_refresh_fires_before_expiry() {
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let instant = schedule_proactive_refresh(expires_at, 60, 0);
        // The instant must be strictly before the expiry time (converted to
        // SystemTime for comparison).
        let remaining = expires_at
            .duration_since(SystemTime::now())
            .expect("expiry should be in the future");
        let scheduled_from_now = instant.duration_since(Instant::now());
        // scheduled_from_now should be < remaining (fires before expiry)
        assert!(
            scheduled_from_now < remaining,
            "refresh must fire before expiry: scheduled={scheduled_from_now:?} remaining={remaining:?}"
        );
    }

    /// B3-a: Jitter must be within `[0, jitter_max_secs)`.
    #[test]
    fn test_b3a_schedule_proactive_refresh_jitter_bounded() {
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let margin_secs = 60u64;
        let jitter_max = 15u64;

        // Run many times and verify jitter never exceeds the bound.
        for _ in 0..200 {
            let instant = schedule_proactive_refresh(expires_at, margin_secs, jitter_max);
            let scheduled_from_now = instant.duration_since(Instant::now());
            // Maximum: remaining - margin + (jitter_max - 1)
            // = 300 - 60 + 14 = 254 s
            // Minimum: remaining - margin + 0 = 240 s
            assert!(
                scheduled_from_now <= Duration::from_secs(300 - margin_secs + jitter_max),
                "jitter exceeded bound: {scheduled_from_now:?}"
            );
            assert!(
                scheduled_from_now >= Duration::from_secs(300u64.saturating_sub(margin_secs + 1)),
                "scheduled too early: {scheduled_from_now:?}"
            );
        }
    }

    /// B3-a: When `expires_at` is already past the margin (or in the past),
    /// the function must return a near-future instant (~5 s), never panic.
    #[test]
    fn test_b3a_schedule_proactive_refresh_past_expiry_fires_soon() {
        // expiry = now + 30s, margin = 60s → already past margin window
        let expires_at = SystemTime::now() + Duration::from_secs(30);
        let instant = schedule_proactive_refresh(expires_at, 60, 0);
        let scheduled_from_now = instant.duration_since(Instant::now());
        assert!(
            scheduled_from_now <= Duration::from_secs(10),
            "past-margin expiry should fire soon: {scheduled_from_now:?}"
        );
    }

    // ── B2-a: EndpointMonitor unit tests ──────────────────────────────────

    fn addr_map(entries: &[(&str, &[&str])]) -> BTreeMap<String, Vec<IpAddr>> {
        entries
            .iter()
            .map(|(iface, addrs)| {
                (
                    iface.to_string(),
                    addrs.iter().map(|a| a.parse().unwrap()).collect(),
                )
            })
            .collect()
    }

    /// B2-a: An address appearing on an interface emits a change event with
    /// the correct old/new address sets.
    #[test]
    fn test_b2a_interface_address_added_emits_event() {
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_string()]);

        // Baseline: no addresses seen yet → no event.
        let initial = addr_map(&[("eth0", &["192.0.2.1"])]);
        let event = monitor.poll_with_addrs(initial);
        assert!(
            event.is_some(),
            "first poll with new address should emit event"
        );
        let ev = event.unwrap();
        assert_eq!(ev.interface, "eth0");
        assert!(ev.old_addrs.is_empty());
        assert_eq!(ev.new_addrs, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);

        // Same address, second poll → no event.
        let same = addr_map(&[("eth0", &["192.0.2.1"])]);
        assert!(monitor.poll_with_addrs(same).is_none());

        // Address changes → event with old and new.
        let changed = addr_map(&[("eth0", &["192.0.2.2"])]);
        let ev2 = monitor
            .poll_with_addrs(changed)
            .expect("changed address must emit event");
        assert_eq!(ev2.old_addrs, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(ev2.new_addrs, vec!["192.0.2.2".parse::<IpAddr>().unwrap()]);
    }

    /// B2-a: When an interface loses all its addresses, the monitor emits an
    /// event with an empty `new_addrs` (interface went down).
    #[test]
    fn test_b2a_interface_down_emits_event() {
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_string()]);

        // Establish baseline.
        monitor.poll_with_addrs(addr_map(&[("eth0", &["198.51.100.5"])]));

        // Interface disappears (no routable addrs → filtered out).
        let gone = BTreeMap::new();
        let ev = monitor
            .poll_with_addrs(gone)
            .expect("interface removal must emit event");
        assert_eq!(ev.interface, "eth0");
        assert_eq!(
            ev.old_addrs,
            vec!["198.51.100.5".parse::<IpAddr>().unwrap()]
        );
        assert!(ev.new_addrs.is_empty());
    }

    /// B2-a: Address changes on the WireGuard tunnel interface (`rustynet0`)
    /// must be silently ignored — they are not underlay mobility events.
    #[test]
    fn test_b2a_rustynet_interface_changes_ignored() {
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_string()]);

        // Only the tunnel interface changes.
        let tunnel_only = addr_map(&[("rustynet0", &["10.100.0.1"])]);
        assert!(
            monitor.poll_with_addrs(tunnel_only).is_none(),
            "rustynet0 address change must not emit an event"
        );
    }

    /// B2-a: Loopback and link-local addresses must not trigger events.
    #[test]
    fn test_b2a_loopback_and_link_local_ignored() {
        let mut monitor = EndpointMonitor::new(vec![]);

        // Loopback addresses are not routable.
        let lo = addr_map(&[("lo", &["127.0.0.1", "::1"])]);
        assert!(
            monitor.poll_with_addrs(lo).is_none(),
            "loopback addresses must be ignored"
        );

        // Link-local IPv4.
        let link_local = addr_map(&[("eth0", &["169.254.1.2"])]);
        assert!(
            monitor.poll_with_addrs(link_local).is_none(),
            "link-local IPv4 must be ignored"
        );

        // Link-local IPv6 (fe80::1).
        let link_local6 = addr_map(&[("eth0", &["fe80::1"])]);
        assert!(
            monitor.poll_with_addrs(link_local6).is_none(),
            "link-local IPv6 must be ignored"
        );
    }
}
