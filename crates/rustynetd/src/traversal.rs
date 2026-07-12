#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, VerifyingKey};
use rand::TryRngCore;
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
    /// TOTAL gather deadline across ALL configured STUN servers (FIS-0018):
    /// the socket path fires every binding request up front and collects
    /// under one deadline; the (singleton) round-trip path slices this
    /// budget per server. Not a per-server timeout.
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
pub struct VerifiedTraversalRecord {
    pub candidates: Vec<TraversalCandidate>,
    pub generated_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: u64,
    pub verified_at_unix: u64,
}

#[derive(Debug, Clone, Default)]
pub struct VerifiedTraversalIndex {
    index: BTreeMap<(String, String), VerifiedTraversalRecord>,
}

impl VerifiedTraversalIndex {
    pub fn new() -> Self {
        Self {
            index: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, source: String, target: String, record: VerifiedTraversalRecord) {
        self.index.insert((source, target), record);
    }

    pub fn get(&self, source: &str, target: &str) -> Option<&VerifiedTraversalRecord> {
        self.index.get(&(source.to_owned(), target.to_owned()))
    }

    pub fn prune_expired(&mut self, now_unix: u64) {
        self.index
            .retain(|_, record| record.expires_at_unix > now_unix);
    }

    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
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
    ProbeSend(String),
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
            TraversalError::ProbeSend(message) => {
                write!(f, "probe send failed: {message}")
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
        let local_bound_endpoint =
            self.local_socket
                .local_addr()
                .ok()
                .map(|bound_addr| SocketEndpoint {
                    addr: bound_addr.ip(),
                    port: bound_addr.port(),
                });
        let srflx_results = self.query_stun_servers_batched();

        collect_gathered_candidates(
            local_bound_endpoint,
            &self.host_candidates,
            &self.rustynet_interface_addrs,
            observed_at_unix,
            srflx_results,
        )
    }

    /// FIS-0011: fire-all-then-collect srflx gathering with an
    /// RFC 5389 §7.2.1-shaped retransmission ladder.
    ///
    /// All binding requests go out up front (own transaction id each; a
    /// retransmission reuses its original id per the RFC), then one receive
    /// loop demuxes responses by source address + transaction-id echo until
    /// the shared gather deadline. An unanswered request retransmits on its
    /// RTO ladder (250ms initial, doubling, at most
    /// [`STUN_MAX_REQUEST_ATTEMPTS`] sends — sized down from the RFC's 7
    /// because this is a short-budget candidate discovery, not a control
    /// transaction). This simultaneously fixes the old serial path's
    /// starvation bug (server 1's full-budget `recv_from` blanked servers
    /// 2..N) and its single-shot fragility (one lost datagram cost the whole
    /// gather cycle). Results are per-server, in server order.
    fn query_stun_servers_batched(&self) -> Vec<Result<SocketEndpoint, TraversalError>> {
        let timed_out = || TraversalError::Stun("stun response timed out".to_owned());
        let mut results: Vec<Result<SocketEndpoint, TraversalError>> =
            self.stun_servers.iter().map(|_| Err(timed_out())).collect();
        if self.stun_servers.is_empty() {
            return results;
        }
        if let Err(err) = self.local_socket.set_write_timeout(Some(self.timeout)) {
            let message = format!("failed to set stun write timeout: {err}");
            for slot in &mut results {
                *slot = Err(TraversalError::Stun(message.clone()));
            }
            return results;
        }

        let deadline = Instant::now() + self.timeout;
        let mut outstanding: Vec<OutstandingStunQuery> = Vec::new();
        for (server_index, server) in self.stun_servers.iter().enumerate() {
            let mut transaction_id = [0u8; 12];
            if let Err(err) = rand::rngs::OsRng.try_fill_bytes(transaction_id.as_mut_slice()) {
                results[server_index] = Err(TraversalError::Stun(format!(
                    "os randomness unavailable: {err}"
                )));
                continue;
            }
            let request = build_stun_binding_request(transaction_id);
            if let Err(err) = self.local_socket.send_to(request.as_slice(), *server) {
                results[server_index] = Err(TraversalError::Stun(format!(
                    "failed to send stun request: {err}"
                )));
                continue;
            }
            outstanding.push(OutstandingStunQuery {
                server_index,
                server: *server,
                transaction_id,
                next_retransmit_at: Instant::now() + STUN_INITIAL_RTO,
                rto: STUN_INITIAL_RTO,
                attempts: 1,
            });
        }

        let mut buffer = [0u8; 1500];
        while !outstanding.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            // Wake at the earliest pending retransmit (or the deadline when
            // every ladder is exhausted); floor 1ms so a due-now retransmit
            // cannot busy-spin the receive.
            let wake_at = outstanding
                .iter()
                .filter(|query| query.attempts < STUN_MAX_REQUEST_ATTEMPTS)
                .map(|query| query.next_retransmit_at)
                .min()
                .map_or(deadline, |at| at.min(deadline));
            let wait = wake_at
                .saturating_duration_since(now)
                .max(Duration::from_millis(1));
            if self.local_socket.set_read_timeout(Some(wait)).is_err() {
                break;
            }
            match self.local_socket.recv_from(&mut buffer) {
                Ok((received, source)) => {
                    let Some(position) =
                        outstanding.iter().position(|query| query.server == source)
                    else {
                        // Response from an unqueried source: reject.
                        continue;
                    };
                    match parse_stun_xor_mapped_address(
                        buffer[..received].as_ref(),
                        outstanding[position].transaction_id,
                    ) {
                        Ok(addr) => {
                            let query = outstanding.swap_remove(position);
                            results[query.server_index] = Ok(SocketEndpoint {
                                addr: addr.ip(),
                                port: addr.port(),
                            });
                        }
                        // Malformed or wrong transaction id from a real
                        // target: drop the datagram, keep the query pending.
                        Err(_) => continue,
                    }
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::WouldBlock
                        || err.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Receive window elapsed: fall through to the
                    // retransmit sweep below.
                }
                Err(_) => break,
            }
            let now = Instant::now();
            for query in &mut outstanding {
                if query.attempts < STUN_MAX_REQUEST_ATTEMPTS && now >= query.next_retransmit_at {
                    let request = build_stun_binding_request(query.transaction_id);
                    if self
                        .local_socket
                        .send_to(request.as_slice(), query.server)
                        .is_ok()
                    {
                        query.attempts += 1;
                        query.rto = query.rto.saturating_mul(2);
                        query.next_retransmit_at = now + query.rto;
                    } else {
                        // Send failure mid-gather: stop retransmitting this
                        // query; an earlier send may still be answered.
                        query.attempts = STUN_MAX_REQUEST_ATTEMPTS;
                    }
                }
            }
        }
        results
    }
}

/// Initial retransmission timeout for the FIS-0011 STUN ladder
/// (RFC 5389 §7.2.1 default is 500ms; halved because the whole gather
/// budget defaults to 2s and this is candidate discovery).
const STUN_INITIAL_RTO: Duration = Duration::from_millis(250);
/// Total sends per server per gather (initial + retransmits) — the RFC's
/// `Rc`, sized down from 7 for the short gather budget.
const STUN_MAX_REQUEST_ATTEMPTS: u8 = 3;

/// One in-flight binding request awaiting its response or next retransmit.
struct OutstandingStunQuery {
    server_index: usize,
    server: SocketAddr,
    transaction_id: [u8; 12],
    next_retransmit_at: Instant,
    rto: Duration,
    attempts: u8,
}

fn collect_gathered_candidates(
    local_bound_endpoint: Option<SocketEndpoint>,
    host_candidates: &[SocketEndpoint],
    rustynet_interface_addrs: &BTreeSet<IpAddr>,
    observed_at_unix: u64,
    srflx_results: Vec<Result<SocketEndpoint, TraversalError>>,
) -> Vec<TraversalCandidate> {
    let mut candidates = Vec::new();
    let host_priority = 900;
    let srflx_priority = 850;

    if let Some(endpoint) = local_bound_endpoint
        && is_candidate_endpoint_allowed(endpoint, rustynet_interface_addrs)
    {
        candidates.push(TraversalCandidate {
            endpoint,
            source: CandidateSource::Host,
            priority: host_priority,
            observed_at_unix,
        });
    }

    for endpoint in host_candidates {
        if is_candidate_endpoint_allowed(*endpoint, rustynet_interface_addrs) {
            candidates.push(TraversalCandidate {
                endpoint: *endpoint,
                source: CandidateSource::Host,
                priority: host_priority,
                observed_at_unix,
            });
        }
    }

    for result in srflx_results {
        if let Ok(endpoint) = result
            && is_candidate_endpoint_allowed(endpoint, rustynet_interface_addrs)
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

fn is_candidate_endpoint_allowed(
    endpoint: SocketEndpoint,
    rustynet_interface_addrs: &BTreeSet<IpAddr>,
) -> bool {
    if endpoint.port == 0 {
        return false;
    }
    let ip = endpoint.addr;
    #[cfg(not(test))]
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    #[cfg(test)]
    if ip.is_unspecified() || ip.is_multicast() {
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
            "stun message is shorter than header".to_owned(),
        ));
    }
    let message_type = u16::from_be_bytes([message[0], message[1]]);
    if message_type != STUN_BINDING_RESPONSE_TYPE {
        return Err(TraversalError::Stun(
            "stun message is not a binding response".to_owned(),
        ));
    }
    let declared_len = usize::from(u16::from_be_bytes([message[2], message[3]]));
    let expected_len = 20usize.saturating_add(declared_len);
    if expected_len > message.len() {
        return Err(TraversalError::Stun("stun message is truncated".to_owned()));
    }
    let cookie = u32::from_be_bytes([message[4], message[5], message[6], message[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(TraversalError::Stun(
            "stun magic cookie mismatch".to_owned(),
        ));
    }
    if message[8..20] != transaction_id {
        return Err(TraversalError::Stun(
            "stun transaction id mismatch".to_owned(),
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
                "stun attribute exceeds message boundary".to_owned(),
            ));
        }
        let value = &message[offset..attr_end];
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
            if attr_len < 8 {
                return Err(TraversalError::Stun(
                    "xor-mapped-address attribute too short".to_owned(),
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
                            "xor-mapped-address ipv4 attribute too short".to_owned(),
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
                            "xor-mapped-address ipv6 attribute too short".to_owned(),
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
                        "xor-mapped-address has unsupported address family".to_owned(),
                    ));
                }
            };
            return Ok(endpoint);
        }
        let padded_len = (attr_len + 3) & !3;
        offset = offset.saturating_add(padded_len);
    }

    Err(TraversalError::Stun(
        "stun response does not contain xor-mapped-address".to_owned(),
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
            "coordination payload/header mismatch".to_owned(),
        ));
    }
    let canonical_payload = serialize_coordination_payload(&parsed);
    if canonical_payload != record.payload {
        return Err(TraversalError::Coordination(
            "coordination payload canonicalization mismatch".to_owned(),
        ));
    }

    let signature_bytes = decode_hex_to_fixed::<64>(record.signature_hex.as_str())
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let verifying_key = VerifyingKey::from_bytes(endpoint_hint_verifier_key)
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)?;
    verifying_key
        .verify_strict(record.payload.as_bytes(), &signature)
        .map_err(|_| TraversalError::CoordinationSignatureInvalid)
}

fn parse_coordination_payload(payload: &str) -> Result<ParsedCoordinationPayload, TraversalError> {
    let mut fields = BTreeMap::<String, String>::new();
    for line in payload.lines() {
        let (key, value) = line.split_once('=').ok_or_else(|| {
            TraversalError::Coordination("coordination payload line missing '='".to_owned())
        })?;
        if key.trim().is_empty() {
            return Err(TraversalError::Coordination(
                "coordination payload key is empty".to_owned(),
            ));
        }
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(TraversalError::Coordination(format!(
                "coordination payload duplicate key: {key}"
            )));
        }
    }
    if fields.len() != 9 {
        return Err(TraversalError::Coordination(
            "coordination payload has unexpected field count".to_owned(),
        ));
    }

    let version = fields.get("version").ok_or_else(|| {
        TraversalError::Coordination("coordination payload missing version".to_owned())
    })?;
    if version != "1" {
        return Err(TraversalError::Coordination(
            "coordination payload version is unsupported".to_owned(),
        ));
    }
    let payload_type = fields.get("type").ok_or_else(|| {
        TraversalError::Coordination("coordination payload missing type".to_owned())
    })?;
    if payload_type != "traversal_coordination" {
        return Err(TraversalError::Coordination(
            "coordination payload type is unsupported".to_owned(),
        ));
    }

    let session_id = decode_hex_to_fixed::<16>(
        fields
            .get("session_id")
            .ok_or_else(|| {
                TraversalError::Coordination("coordination payload missing session_id".to_owned())
            })?
            .as_str(),
    )
    .map_err(|_| TraversalError::Coordination("coordination session_id is invalid".to_owned()))?;
    let nonce = decode_hex_to_fixed::<16>(
        fields
            .get("nonce")
            .ok_or_else(|| {
                TraversalError::Coordination("coordination payload missing nonce".to_owned())
            })?
            .as_str(),
    )
    .map_err(|_| TraversalError::Coordination("coordination nonce is invalid".to_owned()))?;
    let probe_start_unix = parse_u64_field(&fields, "probe_start_unix")?;
    let issued_at_unix = parse_u64_field(&fields, "issued_at_unix")?;
    let expires_at_unix = parse_u64_field(&fields, "expires_at_unix")?;
    let node_a = fields
        .get("node_a")
        .ok_or_else(|| {
            TraversalError::Coordination("coordination payload missing node_a".to_owned())
        })?
        .trim()
        .to_owned();
    let node_b = fields
        .get("node_b")
        .ok_or_else(|| {
            TraversalError::Coordination("coordination payload missing node_b".to_owned())
        })?
        .trim()
        .to_owned();
    if node_a.is_empty() || node_b.is_empty() {
        return Err(TraversalError::Coordination(
            "coordination payload node ids must not be empty".to_owned(),
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

// Lab pipeline distributes traversal bundles once; coordination records must
// remain valid for the full pipeline window.  Production nodes receive fresh
// records from the assignment-refresh timer and never rely on a long TTL.
pub const MAX_COORDINATION_TTL_SECS: u64 = 86400;
pub const MAX_COORDINATION_FUTURE_START_SECS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalDecisionReason {
    SimultaneousOpenHandshakeObserved,
    NoDirectCandidatesRelayArmed,
    DirectProbeExhaustedRelayArmed,
    DirectProbeExhaustedFailClosed,
    /// D5.5 — the ICE-pair race runner sent every pair in a round
    /// concurrently and observed a fresh handshake before the round
    /// budget elapsed. The winning pair (selected by RFC 8445 pair
    /// priority + endpoint attribution when the runtime provides
    /// it) is carried in the `Direct` variant's `endpoint` field.
    IcePairRaceHandshakeObserved,
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
            TraversalDecisionReason::IcePairRaceHandshakeObserved => {
                "ice_pair_race_handshake_observed"
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
    /// D5.5 — endpoint attribution for the ICE-pair race runner. A
    /// runtime that can report which specific remote endpoint
    /// completed the most-recent handshake returns it here so the
    /// race runner can return the winning pair, not just "some
    /// handshake landed". The default `Ok(None)` keeps the existing
    /// sequential `execute_simultaneous_open` path working
    /// unchanged for runtimes that don't track per-endpoint state.
    fn handshake_endpoint(&mut self) -> Result<Option<SocketEndpoint>, TraversalError> {
        Ok(None)
    }
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

    /// Thin delegate: the NAT-conditioned 15/25 values moved into
    /// [`crate::keepalive::KeepalivePrior`] as the FIS-0015 estimator's
    /// cold-start priors (see [`keepalive_prior_for_nat`]). Kept until
    /// `TraversalSession`'s disposition is settled by FIS-0010.
    pub fn recommended_keepalive_secs(nat_profile: NatProfile) -> u64 {
        u64::from(keepalive_prior_for_nat(Some(nat_profile)).prior_interval_secs())
    }
}

/// Map an (optionally unknown) NAT profile onto the FIS-0015 keepalive
/// cold-start prior. Unknown NAT fails toward the hard prior: no raising,
/// 15s — the strictest secure default.
pub fn keepalive_prior_for_nat(
    nat_profile: Option<NatProfile>,
) -> crate::keepalive::KeepalivePrior {
    match nat_profile {
        Some(profile) if !profile.is_hard_nat() && profile.preserves_port => {
            crate::keepalive::KeepalivePrior::DirectEasyNat
        }
        _ => crate::keepalive::KeepalivePrior::DirectHardOrUnknownNat,
    }
}

/// FIS-0010: direct↔relay flap-damping circuit breaker (Nygard's Circuit
/// Breaker driven by an EWMA failure-intensity estimator).
///
/// A bare consecutive-failure counter resets on one success, so the exact
/// pathology that hurts users — a path good enough to occasionally
/// handshake but too flaky to hold — never trips it. The EWMA of the
/// failure indicator captures RATE: sustained flapping pushes intensity
/// over the open threshold, the breaker opens, and the daemon stops
/// re-racing the known-flaky direct path for an exponentially growing
/// cooldown (deterministic ladder from `resilience::next_reconnect_delay_ms`
/// — the FIS-0016 primitive — plus additive quarter-jitter; Full Jitter is
/// deliberately NOT used here because a uniform-from-zero draw could yield
/// a ~0s cooldown and defeat the hold-down). Cooldown expiry is the
/// half-open state: one direct trial is allowed; success closes the
/// breaker immediately, failure re-opens with a longer cooldown. Below
/// threshold the daemon's behavior is byte-identical to today. Every
/// uncertain state biases toward relay — the available, safe choice.
///
/// Lives OUTSIDE `TraversalProbeStatus` on purpose: that map is rebuilt
/// from scratch every sync pass; cross-pass state must survive it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FlapBreaker {
    intensity: f32,
    open_until: u64,
    exponent: u8,
    consecutive_good: u16,
}

impl Default for FlapBreaker {
    fn default() -> Self {
        Self::new()
    }
}

impl FlapBreaker {
    const ALPHA: f32 = 0.3;
    const THETA_OPEN: f32 = 0.6;
    const THETA_CLOSE: f32 = 0.3;
    const BASE_COOLDOWN_SECS: u64 = 10;
    const MAX_EXPONENT: u8 = 6;
    const FULL_RECOVERY_INTERVALS: u16 = 10;

    pub fn new() -> Self {
        Self {
            intensity: 0.0,
            open_until: 0,
            exponent: 0,
            consecutive_good: 0,
        }
    }

    /// Record one race outcome (failure = the race ended on relay/stale
    /// instead of a fresh direct handshake).
    pub fn record_outcome(&mut self, is_failure: bool, now_unix: u64) {
        let indicator = if is_failure { 1.0 } else { 0.0 };
        self.intensity = (1.0 - Self::ALPHA) * self.intensity + Self::ALPHA * indicator;

        if is_failure {
            if self.intensity > Self::THETA_OPEN && self.open_until <= now_unix {
                let policy = crate::resilience::ReconnectPolicy {
                    initial_backoff_ms: Self::BASE_COOLDOWN_SECS * 1_000,
                    multiplier: 2,
                    max_backoff_ms: Self::BASE_COOLDOWN_SECS * 1_000 * (1 << Self::MAX_EXPONENT),
                };
                let cooldown_secs =
                    crate::resilience::next_reconnect_delay_ms(policy, u32::from(self.exponent))
                        / 1_000;
                // Additive quarter-jitter, fail-soft to zero on CSPRNG
                // failure (decorrelation aid, not a security primitive —
                // same rationale as schedule_proactive_refresh).
                let jitter = {
                    let mut buf = [0u8; 8];
                    match rand::rngs::OsRng.try_fill_bytes(&mut buf) {
                        Ok(()) => u64::from_le_bytes(buf) % (cooldown_secs / 4 + 1),
                        Err(_) => 0,
                    }
                };
                self.open_until = now_unix.saturating_add(cooldown_secs + jitter);
                self.exponent = (self.exponent + 1).min(Self::MAX_EXPONENT);
                self.consecutive_good = 0;
            }
        } else {
            // A success arrives only while closed or on the half-open
            // trial — either way the breaker closes immediately.
            self.open_until = 0;
            if self.intensity < Self::THETA_CLOSE {
                self.consecutive_good =
                    (self.consecutive_good + 1).min(Self::FULL_RECOVERY_INTERVALS);
                if self.consecutive_good >= Self::FULL_RECOVERY_INTERVALS {
                    // Sustained recovery: the backoff ladder resets.
                    self.exponent = 0;
                }
            } else {
                self.consecutive_good = 0;
            }
        }
    }

    /// While open, the daemon withholds direct re-races (stays on relay).
    pub fn is_open(&self, now_unix: u64) -> bool {
        self.open_until > now_unix && self.intensity > Self::THETA_CLOSE
    }

    /// Fully closed (not open, not half-open). The FIS-0013 quality
    /// trigger fires only in this state — the breaker owns direct-relay
    /// damping and the quality re-race must never bypass it.
    pub fn is_closed(&self, now_unix: u64) -> bool {
        !self.is_open(now_unix) && self.intensity <= Self::THETA_OPEN
    }

    pub fn intensity(&self) -> f32 {
        self.intensity
    }

    /// Observability label: closed / open / half_open.
    pub fn state_label(&self, now_unix: u64) -> &'static str {
        if self.is_open(now_unix) {
            "open"
        } else if self.intensity > Self::THETA_OPEN {
            "half_open"
        } else {
            "closed"
        }
    }
}

/// FIS-0013: daemon-side per-peer path-quality state, SEPARATE from
/// `traversal_probe_statuses` (rebuilt from scratch every sync pass).
/// Nothing here runs per-packet or per-10ms-tick — samples arrive at the
/// daemon's ~1s reconcile cadence.
#[derive(Debug, Clone, Copy)]
pub struct PathQualityState {
    srtt_ms: f32,
    rttvar_ms: f32,
    /// Slow RTT average (~20-rekey time constant) — the baseline the fast
    /// SRTT is compared against for relative degradation.
    srtt_slow_ms: f32,
    loss_ewma: f32,
    rtt_samples: u8,
    degraded_streak: u8,
    last_quality_rerace_unix: u64,
    /// FIS-0021 delta 3: boringtun's `last_rtt` is STICKY (the same value
    /// repeats every poll until the next handshake), so RTT evidence is
    /// ingested only when the handshake advanced, and the RTT arm is gated
    /// on the age of the last real ingest — not on poll liveness (which a
    /// loss-only poll refreshes every second, making a 10s gate vacuous).
    last_rtt_handshake_unix: Option<u64>,
    last_rtt_ingest_unix: u64,
}

impl Default for PathQualityState {
    fn default() -> Self {
        Self {
            srtt_ms: 0.0,
            rttvar_ms: 0.0,
            srtt_slow_ms: 0.0,
            loss_ewma: 0.0,
            rtt_samples: 0,
            degraded_streak: 0,
            last_quality_rerace_unix: 0,
            last_rtt_handshake_unix: None,
            last_rtt_ingest_unix: 0,
        }
    }
}

impl PathQualityState {
    const LOSS_DEGRADE_THRESHOLD: f32 = 0.05;
    const DEGRADED_STREAK_MIN: u8 = 5;
    const RTT_SAMPLES_MIN: u8 = 2;
    const RTT_SLOW_ALPHA: f32 = 0.05;
    const RTT_FAST_ALPHA: f32 = 0.125;
    const RTT_VAR_BETA: f32 = 0.25;
    const RTT_RELATIVE_THRESHOLD: f32 = 2.0;
    const RTT_ABSOLUTE_THRESHOLD_MS: f32 = 50.0;
    const LOSS_ALPHA: f32 = 0.3;
    /// Max staleness of the last REAL RTT ingest for the RTT arm — sized to
    /// RTT's ~120s handshake cadence ("at most one missed handshake"), not
    /// to the 1s poll cadence.
    const RTT_INGEST_MAX_AGE_SECS: u64 = 240;
    /// Minimum spacing between quality-triggered re-races per peer.
    pub const QUALITY_RERACE_DWELL_SECS: u64 = 300;

    /// Ingest one ~1s poll sample. Returns `Some(true)` when sustained
    /// degradation (loss OR RTT arm) warrants a quality re-race and the
    /// per-peer dwell has elapsed; `None` otherwise.
    fn ingest_sample(
        &mut self,
        sample: rustynet_backend_api::PeerPathSample,
        now_unix: u64,
    ) -> Option<bool> {
        // FIS-0021 delta 3: only a handshake ADVANCE carries a fresh RTT
        // sample; the sticky repeat of the same value every poll must not
        // re-enter the estimators.
        let fresh_rtt = sample
            .latest_handshake
            .is_some_and(|handshake| self.last_rtt_handshake_unix != Some(handshake));
        if let Some(rtt) = sample.rtt
            && fresh_rtt
        {
            self.last_rtt_handshake_unix = sample.latest_handshake;
            self.last_rtt_ingest_unix = now_unix;
            let rtt = rtt as f32;
            if self.rtt_samples == 0 {
                self.srtt_ms = rtt;
                self.rttvar_ms = rtt / 2.0;
                self.srtt_slow_ms = rtt;
            } else {
                let abs_diff = (self.srtt_ms - rtt).abs();
                self.rttvar_ms =
                    (1.0 - Self::RTT_VAR_BETA) * self.rttvar_ms + Self::RTT_VAR_BETA * abs_diff;
                self.srtt_ms =
                    (1.0 - Self::RTT_FAST_ALPHA) * self.srtt_ms + Self::RTT_FAST_ALPHA * rtt;
                self.srtt_slow_ms = (1.0 - Self::RTT_SLOW_ALPHA) * self.srtt_slow_ms
                    + Self::RTT_SLOW_ALPHA * self.srtt_ms;
            }
            self.rtt_samples = self.rtt_samples.saturating_add(1);
        }
        self.loss_ewma = (1.0 - Self::LOSS_ALPHA) * self.loss_ewma + Self::LOSS_ALPHA * sample.loss;

        // Two arms, EITHER can flag a degraded poll: sustained loss, or the
        // fast RTT running 2x the slow baseline AND +50ms absolute.
        let loss_degraded = self.loss_ewma >= Self::LOSS_DEGRADE_THRESHOLD;
        let rtt_fresh_enough = self.rtt_samples > 0
            && now_unix.saturating_sub(self.last_rtt_ingest_unix) <= Self::RTT_INGEST_MAX_AGE_SECS;
        let rtt_degraded = self.rtt_samples >= Self::RTT_SAMPLES_MIN
            && rtt_fresh_enough
            && self.srtt_ms >= Self::RTT_RELATIVE_THRESHOLD * self.srtt_slow_ms
            && self.srtt_ms - self.srtt_slow_ms >= Self::RTT_ABSOLUTE_THRESHOLD_MS;

        if loss_degraded || rtt_degraded {
            self.degraded_streak = self
                .degraded_streak
                .saturating_add(1)
                .min(Self::DEGRADED_STREAK_MIN + 1);
        } else {
            self.degraded_streak = self.degraded_streak.saturating_sub(1);
        }

        if self.degraded_streak >= Self::DEGRADED_STREAK_MIN
            && now_unix >= self.last_quality_rerace_unix + Self::QUALITY_RERACE_DWELL_SECS
        {
            self.last_quality_rerace_unix = now_unix;
            self.degraded_streak = 0;
            Some(true)
        } else {
            None
        }
    }
}

/// FIS-0013: per-peer quality trackers, daemon-owned, persistent across
/// sync passes.
#[derive(Debug, Default)]
pub struct PathQualityTracker {
    peers: std::collections::BTreeMap<rustynet_backend_api::NodeId, PathQualityState>,
}

impl PathQualityTracker {
    pub fn ingest_sample(
        &mut self,
        node_id: &rustynet_backend_api::NodeId,
        sample: rustynet_backend_api::PeerPathSample,
        now_unix: u64,
    ) -> Option<bool> {
        self.peers
            .entry(node_id.clone())
            .or_default()
            .ingest_sample(sample, now_unix)
    }

    /// Drop trackers for peers no longer present.
    pub fn retain_peers(
        &mut self,
        keep: &std::collections::BTreeSet<rustynet_backend_api::NodeId>,
    ) {
        self.peers.retain(|node_id, _| keep.contains(node_id));
    }
}

/// FIS-0009 Phase 3 input: the peer's cross-session traversal prior,
/// reduced to what the pair race needs. `None` (or the flag being off)
/// ranks exactly as today.
#[derive(Debug, Clone, Default)]
pub struct PriorRanking {
    pub last_success_class: Option<crate::peer_traversal_prior::CandidateClass>,
    pub per_class_probability:
        std::collections::BTreeMap<crate::peer_traversal_prior::CandidateClass, f32>,
}

impl PriorRanking {
    fn probability_for_pair(&self, pair: &crate::ice_priority::CandidatePair) -> f32 {
        match pair_candidate_class(pair) {
            Some(class) => self
                .per_class_probability
                .get(&class)
                .copied()
                .unwrap_or(0.5),
            None => 0.5,
        }
    }
}

/// Class of a candidate pair for prior scoring: keyed on the REMOTE
/// candidate (the destination we are trying to reach — the
/// Happy-Eyeballs axis). Relay-kind candidates score neutral.
fn pair_candidate_class(
    pair: &crate::ice_priority::CandidatePair,
) -> Option<crate::peer_traversal_prior::CandidateClass> {
    use crate::ice_priority::CandidateKind;
    use crate::peer_traversal_prior::CandidateClass;
    match (pair.remote.kind, pair.remote.addr.ip()) {
        (CandidateKind::Host, IpAddr::V4(_)) => Some(CandidateClass::HostV4),
        (CandidateKind::Host, IpAddr::V6(_)) => Some(CandidateClass::HostV6),
        (CandidateKind::ServerReflexive, IpAddr::V4(_)) => Some(CandidateClass::SrflxV4),
        (CandidateKind::ServerReflexive, IpAddr::V6(_)) => Some(CandidateClass::SrflxV6),
        (CandidateKind::Relay, _) => None,
    }
}

/// FIS-0009: stable secondary re-rank of the RFC-8445-priority-sorted pair
/// list by the peer's prior, then the Happy-Eyeballs front-float.
///
/// A pair may move at most ±2 positions from its ICE rank (a good class,
/// posterior → 1.0, gains 2 slots; a bad one loses 2) — a deliberate,
/// slot-bounded rendering of the design's "only breaks ties / promotes a
/// historically-winning class a few slots, never overrides a large
/// ICE-priority gap". The RFC 8445 ordering itself and the deterministic
/// role assignment are untouched — this re-ranks an already-valid list.
/// Finally, if the peer's `last_success_class` is present in the pair
/// list, exactly ONE pair of that class floats to the front of round 0.
fn prior_rerank_pairs(pairs: &mut [crate::ice_priority::CandidatePair], ranking: &PriorRanking) {
    // 2.5 slot-units so a full-confidence class STRICTLY passes 2 positions
    // (a 2.0 shift only ties with the neighbor's key, and stable tie-break
    // resolves back to ICE order) while 3 positions stays unreachable:
    // passing 3 pairs would need i - 2.5 < i - 3.
    const MAX_SLOT_SHIFT: f32 = 2.5;
    let mut keyed: Vec<(f32, usize)> = pairs
        .iter()
        .enumerate()
        .map(|(index, pair)| {
            let posterior = ranking.probability_for_pair(pair);
            let shift = MAX_SLOT_SHIFT * (posterior - 0.5) * 2.0;
            (index as f32 - shift, index)
        })
        .collect();
    // Stable by original index (the tuple's second element breaks ties
    // deterministically; f32 keys here are always finite).
    keyed.sort_by(|a, b| {
        a.0.partial_cmp(&b.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.1.cmp(&b.1))
    });
    let reordered: Vec<crate::ice_priority::CandidatePair> = keyed
        .iter()
        .map(|(_, index)| pairs[*index].clone())
        .collect();
    pairs.clone_from_slice(&reordered);

    if let Some(last_class) = ranking.last_success_class
        && let Some(position) = pairs
            .iter()
            .position(|pair| pair_candidate_class(pair) == Some(last_class))
        && position > 0
    {
        pairs[..=position].rotate_right(1);
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
        validate_candidates("local", local_candidates, self.config.clone())?;
        validate_candidates("remote", remote_candidates, self.config.clone())?;

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
        base_pairs.sort_by_key(|right| std::cmp::Reverse(right.2));
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
        validate_candidates("remote", remote_candidates, self.config.clone())?;

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
                "coordination expires_at_unix must be greater than issued_at_unix".to_owned(),
            ));
        }
        if record.expires_at_unix.saturating_sub(record.issued_at_unix) > MAX_COORDINATION_TTL_SECS
        {
            return Err(TraversalError::Coordination(
                "coordination ttl exceeds max supported value".to_owned(),
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

    #[allow(clippy::too_many_arguments)]
    pub fn execute_simultaneous_open<R: SimultaneousOpenRuntime, W: SimultaneousOpenWaiter>(
        &self,
        runtime: &mut R,
        waiter: &mut W,
        schedule: CoordinationSchedule,
        local_candidates: &[TraversalCandidate],
        remote_candidates: &[TraversalCandidate],
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

        let plan = match self.plan_direct_probes(local_candidates, remote_candidates) {
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
        let mut waited_for_attempt_delay = Duration::ZERO;
        for (index, pair) in plan.pairs.iter().enumerate() {
            let scheduled_delay = Duration::from_millis(pair.delay_ms);
            if scheduled_delay > waited_for_attempt_delay {
                waiter.wait(scheduled_delay - waited_for_attempt_delay);
                waited_for_attempt_delay = scheduled_delay;
            }
            runtime.send_probe(pair.remote.endpoint, pair.round)?;
            let latest = runtime.latest_handshake_unix()?;
            if handshake_advanced(observed_latest, latest)
                && handshake_is_fresh(latest, now_unix, handshake_freshness_secs)
            {
                return Ok(SimultaneousOpenResult {
                    decision: TraversalDecision::Direct {
                        endpoint: pair.remote.endpoint,
                        reason: TraversalDecisionReason::SimultaneousOpenHandshakeObserved,
                    },
                    attempts: index + 1,
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
                attempts: plan.pairs.len(),
                latest_handshake_unix: observed_latest,
                waited_for_start: schedule.wait_duration,
            });
        }

        Ok(SimultaneousOpenResult {
            decision: TraversalDecision::FailClosed {
                reason: TraversalDecisionReason::DirectProbeExhaustedFailClosed,
                rounds: self.config.simultaneous_open_rounds,
            },
            attempts: plan.pairs.len(),
            latest_handshake_unix: observed_latest,
            waited_for_start: schedule.wait_duration,
        })
    }

    /// D5.5 — parallel ICE-pair race.
    ///
    /// Differences from `execute_simultaneous_open`:
    ///
    /// 1. Pair ordering uses the RFC 8445 §6.1.2.3 pair-priority
    ///    formula via `crate::ice_priority::generate_candidate_pairs`,
    ///    parameterised by the deterministic controlling/controlled
    ///    role decided from the lex-min of the two node IDs.
    /// 2. Each round sends ALL pairs concurrently (back-to-back
    ///    `send_probe` calls in priority order) BEFORE checking the
    ///    handshake state, so a marginal-NAT path that needs multiple
    ///    simultaneous outbound packets to punch through has the
    ///    chance the existing serial loop denies it.
    /// 3. The winning endpoint is identified by `handshake_endpoint`
    ///    (runtime-extension method) when available, falling back to
    ///    the highest-priority pair we just probed in that round so
    ///    the back-compat default (`Ok(None)`) still produces a
    ///    sensible Direct decision.
    ///
    /// All other behaviour — relay fallback, fail-closed exhaustion,
    /// freshness window — mirrors `execute_simultaneous_open`.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_ice_pair_race<R: SimultaneousOpenRuntime, W: SimultaneousOpenWaiter>(
        &self,
        runtime: &mut R,
        waiter: &mut W,
        schedule: CoordinationSchedule,
        local_candidates: &[TraversalCandidate],
        remote_candidates: &[TraversalCandidate],
        local_node_id: &[u8; 32],
        remote_node_id: &[u8; 32],
        relay_endpoint: Option<SocketEndpoint>,
        now_unix: u64,
        handshake_freshness_secs: u64,
        prior_ranking: Option<&PriorRanking>,
        quality_demoted_endpoint: Option<SocketEndpoint>,
    ) -> Result<SimultaneousOpenResult, TraversalError> {
        if handshake_freshness_secs == 0 {
            return Err(TraversalError::InvalidConfig(
                "handshake freshness window must be greater than zero",
            ));
        }
        waiter.wait(schedule.wait_duration);

        let local_direct: Vec<TraversalCandidate> = local_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect();
        let remote_direct: Vec<TraversalCandidate> = remote_candidates
            .iter()
            .copied()
            .filter(|candidate| candidate.source.direct_eligible())
            .collect();
        if local_direct.is_empty() || remote_direct.is_empty() {
            return self.relay_or_fail_closed_for_race(
                &schedule,
                relay_endpoint,
                runtime,
                0,
                0,
                TraversalDecisionReason::NoDirectCandidatesRelayArmed,
            );
        }
        let local_prioritised =
            crate::ice_priority::prioritize_traversal_candidates(&local_direct, "local");
        let remote_prioritised =
            crate::ice_priority::prioritize_traversal_candidates(&remote_direct, "remote");
        let role = crate::ice_priority::decide_role(local_node_id, remote_node_id);
        let mut pairs = crate::ice_priority::generate_candidate_pairs(
            &local_prioritised,
            &remote_prioritised,
            role,
        );
        if pairs.is_empty() {
            return self.relay_or_fail_closed_for_race(
                &schedule,
                relay_endpoint,
                runtime,
                0,
                0,
                TraversalDecisionReason::NoDirectCandidatesRelayArmed,
            );
        }
        if let Some(ranking) = prior_ranking {
            // FIS-0009: re-rank BEFORE the cap so a promoted class survives
            // max_probe_pairs truncation.
            prior_rerank_pairs(&mut pairs, ranking);
        }
        if let Some(demoted) = quality_demoted_endpoint {
            // FIS-0013: incumbent demotion applies LAST (after the RFC 8445
            // sort and the FIS-0009 re-rank — both stable transforms on the
            // same seam). Demote-don't-exclude: pairs targeting the rotten
            // incumbent still race, at the back, and may win if every
            // alternate fails handshake.
            let (mut kept, incumbent): (Vec<_>, Vec<_>) = pairs.drain(..).partition(|pair| {
                !(pair.remote.addr.ip() == demoted.addr && pair.remote.addr.port() == demoted.port)
            });
            kept.extend(incumbent);
            pairs = kept;
        }
        pairs.truncate(self.config.max_probe_pairs);

        let mut observed_latest = runtime.latest_handshake_unix()?;
        let mut total_attempts = 0usize;
        let mut elapsed = Duration::ZERO;
        for round in 0..self.config.simultaneous_open_rounds {
            let round_delay = Duration::from_millis(
                self.config
                    .round_spacing_ms
                    .saturating_mul(u64::from(round)),
            );
            if round_delay > elapsed {
                waiter.wait(round_delay - elapsed);
                elapsed = round_delay;
            }
            // Fire ALL pairs of this round before polling — this is
            // the core of the "parallel" race. Each probe is one
            // outbound datagram; sending them back-to-back lets the
            // remote side observe simultaneous binding requests, which
            // is what marginal-NAT topologies need to succeed.
            for pair in &pairs {
                runtime.send_probe(
                    crate::ice_priority::socket_addr_to_socket_endpoint(pair.remote.addr),
                    round,
                )?;
                total_attempts = total_attempts.saturating_add(1);
            }
            let latest = runtime.latest_handshake_unix()?;
            if handshake_advanced(observed_latest, latest)
                && handshake_is_fresh(latest, now_unix, handshake_freshness_secs)
            {
                let winning_endpoint = match runtime.handshake_endpoint()? {
                    Some(endpoint) => endpoint,
                    None => {
                        crate::ice_priority::socket_addr_to_socket_endpoint(pairs[0].remote.addr)
                    }
                };
                return Ok(SimultaneousOpenResult {
                    decision: TraversalDecision::Direct {
                        endpoint: winning_endpoint,
                        reason: TraversalDecisionReason::IcePairRaceHandshakeObserved,
                    },
                    attempts: total_attempts,
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

        self.relay_or_fail_closed_for_race(
            &schedule,
            relay_endpoint,
            runtime,
            total_attempts,
            self.config.simultaneous_open_rounds,
            TraversalDecisionReason::DirectProbeExhaustedRelayArmed,
        )
    }

    fn relay_or_fail_closed_for_race<R: SimultaneousOpenRuntime>(
        &self,
        schedule: &CoordinationSchedule,
        relay_endpoint: Option<SocketEndpoint>,
        runtime: &mut R,
        attempts: usize,
        rounds_used: u8,
        relay_reason: TraversalDecisionReason,
    ) -> Result<SimultaneousOpenResult, TraversalError> {
        if let Some(endpoint) = relay_endpoint {
            return Ok(SimultaneousOpenResult {
                decision: TraversalDecision::Relay {
                    endpoint,
                    reason: relay_reason,
                    rounds: rounds_used,
                },
                attempts,
                latest_handshake_unix: runtime.latest_handshake_unix()?,
                waited_for_start: schedule.wait_duration,
            });
        }
        Ok(SimultaneousOpenResult {
            decision: TraversalDecision::FailClosed {
                reason: TraversalDecisionReason::DirectProbeExhaustedFailClosed,
                rounds: rounds_used,
            },
            attempts,
            latest_handshake_unix: runtime.latest_handshake_unix()?,
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
    value.is_some_and(|timestamp| now_unix.saturating_sub(timestamp) <= freshness_secs)
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
    // Fail-soft on CSPRNG failure: jitter exists only to prevent a thundering
    // herd of refreshes across nodes that bootstrapped at the same time; it is
    // not a security primitive. Falling back to zero jitter on a transient OS
    // randomness failure keeps the long-running daemon alive at the cost of a
    // brief loss of refresh decorrelation. (Compare with the relay session-id
    // path, which fails closed because a predictable id is exploitable.)
    let jitter_secs = if jitter_max_secs > 0 {
        let mut buf = [0u8; 8];
        match rand::rngs::OsRng.try_fill_bytes(&mut buf) {
            Ok(()) => u64::from_le_bytes(buf) % jitter_max_secs,
            Err(err) => {
                eprintln!("traversal refresh jitter skipped: OS randomness unavailable: {err}");
                0
            }
        }
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
/// the `WireGuard` tunnel address from triggering spurious events.
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

        // Detect removed interfaces. Only the first removal is acted on
        // per reconcile pass; subsequent removals roll up next tick.
        let removed = self
            .last_seen_addrs
            .keys()
            .find(|k| !current_filtered.contains_key(*k))
            .cloned();
        if let Some(iface) = removed {
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
        CandidateSource, CoordinationReplayWindow, CoordinationSchedule, EndpointMonitor,
        NatFilteringBehavior, NatMappingBehavior, NatProfile, PathMode, SimultaneousOpenRuntime,
        SimultaneousOpenWaiter, TransitionReason, TraversalCandidate, TraversalDecision,
        TraversalDecisionReason, TraversalEngine, TraversalEngineConfig, TraversalError,
        TraversalSession, collect_gathered_candidates, direct_udp_viable,
        parse_stun_xor_mapped_address, schedule_proactive_refresh,
    };
    use rustynet_backend_api::{NodeId, SocketEndpoint};
    use rustynet_control::roles::RoleCapability;
    use rustynet_control::{ControlPlaneCore, NodeMetadata, TraversalCoordinationRecord};
    use rustynet_policy::{PolicyRule, PolicySet, Protocol, RuleAction};
    use std::collections::BTreeMap;

    use std::net::{IpAddr, Ipv4Addr};

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
    fn candidate_endpoint_filter_rejects_unroutable_and_own_addrs() {
        use std::collections::BTreeSet;
        let v6 = |s: &str, port: u16| SocketEndpoint {
            addr: s.parse().unwrap(),
            port,
        };
        let no_ifaces: BTreeSet<IpAddr> = BTreeSet::new();

        // Routable v4/v6 on a nonzero port are allowed.
        assert!(super::is_candidate_endpoint_allowed(
            endpoint([203, 0, 113, 7], 51820),
            &no_ifaces
        ));
        assert!(super::is_candidate_endpoint_allowed(
            v6("2001:db8::1", 51820),
            &no_ifaces
        ));

        // Cfg-invariant rejects. (Loopback is intentionally allowed under
        // cfg(test) so tests can dial 127.0.0.1, so it is not asserted here.)
        for bad in [
            endpoint([203, 0, 113, 7], 0),           // port 0
            endpoint([0, 0, 0, 0], 51820),           // unspecified
            endpoint([224, 0, 0, 1], 51820),         // multicast
            endpoint([169, 254, 1, 1], 51820),       // v4 link-local
            endpoint([255, 255, 255, 255], 51820),   // broadcast
        ] {
            assert!(!super::is_candidate_endpoint_allowed(bad, &no_ifaces));
        }
        assert!(!super::is_candidate_endpoint_allowed(
            v6("fe80::1", 51820),
            &no_ifaces
        )); // v6 link-local
        assert!(!super::is_candidate_endpoint_allowed(v6("::", 51820), &no_ifaces)); // v6 unspecified

        // Anti-reflection: an endpoint that is one of our own interface addrs
        // is rejected.
        let mut own: BTreeSet<IpAddr> = BTreeSet::new();
        own.insert("203.0.113.7".parse::<IpAddr>().unwrap());
        assert!(!super::is_candidate_endpoint_allowed(
            endpoint([203, 0, 113, 7], 51820),
            &own
        ));
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
    fn endpoint_roam_to_identical_endpoint_is_noop() {
        let peer = NodeId::new("peer-roam-same").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let endpoint = endpoint([198, 51, 100, 5], 55123);

        session.on_direct_probe_success(endpoint, 120);
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(endpoint));

        let previous_transition = session.last_transition;
        let event = session.on_endpoint_roamed(endpoint, 150);
        assert!(
            event.is_none(),
            "roam to identical endpoint must not emit a transition"
        );
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(endpoint));
        assert_eq!(
            session.last_transition, previous_transition,
            "no-op roam must not overwrite last_transition"
        );
    }

    #[test]
    fn endpoint_roam_on_relay_path_does_not_promote_to_direct() {
        let peer = NodeId::new("peer-roam-relay").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let relay_endpoint = endpoint([198, 51, 100, 10], 51820);

        assert_eq!(session.path, PathMode::Relay);
        let event = session.on_endpoint_roamed(relay_endpoint, 130);
        assert!(
            event.is_none(),
            "roaming while on relay path must not emit a direct-mode transition"
        );
        assert_eq!(
            session.path,
            PathMode::Relay,
            "path mode must remain Relay across endpoint roam"
        );
        assert_eq!(
            session.active_endpoint,
            Some(relay_endpoint),
            "active endpoint should record the observed roam even on relay path"
        );
    }

    #[test]
    fn endpoint_roam_after_multiple_distinct_changes_keeps_direct_session() {
        let peer = NodeId::new("peer-multi-roam").expect("node id should be valid");
        let mut session = TraversalSession::new(peer, 100);
        let endpoints = [
            endpoint([198, 51, 100, 5], 55101),
            endpoint([198, 51, 100, 6], 55102),
            endpoint([198, 51, 100, 7], 55103),
            endpoint([198, 51, 100, 8], 55104),
        ];

        session.on_direct_probe_success(endpoints[0], 120);
        let mut now = 130u64;
        let mut last_event_ts = 0u64;
        for next in &endpoints[1..] {
            let event = session
                .on_endpoint_roamed(*next, now)
                .expect("distinct endpoint roam should emit a transition");
            assert_eq!(event.from, PathMode::Direct);
            assert_eq!(event.to, PathMode::Direct);
            assert_eq!(event.reason, TransitionReason::EndpointRoamed);
            assert_eq!(event.at_unix, now);
            last_event_ts = now;
            now = now.saturating_add(15);
        }
        assert_eq!(session.path, PathMode::Direct);
        assert_eq!(session.active_endpoint, Some(*endpoints.last().unwrap()));
        assert_eq!(session.last_transition.at_unix, last_event_ts);
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
        // Unknown NAT (no profile) resolves to the hard prior: 15s, no raise.
        assert_eq!(
            super::keepalive_prior_for_nat(None).prior_interval_secs(),
            15
        );
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
                .on_direct_probe_timeout(101, fallback_config.clone())
                .is_none()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert!(
            session
                .on_direct_probe_timeout(102, fallback_config.clone())
                .is_some()
        );
        assert_eq!(session.path, PathMode::Relay);
        assert_eq!(session.active_endpoint, None);

        let direct_endpoint = endpoint([203, 0, 113, 21], 51820);
        session.on_direct_probe_success(direct_endpoint, 103);
        assert_eq!(session.path, PathMode::Direct);
        session.on_direct_probe_timeout(104, fallback_config.clone());
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
        let rustynet_if_ips = [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))];
        let rustynet_if_ip_set = rustynet_if_ips.iter().copied().collect();
        let host_candidates = [SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 0,
        }];
        let local_bound = Some(SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 40123,
        });
        let candidates = collect_gathered_candidates(
            local_bound,
            &host_candidates,
            &rustynet_if_ip_set,
            1,
            vec![
                Ok(SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    port: 51820,
                }),
                Ok(SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    port: 51820,
                }),
                Err(TraversalError::Stun("stun response timed out".to_owned())),
            ],
        );
        assert!(candidates.iter().any(|c| c.source == CandidateSource::Host));
        assert!(
            candidates
                .iter()
                .any(|c| c.source == CandidateSource::ServerReflexive)
        );
        let results = collect_gathered_candidates(
            local_bound,
            &host_candidates,
            &rustynet_if_ip_set,
            1,
            vec![Err(TraversalError::Stun(
                "stun response timed out".to_owned(),
            ))],
        );
        assert!(results.iter().all(|c| c.source == CandidateSource::Host));
    }

    /// XOR-MAPPED-ADDRESS binding response for the traversal parser.
    fn build_stun_test_response(transaction_id: [u8; 12], mapped: std::net::SocketAddr) -> Vec<u8> {
        let std::net::SocketAddr::V4(mapped_v4) = mapped else {
            panic!("test helper is v4-only");
        };
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        message.extend_from_slice(&transaction_id);
        message.extend_from_slice(&0x0020u16.to_be_bytes());
        message.extend_from_slice(&8u16.to_be_bytes());
        message.push(0x00);
        message.push(0x01);
        let cookie_bytes = 0x2112_A442u32.to_be_bytes();
        let port_mask = u16::from_be_bytes([cookie_bytes[0], cookie_bytes[1]]);
        message.extend_from_slice(&(mapped_v4.port() ^ port_mask).to_be_bytes());
        for (index, byte) in mapped_v4.ip().octets().iter().enumerate() {
            message.push(byte ^ cookie_bytes[index]);
        }
        let declared_len = (message.len() - 20) as u16;
        message[2..4].copy_from_slice(&declared_len.to_be_bytes());
        message
    }

    /// STUN test server: drops the first `drop_first` requests, then (when
    /// `respond`) answers the next one and exits. When `respond` is false it
    /// only counts until `serve_for` elapses. Returns the request count.
    fn spawn_stun_ladder_server(
        drop_first: usize,
        respond: bool,
        serve_for: Duration,
    ) -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind stun test server");
        let addr = socket.local_addr().expect("stun test server addr");
        let handle = std::thread::spawn(move || {
            let deadline = Instant::now() + serve_for;
            let mut received = 0usize;
            let mut buffer = [0u8; 1500];
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return received;
                }
                socket
                    .set_read_timeout(Some(remaining))
                    .expect("server read timeout");
                let Ok((len, source)) = socket.recv_from(&mut buffer) else {
                    return received;
                };
                if len < 20 {
                    continue;
                }
                received += 1;
                if received <= drop_first || !respond {
                    continue;
                }
                let mut transaction_id = [0u8; 12];
                transaction_id.copy_from_slice(&buffer[8..20]);
                let response = build_stun_test_response(transaction_id, source);
                let _ = socket.send_to(&response, source);
                return received;
            }
        });
        (addr, handle)
    }

    fn ladder_test_gatherer(
        servers: Vec<std::net::SocketAddr>,
        timeout: Duration,
    ) -> super::CandidateGatherer {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind gather socket");
        super::CandidateGatherer::new(socket, servers, timeout, Vec::new(), Vec::new())
            .expect("gatherer config valid")
    }

    #[test]
    fn stun_gather_recovers_lost_response_via_retransmit() {
        // FIS-0011: the old single-shot path lost the whole gather cycle to
        // one dropped datagram; the RTO ladder recovers within one RTO.
        let (server, handle) = spawn_stun_ladder_server(1, true, Duration::from_secs(4));
        let gatherer = ladder_test_gatherer(vec![server], Duration::from_secs(2));

        let candidates = gatherer.gather();
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.source == CandidateSource::ServerReflexive),
            "retransmit must recover the dropped first response"
        );
        let requests_seen = handle.join().expect("server joins");
        assert_eq!(requests_seen, 2, "one drop + one answered retransmit");
    }

    #[test]
    fn stun_gather_slow_server_no_longer_starves_others() {
        // Old behavior: server 1's full-budget recv_from consumed the whole
        // deadline and server 2 was never queried. Fire-all means the live
        // server answers regardless of the blackhole (RFC 5737 TEST-NET-1).
        let blackhole: std::net::SocketAddr = "192.0.2.1:3478".parse().expect("blackhole addr");
        let (live, handle) = spawn_stun_ladder_server(0, true, Duration::from_secs(4));
        let timeout = Duration::from_millis(800);
        let gatherer = ladder_test_gatherer(vec![blackhole, live], timeout);

        let started = Instant::now();
        let candidates = gatherer.gather();
        let elapsed = started.elapsed();

        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.source == CandidateSource::ServerReflexive),
            "live server behind a blackhole must still yield its srflx candidate"
        );
        assert!(
            elapsed < timeout * 2,
            "gather must stay within ~one shared deadline, took {elapsed:?}"
        );
        let _ = handle.join();
    }

    #[test]
    fn stun_gather_dark_server_gives_up_after_rc_attempts_within_deadline() {
        let serve_for = Duration::from_millis(1900);
        let (dark, handle) = spawn_stun_ladder_server(usize::MAX, false, serve_for);
        let timeout = Duration::from_millis(1500);
        let gatherer = ladder_test_gatherer(vec![dark], timeout);

        let started = Instant::now();
        let candidates = gatherer.gather();
        let elapsed = started.elapsed();

        assert!(
            !candidates
                .iter()
                .any(|candidate| candidate.source == CandidateSource::ServerReflexive),
            "dark server must yield no srflx candidate"
        );
        assert!(
            elapsed < timeout + Duration::from_millis(500),
            "ladder must not blow the shared deadline, took {elapsed:?}"
        );
        // RTO ladder: sends at ~0ms, ~250ms, ~750ms — then no more within
        // the 1.5s budget (next would be at 1750ms).
        let requests_seen = handle.join().expect("server joins");
        assert_eq!(
            requests_seen,
            usize::from(super::STUN_MAX_REQUEST_ATTEMPTS),
            "ladder must stop at Rc sends"
        );
    }

    fn rerank_pair(
        remote_v4: &str,
        kind: crate::ice_priority::CandidateKind,
        priority: u64,
    ) -> crate::ice_priority::CandidatePair {
        let remote_addr: std::net::SocketAddr = remote_v4.parse().expect("addr");
        let local_addr: std::net::SocketAddr = "10.0.0.1:51820".parse().expect("addr");
        crate::ice_priority::CandidatePair {
            local: crate::ice_priority::PrioritizedCandidate {
                addr: local_addr,
                kind: crate::ice_priority::CandidateKind::Host,
                priority: 100,
                foundation: format!("local-{remote_v4}"),
            },
            remote: crate::ice_priority::PrioritizedCandidate {
                addr: remote_addr,
                kind,
                priority: 100,
                foundation: format!("remote-{remote_v4}"),
            },
            pair_priority: priority,
        }
    }

    #[test]
    fn flap_breaker_steady_good_never_opens() {
        let mut breaker = super::FlapBreaker::new();
        for tick in 0..100u64 {
            breaker.record_outcome(false, tick);
            assert!(!breaker.is_open(tick));
            assert_eq!(breaker.state_label(tick), "closed");
        }
        assert!(breaker.intensity() < 0.01);
    }

    #[test]
    fn flap_breaker_single_failure_does_not_open() {
        let mut breaker = super::FlapBreaker::new();
        breaker.record_outcome(true, 10);
        // One failure: intensity = 0.3, under the 0.6 open threshold.
        assert!(!breaker.is_open(11));
    }

    #[test]
    fn flap_breaker_sustained_flapping_opens_and_holds_relay() {
        let mut breaker = super::FlapBreaker::new();
        // Six rapid failures (a flap burst inside one reconcile window):
        // intensity 1 - 0.7^3 = 0.657 crosses theta_open on the third.
        for now in 0..6u64 {
            breaker.record_outcome(true, now);
        }
        // Opened at now=2 with cooldown 10s + <=25% jitter: open_until in
        // [12, 14].
        assert!(breaker.is_open(6), "sustained failures must open");
        assert_eq!(breaker.state_label(6), "open");
        assert!(breaker.is_open(11), "must still hold at 11s");
        assert!(!breaker.is_open(17), "first cooldown is bounded by 14s");
    }

    #[test]
    fn flap_breaker_half_open_success_closes_failure_reopens_longer() {
        let mut breaker = super::FlapBreaker::new();
        for now in 0..6u64 {
            breaker.record_outcome(true, now);
        }
        // Opened at now=2, open_until in [12, 14]. Cooldown expires ->
        // half-open: one trial allowed.
        let now = 20u64;
        assert!(!breaker.is_open(now));
        assert_eq!(breaker.state_label(now), "half_open");

        // Trial FAILURE re-opens with the NEXT ladder step (20s + jitter,
        // open_until in [40, 45]) — strictly longer than the first.
        breaker.record_outcome(true, now);
        assert!(breaker.is_open(now));
        assert!(
            breaker.is_open(now + 15),
            "second cooldown must exceed the first ladder step"
        );

        // Wait out the longer cooldown, then a trial SUCCESS closes it.
        let now = 120u64;
        assert!(!breaker.is_open(now));
        breaker.record_outcome(false, now);
        assert!(!breaker.is_open(now));
        assert_eq!(breaker.open_until, 0, "success must clear the hold-down");
    }

    #[test]
    fn flap_breaker_sustained_recovery_resets_backoff_ladder() {
        let mut breaker = super::FlapBreaker::new();
        let mut now = 0u64;
        for _ in 0..8 {
            breaker.record_outcome(true, now);
            now += 200; // wait out each cooldown so the ladder climbs
        }
        let climbed_exponent = breaker.exponent;
        assert!(climbed_exponent >= 2, "ladder should have climbed");

        // Long run of successes: intensity decays below theta_close and
        // after 10 consecutive good intervals the ladder fully resets.
        for _ in 0..20 {
            breaker.record_outcome(false, now);
            now += 30;
        }
        assert_eq!(breaker.exponent, 0, "sustained recovery resets backoff");
        assert_eq!(breaker.state_label(now), "closed");
    }

    #[test]
    fn path_quality_loss_arm_triggers_after_sustained_streak_and_dwell() {
        use rustynet_backend_api::PeerPathSample;
        let mut state = super::PathQualityState::default();
        let clean = PeerPathSample {
            loss: 0.0,
            rtt: Some(40),
            rttvar: None,
            latest_handshake: Some(1),
        };
        let lossy = PeerPathSample {
            loss: 0.2,
            rtt: Some(40),
            rttvar: None,
            latest_handshake: Some(1),
        };
        // Clean polls never trigger.
        for tick in 1_000_000..1_000_010u64 {
            assert_eq!(state.ingest_sample(clean, tick), None);
        }
        // Sustained loss: EWMA crosses 5% quickly; the trigger still needs
        // 5 consecutive degraded polls.
        let mut fired_at = None;
        for tick in 1_000_010..1_000_030u64 {
            if state.ingest_sample(lossy, tick) == Some(true) {
                fired_at = Some(tick);
                break;
            }
        }
        let fired_at = fired_at.expect("sustained loss must trigger");
        assert!(
            (1_000_014..=1_000_020).contains(&fired_at),
            "trigger after ~5 degraded polls, got {fired_at}"
        );
        // Dwell: an immediate re-trigger is suppressed for 300s.
        for tick in fired_at + 1..fired_at + 50 {
            assert_eq!(state.ingest_sample(lossy, tick), None, "dwell holds");
        }
        // After the dwell elapses, sustained degradation may fire again.
        let mut refired = false;
        for tick in fired_at + 301..fired_at + 340 {
            if state.ingest_sample(lossy, tick) == Some(true) {
                refired = true;
                break;
            }
        }
        assert!(refired, "post-dwell sustained degradation re-triggers");
    }

    #[test]
    fn path_quality_rtt_arm_needs_relative_and_absolute_degradation() {
        use rustynet_backend_api::PeerPathSample;
        // Each poll carries a fresh handshake so the RTT ingest advances
        // (the sticky-repeat dedupe is pinned separately below).
        let sample = |rtt: u32, handshake: u64| PeerPathSample {
            loss: 0.0,
            rtt: Some(rtt),
            rttvar: None,
            latest_handshake: Some(handshake),
        };
        // Baseline 20ms, spike to 60ms: 3x relative but only +40ms absolute
        // — must NOT trigger (both arms required).
        let mut state = super::PathQualityState::default();
        for tick in 1_000_000..1_000_020u64 {
            assert_eq!(state.ingest_sample(sample(20, tick), tick), None);
        }
        for tick in 1_000_020..1_000_060u64 {
            assert_eq!(
                state.ingest_sample(sample(60, tick), tick),
                None,
                "3x relative without +50ms absolute must not trigger"
            );
        }
        // Baseline 40ms, sustained 400ms: BOTH arms satisfied -> triggers.
        let mut state = super::PathQualityState::default();
        for tick in 1_000_000..1_000_020u64 {
            assert_eq!(state.ingest_sample(sample(40, tick), tick), None);
        }
        let mut fired = false;
        for tick in 1_000_020..1_000_120u64 {
            if state.ingest_sample(sample(400, tick), tick) == Some(true) {
                fired = true;
                break;
            }
        }
        assert!(fired, "10x + 360ms sustained RTT degradation must trigger");
    }

    #[test]
    fn path_quality_rtt_arm_gated_on_ingest_age_not_poll_age() {
        use rustynet_backend_api::PeerPathSample;
        // FIS-0021 delta 3: the sticky repeat of one handshake's RTT must
        // ingest exactly once, and once the last REAL ingest goes stale
        // (>240s), the RTT arm cannot keep a degraded verdict alive no
        // matter how fresh the loss-only polling is.
        let mut state = super::PathQualityState::default();
        // Establish a baseline with fresh handshakes.
        for tick in 1_000_000..1_000_010u64 {
            let _ = state.ingest_sample(
                PeerPathSample {
                    loss: 0.0,
                    rtt: Some(40),
                    rttvar: None,
                    latest_handshake: Some(tick),
                },
                tick,
            );
        }
        // One degraded handshake, then the SAME handshake repeats for 400
        // polls (sticky last_rtt): only one ingest, and past 240s the RTT
        // arm goes stale — no trigger may ever fire.
        let sticky = PeerPathSample {
            loss: 0.0,
            rtt: Some(400),
            rttvar: None,
            latest_handshake: Some(1_000_010),
        };
        for tick in 1_000_010..1_000_410u64 {
            assert_eq!(
                state.ingest_sample(sticky, tick),
                None,
                "sticky RTT repeats must not accumulate degraded evidence"
            );
        }
    }

    #[test]
    fn quality_demoted_incumbent_sorts_last_but_stays_in_race() {
        use crate::ice_priority::CandidateKind;
        // Reuse the rerank pair fixture; demote the TOP ICE pair.
        let pairs_input = vec![
            rerank_pair("203.0.113.1:1", CandidateKind::Host, 500),
            rerank_pair("203.0.113.2:2", CandidateKind::Host, 400),
            rerank_pair("203.0.113.3:3", CandidateKind::ServerReflexive, 300),
        ];
        // The demotion transform lives inline in execute_ice_pair_race;
        // reproduce its partition here against the same shape to pin the
        // semantics: demoted incumbent moves to the END, order of the rest
        // is preserved, nothing is excluded.
        let demoted = SocketEndpoint {
            addr: "203.0.113.1".parse().expect("addr"),
            port: 1,
        };
        let mut pairs = pairs_input;
        let (mut kept, incumbent): (Vec<_>, Vec<_>) = pairs.drain(..).partition(|pair| {
            !(pair.remote.addr.ip() == demoted.addr && pair.remote.addr.port() == demoted.port)
        });
        kept.extend(incumbent);
        assert_eq!(kept.len(), 3, "demote, never exclude");
        assert_eq!(kept[0].remote.addr.port(), 2);
        assert_eq!(kept[1].remote.addr.port(), 3);
        assert_eq!(kept[2].remote.addr.port(), 1, "incumbent races last");
    }

    #[test]
    fn prior_rerank_is_identity_without_evidence() {
        use crate::ice_priority::CandidateKind;
        let mut pairs = vec![
            rerank_pair("203.0.113.1:1", CandidateKind::Host, 400),
            rerank_pair("203.0.113.2:2", CandidateKind::ServerReflexive, 300),
            rerank_pair("203.0.113.3:3", CandidateKind::Host, 200),
        ];
        let baseline = pairs.clone();
        // Empty ranking: every class scores the neutral 0.5 → no movement.
        super::prior_rerank_pairs(&mut pairs, &super::PriorRanking::default());
        assert_eq!(pairs, baseline, "no evidence must not reorder");
    }

    #[test]
    fn prior_rerank_promotes_winning_class_bounded_slots() {
        use crate::ice_priority::CandidateKind;
        use crate::peer_traversal_prior::CandidateClass;
        let mut pairs = vec![
            rerank_pair("203.0.113.1:1", CandidateKind::Host, 500),
            rerank_pair("203.0.113.2:2", CandidateKind::Host, 400),
            rerank_pair("203.0.113.3:3", CandidateKind::Host, 300),
            rerank_pair("203.0.113.4:4", CandidateKind::ServerReflexive, 200),
        ];
        let ranking = super::PriorRanking {
            last_success_class: None,
            per_class_probability: [
                (CandidateClass::SrflxV4, 1.0),
                (CandidateClass::HostV4, 0.5),
            ]
            .into_iter()
            .collect(),
        };
        super::prior_rerank_pairs(&mut pairs, &ranking);
        // SrflxV4 posterior 1.0 → gains exactly 2 slots (index 3 → 1),
        // never jumps the whole list: the top ICE pair stays first.
        assert_eq!(pairs[0].remote.addr.port(), 1, "top ICE pair holds rank");
        assert_eq!(
            pairs[1].remote.kind,
            CandidateKind::ServerReflexive,
            "winning class promoted a bounded number of slots"
        );
    }

    #[test]
    fn prior_front_float_moves_last_success_class_first() {
        use crate::ice_priority::CandidateKind;
        use crate::peer_traversal_prior::CandidateClass;
        let mut pairs = vec![
            rerank_pair("203.0.113.1:1", CandidateKind::Host, 500),
            rerank_pair("203.0.113.2:2", CandidateKind::Host, 400),
            rerank_pair("203.0.113.3:3", CandidateKind::ServerReflexive, 300),
            rerank_pair("203.0.113.4:4", CandidateKind::ServerReflexive, 200),
        ];
        let ranking = super::PriorRanking {
            last_success_class: Some(CandidateClass::SrflxV4),
            per_class_probability: std::collections::BTreeMap::new(),
        };
        super::prior_rerank_pairs(&mut pairs, &ranking);
        // Exactly ONE pair of the last-success class floats to the front;
        // relative order of everything else is preserved.
        assert_eq!(
            pairs[0].remote.addr.port(),
            3,
            "first srflx pair floats to front"
        );
        assert_eq!(pairs[1].remote.addr.port(), 1);
        assert_eq!(pairs[2].remote.addr.port(), 2);
        assert_eq!(pairs[3].remote.addr.port(), 4, "only one pair floats");
    }

    #[test]
    fn coordination_record_validation_and_execute_simultaneous_open_behaviour() {
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        let node_a = rustynet_control::NodeMetadata {
            node_id: "node-a".to_owned(),
            hostname: "a".to_owned(),
            os: "linux".to_owned(),
            tags: vec![],
            capabilities: vec![RoleCapability::Client],
            owner: "owner-a".to_owned(),
            endpoint: "127.0.0.1:51820".to_owned(),
            last_seen_unix: 1,
            public_key: [1u8; 32],
        };
        let node_b = rustynet_control::NodeMetadata {
            node_id: "node-b".to_owned(),
            hostname: "b".to_owned(),
            os: "linux".to_owned(),
            tags: vec![],
            capabilities: vec![RoleCapability::Client],
            owner: "owner-b".to_owned(),
            endpoint: "127.0.0.1:51821".to_owned(),
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
            node_a: "node-a".to_owned(),
            node_b: "node-b".to_owned(),
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

        let local_candidates = vec![candidate([10, 0, 0, 10], 51820, CandidateSource::Host, 900)];
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
                local_candidates.as_slice(),
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

        #[derive(Clone, Default)]
        struct SharedTraversalState {
            waited: std::rc::Rc<std::cell::Cell<bool>>,
        }

        struct WaitDrivenHandshakeRuntime {
            state: SharedTraversalState,
            sent: Vec<(SocketEndpoint, u8)>,
            observed_handshake_unix: u64,
        }
        impl SimultaneousOpenRuntime for WaitDrivenHandshakeRuntime {
            fn send_probe(
                &mut self,
                endpoint: SocketEndpoint,
                round: u8,
            ) -> Result<(), TraversalError> {
                self.sent.push((endpoint, round));
                Ok(())
            }

            fn latest_handshake_unix(&mut self) -> Result<Option<u64>, TraversalError> {
                Ok(self
                    .state
                    .waited
                    .get()
                    .then_some(self.observed_handshake_unix))
            }
        }

        struct RecordingWaiter {
            state: SharedTraversalState,
            waits: Vec<Duration>,
        }
        impl SimultaneousOpenWaiter for RecordingWaiter {
            fn wait(&mut self, duration: Duration) {
                self.waits.push(duration);
                if !duration.is_zero() {
                    self.state.waited.set(true);
                }
            }
        }

        let shared_state = SharedTraversalState::default();
        let mut delayed_runtime = WaitDrivenHandshakeRuntime {
            state: shared_state.clone(),
            sent: Vec::new(),
            observed_handshake_unix: now,
        };
        let mut delayed_waiter = RecordingWaiter {
            state: shared_state,
            waits: Vec::new(),
        };
        let delayed_result = engine
            .execute_simultaneous_open(
                &mut delayed_runtime,
                &mut delayed_waiter,
                schedule2,
                local_candidates.as_slice(),
                direct_candidates.as_slice(),
                None,
                now,
                120,
            )
            .expect("delayed direct probe should succeed");

        match delayed_result.decision {
            TraversalDecision::Direct { endpoint, reason } => {
                assert_eq!(endpoint, direct_candidates[0].endpoint);
                assert_eq!(
                    reason,
                    TraversalDecisionReason::SimultaneousOpenHandshakeObserved
                );
            }
            other => panic!("expected delayed direct decision, got {other:?}"),
        }
        assert_eq!(delayed_result.attempts, 2);
        assert_eq!(delayed_runtime.sent.len(), 2);
        assert_eq!(delayed_runtime.sent[0].1, 0);
        assert_eq!(delayed_runtime.sent[1].1, 1);
        assert_eq!(
            delayed_waiter.waits,
            vec![
                Duration::ZERO,
                Duration::from_millis(engine.config.round_spacing_ms)
            ]
        );
    }

    // ── A4: Adversarial traversal hardening tests ─────────────────────────

    /// A4: A coordination record with an invalid (forged) signature must be
    /// rejected.  The daemon must not switch paths based on forged records.
    #[test]
    fn test_a4_forged_signature_coordination_record_rejected() {
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        core.nodes
            .upsert(NodeMetadata {
                node_id: "node-a".to_owned(),
                hostname: "host-a".to_owned(),
                os: "linux".to_owned(),
                tags: vec![],
                capabilities: vec![RoleCapability::Client],
                owner: "user".to_owned(),
                endpoint: "1.2.3.4:1234".to_owned(),
                last_seen_unix: 0,
                public_key: [0u8; 32],
            })
            .expect("upsert a");
        core.nodes
            .upsert(NodeMetadata {
                node_id: "node-b".to_owned(),
                hostname: "host-b".to_owned(),
                os: "linux".to_owned(),
                tags: vec![],
                capabilities: vec![RoleCapability::Client],
                owner: "user".to_owned(),
                endpoint: "5.6.7.8:5678".to_owned(),
                last_seen_unix: 0,
                public_key: [0u8; 32],
            })
            .expect("upsert b");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = TraversalCoordinationRecord {
            session_id: [1u8; 16],
            probe_start_unix: now + 2,
            node_a: "node-a".to_owned(),
            node_b: "node-b".to_owned(),
            issued_at_unix: now,
            expires_at_unix: now + 20,
            nonce: [9u8; 16],
        };
        let mut signed = core
            .signed_traversal_coordination_record(record)
            .expect("sign");
        // Corrupt the signature bytes.
        let mut corrupted = signed.signature_hex.clone();
        if corrupted.starts_with('0') {
            corrupted.replace_range(0..1, "1");
        } else {
            corrupted.replace_range(0..1, "0");
        }
        signed.signature_hex = corrupted;

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
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        core.nodes
            .upsert(NodeMetadata {
                node_id: "node-a".to_owned(),
                hostname: "host-a".to_owned(),
                os: "linux".to_owned(),
                tags: vec![],
                capabilities: vec![RoleCapability::Client],
                owner: "user".to_owned(),
                endpoint: "1.2.3.4:1234".to_owned(),
                last_seen_unix: 0,
                public_key: [0u8; 32],
            })
            .expect("upsert a");
        core.nodes
            .upsert(NodeMetadata {
                node_id: "node-b".to_owned(),
                hostname: "host-b".to_owned(),
                os: "linux".to_owned(),
                tags: vec![],
                capabilities: vec![RoleCapability::Client],
                owner: "user".to_owned(),
                endpoint: "5.6.7.8:5678".to_owned(),
                last_seen_unix: 0,
                public_key: [0u8; 32],
            })
            .expect("upsert b");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let record = TraversalCoordinationRecord {
            session_id: [2u8; 16],
            probe_start_unix: now + 1,
            node_a: "node-a".to_owned(),
            node_b: "node-b".to_owned(),
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

    #[test]
    fn test_a4_expired_coordination_record_rejected() {
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        for (node_id, endpoint) in [("node-a", "1.2.3.4:1234"), ("node-b", "5.6.7.8:5678")] {
            core.nodes
                .upsert(NodeMetadata {
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec![],
                    capabilities: vec![RoleCapability::Client],
                    owner: "user".to_owned(),
                    endpoint: endpoint.to_owned(),
                    last_seen_unix: 0,
                    public_key: [0u8; 32],
                })
                .expect("upsert node");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [3u8; 16],
                probe_start_unix: now.saturating_sub(5),
                node_a: "node-a".to_owned(),
                node_b: "node-b".to_owned(),
                issued_at_unix: now.saturating_sub(20),
                expires_at_unix: now.saturating_sub(1),
                nonce: [0xcd; 16],
            })
            .expect("sign");

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
            matches!(err, Err(TraversalError::CoordinationExpired)),
            "expired coordination must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_a4_wrong_node_coordination_record_rejected() {
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        for (node_id, endpoint) in [("node-a", "1.2.3.4:1234"), ("node-b", "5.6.7.8:5678")] {
            core.nodes
                .upsert(NodeMetadata {
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec![],
                    capabilities: vec![RoleCapability::Client],
                    owner: "user".to_owned(),
                    endpoint: endpoint.to_owned(),
                    last_seen_unix: 0,
                    public_key: [0u8; 32],
                })
                .expect("upsert node");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let signed = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [4u8; 16],
                probe_start_unix: now.saturating_add(1),
                node_a: "node-a".to_owned(),
                node_b: "node-b".to_owned(),
                issued_at_unix: now,
                expires_at_unix: now.saturating_add(20),
                nonce: [0xef; 16],
            })
            .expect("sign");

        let engine = TraversalEngine::new(TraversalEngineConfig::default()).expect("engine");
        let mut replay = CoordinationReplayWindow::default();
        let err = engine.validate_signed_coordination_record(
            &signed,
            &NodeId::new("node-a").unwrap(),
            &NodeId::new("node-c").unwrap(),
            &core.endpoint_hint_verifying_key,
            &mut replay,
            now,
        );
        assert!(
            matches!(err, Err(TraversalError::CoordinationNodeMismatch)),
            "wrong-node coordination must be rejected: {err:?}"
        );
    }

    #[test]
    fn test_a4_malformed_coordination_payload_rejected() {
        let mut policy = PolicySet::default();
        policy.rules.push(PolicyRule {
            src: "node:node-a".to_owned(),
            dst: "node:node-b".to_owned(),
            protocol: Protocol::Udp,
            action: RuleAction::Allow,
        });
        let core = ControlPlaneCore::new(vec![0u8; 32], policy);
        for (node_id, endpoint) in [("node-a", "1.2.3.4:1234"), ("node-b", "5.6.7.8:5678")] {
            core.nodes
                .upsert(NodeMetadata {
                    node_id: node_id.to_owned(),
                    hostname: node_id.to_owned(),
                    os: "linux".to_owned(),
                    tags: vec![],
                    capabilities: vec![RoleCapability::Client],
                    owner: "user".to_owned(),
                    endpoint: endpoint.to_owned(),
                    last_seen_unix: 0,
                    public_key: [0u8; 32],
                })
                .expect("upsert node");
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut signed = core
            .signed_traversal_coordination_record(TraversalCoordinationRecord {
                session_id: [5u8; 16],
                probe_start_unix: now.saturating_add(1),
                node_a: "node-a".to_owned(),
                node_b: "node-b".to_owned(),
                issued_at_unix: now,
                expires_at_unix: now.saturating_add(20),
                nonce: [0xaa; 16],
            })
            .expect("sign");
        signed.payload = signed.payload.replace("node_b=node-b\n", "");

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
            matches!(err, Err(TraversalError::Coordination(_))),
            "malformed coordination payload must be rejected: {err:?}"
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

    /// Regression: a previous revision of `schedule_proactive_refresh` called
    /// `OsRng::try_fill_bytes(...).expect(...)` for the jitter buffer. A CSPRNG
    /// failure (early-boot, jail without /dev/urandom, hardware fault) would
    /// then crash the long-running daemon's traversal scheduler. The current
    /// implementation must instead fall back to zero jitter and log. We pin
    /// this two ways:
    ///   1. Source-grep `traversal.rs` to ensure no `expect(` follows
    ///      `try_fill_bytes` inside `schedule_proactive_refresh` ever returns.
    ///   2. Make sure `jitter_max_secs = 0` never invokes the CSPRNG branch
    ///      (it would be a panic if `OsRng` were unavailable, which we cannot
    ///      simulate without injection).
    #[test]
    fn schedule_proactive_refresh_does_not_panic_on_csprng_unavailability() {
        let crate_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = std::fs::read_to_string(crate_root.join("src/traversal.rs"))
            .expect("traversal source readable");
        // The fixed implementation must contain the recovery arm.
        assert!(
            source.contains("traversal refresh jitter skipped"),
            "schedule_proactive_refresh must fail-soft to zero jitter on CSPRNG failure; \
             the recovery `eprintln!` marker is missing — a regression would re-introduce a \
             daemon panic on any transient OS-randomness fault"
        );
        // And must not still contain the old panicking `expect` call.
        // We look for the exact bytes of the original expect message; if
        // someone re-introduces it, this guard fires. Build the needle
        // from chunks so this test's own source does not match it.
        let needle = ["os randomness unavailable", " for traversal refresh jitter"].concat();
        let panicking_pattern = format!(".expect(\"{needle}\")");
        assert!(
            !source.contains(&panicking_pattern),
            "the previous panicking expect on the jitter CSPRNG call has reappeared"
        );

        // jitter_max_secs = 0 is the no-CSPRNG path; verify it never invokes
        // anything that could panic by running it under the usual env.
        let expires_at = SystemTime::now() + Duration::from_secs(300);
        let _ = schedule_proactive_refresh(expires_at, 60, 0);
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
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_owned()]);

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
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_owned()]);

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

    /// B2-a: Address changes on the `WireGuard` tunnel interface (`rustynet0`)
    /// must be silently ignored — they are not underlay mobility events.
    #[test]
    fn test_b2a_rustynet_interface_changes_ignored() {
        let mut monitor = EndpointMonitor::new(vec!["rustynet".to_owned()]);

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

    /// HP2-01: Verified traversal index lifecycle.
    #[test]
    fn test_verified_traversal_index_lifecycle() {
        let mut index = super::VerifiedTraversalIndex::new();
        assert!(index.is_empty());

        let record = super::VerifiedTraversalRecord {
            candidates: vec![],
            generated_at_unix: 100,
            expires_at_unix: 200,
            nonce: 1,
            verified_at_unix: 150,
        };

        index.insert("node-a".to_owned(), "node-b".to_owned(), record.clone());
        assert_eq!(index.len(), 1);

        let retrieved = index.get("node-a", "node-b").expect("should exist");
        assert_eq!(retrieved.nonce, 1);

        index.prune_expired(199);
        assert_eq!(index.len(), 1);

        index.prune_expired(200);
        assert_eq!(index.len(), 0);
    }

    fn valid_stun_xor_mapped_message(transaction_id: [u8; 12]) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(&0x0101u16.to_be_bytes());
        message.extend_from_slice(&0u16.to_be_bytes());
        message.extend_from_slice(&0x2112_A442u32.to_be_bytes());
        message.extend_from_slice(&transaction_id);
        message.extend_from_slice(&0x0020u16.to_be_bytes()); // XOR-MAPPED-ADDRESS
        message.extend_from_slice(&8u16.to_be_bytes()); // attr len
        message.push(0x00);
        message.push(0x01); // IPv4 family
        let cookie = 0x2112_A442u32.to_be_bytes();
        let port_mask = u16::from_be_bytes([cookie[0], cookie[1]]);
        message.extend_from_slice(&(51820u16 ^ port_mask).to_be_bytes());
        for (i, octet) in Ipv4Addr::new(203, 0, 113, 5).octets().iter().enumerate() {
            message.push(octet ^ cookie[i]);
        }
        let declared_len = (message.len() - 20) as u16;
        message[2..4].copy_from_slice(&declared_len.to_be_bytes());
        message
    }

    #[test]
    fn parse_stun_xor_mapped_address_never_panics_on_arbitrary_input() {
        // Parser-never-panics invariant: the STUN binding-response decoder runs
        // on untrusted network bytes, so on any input — truncated mid-attribute,
        // bit-flipped, or random — it must return Err, never panic.
        let tid: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let valid = valid_stun_xor_mapped_message(tid);

        for len in 0..=valid.len() {
            let _ = parse_stun_xor_mapped_address(&valid[..len], tid);
        }
        for i in 0..valid.len() {
            let mut corrupted = valid.clone();
            corrupted[i] ^= 0xFF;
            let _ = parse_stun_xor_mapped_address(&corrupted, tid);
        }
        for len in [0usize, 1, 19, 20, 21, 64, 512, 4096] {
            let _ = parse_stun_xor_mapped_address(&vec![0u8; len], tid);
            let _ = parse_stun_xor_mapped_address(&vec![0xFFu8; len], tid);
        }
        let mut seed = 0xDEAD_BEEF_CAFE_F00Du64;
        for len in 0..384usize {
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                bytes.push((seed >> 33) as u8);
            }
            let _ = parse_stun_xor_mapped_address(&bytes, tid);
        }
    }

    #[test]
    fn parse_coordination_payload_never_panics_on_arbitrary_input() {
        // Parser-never-panics invariant for the coordination-record payload
        // decoder (untrusted peer input parsed before signature application).
        let payload = super::serialize_coordination_payload(&super::ParsedCoordinationPayload {
            session_id: [5u8; 16],
            probe_start_unix: 1_700_000_100,
            node_a: "node-a".to_owned(),
            node_b: "node-b".to_owned(),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_200,
            nonce: [0xaau8; 16],
        });

        for (offset, _) in payload
            .char_indices()
            .chain(std::iter::once((payload.len(), ' ')))
        {
            let _ = super::parse_coordination_payload(&payload[..offset]);
        }
        for probe in [
            "",
            "\n\n",
            "novalue",
            "version=1\nsession_id=zz",
            &"k=v\n".repeat(20_000),
        ] {
            let _ = super::parse_coordination_payload(probe);
        }
        let mut seed = 0x0BAD_F00D_1234_5678u64;
        for len in 0..256usize {
            let mut s = String::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s.push((0x20 + (seed >> 40) as u8 % 0x5f) as char);
            }
            let _ = super::parse_coordination_payload(&s);
        }
    }
}
