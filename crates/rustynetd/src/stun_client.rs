#![forbid(unsafe_code)]

use rand::TryRngCore;
use std::fmt;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// Initial retransmission timeout for the FIS-0011 STUN ladder
/// (RFC 5389 §7.2.1 default is 500ms; halved because the whole gather
/// budget defaults to 2s and this is candidate discovery).
pub(crate) const STUN_INITIAL_RTO: Duration = Duration::from_millis(250);
/// Total sends per server per gather (initial + retransmits) — the RFC's
/// `Rc`, sized down from 7 for the short gather budget.
pub(crate) const STUN_MAX_REQUEST_ATTEMPTS: u8 = 3;

pub(crate) trait StunQuerySocket {
    fn set_read_timeout(&self, duration: Option<Duration>) -> std::io::Result<()>;
    /// Bound the batched gather's sends. UDP sends rarely block, so test
    /// fakes may keep this no-op default; the real socket forwards to the
    /// OS.
    fn set_write_timeout(&self, _duration: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

impl StunQuerySocket for UdpSocket {
    fn set_read_timeout(&self, duration: Option<Duration>) -> std::io::Result<()> {
        UdpSocket::set_read_timeout(self, duration)
    }

    fn set_write_timeout(&self, duration: Option<Duration>) -> std::io::Result<()> {
        UdpSocket::set_write_timeout(self, duration)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        UdpSocket::local_addr(self)
    }

    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        UdpSocket::send_to(self, buf, target)
    }

    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf)
    }
}

/// Per-target failure from the shared STUN gather core (NAT-3). Display
/// output preserves the exact message strings the traversal path used
/// before the consolidation, so caller-side diagnostics stay stable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StunGatherError {
    /// No valid response arrived before the shared gather deadline.
    TimedOut,
    /// OS randomness for the transaction id was unavailable (fail closed
    /// rather than send a predictable id).
    RandomnessUnavailable(String),
    /// The initial binding-request send failed.
    SendFailed(String),
    /// Socket timeout configuration failed before any request went out.
    SocketConfig(String),
}

impl fmt::Display for StunGatherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StunGatherError::TimedOut => f.write_str("stun response timed out"),
            StunGatherError::RandomnessUnavailable(err) => {
                write!(f, "os randomness unavailable: {err}")
            }
            StunGatherError::SendFailed(err) => {
                write!(f, "failed to send stun request: {err}")
            }
            StunGatherError::SocketConfig(err) => {
                write!(f, "failed to set stun write timeout: {err}")
            }
        }
    }
}

/// One in-flight binding request awaiting its response or next retransmit.
struct OutstandingStunQuery {
    target_index: usize,
    target: SocketAddr,
    transaction_id: [u8; 12],
    next_retransmit_at: Instant,
    rto: Duration,
    attempts: u8,
}

/// Generate a fresh 96-bit STUN transaction id from OS randomness. Fails
/// closed — no request goes out — rather than sending a predictable id.
fn generate_transaction_id() -> Result<[u8; 12], String> {
    let mut transaction_id = [0u8; 12];
    rand::rngs::OsRng
        .try_fill_bytes(transaction_id.as_mut_slice())
        .map_err(|err| err.to_string())?;
    Ok(transaction_id)
}

/// NAT-3 shared STUN gather core: fire-all + demux-by-source+tx-id with
/// the FIS-0011 RTO retransmission ladder, over any [`StunQuerySocket`].
///
/// All binding requests go out up front (own transaction id each; a
/// retransmission reuses its original id per RFC 5389 §7.2.1), then one
/// receive loop demuxes responses by source address + transaction-id echo
/// until the shared gather deadline. An unanswered request retransmits on
/// its RTO ladder ([`STUN_INITIAL_RTO`] initial, doubling, at most
/// [`STUN_MAX_REQUEST_ATTEMPTS`] sends — sized down from the RFC's 7
/// because this is short-budget candidate discovery, not a control
/// transaction). Results are per-target, in target order.
///
/// Both batched production paths delegate here —
/// `StunClient::gather_mapped_endpoints_batched` and
/// `traversal::CandidateGatherer::query_stun_servers_batched` — so the
/// wire format and retry behavior cannot silently drift apart again. This
/// module is the canonical wire-format home (`rustynet-netns-probe` is
/// byte-pinned to it).
pub(crate) fn gather_stun_mappings<S: StunQuerySocket>(
    socket: &S,
    targets: &[SocketAddr],
    timeout: Duration,
) -> Vec<Result<SocketAddr, StunGatherError>> {
    let mut results: Vec<Result<SocketAddr, StunGatherError>> = targets
        .iter()
        .map(|_| Err(StunGatherError::TimedOut))
        .collect();
    if targets.is_empty() {
        return results;
    }
    if let Err(err) = socket.set_write_timeout(Some(timeout)) {
        let message = err.to_string();
        for slot in &mut results {
            *slot = Err(StunGatherError::SocketConfig(message.clone()));
        }
        return results;
    }

    let deadline = Instant::now() + timeout;
    let mut outstanding: Vec<OutstandingStunQuery> = Vec::new();
    for (target_index, target) in targets.iter().enumerate() {
        let transaction_id = match generate_transaction_id() {
            Ok(transaction_id) => transaction_id,
            Err(err) => {
                results[target_index] = Err(StunGatherError::RandomnessUnavailable(err));
                continue;
            }
        };
        let request = build_binding_request(&transaction_id);
        if let Err(err) = socket.send_to(request.as_slice(), *target) {
            results[target_index] = Err(StunGatherError::SendFailed(err.to_string()));
            continue;
        }
        outstanding.push(OutstandingStunQuery {
            target_index,
            target: *target,
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
        if socket.set_read_timeout(Some(wait)).is_err() {
            break;
        }
        match socket.recv_from(&mut buffer) {
            Ok((received, source)) => {
                let Some(position) = outstanding.iter().position(|query| query.target == source)
                else {
                    // Response from an unqueried source: reject.
                    continue;
                };
                match parse_binding_response(
                    &buffer[..received],
                    &outstanding[position].transaction_id,
                ) {
                    Ok(mapped) => {
                        let query = outstanding.swap_remove(position);
                        results[query.target_index] = Ok(mapped);
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
                // Receive window elapsed: fall through to the retransmit
                // sweep below.
            }
            Err(_) => break,
        }
        let now = Instant::now();
        for query in &mut outstanding {
            if query.attempts < STUN_MAX_REQUEST_ATTEMPTS && now >= query.next_retransmit_at {
                let request = build_binding_request(&query.transaction_id);
                if socket.send_to(request.as_slice(), query.target).is_ok() {
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

/// Attempt timeouts for one server's slice of the (serial, singleton
/// transport) round-trip gather: the FIS-0011 RTO schedule with the final
/// attempt receiving whatever remains of the slice. The timeouts sum to at
/// most the slice — a fully-unresponsive server still consumes no more
/// than its slice, preserving the FIS-0018 total-budget invariant — and
/// the schedule is computed arithmetically from the slice so it is
/// deterministic and testable.
fn round_trip_attempt_timeouts(slice: Duration) -> Vec<Duration> {
    let mut timeouts = Vec::with_capacity(usize::from(STUN_MAX_REQUEST_ATTEMPTS));
    let mut remaining = slice;
    let mut rto = STUN_INITIAL_RTO;
    for attempt in 1..=STUN_MAX_REQUEST_ATTEMPTS {
        if remaining.is_zero() {
            break;
        }
        let timeout = if attempt == STUN_MAX_REQUEST_ATTEMPTS {
            remaining
        } else {
            rto.min(remaining)
        };
        timeouts.push(timeout);
        remaining = remaining.saturating_sub(timeout);
        rto = rto.saturating_mul(2);
    }
    timeouts
}

/// Result of a STUN query containing full mapped endpoint information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResult {
    /// The full mapped public endpoint (IP + port) as seen by the STUN server.
    pub mapped_endpoint: SocketAddr,
    /// The STUN server that was queried.
    pub server: SocketAddr,
    /// The local address of the socket used for the query.
    pub local_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunTransportRoundTrip {
    pub response: Vec<u8>,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct StunClient {
    servers: Vec<String>,
    timeout: Duration,
}

impl StunClient {
    pub fn new(servers: Vec<String>, timeout: Duration) -> Self {
        Self { servers, timeout }
    }

    /// Gather public mapped endpoints from STUN servers.
    ///
    /// Returns the full `SocketAddr` (IP + port) as observed by each STUN
    /// server. The mapped port is the actual NAT-translated port — not a guess
    /// or an attached `wg_listen_port` — so the returned candidates are safe
    /// to publish as srflx peer endpoints. This is the foundation of the
    /// dataplane traversal path; see
    /// `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
    /// §D2 for the contract this method satisfies.
    ///
    /// # Arguments
    /// * `socket` - Optional socket to use for queries. If provided, the
    ///   mapped endpoint reflects the NAT mapping for that specific socket
    ///   (i.e. the same UDP socket later used for peer traffic — the
    ///   correct behaviour in production). If `None`, creates a fresh
    ///   ephemeral socket per query — useful only for unit-test diversity
    ///   probes.
    ///
    /// # Returns
    /// A vector of `StunResult` containing the full mapped endpoint
    /// information for each STUN server that responded. Deduplicated by
    /// mapped endpoint.
    pub fn gather_mapped_endpoints(&self, socket: Option<&UdpSocket>) -> Vec<StunResult> {
        // FIS-0018: batched-send + single-receiver demux. Total gather
        // wall-clock is bounded by ONE `self.timeout` regardless of server
        // count (previously each server consumed a full serial timeout).
        match socket {
            Some(socket) => self.gather_mapped_endpoints_batched(socket),
            None => {
                // Test-only mode (production always passes Some): one
                // ephemeral socket for the whole batch.
                let Ok(owned_socket) = UdpSocket::bind("0.0.0.0:0") else {
                    return Vec::new();
                };
                self.gather_mapped_endpoints_batched(&owned_socket)
            }
        }
    }

    /// Resolve each configured server and delegate to the NAT-3 shared
    /// gather core ([`gather_stun_mappings`]): fire-all, demux by source
    /// address + tx-id echo, FIS-0011 RTO retransmit ladder. The ladder is
    /// new to this path — previously each server was sent exactly one
    /// request, so a single lost datagram silently forfeited that server
    /// for the whole cycle. Results assemble in server order (not arrival
    /// order) with the same dedup predicate, so an all-responsive fixture
    /// produces byte-identical output to the pre-consolidation version.
    fn gather_mapped_endpoints_batched<S: StunQuerySocket>(&self, socket: &S) -> Vec<StunResult> {
        let Ok(local_addr) = socket.local_addr() else {
            return Vec::new();
        };
        let mut targets: Vec<SocketAddr> = Vec::new();
        for server in &self.servers {
            let Ok(server_addrs) = server.to_socket_addrs() else {
                continue;
            };
            let Some(target) = server_addrs.into_iter().next() else {
                continue;
            };
            targets.push(target);
        }
        let outcomes = gather_stun_mappings(socket, targets.as_slice(), self.timeout);

        let mut results = Vec::new();
        for (target, outcome) in targets.into_iter().zip(outcomes) {
            let Ok(mapped_endpoint) = outcome else {
                continue;
            };
            if !results
                .iter()
                .any(|existing: &StunResult| existing.mapped_endpoint == mapped_endpoint)
            {
                results.push(StunResult {
                    mapped_endpoint,
                    server: target,
                    local_addr,
                });
            }
        }
        results
    }

    /// Gather public mapped endpoints using a backend-owned authoritative
    /// round-trip transport instead of a daemon-owned socket.
    ///
    /// FIS-0018: the authoritative round-trip transport is a hard singleton
    /// (queries must stay sequential), so the fix is budget accounting:
    /// each server gets `timeout / N` so an unresponsive server can no
    /// longer eat the others' budget — total gather wall-clock stays <= one
    /// `self.timeout`. N=1 receives the full timeout.
    ///
    /// NAT-3 adds the FIS-0011 retransmission ladder INSIDE each server's
    /// slice ([`round_trip_attempt_timeouts`]): up to
    /// [`STUN_MAX_REQUEST_ATTEMPTS`] round-trips per server on the RTO
    /// schedule, reusing the transaction id per RFC 5389 §7.2.1, so one
    /// dropped datagram no longer forfeits the server's entire slice. The
    /// sequential structure and the singleton invariant are untouched.
    ///
    /// Deferred (NAT-3 phase 4): true tx-id multiplexing over the singleton
    /// transport would remove the serial sum entirely, but requires
    /// redesigning the userspace-shared worker's one-in-flight
    /// request/reply slot (`RuntimeRequest::AuthoritativeRoundTrip` +
    /// `acquire_round_trip_slot`) into pending-transaction bookkeeping in
    /// the dataplane worker loop — deliberately not attempted here.
    pub fn gather_mapped_endpoints_with_round_trip<F>(&self, mut round_trip: F) -> Vec<StunResult>
    where
        F: FnMut(SocketAddr, &[u8], Duration) -> Result<StunTransportRoundTrip, String>,
    {
        let mut results = Vec::new();
        for server in &self.servers {
            let Ok(server_addrs) = server.to_socket_addrs() else {
                continue;
            };
            let Some(target) = server_addrs.into_iter().next() else {
                continue;
            };
            let Ok(tx_id) = generate_transaction_id() else {
                continue;
            };
            let request = build_binding_request(&tx_id);
            let mut validated = None;
            for attempt_timeout in round_trip_attempt_timeouts(self.per_server_slice()) {
                let Ok(response) = round_trip(target, request.as_slice(), attempt_timeout) else {
                    // Lost datagram or transport timeout: retry on the
                    // ladder (same transaction id, per RFC 5389 §7.2.1).
                    continue;
                };
                if response.remote_addr != target {
                    // Off-target response: treat like a dropped datagram
                    // and keep the ladder going, mirroring the batched
                    // path's "reject, keep pending" behavior.
                    continue;
                }
                let Ok(mapped_endpoint) = parse_binding_response(&response.response, &tx_id) else {
                    // Malformed or wrong tx-id from the real target: same.
                    continue;
                };
                validated = Some((mapped_endpoint, response.local_addr));
                break;
            }
            let Some((mapped_endpoint, local_addr)) = validated else {
                continue;
            };
            if !results
                .iter()
                .any(|existing: &StunResult| existing.mapped_endpoint == mapped_endpoint)
            {
                results.push(StunResult {
                    mapped_endpoint,
                    server: target,
                    local_addr,
                });
            }
        }
        results
    }

    /// Single-query serial path. Production migrated to the batched
    /// gather (FIS-0018); kept for the d2 port-identity contract tests.
    #[cfg(test)]
    fn query_stun_server_with_socket<S: StunQuerySocket>(
        &self,
        target: SocketAddr,
        socket: &S,
    ) -> Result<StunResult, String> {
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;

        let local_addr = socket.local_addr().map_err(|e| e.to_string())?;

        let tx_id = generate_transaction_id()?;
        let request = build_binding_request(&tx_id);

        socket
            .send_to(request.as_slice(), target)
            .map_err(|e| e.to_string())?;

        let mut buf = [0u8; 1024];
        let (len, _src) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;

        let mapped_endpoint = parse_binding_response(&buf[..len], &tx_id)?;

        Ok(StunResult {
            mapped_endpoint,
            server: target,
            local_addr,
        })
    }

    /// Per-server slice of the total gather budget for the (serial,
    /// singleton-transport) round-trip path: `timeout / server_count`,
    /// full timeout for a single server.
    fn per_server_slice(&self) -> Duration {
        let count = u32::try_from(self.servers.len().max(1)).unwrap_or(u32::MAX);
        self.timeout / count
    }
}

/// Test-only method shims onto the free wire-format functions below, so
/// the existing parser fixture suite keeps its call shape. Production
/// paths call the free functions directly.
#[cfg(test)]
impl StunClient {
    fn parse_binding_response(&self, buf: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
        parse_binding_response(buf, tx_id)
    }

    fn parse_xor_mapped_address(&self, val: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
        parse_xor_mapped_address(val, tx_id)
    }

    fn parse_mapped_address(&self, val: &[u8]) -> Result<SocketAddr, String> {
        parse_mapped_address(val)
    }
}

/// Build the 20-byte header-only binding request. This byte layout is the
/// canonical one: `rustynet-netns-probe` is byte-pinned to it.
fn build_binding_request(tx_id: &[u8; 12]) -> [u8; 20] {
    let mut packet = [0u8; 20];
    packet[0..2].copy_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    packet[2..4].copy_from_slice(&0u16.to_be_bytes()); // Length
    packet[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    packet[8..20].copy_from_slice(tx_id);
    packet
}

fn parse_binding_response(buf: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
    if buf.len() < 20 {
        return Err("response too short".to_owned());
    }
    let type_ = u16::from_be_bytes([buf[0], buf[1]]);
    if type_ != STUN_BINDING_RESPONSE {
        return Err(format!("unexpected response type: 0x{type_:04x}"));
    }
    let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err("invalid magic cookie".to_owned());
    }
    if &buf[8..20] != tx_id {
        return Err("transaction id mismatch".to_owned());
    }
    if buf.len() < 20 + length {
        return Err("truncated response".to_owned());
    }

    let mut pos = 20;
    let end = 20 + length;
    let mut mapped_addr = None;
    let mut xor_mapped_addr = None;

    while pos + 4 <= end {
        let attr_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let attr_len = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        let attr_end = pos + 4 + attr_len;
        if attr_end > end {
            return Err("stun attribute exceeds message boundary".to_owned());
        }
        let attr_value = &buf[pos + 4..attr_end];

        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS
            && let Ok(addr) = parse_xor_mapped_address(attr_value, tx_id)
        {
            xor_mapped_addr = Some(addr);
        } else if attr_type == STUN_ATTR_MAPPED_ADDRESS
            && let Ok(addr) = parse_mapped_address(attr_value)
        {
            mapped_addr = Some(addr);
        }

        // Align to 4 bytes
        let padding = (4 - (attr_len % 4)) % 4;
        pos = attr_end + padding;
    }

    if let Some(addr) = xor_mapped_addr {
        Ok(addr)
    } else if let Some(addr) = mapped_addr {
        Ok(addr)
    } else {
        Err("no mapped address attribute found".to_owned())
    }
}

fn parse_xor_mapped_address(val: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
    if val.len() < 8 {
        return Err("xor mapped addr too short".to_owned());
    }
    let _reserved = val[0];
    let family = val[1];
    let port_xor = u16::from_be_bytes([val[2], val[3]]);
    let port = port_xor ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

    if family == 0x01 {
        // IPv4
        if val.len() < 8 {
            return Err("ipv4 too short".to_owned());
        }
        let ip_xor = u32::from_be_bytes([val[4], val[5], val[6], val[7]]);
        let ip = ip_xor ^ STUN_MAGIC_COOKIE;
        Ok(SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::from(ip)),
            port,
        ))
    } else if family == 0x02 {
        // IPv6
        if val.len() < 20 {
            return Err("ipv6 too short".to_owned());
        }
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let mut addr = [0u8; 16];
        for (index, slot) in addr.iter_mut().enumerate() {
            let mask = if index < 4 {
                cookie[index]
            } else {
                tx_id[index - 4]
            };
            *slot = val[4 + index] ^ mask;
        }
        Ok(SocketAddr::new(
            IpAddr::V6(std::net::Ipv6Addr::from(addr)),
            port,
        ))
    } else {
        Err(format!("unknown family: 0x{family:02x}"))
    }
}

fn parse_mapped_address(val: &[u8]) -> Result<SocketAddr, String> {
    if val.len() < 8 {
        return Err("mapped addr too short".to_owned());
    }
    let _reserved = val[0];
    let family = val[1];
    let port = u16::from_be_bytes([val[2], val[3]]);

    if family == 0x01 {
        // IPv4
        if val.len() < 8 {
            return Err("ipv4 too short".to_owned());
        }
        let ip = std::net::Ipv4Addr::new(val[4], val[5], val[6], val[7]);
        Ok(SocketAddr::new(IpAddr::V4(ip), port))
    } else if family == 0x02 {
        // IPv6
        // Not supported
        Err("ipv6 mapped addr not supported".to_owned())
    } else {
        Err(format!("unknown family: 0x{family:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::sync::Mutex;

    fn build_xor_mapped_binding_response(tx_id: &[u8], mapped_endpoint: SocketAddr) -> Vec<u8> {
        let mut attribute = Vec::new();
        attribute.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        match mapped_endpoint {
            SocketAddr::V4(endpoint) => {
                attribute.extend_from_slice(&(8u16).to_be_bytes());
                attribute.push(0);
                attribute.push(0x01);
                let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                attribute.extend_from_slice(&xored_port.to_be_bytes());
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (byte, mask) in endpoint.ip().octets().iter().zip(cookie.iter()) {
                    attribute.push(byte ^ mask);
                }
            }
            SocketAddr::V6(endpoint) => {
                attribute.extend_from_slice(&(20u16).to_be_bytes());
                attribute.push(0);
                attribute.push(0x02);
                let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                attribute.extend_from_slice(&xored_port.to_be_bytes());
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (index, byte) in endpoint.ip().octets().iter().enumerate() {
                    let mask = if index < 4 {
                        cookie[index]
                    } else {
                        tx_id[index - 4]
                    };
                    attribute.push(byte ^ mask);
                }
            }
        }

        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(tx_id);
        response.extend_from_slice(&attribute);
        response
    }

    #[test]
    fn test_stun_result_contains_full_endpoint() {
        // Verify StunResult structure captures full mapped endpoint
        let result = StunResult {
            mapped_endpoint: "1.2.3.4:12345".parse().unwrap(),
            server: "74.125.250.129:3478".parse().unwrap(),
            local_addr: "0.0.0.0:51820".parse().unwrap(),
        };

        // The mapped port should be preserved, not guessed
        assert_eq!(result.mapped_endpoint.port(), 12345);
        assert_eq!(result.mapped_endpoint.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_parse_xor_mapped_address_extracts_full_endpoint() {
        let client = StunClient::new(vec![], Duration::from_secs(1));

        // XOR-MAPPED-ADDRESS for 192.0.2.1:32853 (RFC 5389 example)
        // Port XOR: 32853 XOR (0x2112 >> 0) = 0x8055 XOR 0x2112 = 0xA147 (unxor'd port)
        // Actually let's use a simpler test value
        // mapped port 51820 = 0xCA6C, cookie upper = 0x2112, xor = 0xEB7E
        // mapped IP 203.0.113.1, xor with cookie 0x2112A442 = ...

        // Build test value for 1.2.3.4:5678
        // port 5678 = 0x162E, XOR with 0x2112 = 0x373C
        // ip 1.2.3.4 = 0x01020304, XOR with 0x2112A442 = 0x2010A746
        let val = [
            0x00, // reserved
            0x01, // IPv4
            0x37, 0x3C, // XOR'd port (5678 XOR 0x2112)
            0x20, 0x10, 0xA7, 0x46, // XOR'd IP (1.2.3.4 XOR 0x2112A442)
        ];

        let result = client.parse_xor_mapped_address(&val, &[0u8; 12]).unwrap();
        assert_eq!(result.port(), 5678);
        assert_eq!(result.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn test_parse_xor_mapped_address_extracts_ipv6_endpoint() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0xAA; 12];
        let endpoint = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 6000);
        let mut val = Vec::with_capacity(20);
        val.push(0x00);
        val.push(0x02);
        let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        val.extend_from_slice(&xored_port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        for (index, byte) in endpoint
            .ip()
            .to_string()
            .parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .iter()
            .enumerate()
        {
            let mask = if index < 4 {
                cookie[index]
            } else {
                tx_id[index - 4]
            };
            val.push(byte ^ mask);
        }

        let result = client.parse_xor_mapped_address(&val, &tx_id).unwrap();
        assert_eq!(result, endpoint);
    }

    #[test]
    fn test_parse_mapped_address_extracts_full_endpoint() {
        let client = StunClient::new(vec![], Duration::from_secs(1));

        // MAPPED-ADDRESS for 10.20.30.40:9999
        let val = [
            0x00, // reserved
            0x01, // IPv4
            0x27, 0x0F, // port 9999
            10, 20, 30, 40, // IP
        ];

        let result = client.parse_mapped_address(&val).unwrap();
        assert_eq!(result.port(), 9999);
        assert_eq!(result.ip().to_string(), "10.20.30.40");
    }

    #[test]
    fn test_gather_mapped_endpoints_returns_vec_of_socket_addr() {
        // This is a structural test - actual STUN queries need network
        let client = StunClient::new(vec![], Duration::from_secs(1));

        // With no servers, should return empty vec
        let results = client.gather_mapped_endpoints(None);
        assert!(results.is_empty());
    }

    #[test]
    fn test_gather_mapped_endpoints_with_round_trip_uses_authoritative_local_addr() {
        let server_addr: SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let local_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let mapped_endpoint: SocketAddr = "198.51.100.24:62000".parse().unwrap();
        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_secs(1));

        let results =
            client.gather_mapped_endpoints_with_round_trip(|target, request, _timeout| {
                assert_eq!(target, server_addr);
                Ok(StunTransportRoundTrip {
                    response: build_xor_mapped_binding_response(&request[8..20], mapped_endpoint),
                    remote_addr: server_addr,
                    local_addr,
                })
            });

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mapped_endpoint, mapped_endpoint);
        assert_eq!(results[0].local_addr, local_addr);
        assert_eq!(results[0].server, server_addr);
    }

    #[test]
    fn test_parse_binding_response_rejects_attribute_past_message_boundary() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x11; 12];
        let mut response = Vec::new();
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tx_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes());
        response.extend_from_slice(&[0u8; 4]);

        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("truncated attribute must fail");
        assert!(err.contains("message boundary"));
    }

    #[test]
    fn test_gather_mapped_endpoints_uses_provided_socket_identity() {
        let server_addr: SocketAddr = "127.0.0.1:3478".parse().expect("socket addr should parse");
        let local_addr: SocketAddr = "127.0.0.1:51820".parse().expect("socket addr should parse");
        let socket = ScriptedStunSocket::new(local_addr, server_addr);
        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_secs(2));

        let result = client
            .query_stun_server_with_socket(server_addr, &socket)
            .expect("provided socket identity query should succeed");
        assert_eq!(result.server, server_addr);
        assert_eq!(result.local_addr, local_addr);
        assert_eq!(result.mapped_endpoint, local_addr);
        assert_eq!(socket.last_target(), Some(server_addr));
        assert_eq!(socket.last_request_len(), Some(20));
    }

    fn binding_response_for_endpoint(endpoint: SocketAddr, tx_id: &[u8; 12]) -> Vec<u8> {
        let mut attr = Vec::with_capacity(8);
        attr.push(0x00);
        attr.push(0x01);
        let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        attr.extend_from_slice(&xored_port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let octets = match endpoint.ip() {
            IpAddr::V4(addr) => addr.octets(),
            IpAddr::V6(_) => panic!("test helper only supports ipv4"),
        };
        for (index, byte) in octets.iter().enumerate() {
            attr.push(byte ^ cookie[index]);
        }

        let mut response = Vec::with_capacity(32);
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&(attr.len() as u16 + 4).to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(tx_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        response.extend_from_slice(&attr);
        response
    }

    #[derive(Debug)]
    struct ScriptedStunSocket {
        local_addr: SocketAddr,
        expected_server: SocketAddr,
        state: Mutex<ScriptedStunSocketState>,
    }

    #[derive(Debug, Default)]
    struct ScriptedStunSocketState {
        last_target: Option<SocketAddr>,
        last_request_len: Option<usize>,
        last_tx_id: Option<[u8; 12]>,
    }

    impl ScriptedStunSocket {
        fn new(local_addr: SocketAddr, expected_server: SocketAddr) -> Self {
            Self {
                local_addr,
                expected_server,
                state: Mutex::new(ScriptedStunSocketState::default()),
            }
        }

        fn last_target(&self) -> Option<SocketAddr> {
            self.state
                .lock()
                .expect("mutex should not be poisoned")
                .last_target
        }

        fn last_request_len(&self) -> Option<usize> {
            self.state
                .lock()
                .expect("mutex should not be poisoned")
                .last_request_len
        }
    }

    impl StunQuerySocket for ScriptedStunSocket {
        fn set_read_timeout(&self, _duration: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
            assert_eq!(target, self.expected_server);
            assert_eq!(buf.len(), 20, "binding request should be header-only");
            let tx_id: [u8; 12] = buf[8..20]
                .try_into()
                .expect("transaction id should be present");
            let mut state = self.state.lock().expect("mutex should not be poisoned");
            state.last_target = Some(target);
            state.last_request_len = Some(buf.len());
            state.last_tx_id = Some(tx_id);
            Ok(buf.len())
        }

        fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let tx_id = self
                .state
                .lock()
                .expect("mutex should not be poisoned")
                .last_tx_id
                .expect("send_to should capture transaction id before recv");
            let response = binding_response_for_endpoint(self.local_addr, &tx_id);
            let len = response.len();
            buf[..len].copy_from_slice(&response);
            Ok((len, self.expected_server))
        }
    }

    // ---------- Adversarial-input hardening tests ----------
    //
    // These tests exercise the STUN parser against attacker-crafted byte
    // sequences. The STUN server is untrusted: every byte of the response
    // is attacker-controlled and the parser must reject malformed input
    // without panicking, looping, or reading past the buffer.

    fn build_response_header(length: u16, magic: u32, tx_id: &[u8; 12]) -> Vec<u8> {
        let mut response = Vec::with_capacity(20 + length as usize);
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&length.to_be_bytes());
        response.extend_from_slice(&magic.to_be_bytes());
        response.extend_from_slice(tx_id);
        response
    }

    #[test]
    fn stun_parser_handles_empty_buffer() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let err = client
            .parse_binding_response(&[], &[0u8; 12])
            .expect_err("empty buffer must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_truncated_header() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        // 19 bytes — one short of the 20-byte STUN header.
        let buf = [0u8; 19];
        let err = client
            .parse_binding_response(&buf, &[0u8; 12])
            .expect_err("truncated header must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_single_byte_buffer() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let err = client
            .parse_binding_response(&[0xFF], &[0u8; 12])
            .expect_err("single byte must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_message_with_wrong_magic_cookie() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x42; 12];
        // Magic cookie set to bogus 0xDEADBEEF.
        let response = build_response_header(0, 0xDEADBEEF, &tx_id);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("wrong magic cookie must be rejected");
        assert!(err.contains("magic cookie"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_response_with_wrong_transaction_id() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let request_tx_id = [0xAA; 12];
        let response_tx_id = [0xBB; 12];
        // Server replies with a different tx_id — classic forged-response
        // injection. Parser must reject so attacker cannot inject a
        // mapping for an unrelated outstanding request.
        let response = build_response_header(0, STUN_MAGIC_COOKIE, &response_tx_id);
        let err = client
            .parse_binding_response(&response, &request_tx_id)
            .expect_err("tx_id mismatch must be rejected");
        assert!(err.contains("transaction id"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_response_to_non_binding_request() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x33; 12];
        // Build a Binding *Error* Response (0x0111) instead of Success (0x0101).
        let mut response = Vec::with_capacity(20);
        response.extend_from_slice(&0x0111u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&tx_id);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("non-success response must be rejected");
        assert!(err.contains("unexpected response type"), "got: {err}");

        // Also reject a request opcode echoed back as if it were a response.
        let mut request_echoed = Vec::with_capacity(20);
        request_echoed.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        request_echoed.extend_from_slice(&0u16.to_be_bytes());
        request_echoed.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        request_echoed.extend_from_slice(&tx_id);
        let err = client
            .parse_binding_response(&request_echoed, &tx_id)
            .expect_err("request opcode in response position must be rejected");
        assert!(err.contains("unexpected response type"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_message_length_past_buffer_end() {
        // Header claims 100 bytes of attributes but buffer only has 20 bytes.
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x55; 12];
        let response = build_response_header(100, STUN_MAGIC_COOKIE, &tx_id);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("length past buffer end must be rejected");
        assert!(err.contains("truncated"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_attribute_length_past_buffer_end() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x66; 12];
        // Message length says we have 8 bytes of attributes (one TLV header).
        // The TLV claims its value is 1024 bytes — far beyond the message.
        let mut response = build_response_header(8, STUN_MAGIC_COOKIE, &tx_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&1024u16.to_be_bytes());
        response.extend_from_slice(&[0u8; 4]);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("attribute length past buffer end must be rejected");
        assert!(err.contains("message boundary"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_zero_length_attribute_run() {
        // Crafted malicious response: a long run of zero-length attributes
        // each with type 0x4242 (unknown comprehension-required).
        // The parser must NOT spin forever; each iteration must advance
        // pos by at least 4 (the TLV header itself), so the loop
        // terminates once we reach `end`.
        //
        // We additionally assert no mapped address is found, so the call
        // returns "no mapped address attribute found".
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x77; 12];
        // 8 zero-length attributes = 32 bytes of attribute area.
        let attr_count = 8u16;
        let length = attr_count * 4;
        let mut response = build_response_header(length, STUN_MAGIC_COOKIE, &tx_id);
        for _ in 0..attr_count {
            response.extend_from_slice(&0x4242u16.to_be_bytes()); // unknown type
            response.extend_from_slice(&0u16.to_be_bytes()); // length zero
        }
        // If the loop didn't advance on length=0, this call would hang or panic.
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("response with no mapped address must err");
        assert!(err.contains("no mapped address"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_xor_mapped_address_with_short_ipv4_payload() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        // IPv4 family but only 6 bytes (header + family + port, no IP).
        let val = [0x00u8, 0x01, 0x12, 0x34, 0xAA, 0xBB];
        let err = client
            .parse_xor_mapped_address(&val, &[0u8; 12])
            .expect_err("short IPv4 XOR-MAPPED-ADDRESS must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_xor_mapped_address_with_short_ipv6_payload() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        // IPv6 family declared but only 12 bytes provided (need 20).
        let mut val = vec![0x00u8, 0x02, 0x12, 0x34];
        val.extend_from_slice(&[0u8; 8]);
        assert_eq!(val.len(), 12);
        let err = client
            .parse_xor_mapped_address(&val, &[0u8; 12])
            .expect_err("short IPv6 XOR-MAPPED-ADDRESS must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_xor_mapped_address_with_unknown_family() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        // Family 0x07 — neither IPv4 (0x01) nor IPv6 (0x02).
        let val = [0x00u8, 0x07, 0x12, 0x34, 0xAA, 0xBB, 0xCC, 0xDD];
        let err = client
            .parse_xor_mapped_address(&val, &[0u8; 12])
            .expect_err("unknown family must be rejected");
        assert!(err.contains("unknown family"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_mapped_address_with_short_ipv4_payload() {
        let client = StunClient::new(vec![], Duration::from_secs(1));
        // 7 bytes — header + family + port + 3 of 4 IP octets.
        let val = [0x00u8, 0x01, 0x27, 0x0F, 1, 2, 3];
        let err = client
            .parse_mapped_address(&val)
            .expect_err("short IPv4 MAPPED-ADDRESS must be rejected");
        assert!(err.contains("too short"), "got: {err}");
    }

    #[test]
    fn stun_parser_ignores_unknown_attribute_in_success_response() {
        // RFC 5389 §7.3.1: unknown comprehension-required attributes in a
        // Success Response MUST be ignored (not rejected). A real
        // XOR-MAPPED-ADDRESS following an unknown attribute must still
        // parse successfully.
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x88; 12];
        let endpoint: SocketAddr = "192.0.2.42:7777".parse().unwrap();

        // Build XOR-MAPPED-ADDRESS attribute (TLV header + 8 byte value = 12 bytes).
        let mut xor_attr = Vec::with_capacity(12);
        xor_attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        xor_attr.extend_from_slice(&8u16.to_be_bytes());
        xor_attr.push(0);
        xor_attr.push(0x01);
        let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        xor_attr.extend_from_slice(&xored_port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        match endpoint.ip() {
            IpAddr::V4(addr) => {
                for (index, byte) in addr.octets().iter().enumerate() {
                    xor_attr.push(byte ^ cookie[index]);
                }
            }
            IpAddr::V6(_) => unreachable!(),
        }

        // Build an unknown comprehension-required attribute (type 0x002A,
        // 4-byte payload, total 8 bytes). 0x002A is in the 0x0000-0x7FFF
        // comprehension-required range but is not one we know.
        let mut unknown_attr = Vec::with_capacity(8);
        unknown_attr.extend_from_slice(&0x002Au16.to_be_bytes());
        unknown_attr.extend_from_slice(&4u16.to_be_bytes());
        unknown_attr.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let total_attr_len = (unknown_attr.len() + xor_attr.len()) as u16;
        let mut response = build_response_header(total_attr_len, STUN_MAGIC_COOKIE, &tx_id);
        response.extend_from_slice(&unknown_attr);
        response.extend_from_slice(&xor_attr);

        let parsed = client
            .parse_binding_response(&response, &tx_id)
            .expect("XOR-MAPPED-ADDRESS after unknown attr must still parse");
        assert_eq!(parsed, endpoint);
    }

    #[test]
    fn stun_parser_handles_padding_at_end_of_buffer() {
        // Positive boundary: an attribute whose length is not a multiple
        // of 4 must be 4-byte padded by the sender. Parser must accept
        // proper trailing padding without reading past the message end.
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0x99; 12];

        // Use an unknown 1-byte attribute (3 bytes of padding to align)
        // followed by a valid XOR-MAPPED-ADDRESS.
        let mut unknown = Vec::with_capacity(8);
        unknown.extend_from_slice(&0x002Bu16.to_be_bytes()); // unknown, comp-required
        unknown.extend_from_slice(&1u16.to_be_bytes());
        unknown.push(0xAB);
        unknown.extend_from_slice(&[0u8; 3]); // padding to 4-byte boundary

        let endpoint: SocketAddr = "203.0.113.7:1234".parse().unwrap();
        let mut xor_attr = Vec::with_capacity(12);
        xor_attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        xor_attr.extend_from_slice(&8u16.to_be_bytes());
        xor_attr.push(0);
        xor_attr.push(0x01);
        let xored_port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        xor_attr.extend_from_slice(&xored_port.to_be_bytes());
        let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        if let IpAddr::V4(addr) = endpoint.ip() {
            for (index, byte) in addr.octets().iter().enumerate() {
                xor_attr.push(byte ^ cookie[index]);
            }
        }

        let total_len = (unknown.len() + xor_attr.len()) as u16;
        let mut response = build_response_header(total_len, STUN_MAGIC_COOKIE, &tx_id);
        response.extend_from_slice(&unknown);
        response.extend_from_slice(&xor_attr);

        let parsed = client
            .parse_binding_response(&response, &tx_id)
            .expect("padded attribute followed by XOR-MAPPED-ADDRESS must parse");
        assert_eq!(parsed, endpoint);
    }

    #[test]
    fn stun_parser_handles_max_attribute_length_without_overflow() {
        // Attempt to provoke arithmetic overflow / panic via attr_len = u16::MAX
        // when the message length is much smaller. Must reject cleanly,
        // not panic with attempt-to-add-with-overflow or out-of-bounds index.
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0xCC; 12];
        let mut response = build_response_header(8, STUN_MAGIC_COOKIE, &tx_id);
        response.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&u16::MAX.to_be_bytes());
        response.extend_from_slice(&[0u8; 4]);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("u16::MAX attribute length must be rejected, not panic");
        assert!(err.contains("message boundary"), "got: {err}");
    }

    #[test]
    fn stun_parser_rejects_short_message_with_only_partial_attribute_header() {
        // Message length declared 3 bytes (less than a 4-byte TLV header).
        // The buffer holds those 3 bytes, but the loop guard `pos + 4 <= end`
        // rejects the iteration, and the parser falls through to "no mapped
        // address" rather than reading past the message.
        let client = StunClient::new(vec![], Duration::from_secs(1));
        let tx_id = [0xDD; 12];
        let mut response = build_response_header(3, STUN_MAGIC_COOKIE, &tx_id);
        response.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let err = client
            .parse_binding_response(&response, &tx_id)
            .expect_err("partial attribute header must not produce a mapping");
        assert!(err.contains("no mapped address"), "got: {err}");
    }

    // ---- D2: STUN srflx port discovery contract ----
    //
    // Per `RustynetDataplaneExecutionPlan_2026-05-18.md` §D2: the srflx
    // candidate port the STUN client surfaces must equal the bound transport
    // socket's actual external port — never a guess, never an attached
    // `wg_listen_port`. The structural test
    // `test_gather_mapped_endpoints_with_round_trip_uses_authoritative_local_addr`
    // pins this via a mock round-trip. The two tests below pin the same
    // contract end-to-end against real `UdpSocket` instances on loopback
    // (one IPv4, one IPv6), with an in-process STUN echo server that mirrors
    // the source endpoint back as XOR-MAPPED-ADDRESS. Over loopback, no NAT
    // applies, so the mapped endpoint and the bound socket's local address
    // must be identical — that's the "discovered port == bound port"
    // invariant.

    fn spawn_local_stun_echo(bind_addr: SocketAddr) -> (SocketAddr, std::thread::JoinHandle<()>) {
        let server_socket = UdpSocket::bind(bind_addr).expect("bind echo server");
        server_socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set echo server read timeout");
        let server_addr = server_socket.local_addr().expect("echo server local_addr");
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            let Ok((len, src)) = server_socket.recv_from(&mut buf) else {
                return;
            };
            if len < 20 {
                return;
            }
            let tx_id: [u8; 12] = buf[8..20].try_into().expect("tx_id slice");
            let response = build_xor_mapped_binding_response(&tx_id, src);
            let _ = server_socket.send_to(&response, src);
        });
        (server_addr, handle)
    }

    #[test]
    fn d2_stun_v4_discovered_port_equals_bound_socket_port() {
        let (server_addr, server_handle) =
            spawn_local_stun_echo("127.0.0.1:0".parse().expect("v4 bind addr parses"));

        let client_socket = UdpSocket::bind("127.0.0.1:0").expect("v4 client bind");
        let bound_local = client_socket.local_addr().expect("v4 client local_addr");

        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_secs(5));
        let result = client
            .query_stun_server_with_socket(server_addr, &client_socket)
            .expect("v4 stun query succeeds against in-process echo");

        // Contract: the discovered mapped endpoint over loopback (no NAT
        // remap) must be byte-identical to the bound socket's local address.
        // If this assertion ever fails, the STUN client has reintroduced
        // the "attach wg_listen_port to discovered IP" bug from
        // `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` §8.1.
        assert_eq!(
            result.mapped_endpoint, bound_local,
            "discovered srflx endpoint must equal bound socket's local_addr (v4)"
        );
        assert_eq!(
            result.mapped_endpoint.port(),
            bound_local.port(),
            "discovered port must equal bound port (v4)"
        );
        assert_eq!(
            result.local_addr, bound_local,
            "StunResult.local_addr must equal the socket's actual local_addr (v4)"
        );
        assert_eq!(result.server, server_addr);

        server_handle.join().expect("echo server thread joins");
    }

    #[test]
    fn d2_stun_v6_discovered_port_equals_bound_socket_port() {
        let (server_addr, server_handle) =
            spawn_local_stun_echo("[::1]:0".parse().expect("v6 bind addr parses"));

        let client_socket = UdpSocket::bind("[::1]:0").expect("v6 client bind");
        let bound_local = client_socket.local_addr().expect("v6 client local_addr");

        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_secs(5));
        let result = client
            .query_stun_server_with_socket(server_addr, &client_socket)
            .expect("v6 stun query succeeds against in-process echo");

        assert_eq!(
            result.mapped_endpoint, bound_local,
            "discovered srflx endpoint must equal bound socket's local_addr (v6)"
        );
        assert_eq!(
            result.mapped_endpoint.port(),
            bound_local.port(),
            "discovered port must equal bound port (v6)"
        );
        assert_eq!(
            result.local_addr, bound_local,
            "StunResult.local_addr must equal the socket's actual local_addr (v6)"
        );
        assert_eq!(result.server, server_addr);

        server_handle.join().expect("echo server thread joins");
    }

    /// Scripted in-memory socket for deterministic batched-gather tests:
    /// records sends, then serves a fixed sequence of (payload, source)
    /// datagrams. Responses are pre-scripted closures over the recorded
    /// tx-ids so arrival order is fully controlled.
    struct ScriptedBatchSocket {
        local: SocketAddr,
        sent: std::cell::RefCell<Vec<(Vec<u8>, SocketAddr)>>,
        // Each entry: (target the response claims to come from, build fn
        // input index into `sent` for the tx-id, or None for a bogus tx-id).
        responses: std::cell::RefCell<std::collections::VecDeque<(SocketAddr, Option<usize>)>>,
        mapped: SocketAddr,
    }

    impl ScriptedBatchSocket {
        fn new(mapped: SocketAddr) -> Self {
            Self {
                local: "127.0.0.1:40000".parse().expect("local addr"),
                sent: std::cell::RefCell::new(Vec::new()),
                responses: std::cell::RefCell::new(std::collections::VecDeque::new()),
                mapped,
            }
        }

        fn queue_response(&self, from: SocketAddr, echo_tx_of_send: Option<usize>) {
            self.responses
                .borrow_mut()
                .push_back((from, echo_tx_of_send));
        }
    }

    impl StunQuerySocket for ScriptedBatchSocket {
        fn set_read_timeout(&self, _duration: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local)
        }

        fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
            self.sent.borrow_mut().push((buf.to_vec(), target));
            Ok(buf.len())
        }

        fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let Some((from, echo_index)) = self.responses.borrow_mut().pop_front() else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "no more scripted responses",
                ));
            };
            let tx_id: [u8; 12] = match echo_index {
                Some(index) => self.sent.borrow()[index].0[8..20]
                    .try_into()
                    .expect("tx id slice"),
                None => [0xEE; 12],
            };
            let response = build_xor_mapped_binding_response(&tx_id, self.mapped);
            buf[..response.len()].copy_from_slice(&response);
            Ok((response.len(), from))
        }
    }

    #[test]
    fn multi_server_gather_completes_within_one_gather_deadline() {
        // Two responsive echoes + one blackhole (RFC 5737 TEST-NET-1, never
        // routable from CI): both live results must arrive and total elapsed
        // must stay bounded by ~one gather deadline, not a per-server sum.
        let (server_a, handle_a) = spawn_local_stun_echo("127.0.0.1:0".parse().expect("bind addr"));
        let (server_b, handle_b) = spawn_local_stun_echo("127.0.0.1:0".parse().expect("bind addr"));
        let blackhole = "192.0.2.1:3478";

        let timeout = Duration::from_millis(700);
        let client = StunClient::new(
            vec![
                server_a.to_string(),
                blackhole.to_owned(),
                server_b.to_string(),
            ],
            timeout,
        );
        let socket = UdpSocket::bind("127.0.0.1:0").expect("client bind");

        let started = Instant::now();
        let results = client.gather_mapped_endpoints(Some(&socket));
        let elapsed = started.elapsed();

        // Old serial behavior would need >= 2x timeout to even reach
        // server_b behind the blackhole; batched must stay within ~1x
        // (plus scheduling slack).
        assert!(
            elapsed < timeout * 2,
            "batched gather took {elapsed:?}, serial-shaped latency"
        );
        assert_eq!(
            results.len(),
            1,
            "loopback echoes map to one deduped endpoint"
        );
        assert_eq!(
            results[0].server, server_a,
            "server-order assembly: first responsive server wins the dedup slot"
        );
        handle_a.join().expect("echo a joins");
        handle_b.join().expect("echo b joins");
    }

    #[test]
    fn multi_server_gather_dedups_identical_mapped_endpoints() {
        // Both echoes observe the same client socket, so both report the
        // identical mapped endpoint — dedup must collapse them to one.
        let (server_a, handle_a) = spawn_local_stun_echo("127.0.0.1:0".parse().expect("bind addr"));
        let (server_b, handle_b) = spawn_local_stun_echo("127.0.0.1:0".parse().expect("bind addr"));
        let client = StunClient::new(
            vec![server_a.to_string(), server_b.to_string()],
            Duration::from_millis(700),
        );
        let socket = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        let bound_local = socket.local_addr().expect("local addr");

        let results = client.gather_mapped_endpoints(Some(&socket));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mapped_endpoint, bound_local);
        handle_a.join().expect("echo a joins");
        handle_b.join().expect("echo b joins");
    }

    #[test]
    fn multi_server_gather_output_is_server_order_not_arrival_order() {
        let server_a: SocketAddr = "127.0.0.1:5001".parse().expect("addr");
        let server_b: SocketAddr = "127.0.0.1:5002".parse().expect("addr");
        let client = StunClient::new(
            vec![server_a.to_string(), server_b.to_string()],
            Duration::from_millis(200),
        );
        // Distinct mapped endpoints per response are impossible with one
        // shared `mapped` — use identical mapped, but assert ORDER via the
        // `server` field: responses arrive B-first, output must be A-first.
        // With identical mapped endpoints dedup keeps exactly one — the one
        // in SERVER order (A), even though B arrived first.
        let socket = ScriptedBatchSocket::new("198.51.100.7:4242".parse().expect("mapped"));
        socket.queue_response(server_b, Some(1)); // B answers first
        socket.queue_response(server_a, Some(0)); // A answers second

        let results = client.gather_mapped_endpoints_batched(&socket);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].server, server_a,
            "output must assemble in server order, not arrival order"
        );
    }

    #[test]
    fn single_server_gather_behavior_unchanged() {
        let (server_addr, handle) =
            spawn_local_stun_echo("127.0.0.1:0".parse().expect("bind addr"));
        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_secs(5));
        let socket = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        let bound_local = socket.local_addr().expect("local addr");

        let results = client.gather_mapped_endpoints(Some(&socket));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mapped_endpoint, bound_local);
        assert_eq!(results[0].server, server_addr);
        assert_eq!(results[0].local_addr, bound_local);
        handle.join().expect("echo joins");
    }

    #[test]
    fn batched_gather_ignores_response_from_unqueried_source() {
        let server_a: SocketAddr = "127.0.0.1:5003".parse().expect("addr");
        let intruder: SocketAddr = "127.0.0.1:5999".parse().expect("addr");
        let client = StunClient::new(vec![server_a.to_string()], Duration::from_millis(200));
        let socket = ScriptedBatchSocket::new("198.51.100.7:4242".parse().expect("mapped"));
        // A perfectly well-formed response (correct tx-id!) from a source we
        // never queried must be rejected; the real server then answers.
        socket.queue_response(intruder, Some(0));
        socket.queue_response(server_a, Some(0));

        let results = client.gather_mapped_endpoints_batched(&socket);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].server, server_a);

        // And if ONLY the intruder answers, the gather yields nothing.
        let socket = ScriptedBatchSocket::new("198.51.100.7:4242".parse().expect("mapped"));
        socket.queue_response(intruder, Some(0));
        let results = client.gather_mapped_endpoints_batched(&socket);
        assert!(
            results.is_empty(),
            "unqueried source must never produce a candidate"
        );
    }

    #[test]
    fn round_trip_gather_slices_budget_across_servers() {
        // 900ms / 3 servers = 300ms per slice; the NAT-3 ladder subdivides
        // each slice into RTO-scheduled attempts (250ms, then the 50ms
        // remainder) whose timeouts sum to the slice, preserving the
        // FIS-0018 total-budget invariant.
        let client = StunClient::new(
            vec![
                "127.0.0.1:5001".to_owned(),
                "127.0.0.1:5002".to_owned(),
                "127.0.0.1:5003".to_owned(),
            ],
            Duration::from_millis(900),
        );
        let mut observed = Vec::new();
        let _ = client.gather_mapped_endpoints_with_round_trip(|_target, _req, timeout| {
            observed.push(timeout);
            Err("unresponsive".to_owned())
        });
        let slice_ladder = [Duration::from_millis(250), Duration::from_millis(50)];
        let expected: Vec<Duration> = slice_ladder
            .iter()
            .copied()
            .cycle()
            .take(slice_ladder.len() * 3)
            .collect();
        assert_eq!(observed, expected);
        let total: Duration = observed.iter().sum();
        assert!(
            total <= Duration::from_millis(900),
            "requested waits {total:?} exceed the gather budget"
        );
    }

    #[test]
    fn round_trip_gather_single_server_ladder_spans_full_timeout() {
        let client = StunClient::new(
            vec!["127.0.0.1:5001".to_owned()],
            Duration::from_millis(900),
        );
        let mut observed = Vec::new();
        let _ = client.gather_mapped_endpoints_with_round_trip(|_target, _req, timeout| {
            observed.push(timeout);
            Err("unresponsive".to_owned())
        });
        assert_eq!(
            observed,
            vec![
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_millis(150),
            ],
            "RTO ladder then the slice remainder, summing to the full timeout"
        );
    }

    #[test]
    fn round_trip_attempt_timeouts_sum_to_slice_and_follow_rto() {
        // Slice larger than the ladder: RTO, 2*RTO, remainder.
        assert_eq!(
            round_trip_attempt_timeouts(Duration::from_millis(900)),
            vec![
                Duration::from_millis(250),
                Duration::from_millis(500),
                Duration::from_millis(150)
            ]
        );
        // Slice shorter than the full ladder: truncated, still sums to
        // the slice.
        assert_eq!(
            round_trip_attempt_timeouts(Duration::from_millis(300)),
            vec![Duration::from_millis(250), Duration::from_millis(50)]
        );
        assert_eq!(
            round_trip_attempt_timeouts(Duration::from_millis(200)),
            vec![Duration::from_millis(200)]
        );
        assert_eq!(
            round_trip_attempt_timeouts(Duration::ZERO),
            Vec::<Duration>::new()
        );
    }

    #[test]
    fn round_trip_gather_lossy_server_recovers_within_slice() {
        // NAT-3: one dropped datagram no longer forfeits the server's
        // entire slice — the ladder's second attempt produces the
        // candidate, reusing the same transaction id (RFC 5389 §7.2.1).
        let server_addr: SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let local_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let mapped_endpoint: SocketAddr = "198.51.100.24:62000".parse().unwrap();
        let client = StunClient::new(vec![server_addr.to_string()], Duration::from_millis(900));

        let mut attempts = 0usize;
        let mut tx_ids: Vec<Vec<u8>> = Vec::new();
        let results =
            client.gather_mapped_endpoints_with_round_trip(|target, request, _timeout| {
                assert_eq!(target, server_addr);
                attempts += 1;
                tx_ids.push(request[8..20].to_vec());
                if attempts == 1 {
                    return Err("timed out".to_owned());
                }
                Ok(StunTransportRoundTrip {
                    response: build_xor_mapped_binding_response(&request[8..20], mapped_endpoint),
                    remote_addr: server_addr,
                    local_addr,
                })
            });

        assert_eq!(attempts, 2, "second ladder attempt must run and succeed");
        assert_eq!(
            tx_ids[0], tx_ids[1],
            "retransmit must reuse the transaction id"
        );
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].mapped_endpoint, mapped_endpoint);
        assert_eq!(results[0].server, server_addr);
    }

    #[test]
    fn round_trip_gather_dead_server_cannot_starve_live_one() {
        // A dead server consumes at most its slice (its ladder timeouts
        // sum to the slice); the lossy-but-alive server still yields its
        // candidate and the total requested wait stays <= the configured
        // timeout.
        let dead: SocketAddr = "203.0.113.1:3478".parse().unwrap();
        let lossy: SocketAddr = "203.0.113.2:3478".parse().unwrap();
        let local_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let mapped_endpoint: SocketAddr = "198.51.100.24:62000".parse().unwrap();
        let total = Duration::from_millis(1000);
        let client = StunClient::new(vec![dead.to_string(), lossy.to_string()], total);

        let mut waited = Duration::ZERO;
        let mut lossy_attempts = 0usize;
        let results = client.gather_mapped_endpoints_with_round_trip(|target, request, timeout| {
            waited += timeout;
            if target == dead {
                return Err("timed out".to_owned());
            }
            lossy_attempts += 1;
            if lossy_attempts == 1 {
                return Err("timed out".to_owned());
            }
            Ok(StunTransportRoundTrip {
                response: build_xor_mapped_binding_response(&request[8..20], mapped_endpoint),
                remote_addr: lossy,
                local_addr,
            })
        });

        assert_eq!(
            results.len(),
            1,
            "lossy-but-alive server must produce a candidate"
        );
        assert_eq!(results[0].server, lossy);
        assert_eq!(results[0].mapped_endpoint, mapped_endpoint);
        assert!(
            waited <= total,
            "requested waits {waited:?} exceed the total budget {total:?}"
        );
    }

    /// NAT-3 single-loss regression fake: the response to the FIRST request
    /// is lost (recv reports the read window elapsed), and a real response
    /// arrives only once a retransmit has gone out. The pre-consolidation
    /// batched path sent each request exactly once and treated the first
    /// recv timeout as the end of the gather, so it returned nothing here;
    /// the shared core's RTO ladder recovers the server.
    struct SingleLossSocket {
        local: SocketAddr,
        server: SocketAddr,
        mapped: SocketAddr,
        sent: std::cell::RefCell<Vec<Vec<u8>>>,
        answered: std::cell::Cell<bool>,
    }

    impl StunQuerySocket for SingleLossSocket {
        fn set_read_timeout(&self, _duration: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local)
        }

        fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize> {
            assert_eq!(target, self.server);
            self.sent.borrow_mut().push(buf.to_vec());
            Ok(buf.len())
        }

        fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let tx_id: Option<[u8; 12]> = {
                let sent = self.sent.borrow();
                if sent.len() < 2 || self.answered.get() {
                    None
                } else {
                    Some(sent[sent.len() - 1][8..20].try_into().expect("tx id slice"))
                }
            };
            let Some(tx_id) = tx_id else {
                // First request's response is lost; nothing arrives until
                // the ladder retransmits.
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "read window elapsed",
                ));
            };
            self.answered.set(true);
            let response = build_xor_mapped_binding_response(&tx_id, self.mapped);
            buf[..response.len()].copy_from_slice(&response);
            Ok((response.len(), self.server))
        }
    }

    #[test]
    fn batched_gather_survives_single_datagram_loss_via_retransmit() {
        let server: SocketAddr = "127.0.0.1:5004".parse().expect("addr");
        let mapped: SocketAddr = "198.51.100.9:4343".parse().expect("mapped");
        let client = StunClient::new(vec![server.to_string()], Duration::from_secs(2));
        let socket = SingleLossSocket {
            local: "127.0.0.1:40001".parse().expect("local"),
            server,
            mapped,
            sent: std::cell::RefCell::new(Vec::new()),
            answered: std::cell::Cell::new(false),
        };

        let results = client.gather_mapped_endpoints_batched(&socket);

        assert_eq!(
            results.len(),
            1,
            "retransmit must recover the single lost datagram"
        );
        assert_eq!(results[0].mapped_endpoint, mapped);
        assert_eq!(results[0].server, server);
        assert_eq!(
            socket.sent.borrow().len(),
            2,
            "exactly one retransmit expected (initial send + ladder resend)"
        );
    }

    // ---- Ported from traversal.rs (NAT-3 consolidation): the traversal
    // gatherer's parser fixtures now target the one canonical parser. ----

    #[test]
    fn canonical_parser_accepts_traversal_ipv4_fixture() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let port: u16 = 51820;
        let ip = std::net::Ipv4Addr::new(203, 0, 113, 5);
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
        let x_port = port ^ port_mask;
        message.extend_from_slice(&x_port.to_be_bytes());
        let ip_bytes = ip.octets();
        for (index, byte) in ip_bytes.iter().enumerate() {
            message.push(byte ^ cookie_bytes[index]);
        }
        let declared_len = (message.len() - 20) as u16;
        message[2..4].copy_from_slice(&declared_len.to_be_bytes());
        let parsed = parse_binding_response(message.as_slice(), &transaction_id).expect("parse");
        assert_eq!(parsed.port(), port);
        assert_eq!(parsed.ip(), IpAddr::V4(ip));
    }

    #[test]
    fn canonical_parser_rejects_traversal_malformed_fixture() {
        let bad = vec![0u8; 10];
        let tid = [0u8; 12];
        assert!(parse_binding_response(bad.as_slice(), &tid).is_err());
    }

    #[test]
    fn parse_binding_response_never_panics_on_arbitrary_input() {
        // Parser-never-panics invariant (ported from the traversal parser
        // when NAT-3 consolidated the wire format here): the decoder runs
        // on untrusted network bytes, so on any input — truncated
        // mid-attribute, bit-flipped, or random — it must return an error
        // or a decoded endpoint, never panic.
        let tid: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let endpoint: SocketAddr = "203.0.113.5:51820".parse().expect("addr");
        let valid = binding_response_for_endpoint(endpoint, &tid);

        for len in 0..=valid.len() {
            let _ = parse_binding_response(&valid[..len], &tid);
        }
        for index in 0..valid.len() {
            let mut corrupted = valid.clone();
            corrupted[index] ^= 0xFF;
            let _ = parse_binding_response(&corrupted, &tid);
        }
        for len in [0usize, 1, 19, 20, 21, 64, 512, 4096] {
            let _ = parse_binding_response(&vec![0u8; len], &tid);
            let _ = parse_binding_response(&vec![0xFFu8; len], &tid);
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
            let _ = parse_binding_response(&bytes, &tid);
        }
    }
}
