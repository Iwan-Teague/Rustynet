#![forbid(unsafe_code)]

//! D2.3 — programmatic router port-mapping via NAT-PMP / PCP / uPnP IGD.
//!
//! Per `RustynetDataplaneExecutionPlan_2026-05-18.md` §D2.3, the home server
//! probes its router on startup and asks for a UDP port mapping using the
//! standardised protocols. If the router cooperates, the relay binary gets a
//! real port-forward without the user touching their router admin page; if
//! it doesn't, the daemon falls back to the outbound-keepalive trick
//! (decision 2.3 in the same plan) which works on most cone-NAT home
//! routers.
//!
//! This module defines:
//!
//! * [`PortMapper`] — the trait every protocol implementation satisfies.
//! * [`MappingLease`] — the success-shape returned from a granted mapping.
//! * [`PortMapperError`] — the structured failure reasons (no gateway,
//!   protocol not supported, gateway refused, timeout, malformed response).
//! * [`PortMappingProtocol`] — which wire protocol the lease was granted
//!   over (NAT-PMP, PCP, uPnP IGD). Used for forensics + logging.
//! * [`NatPmpClient`] — first implementation. RFC 6886 wire format,
//!   hand-rolled UDP encoder/decoder, no external dependencies.
//!
//! uPnP IGD and PCP follow in subsequent slices within D2.3. The probe
//! orchestrator that tries each in order is also a follow-up.
//!
//! Security framing:
//!
//! * NAT-PMP / PCP / uPnP are unauthenticated LAN-side protocols. The
//!   gateway is trusted by virtue of being the default route — the same
//!   trust assumption every TCP/UDP packet on the host already makes. We do
//!   NOT use these protocols for any authenticated function; they only
//!   request a NAT mapping, which the user could equivalently configure by
//!   hand.
//! * Every response is parsed defensively against malformed input (length
//!   checks, version checks, opcode-mirror checks, result-code dispatch);
//!   this matches the discipline of `stun_client.rs`.
//! * The lease is the only data we trust from the gateway. We do not honour
//!   any "preferred external address" hint — we measure the real external
//!   address via STUN (D2) and treat that as authoritative.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

/// Wire protocols a `MappingLease` can be granted over.
///
/// Used for forensics (so the operator can see which protocol the gateway
/// supported) and for choosing the right release-on-shutdown path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortMappingProtocol {
    /// RFC 6886. Simplest. Apple AirPort + many SOHO routers.
    NatPmp,
    /// RFC 6887. A superset of NAT-PMP; modern but less universally
    /// deployed. Not yet implemented in this module.
    Pcp,
    /// uPnP Internet Gateway Device — SSDP discovery + SOAP. The most
    /// widely supported. Not yet implemented in this module.
    UpnpIgd,
}

impl PortMappingProtocol {
    /// Stable string label suitable for structured-log output. Pinned so
    /// future renames trip a named test rather than silently drifting any
    /// downstream `grep` that watches these labels.
    pub const fn label(self) -> &'static str {
        match self {
            PortMappingProtocol::NatPmp => "nat_pmp",
            PortMappingProtocol::Pcp => "pcp",
            PortMappingProtocol::UpnpIgd => "upnp_igd",
        }
    }
}

/// A successful UDP port-mapping lease from the gateway.
///
/// `external_port` may differ from `internal_port` if the gateway chose
/// not to honour the suggested port (it is suggestion-only per RFC 6886).
/// The lease has a finite lifetime; the caller is expected to refresh
/// before `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingLease {
    pub internal_port: u16,
    pub external_port: u16,
    /// The router's public IP address as the gateway reported it. We do
    /// not trust this for forwarding decisions — we measure the real
    /// public address via STUN — but we surface it for diagnostics so an
    /// operator can correlate the gateway's view with the STUN view.
    pub external_addr: IpAddr,
    pub protocol: PortMappingProtocol,
    /// Absolute deadline by which the lease must be refreshed. The
    /// daemon's refresh loop should aim for ~half this remaining lifetime
    /// to give itself a retry budget if the first refresh attempt fails.
    pub expires_at: Instant,
}

/// Structured failure shapes from a port-mapping request.
///
/// Every variant is informational enough that an operator can decide
/// whether to retry, switch protocols, or fall back to the
/// outbound-keepalive trick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortMapperError {
    /// The host could not determine its default gateway. Implementation
    /// likely lacked permission to read the routing table, or the host has
    /// no default route configured.
    NoGateway(String),
    /// The protocol is not yet implemented in this module (uPnP, PCP) or
    /// the gateway refused the protocol explicitly (NAT-PMP version
    /// mismatch). The probe orchestrator should fall through to the next
    /// protocol.
    ProtocolNotSupported(String),
    /// The gateway responded with a non-success result code. The string
    /// holds the RFC-defined error meaning where known, otherwise the raw
    /// code in hex.
    Refused(String),
    /// The gateway did not respond within the configured timeout.
    /// The probe orchestrator should fall through to the next protocol.
    Timeout,
    /// The gateway responded with bytes that did not parse as the
    /// expected wire format. The string identifies what was wrong.
    InvalidResponse(String),
    /// Local IO failure (socket bind, recv, send). Wraps the underlying
    /// `io::Error` description; we do not pass the error through as a
    /// typed field because `io::Error` is not `Clone`.
    Io(String),
}

impl std::fmt::Display for PortMapperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortMapperError::NoGateway(msg) => write!(f, "no default gateway: {msg}"),
            PortMapperError::ProtocolNotSupported(msg) => {
                write!(f, "port-mapping protocol not supported: {msg}")
            }
            PortMapperError::Refused(msg) => write!(f, "gateway refused port mapping: {msg}"),
            PortMapperError::Timeout => write!(f, "port-mapping request timed out"),
            PortMapperError::InvalidResponse(msg) => write!(f, "invalid gateway response: {msg}"),
            PortMapperError::Io(msg) => write!(f, "port-mapping I/O error: {msg}"),
        }
    }
}

impl std::error::Error for PortMapperError {}

impl From<io::Error> for PortMapperError {
    fn from(value: io::Error) -> Self {
        PortMapperError::Io(value.to_string())
    }
}

/// Common trait every port-mapping protocol implementation satisfies.
///
/// Three operations: request a fresh mapping, refresh an existing lease
/// before it expires, release a mapping early (e.g. on daemon shutdown).
/// Refresh is functionally a re-request with the same suggested external
/// port; release is a re-request with `lease_duration_secs == 0` per
/// RFC 6886 §3.4.
pub trait PortMapper {
    /// Request a UDP port mapping for `internal_port`. The gateway is
    /// free to grant a different external port; callers must read
    /// `lease.external_port` and not assume equality.
    fn request_udp_mapping(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<MappingLease, PortMapperError>;

    /// Refresh an existing lease before `lease.expires_at`. Returns the
    /// updated lease (with a new `expires_at`). Implementations should
    /// honour the previous `external_port` as the suggested port so the
    /// gateway is encouraged to keep the same mapping.
    fn refresh_mapping(&self, lease: &MappingLease) -> Result<MappingLease, PortMapperError>;

    /// Release a mapping early. RFC 6886 §3.4 specifies that a request
    /// with `lease_duration_secs == 0` and `internal_port == 0` releases
    /// all mappings for the requester; this method releases only the
    /// specific lease passed in.
    fn release_mapping(&self, lease: &MappingLease) -> Result<(), PortMapperError>;
}

// ---- NAT-PMP (RFC 6886) ----

/// Default NAT-PMP server port (RFC 6886 §3).
pub const NAT_PMP_SERVER_PORT: u16 = 5351;

/// NAT-PMP protocol version (RFC 6886 §3.2).
const NAT_PMP_VERSION: u8 = 0;

/// Opcodes (RFC 6886 §3).
const NAT_PMP_OP_EXTERNAL_ADDR: u8 = 0;
const NAT_PMP_OP_MAP_UDP: u8 = 1;
const NAT_PMP_OP_RESPONSE_BIT: u8 = 128;

/// Result codes (RFC 6886 §3.5).
const NAT_PMP_RESULT_SUCCESS: u16 = 0;
const NAT_PMP_RESULT_UNSUPPORTED_VERSION: u16 = 1;
const NAT_PMP_RESULT_NOT_AUTHORIZED: u16 = 2;
const NAT_PMP_RESULT_NETWORK_FAILURE: u16 = 3;
const NAT_PMP_RESULT_OUT_OF_RESOURCES: u16 = 4;
const NAT_PMP_RESULT_UNSUPPORTED_OPCODE: u16 = 5;

/// Hand-rolled NAT-PMP client. UDP wire-format per RFC 6886.
///
/// The gateway address is resolved by the caller (typically from the
/// system routing table; a follow-up slice will add automatic detection)
/// so this type is fully testable: the test points it at a local
/// in-process fake gateway.
///
/// Retry behaviour follows RFC 6886 §3.1: the initial request waits
/// `initial_timeout` for a response; on timeout the request is
/// retransmitted with the wait doubling each time, up to `max_attempts`
/// total attempts (default 9 per RFC). If all attempts time out, the
/// client concludes the gateway does not support NAT-PMP.
#[derive(Debug, Clone)]
pub struct NatPmpClient {
    gateway: SocketAddr,
    /// Wait for the first attempt before retransmitting. Per RFC 6886
    /// §3.1 the default is 250 ms; each subsequent retry doubles this.
    initial_timeout: Duration,
    /// Maximum number of retransmissions before declaring the gateway
    /// unsupported. RFC 6886 §3.1 mandates 9 (worst-case ~127.5s); tests
    /// override to 1 or 2 for fast failure-path coverage.
    max_attempts: u8,
}

/// RFC 6886 §3.1 initial timeout for the first attempt.
const NAT_PMP_DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_millis(250);
/// RFC 6886 §3.1 maximum attempts before declaring the gateway
/// unsupported. The total wait at the 9th attempt is 64 seconds, so the
/// cumulative time is roughly 127.5 seconds.
const NAT_PMP_DEFAULT_MAX_ATTEMPTS: u8 = 9;

impl NatPmpClient {
    /// Construct a NAT-PMP client pointed at the given gateway IPv4
    /// with RFC 6886 §3.1 defaults (250 ms initial timeout, 9 attempts).
    /// NAT-PMP is IPv4-only (PCP supersedes it for IPv6).
    pub fn new(gateway_ipv4: Ipv4Addr) -> Self {
        Self {
            gateway: SocketAddr::new(IpAddr::V4(gateway_ipv4), NAT_PMP_SERVER_PORT),
            initial_timeout: NAT_PMP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: NAT_PMP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Builder: override the initial-attempt timeout. Each subsequent
    /// retry doubles this. Per RFC 6886 §3.1 the default is 250 ms;
    /// tests can override to a smaller value for fast failure paths.
    #[must_use]
    pub fn with_initial_timeout(mut self, timeout: Duration) -> Self {
        self.initial_timeout = timeout;
        self
    }

    /// Builder: override the maximum retry attempts. Per RFC 6886 §3.1
    /// the default is 9. Tests can override to 1 or 2 to cover the
    /// timeout-and-give-up path quickly.
    #[must_use]
    pub fn with_max_attempts(mut self, max: u8) -> Self {
        self.max_attempts = max.max(1);
        self
    }

    /// Construct from an arbitrary `SocketAddr` for tests pointing at an
    /// in-process fake gateway on `127.0.0.1`. Defaults match `new()`.
    #[doc(hidden)]
    pub fn new_for_test(gateway: SocketAddr) -> Self {
        Self {
            gateway,
            initial_timeout: NAT_PMP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: NAT_PMP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Build the external-address-request wire bytes.
    /// RFC 6886 §3.2: Version(0) Opcode(0) — 2 bytes total.
    fn encode_external_address_request() -> [u8; 2] {
        [NAT_PMP_VERSION, NAT_PMP_OP_EXTERNAL_ADDR]
    }

    /// Build the UDP-mapping-request wire bytes.
    /// RFC 6886 §3.3: Version(0) Opcode(1) Reserved(2) InternalPort(2)
    /// SuggestedExternalPort(2) RequestedLifetime(4) — 12 bytes total.
    fn encode_udp_map_request(
        internal_port: u16,
        suggested_external_port: u16,
        lease_duration_secs: u32,
    ) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = NAT_PMP_VERSION;
        buf[1] = NAT_PMP_OP_MAP_UDP;
        // bytes 2..4 reserved (zeros).
        buf[4..6].copy_from_slice(&internal_port.to_be_bytes());
        buf[6..8].copy_from_slice(&suggested_external_port.to_be_bytes());
        buf[8..12].copy_from_slice(&lease_duration_secs.to_be_bytes());
        buf
    }

    /// Parse the gateway's external-address response.
    /// RFC 6886 §3.2: Version(0) Opcode(128) ResultCode(2) SSOE(4)
    /// ExternalIPv4(4) — 12 bytes total.
    fn decode_external_address_response(buf: &[u8]) -> Result<Ipv4Addr, PortMapperError> {
        if buf.len() < 12 {
            return Err(PortMapperError::InvalidResponse(format!(
                "external-address response too short: {} bytes (need 12)",
                buf.len()
            )));
        }
        if buf[0] != NAT_PMP_VERSION {
            return Err(PortMapperError::InvalidResponse(format!(
                "external-address response version mismatch: got {}, expected {}",
                buf[0], NAT_PMP_VERSION
            )));
        }
        let expected_opcode = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_EXTERNAL_ADDR;
        if buf[1] != expected_opcode {
            return Err(PortMapperError::InvalidResponse(format!(
                "external-address response opcode mismatch: got 0x{:02x}, expected 0x{:02x}",
                buf[1], expected_opcode
            )));
        }
        let result_code = u16::from_be_bytes([buf[2], buf[3]]);
        if result_code != NAT_PMP_RESULT_SUCCESS {
            return Err(map_result_code(result_code));
        }
        Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
    }

    /// Parse the gateway's UDP-mapping response.
    /// RFC 6886 §3.3: Version(0) Opcode(129) ResultCode(2) SSOE(4)
    /// InternalPort(2) MappedExternalPort(2) PortMappingLifetime(4) —
    /// 16 bytes total.
    fn decode_udp_map_response(
        buf: &[u8],
        sent_internal_port: u16,
    ) -> Result<(u16, u32), PortMapperError> {
        if buf.len() < 16 {
            return Err(PortMapperError::InvalidResponse(format!(
                "map response too short: {} bytes (need 16)",
                buf.len()
            )));
        }
        if buf[0] != NAT_PMP_VERSION {
            return Err(PortMapperError::InvalidResponse(format!(
                "map response version mismatch: got {}, expected {}",
                buf[0], NAT_PMP_VERSION
            )));
        }
        let expected_opcode = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        if buf[1] != expected_opcode {
            return Err(PortMapperError::InvalidResponse(format!(
                "map response opcode mismatch: got 0x{:02x}, expected 0x{:02x}",
                buf[1], expected_opcode
            )));
        }
        let result_code = u16::from_be_bytes([buf[2], buf[3]]);
        if result_code != NAT_PMP_RESULT_SUCCESS {
            return Err(map_result_code(result_code));
        }
        let echoed_internal_port = u16::from_be_bytes([buf[8], buf[9]]);
        if echoed_internal_port != sent_internal_port {
            return Err(PortMapperError::InvalidResponse(format!(
                "map response echoed internal port {echoed_internal_port}, expected {sent_internal_port}"
            )));
        }
        let external_port = u16::from_be_bytes([buf[10], buf[11]]);
        let lifetime_secs = u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]);
        Ok((external_port, lifetime_secs))
    }

    /// UDP round-trip with RFC 6886 §3.1 retry/backoff. Binds an
    /// ephemeral socket, sends the request, waits for the response; on
    /// timeout, retransmits with the wait doubling each time, up to
    /// `max_attempts` total. If every attempt times out, returns
    /// `Timeout` — the caller treats this as "gateway does not support
    /// NAT-PMP" and falls through to the next protocol.
    fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, PortMapperError> {
        // Bind to v4 0.0.0.0:0 because NAT-PMP is IPv4-only.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let mut current_timeout = self.initial_timeout;
        for _attempt in 0..self.max_attempts {
            socket.set_read_timeout(Some(current_timeout))?;
            socket.send_to(request, self.gateway)?;
            let mut buf = [0u8; 64];
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if src.ip() != self.gateway.ip() {
                        return Err(PortMapperError::InvalidResponse(format!(
                            "response source {src} does not match gateway {}",
                            self.gateway
                        )));
                    }
                    return Ok(buf[..len].to_vec());
                }
                // Both WouldBlock and TimedOut surface when set_read_timeout
                // elapses without data; we retry per RFC 6886 §3.1.
                Err(err)
                    if matches!(
                        err.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    current_timeout = current_timeout.saturating_mul(2);
                    continue;
                }
                Err(err) => return Err(PortMapperError::Io(err.to_string())),
            }
        }
        Err(PortMapperError::Timeout)
    }
}

impl PortMapper for NatPmpClient {
    fn request_udp_mapping(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<MappingLease, PortMapperError> {
        if internal_port == 0 {
            return Err(PortMapperError::InvalidResponse(
                "internal_port must be non-zero for a fresh mapping request".to_owned(),
            ));
        }
        let external_addr_response =
            self.round_trip(&NatPmpClient::encode_external_address_request())?;
        let external_addr =
            NatPmpClient::decode_external_address_response(&external_addr_response)?;

        let map_response = self.round_trip(&NatPmpClient::encode_udp_map_request(
            internal_port,
            internal_port,
            lease_duration_secs,
        ))?;
        let (external_port, lifetime_secs) =
            NatPmpClient::decode_udp_map_response(&map_response, internal_port)?;

        Ok(MappingLease {
            internal_port,
            external_port,
            external_addr: IpAddr::V4(external_addr),
            protocol: PortMappingProtocol::NatPmp,
            expires_at: Instant::now() + Duration::from_secs(u64::from(lifetime_secs)),
        })
    }

    fn refresh_mapping(&self, lease: &MappingLease) -> Result<MappingLease, PortMapperError> {
        // Refresh = re-request with the previous external port as the
        // suggested port, so the gateway is encouraged to keep the same
        // mapping. Same lifetime as the original request.
        let lifetime_secs = lease
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(60)
            .try_into()
            .unwrap_or(u32::MAX);

        let external_addr_response =
            self.round_trip(&NatPmpClient::encode_external_address_request())?;
        let external_addr =
            NatPmpClient::decode_external_address_response(&external_addr_response)?;

        let map_response = self.round_trip(&NatPmpClient::encode_udp_map_request(
            lease.internal_port,
            lease.external_port,
            lifetime_secs,
        ))?;
        let (external_port, granted_lifetime) =
            NatPmpClient::decode_udp_map_response(&map_response, lease.internal_port)?;

        Ok(MappingLease {
            internal_port: lease.internal_port,
            external_port,
            external_addr: IpAddr::V4(external_addr),
            protocol: PortMappingProtocol::NatPmp,
            expires_at: Instant::now() + Duration::from_secs(u64::from(granted_lifetime)),
        })
    }

    fn release_mapping(&self, lease: &MappingLease) -> Result<(), PortMapperError> {
        // RFC 6886 §3.4: a release request carries the same internal
        // port, a Suggested External Port of ZERO ("MUST be set to zero
        // by the client on sending, and MUST be ignored by the gateway
        // on reception"), and a Requested Lifetime of zero. The gateway
        // responds with the original internal port, an external port of
        // 0, and a lifetime of 0.
        let response = self.round_trip(&NatPmpClient::encode_udp_map_request(
            lease.internal_port,
            0, // RFC 6886 §3.4 — MUST be zero on release.
            0, // RFC 6886 §3.4 — lifetime = 0 signals release.
        ))?;
        let (_external_port_zero, _lifetime_zero) =
            NatPmpClient::decode_udp_map_response(&response, lease.internal_port)?;
        Ok(())
    }
}

/// Convert a NAT-PMP result code into a typed `PortMapperError`. Values
/// not in RFC 6886 §3.5 fall through to `Refused` with the raw code.
fn map_result_code(code: u16) -> PortMapperError {
    match code {
        NAT_PMP_RESULT_SUCCESS => PortMapperError::Refused(
            "result code 0 (success) reached error path — protocol invariant violated".to_owned(),
        ),
        NAT_PMP_RESULT_UNSUPPORTED_VERSION => PortMapperError::ProtocolNotSupported(
            "gateway reported unsupported NAT-PMP version".to_owned(),
        ),
        NAT_PMP_RESULT_NOT_AUTHORIZED => PortMapperError::Refused(
            "gateway refused: not authorized (port mapping likely disabled in router admin UI)"
                .to_owned(),
        ),
        NAT_PMP_RESULT_NETWORK_FAILURE => PortMapperError::Refused(
            "gateway reported a network failure (transient — retry may help)".to_owned(),
        ),
        NAT_PMP_RESULT_OUT_OF_RESOURCES => {
            PortMapperError::Refused("gateway out of resources (mapping table full)".to_owned())
        }
        NAT_PMP_RESULT_UNSUPPORTED_OPCODE => {
            PortMapperError::ProtocolNotSupported("gateway reported unsupported opcode".to_owned())
        }
        other => PortMapperError::Refused(format!("unrecognised result code 0x{other:04x}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc::{Receiver, Sender, channel};
    use std::thread::JoinHandle;

    fn make_test_client() -> (NatPmpClient, SocketAddr) {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind fake gateway socket");
        let gateway_addr = listener.local_addr().expect("fake gateway local_addr");
        // Drop the listener and let `spawn_fake_gateway` rebind on the
        // same port. The test client uses a short initial timeout +
        // fewer attempts so a non-responding fake gateway test does not
        // wait the RFC default 127.5 seconds.
        drop(listener);
        let client = NatPmpClient::new_for_test(gateway_addr)
            .with_initial_timeout(Duration::from_millis(50))
            .with_max_attempts(3);
        (client, gateway_addr)
    }

    /// Spawn a single-shot fake NAT-PMP gateway on `gateway_addr` that
    /// responds to the next two incoming requests (external-address +
    /// map). Returns a handle so the test can await its completion and a
    /// receiver that observes each received request payload for
    /// assertions.
    fn spawn_fake_gateway(
        gateway_addr: SocketAddr,
        external_ipv4: Ipv4Addr,
        granted_external_port: u16,
        granted_lifetime_secs: u32,
        result_code_for_map: u16,
        expected_request_count: usize,
    ) -> (JoinHandle<()>, Receiver<Vec<u8>>) {
        let socket = UdpSocket::bind(gateway_addr).expect("bind fake gateway");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fake gateway read timeout");
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
        let handle = std::thread::spawn(move || {
            let mut count = 0usize;
            while count < expected_request_count {
                let mut buf = [0u8; 64];
                let (len, src) = match socket.recv_from(&mut buf) {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let req = buf[..len].to_vec();
                let _ = tx.send(req.clone());
                let response = match req.get(1).copied() {
                    Some(NAT_PMP_OP_EXTERNAL_ADDR) => {
                        let mut resp = vec![0u8; 12];
                        resp[0] = NAT_PMP_VERSION;
                        resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_EXTERNAL_ADDR;
                        resp[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
                        resp[4..8].copy_from_slice(&42u32.to_be_bytes()); // SSOE — arbitrary.
                        resp[8..12].copy_from_slice(&external_ipv4.octets());
                        resp
                    }
                    Some(NAT_PMP_OP_MAP_UDP) => {
                        let echoed_internal = u16::from_be_bytes([req[4], req[5]]);
                        let mut resp = vec![0u8; 16];
                        resp[0] = NAT_PMP_VERSION;
                        resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
                        resp[2..4].copy_from_slice(&result_code_for_map.to_be_bytes());
                        resp[4..8].copy_from_slice(&42u32.to_be_bytes()); // SSOE.
                        resp[8..10].copy_from_slice(&echoed_internal.to_be_bytes());
                        resp[10..12].copy_from_slice(&granted_external_port.to_be_bytes());
                        resp[12..16].copy_from_slice(&granted_lifetime_secs.to_be_bytes());
                        resp
                    }
                    _ => break,
                };
                let _ = socket.send_to(&response, src);
                count += 1;
            }
        });
        (handle, rx)
    }

    #[test]
    fn nat_pmp_external_address_request_encoding_matches_rfc_6886() {
        let buf = NatPmpClient::encode_external_address_request();
        assert_eq!(buf, [0, 0], "version=0, opcode=0");
    }

    #[test]
    fn nat_pmp_map_request_encoding_matches_rfc_6886() {
        let buf = NatPmpClient::encode_udp_map_request(51820, 51820, 3600);
        assert_eq!(buf[0], 0, "version=0");
        assert_eq!(buf[1], 1, "opcode=1 (UDP)");
        assert_eq!(&buf[2..4], &[0, 0], "reserved=0");
        assert_eq!(u16::from_be_bytes([buf[4], buf[5]]), 51820, "internal port");
        assert_eq!(
            u16::from_be_bytes([buf[6], buf[7]]),
            51820,
            "suggested external port"
        );
        assert_eq!(
            u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            3600,
            "lifetime seconds"
        );
    }

    #[test]
    fn nat_pmp_external_address_response_round_trips() {
        let mut response = vec![0u8; 12];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_EXTERNAL_ADDR;
        response[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
        response[4..8].copy_from_slice(&100u32.to_be_bytes());
        response[8..12].copy_from_slice(&[203, 0, 113, 5]);
        let addr = NatPmpClient::decode_external_address_response(&response)
            .expect("clean external-address response decodes");
        assert_eq!(addr, Ipv4Addr::new(203, 0, 113, 5));
    }

    #[test]
    fn nat_pmp_external_address_response_rejects_short_buffer() {
        let buf = vec![0u8; 11];
        let err = NatPmpClient::decode_external_address_response(&buf)
            .expect_err("truncated response must be rejected");
        assert!(matches!(err, PortMapperError::InvalidResponse(_)));
    }

    #[test]
    fn nat_pmp_external_address_response_rejects_wrong_opcode() {
        let mut response = vec![0u8; 12];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        let err = NatPmpClient::decode_external_address_response(&response)
            .expect_err("wrong-opcode response must be rejected");
        assert!(matches!(err, PortMapperError::InvalidResponse(msg) if msg.contains("opcode")));
    }

    #[test]
    fn nat_pmp_external_address_response_surfaces_result_code() {
        let mut response = vec![0u8; 12];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_EXTERNAL_ADDR;
        response[2..4].copy_from_slice(&NAT_PMP_RESULT_NOT_AUTHORIZED.to_be_bytes());
        let err = NatPmpClient::decode_external_address_response(&response)
            .expect_err("not-authorized result code surfaces as error");
        assert!(matches!(err, PortMapperError::Refused(msg) if msg.contains("not authorized")));
    }

    #[test]
    fn nat_pmp_map_response_round_trips() {
        let mut response = vec![0u8; 16];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        response[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
        response[4..8].copy_from_slice(&100u32.to_be_bytes());
        response[8..10].copy_from_slice(&51820u16.to_be_bytes());
        response[10..12].copy_from_slice(&62000u16.to_be_bytes());
        response[12..16].copy_from_slice(&3600u32.to_be_bytes());
        let (external_port, lifetime) = NatPmpClient::decode_udp_map_response(&response, 51820)
            .expect("clean map response decodes");
        assert_eq!(external_port, 62000, "gateway granted external port");
        assert_eq!(lifetime, 3600, "gateway granted lease lifetime");
    }

    #[test]
    fn nat_pmp_map_response_rejects_echoed_port_mismatch() {
        // Gateway echoes a different internal port from the one we asked
        // for — this would indicate the response was for a different
        // request (race / spoof attempt). Reject closed.
        let mut response = vec![0u8; 16];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        response[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
        response[8..10].copy_from_slice(&99u16.to_be_bytes()); // wrong port
        response[10..12].copy_from_slice(&62000u16.to_be_bytes());
        response[12..16].copy_from_slice(&3600u32.to_be_bytes());
        let err = NatPmpClient::decode_udp_map_response(&response, 51820)
            .expect_err("echoed-port mismatch must be rejected");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(msg) if msg.contains("echoed internal port"))
        );
    }

    #[test]
    fn nat_pmp_map_response_maps_unsupported_version_to_protocol_not_supported() {
        let mut response = vec![0u8; 16];
        response[0] = NAT_PMP_VERSION;
        response[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        response[2..4].copy_from_slice(&NAT_PMP_RESULT_UNSUPPORTED_VERSION.to_be_bytes());
        let err = NatPmpClient::decode_udp_map_response(&response, 51820)
            .expect_err("unsupported-version result code surfaces as error");
        assert!(matches!(err, PortMapperError::ProtocolNotSupported(_)));
    }

    #[test]
    fn nat_pmp_request_udp_mapping_against_fake_gateway() {
        let (client, gateway_addr) = make_test_client();
        let (handle, rx) = spawn_fake_gateway(
            gateway_addr,
            Ipv4Addr::new(203, 0, 113, 5),
            62000,
            3600,
            NAT_PMP_RESULT_SUCCESS,
            2, // external-address + map
        );

        let lease = client
            .request_udp_mapping(51820, 3600)
            .expect("fake gateway grants mapping");

        assert_eq!(lease.internal_port, 51820);
        assert_eq!(lease.external_port, 62000);
        assert_eq!(
            lease.external_addr,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5))
        );
        assert_eq!(lease.protocol, PortMappingProtocol::NatPmp);
        assert!(
            lease.expires_at > Instant::now(),
            "lease must expire in the future"
        );

        // Verify the wire order: external-address request first, then
        // map request.
        let req1 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("req 1 arrives");
        assert_eq!(req1[1], NAT_PMP_OP_EXTERNAL_ADDR);
        let req2 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("req 2 arrives");
        assert_eq!(req2[1], NAT_PMP_OP_MAP_UDP);
        assert_eq!(u16::from_be_bytes([req2[4], req2[5]]), 51820);
        assert_eq!(
            u32::from_be_bytes([req2[8], req2[9], req2[10], req2[11]]),
            3600
        );

        handle.join().expect("fake gateway thread joins");
    }

    #[test]
    fn nat_pmp_request_udp_mapping_propagates_gateway_refusal() {
        let (client, gateway_addr) = make_test_client();
        let (handle, _rx) = spawn_fake_gateway(
            gateway_addr,
            Ipv4Addr::new(203, 0, 113, 5),
            62000,
            3600,
            NAT_PMP_RESULT_NOT_AUTHORIZED,
            2,
        );

        let err = client
            .request_udp_mapping(51820, 3600)
            .expect_err("gateway refusal must surface");
        assert!(matches!(err, PortMapperError::Refused(msg) if msg.contains("not authorized")));

        handle.join().expect("fake gateway thread joins");
    }

    #[test]
    fn nat_pmp_refresh_mapping_uses_previous_external_port_as_suggestion() {
        let (client, gateway_addr) = make_test_client();
        let (handle, rx) = spawn_fake_gateway(
            gateway_addr,
            Ipv4Addr::new(203, 0, 113, 5),
            62000,
            3600,
            NAT_PMP_RESULT_SUCCESS,
            2,
        );

        let lease = MappingLease {
            internal_port: 51820,
            external_port: 62000,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            protocol: PortMappingProtocol::NatPmp,
            expires_at: Instant::now() + Duration::from_secs(1800),
        };

        let refreshed = client
            .refresh_mapping(&lease)
            .expect("refresh succeeds against fake gateway");
        assert_eq!(refreshed.internal_port, 51820);
        assert_eq!(refreshed.external_port, 62000);

        // External-address request first, then map request with the
        // previous external port as suggestion.
        let _req1 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("req 1 arrives");
        let req2 = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("req 2 arrives");
        let suggested_external = u16::from_be_bytes([req2[6], req2[7]]);
        assert_eq!(
            suggested_external, 62000,
            "refresh must suggest the previous external port to encourage same-mapping retention"
        );

        handle.join().expect("fake gateway thread joins");
    }

    #[test]
    fn port_mapping_protocol_labels_are_stable_snake_case() {
        // Pin the label strings so downstream log-grepping CI never
        // silently drifts on a Rename refactor.
        assert_eq!(PortMappingProtocol::NatPmp.label(), "nat_pmp");
        assert_eq!(PortMappingProtocol::Pcp.label(), "pcp");
        assert_eq!(PortMappingProtocol::UpnpIgd.label(), "upnp_igd");
    }

    #[test]
    fn nat_pmp_release_mapping_sends_zero_as_suggested_external_port_per_rfc_6886_3_4() {
        // RFC 6886 §3.4: "The Suggested External Port MUST be set to
        // zero by the client on sending, and MUST be ignored by the
        // gateway on reception." A previous version of this client
        // erroneously echoed `lease.external_port` here; this test
        // pins the corrected behaviour so any regression trips closed.
        let (client, gateway_addr) = make_test_client();
        // Spawn a fake gateway that only handles one map request — the
        // release request. The fake replies with a release-shaped
        // response: same internal port, external port = 0, lifetime = 0.
        let socket = UdpSocket::bind(gateway_addr).expect("bind fake gateway");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fake gateway read timeout");
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 64];
            let Ok((len, src)) = socket.recv_from(&mut buf) else {
                return;
            };
            let req = buf[..len].to_vec();
            let _ = tx.send(req.clone());
            // Build a release-shape response (RFC 6886 §3.4): success
            // code, echoed internal port, external port = 0, lifetime = 0.
            let echoed_internal = u16::from_be_bytes([req[4], req[5]]);
            let mut resp = vec![0u8; 16];
            resp[0] = NAT_PMP_VERSION;
            resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
            resp[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
            resp[4..8].copy_from_slice(&42u32.to_be_bytes()); // SSOE.
            resp[8..10].copy_from_slice(&echoed_internal.to_be_bytes());
            resp[10..12].copy_from_slice(&0u16.to_be_bytes());
            resp[12..16].copy_from_slice(&0u32.to_be_bytes());
            let _ = socket.send_to(&resp, src);
        });

        let lease = MappingLease {
            internal_port: 51820,
            external_port: 62000,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            protocol: PortMappingProtocol::NatPmp,
            expires_at: Instant::now() + Duration::from_secs(1800),
        };
        client.release_mapping(&lease).expect("release succeeds");

        let req = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("request observed");
        // Internal port should be the lease's internal port.
        let internal = u16::from_be_bytes([req[4], req[5]]);
        assert_eq!(
            internal, 51820,
            "release must carry the lease's internal port"
        );
        // RFC §3.4: Suggested External Port MUST be zero.
        let suggested_external = u16::from_be_bytes([req[6], req[7]]);
        assert_eq!(
            suggested_external, 0,
            "RFC 6886 §3.4: release request's Suggested External Port MUST be zero"
        );
        // Lifetime = 0 marks this as a release.
        let lifetime = u32::from_be_bytes([req[8], req[9], req[10], req[11]]);
        assert_eq!(lifetime, 0, "release request's lifetime MUST be zero");

        handle.join().expect("fake gateway thread joins");
    }

    #[test]
    fn nat_pmp_round_trip_retries_with_exponential_backoff_per_rfc_6886_3_1() {
        // RFC 6886 §3.1: the client waits 250ms then doubles per retry,
        // up to 9 attempts (~127.5s total) before concluding the gateway
        // does not support NAT-PMP. This test bounds the retry count to
        // 3 and the initial timeout to 50ms so the test completes in
        // ~350ms even on the slowest CI. Pass criterion: when the fake
        // gateway never responds, the client returns Timeout — confirming
        // the retry loop terminates (and doesn't deadlock) and that the
        // PortMapperError::Timeout shape is the correct surface for the
        // "gateway unsupported" decision the orchestrator will make.
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind silent fake gateway socket");
        let gateway_addr = listener
            .local_addr()
            .expect("silent fake gateway local_addr");
        // Hold the listener so the kernel doesn't free the port. We
        // never read from it, so the client's send_to packets arrive,
        // and we never reply — every recv_from on the client times out.
        let client = NatPmpClient::new_for_test(gateway_addr)
            .with_initial_timeout(Duration::from_millis(50))
            .with_max_attempts(3);

        let started = Instant::now();
        let err = client
            .request_udp_mapping(51820, 3600)
            .expect_err("silent gateway eventually produces Timeout");
        assert!(
            matches!(err, PortMapperError::Timeout),
            "silent gateway must return PortMapperError::Timeout, got: {err:?}"
        );
        // Sanity: with 50ms initial and 3 attempts (50 + 100 + 200 =
        // 350ms ideal), the elapsed time should be at least the sum of
        // the configured timeouts. Allow generous CI slack.
        let elapsed = started.elapsed();
        assert!(
            elapsed >= Duration::from_millis(300),
            "retry loop must wait at least the cumulative configured timeouts (got {elapsed:?})"
        );

        drop(listener);
    }
}
