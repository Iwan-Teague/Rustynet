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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use rand::RngCore;

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
    /// PCP Mapping Nonce (RFC 6887 §11.2). `None` for NAT-PMP and uPnP IGD
    /// leases — they identify a mapping by `(internal_port, protocol)`
    /// alone. `Some` for PCP leases — the 12-byte Mapping Nonce minted on
    /// the original request, which MUST be echoed on refresh and delete
    /// so the gateway recognises the mapping as belonging to this client.
    pub pcp_nonce: Option<[u8; 12]>,
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
            pcp_nonce: None,
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
            pcp_nonce: None,
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

// ---- PCP (RFC 6887) ----

/// Default PCP server port (RFC 6887 §19.1). Shares port 5351 with
/// NAT-PMP — the gateway distinguishes the two by inspecting the
/// version byte of incoming requests.
pub const PCP_SERVER_PORT: u16 = 5351;

/// PCP protocol version (RFC 6887 §7.1).
const PCP_VERSION: u8 = 2;

/// R-bit mask for the `R|Opcode` byte. R=1 in responses, R=0 in requests
/// (RFC 6887 §7.1).
const PCP_R_BIT_RESPONSE_MASK: u8 = 0x80;

/// Opcode mask for the `R|Opcode` byte (RFC 6887 §7.1).
const PCP_OPCODE_MASK: u8 = 0x7f;

/// MAP opcode value (RFC 6887 §11).
const PCP_OPCODE_MAP: u8 = 1;

/// IANA protocol number for UDP (RFC 6887 §11.1 references the IANA
/// "Protocol Numbers" registry).
const PCP_PROTOCOL_UDP: u8 = 17;

// Result codes (RFC 6887 §7.4).
const PCP_RESULT_SUCCESS: u8 = 0;
const PCP_RESULT_UNSUPP_VERSION: u8 = 1;
const PCP_RESULT_NOT_AUTHORIZED: u8 = 2;
const PCP_RESULT_MALFORMED_REQUEST: u8 = 3;
const PCP_RESULT_UNSUPP_OPCODE: u8 = 4;
const PCP_RESULT_UNSUPP_OPTION: u8 = 5;
const PCP_RESULT_MALFORMED_OPTION: u8 = 6;
const PCP_RESULT_NETWORK_FAILURE: u8 = 7;
const PCP_RESULT_NO_RESOURCES: u8 = 8;
const PCP_RESULT_UNSUPP_PROTOCOL: u8 = 9;
const PCP_RESULT_USER_EX_QUOTA: u8 = 10;
const PCP_RESULT_CANNOT_PROVIDE_EXTERNAL: u8 = 11;
const PCP_RESULT_ADDRESS_MISMATCH: u8 = 12;
const PCP_RESULT_EXCESSIVE_REMOTE_PEERS: u8 = 13;

/// Total PCP MAP request length: 24-byte common header + 36-byte MAP
/// opcode body (RFC 6887 §7.1 + §11.1).
const PCP_MAP_REQUEST_LEN: usize = 60;
/// Total PCP MAP response length: 24-byte common header + 36-byte MAP
/// opcode body.
const PCP_MAP_RESPONSE_LEN: usize = 60;
/// Mapping Nonce length: 96 bits = 12 bytes (RFC 6887 §11.1).
pub const PCP_NONCE_LEN: usize = 12;

/// Practical PCP default initial timeout.
///
/// RFC 6887 §8.1.1 recommends IRT (Initial Retransmission Time) of
/// 3 seconds with no fixed maximum on retransmissions (MRC=0). Those
/// values are sized for general-purpose options that may take time to
/// reach a distant relay. For an on-LAN gateway probing whether the
/// router speaks PCP at all, sub-100ms RTTs are typical; we use 250 ms
/// here so an unresponsive gateway can be diagnosed quickly and the
/// orchestrator can fall through to the next protocol. We document the
/// deviation; operators who need the RFC default can override via
/// [`PcpClient::with_initial_timeout`].
const PCP_DEFAULT_INITIAL_TIMEOUT: Duration = Duration::from_millis(250);

/// Practical PCP default attempt cap.
///
/// RFC 6887 §8.1.1 specifies MRC=0 (no maximum). We cap at 5 (≈7.75 s
/// cumulative at IRT=250 ms with doubling) for the same reason as
/// `PCP_DEFAULT_INITIAL_TIMEOUT`: this is a fast probe, not an
/// indefinite renewal.
const PCP_DEFAULT_MAX_ATTEMPTS: u8 = 5;

/// PCP client. UDP wire format per RFC 6887.
///
/// PCP is a superset of NAT-PMP with first-class IPv6 support; the
/// daemon's port-mapping probe tries PCP before NAT-PMP because a PCP
/// gateway also acts as a NAT-PMP gateway (RFC 6887 §1.1) and PCP gives
/// us richer error reporting.
///
/// Like [`NatPmpClient`], this client is testable: it accepts an
/// arbitrary `SocketAddr` so the test points it at an in-process fake
/// gateway. Mapping Nonce values are cryptographically random via
/// [`rand::rng`] per RFC 6887 §11.2 (the nonce is the authorisation
/// token for renewing/deleting a mapping — predictable nonces would let
/// off-path attackers tear down our mapping).
///
/// Retry behaviour deviates from RFC §8.1.1 (which targets distant
/// relay servers); see the doc comments on
/// [`PCP_DEFAULT_INITIAL_TIMEOUT`] / [`PCP_DEFAULT_MAX_ATTEMPTS`] for
/// the rationale and the override mechanism.
#[derive(Debug, Clone)]
pub struct PcpClient {
    gateway: SocketAddr,
    initial_timeout: Duration,
    max_attempts: u8,
}

impl PcpClient {
    /// Construct a PCP client pointed at the given gateway IP.
    /// Defaults to `PCP_SERVER_PORT` and the practical retry settings
    /// (see module docs).
    pub fn new(gateway: IpAddr) -> Self {
        Self {
            gateway: SocketAddr::new(gateway, PCP_SERVER_PORT),
            initial_timeout: PCP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: PCP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Builder: override the initial-attempt timeout.
    #[must_use]
    pub fn with_initial_timeout(mut self, timeout: Duration) -> Self {
        self.initial_timeout = timeout;
        self
    }

    /// Builder: override the maximum retry attempts.
    #[must_use]
    pub fn with_max_attempts(mut self, max: u8) -> Self {
        self.max_attempts = max.max(1);
        self
    }

    /// Construct from an arbitrary `SocketAddr` for tests pointing at an
    /// in-process fake gateway. Defaults match `new()`.
    #[doc(hidden)]
    pub fn new_for_test(gateway: SocketAddr) -> Self {
        Self {
            gateway,
            initial_timeout: PCP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: PCP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Encode an IPv4 address as an IPv4-mapped IPv6 octet array per
    /// RFC 4291 §2.5.5.2: `::ffff:0:0/96` prefix + 32-bit IPv4 suffix.
    /// PCP carries every address as 128 bits; IPv4 mappings use the
    /// mapped form so PCP gateways serving dual-stack hosts can use a
    /// single Address field width (RFC 6887 §5).
    fn embed_v4_as_v6(addr: Ipv4Addr) -> [u8; 16] {
        let mut buf = [0u8; 16];
        buf[10] = 0xff;
        buf[11] = 0xff;
        buf[12..16].copy_from_slice(&addr.octets());
        buf
    }

    /// Mint a fresh 12-byte Mapping Nonce. RFC 6887 §11.2: "The PCP
    /// client SHOULD generate a unique, cryptographically random nonce"
    /// — predictable nonces would let off-path attackers issue
    /// `lifetime=0` deletes and tear down our mapping.
    fn fresh_nonce() -> [u8; PCP_NONCE_LEN] {
        let mut nonce = [0u8; PCP_NONCE_LEN];
        rand::rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Encode a MAP request (60 bytes total).
    ///
    /// Layout (RFC 6887 §7.1 common header + §11.1 MAP body):
    /// * `[0]` Version = 2
    /// * `[1]` R(1)|Opcode(7) — R=0, Opcode=1
    /// * `[2..4]` Reserved
    /// * `[4..8]` Requested Lifetime (BE u32)
    /// * `[8..24]` PCP Client IP (128 bits)
    /// * `[24..36]` Mapping Nonce (96 bits)
    /// * `[36]` Protocol (17 = UDP)
    /// * `[37..40]` Reserved (24 bits)
    /// * `[40..42]` Internal Port (BE u16)
    /// * `[42..44]` Suggested External Port (BE u16)
    /// * `[44..60]` Suggested External Address (128 bits)
    fn encode_map_request(
        client_ip: IpAddr,
        lifetime_secs: u32,
        nonce: [u8; PCP_NONCE_LEN],
        internal_port: u16,
        suggested_external_port: u16,
        suggested_external_addr: IpAddr,
    ) -> [u8; PCP_MAP_REQUEST_LEN] {
        let mut buf = [0u8; PCP_MAP_REQUEST_LEN];
        buf[0] = PCP_VERSION;
        // R=0, Opcode=MAP=1.
        buf[1] = PCP_OPCODE_MAP;
        // bytes 2..4 reserved (zero).
        buf[4..8].copy_from_slice(&lifetime_secs.to_be_bytes());
        let client_octets = match client_ip {
            IpAddr::V4(v4) => Self::embed_v4_as_v6(v4),
            IpAddr::V6(v6) => v6.octets(),
        };
        buf[8..24].copy_from_slice(&client_octets);

        buf[24..36].copy_from_slice(&nonce);
        buf[36] = PCP_PROTOCOL_UDP;
        // bytes 37..40 reserved (zero).
        buf[40..42].copy_from_slice(&internal_port.to_be_bytes());
        buf[42..44].copy_from_slice(&suggested_external_port.to_be_bytes());
        let external_octets = match suggested_external_addr {
            IpAddr::V4(v4) => Self::embed_v4_as_v6(v4),
            IpAddr::V6(v6) => v6.octets(),
        };
        buf[44..60].copy_from_slice(&external_octets);
        buf
    }

    /// Parse a MAP response (60 bytes minimum).
    fn decode_map_response(
        buf: &[u8],
        sent_nonce: [u8; PCP_NONCE_LEN],
        sent_internal_port: u16,
    ) -> Result<PcpMapResponseFields, PortMapperError> {
        if buf.len() < PCP_MAP_RESPONSE_LEN {
            return Err(PortMapperError::InvalidResponse(format!(
                "PCP MAP response too short: {} bytes (need {PCP_MAP_RESPONSE_LEN})",
                buf.len()
            )));
        }
        if buf[0] != PCP_VERSION {
            return Err(PortMapperError::InvalidResponse(format!(
                "PCP response version mismatch: got {}, expected {PCP_VERSION}",
                buf[0]
            )));
        }
        let r_bit = buf[1] & PCP_R_BIT_RESPONSE_MASK;
        let opcode = buf[1] & PCP_OPCODE_MASK;
        if r_bit == 0 {
            return Err(PortMapperError::InvalidResponse(
                "PCP response R-bit not set".to_owned(),
            ));
        }
        if opcode != PCP_OPCODE_MAP {
            return Err(PortMapperError::InvalidResponse(format!(
                "PCP response opcode mismatch: got {opcode}, expected {PCP_OPCODE_MAP} (MAP)"
            )));
        }
        // buf[2] is Reserved; buf[3] carries the result code.
        let result_code = buf[3];
        if result_code != PCP_RESULT_SUCCESS {
            return Err(pcp_map_result_code(result_code));
        }
        let lifetime = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let mut echoed_nonce = [0u8; PCP_NONCE_LEN];
        echoed_nonce.copy_from_slice(&buf[24..36]);
        if echoed_nonce != sent_nonce {
            return Err(PortMapperError::InvalidResponse(
                "PCP MAP response nonce did not match request nonce".to_owned(),
            ));
        }
        let echoed_protocol = buf[36];
        if echoed_protocol != PCP_PROTOCOL_UDP {
            return Err(PortMapperError::InvalidResponse(format!(
                "PCP MAP response protocol mismatch: got {echoed_protocol}, expected {PCP_PROTOCOL_UDP} (UDP)"
            )));
        }
        let echoed_internal_port = u16::from_be_bytes([buf[40], buf[41]]);
        if echoed_internal_port != sent_internal_port {
            return Err(PortMapperError::InvalidResponse(format!(
                "PCP MAP response echoed internal port {echoed_internal_port}, expected {sent_internal_port}"
            )));
        }
        let external_port = u16::from_be_bytes([buf[42], buf[43]]);
        let mut external_octets = [0u8; 16];
        external_octets.copy_from_slice(&buf[44..60]);
        let external_addr = parse_pcp_address(external_octets);

        Ok(PcpMapResponseFields {
            external_port,
            external_addr,
            granted_lifetime_secs: lifetime,
        })
    }

    /// UDP round-trip with the practical retry/backoff documented at
    /// `PCP_DEFAULT_INITIAL_TIMEOUT`.
    fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, PortMapperError> {
        let socket = match self.gateway.ip() {
            IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
            IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
        };
        socket.connect(self.gateway)?;
        let mut current_timeout = self.initial_timeout;
        for _attempt in 0..self.max_attempts {
            socket.set_read_timeout(Some(current_timeout))?;
            socket.send(request)?;
            let mut buf = [0u8; PCP_MAP_RESPONSE_LEN + 64];
            match socket.recv(&mut buf) {
                Ok(len) => return Ok(buf[..len].to_vec()),
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

    /// Discover the local IP the kernel routes to the gateway. PCP §8.1
    /// requires the Client IP field to match the source address the
    /// gateway sees, otherwise it replies `ADDRESS_MISMATCH`.
    fn discover_local_addr(&self) -> Result<IpAddr, PortMapperError> {
        let socket = match self.gateway.ip() {
            IpAddr::V4(_) => UdpSocket::bind("0.0.0.0:0")?,
            IpAddr::V6(_) => UdpSocket::bind("[::]:0")?,
        };
        socket.connect(self.gateway)?;
        Ok(socket.local_addr()?.ip())
    }
}

/// Parsed fields from a MAP response. Internal to the PCP impl.
#[derive(Debug)]
struct PcpMapResponseFields {
    external_port: u16,
    external_addr: IpAddr,
    granted_lifetime_secs: u32,
}

/// Translate a 128-bit PCP address into an `IpAddr`, surfacing
/// IPv4-mapped IPv6 (`::ffff:X.X.X.X`) as `IpAddr::V4` so callers do
/// not need to know about the wire encoding.
fn parse_pcp_address(octets: [u8; 16]) -> IpAddr {
    const V4_MAPPED_PREFIX: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff];
    if octets[..12] == V4_MAPPED_PREFIX {
        IpAddr::V4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(octets))
    }
}

/// Translate a PCP MAP result code into a typed `PortMapperError`.
/// Per RFC 6887 §7.4, unrecognised codes are treated as `Refused`.
fn pcp_map_result_code(code: u8) -> PortMapperError {
    match code {
        PCP_RESULT_SUCCESS => PortMapperError::Refused(
            "PCP result code 0 (success) reached error path — protocol invariant violated"
                .to_owned(),
        ),
        PCP_RESULT_UNSUPP_VERSION => PortMapperError::ProtocolNotSupported(
            "PCP gateway reported unsupported version".to_owned(),
        ),
        PCP_RESULT_NOT_AUTHORIZED => PortMapperError::Refused(
            "PCP refused: not authorized (port mapping likely disabled in router admin UI)"
                .to_owned(),
        ),
        PCP_RESULT_MALFORMED_REQUEST => PortMapperError::Refused(
            "PCP refused: gateway reported malformed request (client-side bug)".to_owned(),
        ),
        PCP_RESULT_UNSUPP_OPCODE => PortMapperError::ProtocolNotSupported(
            "PCP gateway does not support MAP opcode".to_owned(),
        ),
        PCP_RESULT_UNSUPP_OPTION => {
            PortMapperError::Refused("PCP gateway reported unsupported option".to_owned())
        }
        PCP_RESULT_MALFORMED_OPTION => {
            PortMapperError::Refused("PCP gateway reported malformed option".to_owned())
        }
        PCP_RESULT_NETWORK_FAILURE => PortMapperError::Refused(
            "PCP gateway reported network failure (transient — retry may help)".to_owned(),
        ),
        PCP_RESULT_NO_RESOURCES => PortMapperError::Refused(
            "PCP gateway out of resources (mapping table full)".to_owned(),
        ),
        PCP_RESULT_UNSUPP_PROTOCOL => PortMapperError::ProtocolNotSupported(
            "PCP gateway does not support requested transport protocol".to_owned(),
        ),
        PCP_RESULT_USER_EX_QUOTA => {
            PortMapperError::Refused("PCP gateway: user exceeded quota".to_owned())
        }
        PCP_RESULT_CANNOT_PROVIDE_EXTERNAL => PortMapperError::Refused(
            "PCP gateway cannot honour requested external address/port".to_owned(),
        ),
        PCP_RESULT_ADDRESS_MISMATCH => PortMapperError::Refused(
            "PCP gateway saw a source IP that did not match the embedded Client IP — likely a NAT44 layer in the path"
                .to_owned(),
        ),
        PCP_RESULT_EXCESSIVE_REMOTE_PEERS => {
            PortMapperError::Refused("PCP gateway: excessive remote peers".to_owned())
        }
        other => PortMapperError::Refused(format!("unrecognised PCP result code 0x{other:02x}")),
    }
}

impl PortMapper for PcpClient {
    fn request_udp_mapping(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<MappingLease, PortMapperError> {
        if internal_port == 0 {
            return Err(PortMapperError::InvalidResponse(
                "internal_port must be non-zero for a fresh PCP mapping request".to_owned(),
            ));
        }
        let client_ip = self.discover_local_addr()?;
        let nonce = Self::fresh_nonce();
        // Suggested external IP = all zeros — per RFC 6887 §11.1 this
        // means "any address" and tells the gateway to pick whatever
        // external IP it controls. We rely on STUN (D2) for the
        // authoritative external IP.
        let suggested_external = match client_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let request = Self::encode_map_request(
            client_ip,
            lease_duration_secs,
            nonce,
            internal_port,
            internal_port,
            suggested_external,
        );
        let response = self.round_trip(&request)?;
        let fields = Self::decode_map_response(&response, nonce, internal_port)?;
        Ok(MappingLease {
            internal_port,
            external_port: fields.external_port,
            external_addr: fields.external_addr,
            protocol: PortMappingProtocol::Pcp,
            expires_at: Instant::now()
                + Duration::from_secs(u64::from(fields.granted_lifetime_secs)),
            pcp_nonce: Some(nonce),
        })
    }

    fn refresh_mapping(&self, lease: &MappingLease) -> Result<MappingLease, PortMapperError> {
        // RFC 6887 §11.2.1: a renewal is byte-identical to the original
        // MAP request — same Mapping Nonce, same Internal Port, same
        // Suggested External Port. The nonce is the credential the
        // gateway uses to recognise this as the same client.
        let nonce = lease.pcp_nonce.ok_or_else(|| {
            PortMapperError::InvalidResponse(
                "refresh of a PCP lease without a stored Mapping Nonce — lease was minted by a different protocol or the nonce was dropped".to_owned(),
            )
        })?;
        let lifetime_secs = lease
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(60)
            .try_into()
            .unwrap_or(u32::MAX);
        let client_ip = self.discover_local_addr()?;
        let suggested_external = match client_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let request = Self::encode_map_request(
            client_ip,
            lifetime_secs,
            nonce,
            lease.internal_port,
            lease.external_port,
            suggested_external,
        );
        let response = self.round_trip(&request)?;
        let fields = Self::decode_map_response(&response, nonce, lease.internal_port)?;
        Ok(MappingLease {
            internal_port: lease.internal_port,
            external_port: fields.external_port,
            external_addr: fields.external_addr,
            protocol: PortMappingProtocol::Pcp,
            expires_at: Instant::now()
                + Duration::from_secs(u64::from(fields.granted_lifetime_secs)),
            pcp_nonce: Some(nonce),
        })
    }

    fn release_mapping(&self, lease: &MappingLease) -> Result<(), PortMapperError> {
        // RFC 6887 §15: send a MAP request with Requested Lifetime = 0
        // and the stored Mapping Nonce. Without the matching nonce the
        // gateway will refuse (NOT_AUTHORIZED) — which is the design,
        // because a third party should not be able to delete our
        // mapping by guessing the internal-port.
        let nonce = lease.pcp_nonce.ok_or_else(|| {
            PortMapperError::InvalidResponse(
                "release of a PCP lease without a stored Mapping Nonce — cannot satisfy RFC 6887 §15"
                    .to_owned(),
            )
        })?;
        let client_ip = self.discover_local_addr()?;
        let suggested_external = match client_ip {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let request = Self::encode_map_request(
            client_ip,
            0, // lifetime = 0 → delete
            nonce,
            lease.internal_port,
            0, // suggested external port — ignored for delete
            suggested_external,
        );
        let response = self.round_trip(&request)?;
        // Validate the response is well-formed; the lifetime/external
        // port fields are not meaningful on a successful delete, but the
        // result code is.
        let _fields = Self::decode_map_response(&response, nonce, lease.internal_port)?;
        Ok(())
    }
}

// ---- Probe orchestrator ----

/// Outcome of probing the gateway for a UDP port mapping.
///
/// `Mapped` is the success case — the gateway granted a lease via one of
/// the supported protocols. `NoGatewaySupport` is the soft-failure case —
/// every protocol either timed out or replied "I don't speak that" — and
/// the daemon should fall back to the outbound-keepalive trick
/// (decision 2.3 in `RustynetDataplaneExecutionPlan_2026-05-18.md`).
#[derive(Debug)]
pub enum ProbeOutcome {
    /// A protocol granted us a lease. Use `.protocol` to learn which.
    Mapped(MappingLease),
    /// No protocol responded. The home server should fall back to
    /// outbound keepalives.
    NoGatewaySupport,
}

/// Orchestrator that tries every implemented port-mapping protocol in
/// order against a known gateway.
///
/// Order is **PCP → NAT-PMP** (uPnP IGD is a planned subsequent slice
/// within D2.3; it will slot in as the final fall-through tier). The
/// ordering is justified by RFC 6887 §1.1: a gateway that speaks PCP
/// also speaks NAT-PMP, so probing PCP first is strictly more
/// informative — we get the richer error taxonomy if the gateway
/// supports PCP, and we fall through cheaply if it doesn't.
///
/// Classification of per-protocol outcomes:
///
/// * `Ok(lease)` → return `Mapped(lease)` immediately.
/// * `ProtocolNotSupported` → fall through to the next protocol. This
///   covers UNSUPP_VERSION (PCP) and unsupported-opcode (NAT-PMP).
/// * `Timeout` → fall through. A silent gateway is indistinguishable
///   from one that doesn't speak the protocol.
/// * Any other error (e.g. `Refused`, `Io`, `InvalidResponse`,
///   `NoGateway`) is surfaced to the caller. A `NOT_AUTHORIZED` from
///   one protocol means the operator disabled port mapping in the
///   router admin UI; the other protocol almost certainly does the
///   same. Surfacing the error gets the operator a useful diagnostic
///   instead of a silent fall-through to the keepalive fallback.
pub struct PortMappingProbe {
    /// The gateway socket address (IP + port). Production callers use
    /// [`PortMappingProbe::new`], which fixes the port at 5351 — the
    /// IANA assignment shared by PCP and NAT-PMP. Tests use
    /// [`PortMappingProbe::new_for_test`] so they can point at an
    /// in-process fake gateway on an ephemeral port.
    gateway: SocketAddr,
    initial_timeout: Duration,
    max_attempts: u8,
}

impl PortMappingProbe {
    /// Construct a probe targeting `gateway` on port 5351 (the IANA
    /// port shared by PCP and NAT-PMP). Defaults match the per-protocol
    /// practical retry settings (250 ms initial timeout).
    pub fn new(gateway: IpAddr) -> Self {
        Self {
            gateway: SocketAddr::new(gateway, PCP_SERVER_PORT),
            initial_timeout: PCP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: PCP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Construct from an arbitrary `SocketAddr` for tests pointing at
    /// an in-process fake gateway. Defaults match `new()`.
    #[doc(hidden)]
    pub fn new_for_test(gateway: SocketAddr) -> Self {
        Self {
            gateway,
            initial_timeout: PCP_DEFAULT_INITIAL_TIMEOUT,
            max_attempts: PCP_DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Builder: override the per-protocol initial timeout. Each protocol
    /// applies its own backoff doubling on top of this value.
    #[must_use]
    pub fn with_initial_timeout(mut self, timeout: Duration) -> Self {
        self.initial_timeout = timeout;
        self
    }

    /// Builder: override the per-protocol attempt cap.
    #[must_use]
    pub fn with_max_attempts(mut self, max: u8) -> Self {
        self.max_attempts = max.max(1);
        self
    }

    /// Try every implemented protocol in order. See type docs for
    /// classification rules.
    pub fn probe_udp_mapping(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<ProbeOutcome, PortMapperError> {
        // ---- PCP first ----
        let pcp = PcpClient::new_for_test(self.gateway)
            .with_initial_timeout(self.initial_timeout)
            .with_max_attempts(self.max_attempts);
        match pcp.request_udp_mapping(internal_port, lease_duration_secs) {
            Ok(lease) => return Ok(ProbeOutcome::Mapped(lease)),
            Err(PortMapperError::ProtocolNotSupported(_)) | Err(PortMapperError::Timeout) => {
                // fall through to NAT-PMP.
            }
            Err(other) => return Err(other),
        }

        // ---- NAT-PMP second (IPv4 gateway only) ----
        // RFC 6886 is IPv4-only; an IPv6 gateway address means PCP was
        // the only available protocol and no further fall-through is
        // possible. We surface `NoGatewaySupport` rather than an error
        // because the daemon can still use the keepalive fallback.
        if self.gateway.ip().is_ipv4() {
            let nat_pmp = NatPmpClient::new_for_test(self.gateway)
                .with_initial_timeout(self.initial_timeout)
                .with_max_attempts(self.max_attempts);
            match nat_pmp.request_udp_mapping(internal_port, lease_duration_secs) {
                Ok(lease) => return Ok(ProbeOutcome::Mapped(lease)),
                Err(PortMapperError::ProtocolNotSupported(_)) | Err(PortMapperError::Timeout) => {
                    return Ok(ProbeOutcome::NoGatewaySupport);
                }
                Err(other) => return Err(other),
            }
        }

        Ok(ProbeOutcome::NoGatewaySupport)
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
            pcp_nonce: None,
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
            pcp_nonce: None,
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

    // ---- PCP (RFC 6887) tests ----

    fn make_pcp_test_client() -> (PcpClient, SocketAddr) {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind fake PCP gateway socket");
        let gateway_addr = listener.local_addr().expect("fake PCP gateway local_addr");
        drop(listener);
        let client = PcpClient::new_for_test(gateway_addr)
            .with_initial_timeout(Duration::from_millis(50))
            .with_max_attempts(3);
        (client, gateway_addr)
    }

    /// Spawn a single-shot fake PCP gateway that responds to one MAP
    /// request. Returns a join handle and a request observation channel.
    /// `granted_lifetime_secs` is echoed back; on `result_code` non-zero
    /// the response carries that code and the body fields are filled
    /// with zeros (matching the RFC §7.2 expectation that error
    /// responses still have valid byte layout).
    #[allow(clippy::too_many_arguments)]
    fn spawn_fake_pcp_gateway(
        gateway_addr: SocketAddr,
        external_ipv4: Ipv4Addr,
        granted_external_port: u16,
        granted_lifetime_secs: u32,
        result_code: u8,
        expected_request_count: usize,
        override_response_nonce: Option<[u8; PCP_NONCE_LEN]>,
    ) -> (JoinHandle<()>, Receiver<Vec<u8>>) {
        let socket = UdpSocket::bind(gateway_addr).expect("bind fake PCP gateway");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fake PCP gateway read timeout");
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = channel();
        let handle = std::thread::spawn(move || {
            let mut count = 0usize;
            while count < expected_request_count {
                let mut buf = [0u8; 256];
                let (len, src) = match socket.recv_from(&mut buf) {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let req = buf[..len].to_vec();
                let _ = tx.send(req.clone());
                if req.len() < PCP_MAP_REQUEST_LEN || req[1] != PCP_OPCODE_MAP {
                    break;
                }
                let mut nonce = [0u8; PCP_NONCE_LEN];
                nonce.copy_from_slice(&req[24..36]);
                if let Some(forced) = override_response_nonce {
                    nonce = forced;
                }
                let echoed_internal = u16::from_be_bytes([req[40], req[41]]);
                let mut resp = vec![0u8; PCP_MAP_RESPONSE_LEN];
                resp[0] = PCP_VERSION;
                resp[1] = PCP_R_BIT_RESPONSE_MASK | PCP_OPCODE_MAP;
                resp[2] = 0; // reserved
                resp[3] = result_code;
                resp[4..8].copy_from_slice(&granted_lifetime_secs.to_be_bytes());
                resp[8..12].copy_from_slice(&123u32.to_be_bytes()); // Epoch — arbitrary.
                // bytes 12..24 reserved (zero).
                resp[24..36].copy_from_slice(&nonce);
                resp[36] = PCP_PROTOCOL_UDP;
                // bytes 37..40 reserved.
                resp[40..42].copy_from_slice(&echoed_internal.to_be_bytes());
                resp[42..44].copy_from_slice(&granted_external_port.to_be_bytes());
                // External address: ::ffff:external_ipv4.
                resp[54] = 0xff;
                resp[55] = 0xff;
                resp[56..60].copy_from_slice(&external_ipv4.octets());
                let _ = socket.send_to(&resp, src);
                count += 1;
            }
        });
        (handle, rx)
    }

    #[test]
    fn pcp_map_request_encoding_matches_rfc_6887_layout() {
        // Pin the request wire format byte-by-byte against the layout
        // documented in PcpClient::encode_map_request.
        let nonce: [u8; PCP_NONCE_LEN] = [
            0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac,
        ];
        let buf = PcpClient::encode_map_request(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            3600,
            nonce,
            51820,
            51820,
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        );
        assert_eq!(buf.len(), PCP_MAP_REQUEST_LEN, "60-byte MAP request");
        assert_eq!(buf[0], PCP_VERSION, "version=2");
        assert_eq!(buf[1], PCP_OPCODE_MAP, "R=0, opcode=MAP=1");
        assert_eq!(&buf[2..4], &[0, 0], "reserved=0");
        assert_eq!(
            u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            3600,
            "lifetime"
        );
        // Client IP — IPv4-mapped IPv6.
        assert_eq!(&buf[8..18], &[0u8; 10][..], "v4-mapped high 80 bits = 0");
        assert_eq!(
            &buf[18..20],
            &[0xff, 0xff],
            "v4-mapped mid 16 bits = 0xffff"
        );
        assert_eq!(&buf[20..24], &[192, 168, 1, 100], "client IPv4");
        assert_eq!(&buf[24..36], &nonce, "nonce echoed in request");
        assert_eq!(buf[36], PCP_PROTOCOL_UDP, "protocol=UDP=17");
        assert_eq!(&buf[37..40], &[0, 0, 0], "reserved=0");
        assert_eq!(
            u16::from_be_bytes([buf[40], buf[41]]),
            51820,
            "internal port"
        );
        assert_eq!(
            u16::from_be_bytes([buf[42], buf[43]]),
            51820,
            "suggested external port"
        );
        // Suggested external address = ::ffff:0.0.0.0 = ::ffff:0:0.
        assert_eq!(
            &buf[44..54],
            &[0u8; 10][..],
            "suggested external v4-mapped high 80 bits = 0"
        );
        assert_eq!(
            &buf[54..56],
            &[0xff, 0xff],
            "suggested external v4-mapped mid 16 bits = 0xffff"
        );
        assert_eq!(
            &buf[56..60],
            &[0, 0, 0, 0],
            "suggested external IPv4 = 0.0.0.0 (any)"
        );
    }

    #[test]
    fn pcp_request_udp_mapping_round_trip_against_fake_gateway() {
        let (client, gateway_addr) = make_pcp_test_client();
        let (handle, rx) = spawn_fake_pcp_gateway(
            gateway_addr,
            Ipv4Addr::new(198, 51, 100, 7),
            53420,
            7200,
            PCP_RESULT_SUCCESS,
            1,
            None,
        );

        let lease = client
            .request_udp_mapping(51820, 3600)
            .expect("PCP MAP succeeds against fake gateway");
        assert_eq!(lease.internal_port, 51820);
        assert_eq!(lease.external_port, 53420);
        assert_eq!(
            lease.external_addr,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
        );
        assert_eq!(lease.protocol, PortMappingProtocol::Pcp);
        assert!(
            lease.pcp_nonce.is_some(),
            "PCP lease must carry the Mapping Nonce for renewal/delete"
        );

        let req = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("request arrives");
        assert_eq!(req[0], PCP_VERSION);
        assert_eq!(req[1], PCP_OPCODE_MAP);
        // Verify the nonce on the wire matches what's stored in the lease.
        let mut wire_nonce = [0u8; PCP_NONCE_LEN];
        wire_nonce.copy_from_slice(&req[24..36]);
        assert_eq!(
            lease.pcp_nonce.expect("nonce present"),
            wire_nonce,
            "lease must store the same nonce that was sent on the wire"
        );

        handle.join().expect("fake PCP gateway thread joins");
    }

    #[test]
    fn pcp_response_nonce_mismatch_is_rejected_as_invalid_response() {
        // RFC 6887 §11.2: a response carrying a Mapping Nonce different
        // from the one in the request must be rejected — otherwise an
        // off-path attacker who races our outgoing packet could
        // substitute their own mapping. This test forces a wrong nonce
        // in the fake gateway's response and pins that the client
        // surfaces `InvalidResponse` rather than a successful lease.
        let (client, gateway_addr) = make_pcp_test_client();
        let wrong_nonce: [u8; PCP_NONCE_LEN] = [0xde; PCP_NONCE_LEN];
        let (handle, _rx) = spawn_fake_pcp_gateway(
            gateway_addr,
            Ipv4Addr::new(198, 51, 100, 7),
            53420,
            7200,
            PCP_RESULT_SUCCESS,
            1,
            Some(wrong_nonce),
        );

        let err = client
            .request_udp_mapping(51820, 3600)
            .expect_err("response with wrong nonce must fail");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("nonce")),
            "expected InvalidResponse mentioning nonce, got: {err:?}"
        );

        handle.join().expect("fake PCP gateway thread joins");
    }

    #[test]
    fn pcp_result_code_address_mismatch_maps_to_refused_with_nat44_hint() {
        // RFC 6887 §7.4: ADDRESS_MISMATCH (12) signals that the gateway
        // saw a source IP different from the embedded Client IP — the
        // classic symptom of a NAT44 layer between the host and the
        // gateway. The error message should hint at this so an operator
        // can diagnose the network topology.
        let (client, gateway_addr) = make_pcp_test_client();
        let (handle, _rx) = spawn_fake_pcp_gateway(
            gateway_addr,
            Ipv4Addr::UNSPECIFIED,
            0,
            0,
            PCP_RESULT_ADDRESS_MISMATCH,
            1,
            None,
        );

        let err = client
            .request_udp_mapping(51820, 3600)
            .expect_err("ADDRESS_MISMATCH must surface as an error");
        match err {
            PortMapperError::Refused(msg) => {
                assert!(
                    msg.contains("NAT44") || msg.contains("address") || msg.contains("source"),
                    "expected ADDRESS_MISMATCH error message to hint at the cause, got: {msg}"
                );
            }
            other => panic!("expected Refused, got: {other:?}"),
        }

        handle.join().expect("fake PCP gateway thread joins");
    }

    #[test]
    fn pcp_release_mapping_requires_stored_nonce() {
        // RFC 6887 §15 + §11.2: the Mapping Nonce is the credential
        // used to authorise a delete. A lease without a stored nonce
        // (e.g. a lease minted by NAT-PMP that someone then tried to
        // release via the PCP client) MUST be refused at the client —
        // we should not send a partial PCP delete with a fresh random
        // nonce, because the gateway will refuse it.
        let pcp = PcpClient::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let lease_without_nonce = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            protocol: PortMappingProtocol::NatPmp,
            expires_at: Instant::now() + Duration::from_secs(1800),
            pcp_nonce: None,
        };
        let err = pcp
            .release_mapping(&lease_without_nonce)
            .expect_err("release of nonce-less lease must fail closed");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("Mapping Nonce")),
            "expected InvalidResponse about missing nonce, got: {err:?}"
        );
    }

    #[test]
    fn pcp_unsupp_version_maps_to_protocol_not_supported_for_orchestrator_fallthrough() {
        // The probe orchestrator (follow-up slice in D2.3) uses
        // `ProtocolNotSupported` as the signal to fall through to the
        // next protocol. UNSUPP_VERSION (1) means "this gateway does
        // not speak PCP v2"; it MUST classify as
        // ProtocolNotSupported, not Refused.
        let (client, gateway_addr) = make_pcp_test_client();
        let (handle, _rx) = spawn_fake_pcp_gateway(
            gateway_addr,
            Ipv4Addr::UNSPECIFIED,
            0,
            0,
            PCP_RESULT_UNSUPP_VERSION,
            1,
            None,
        );

        let err = client
            .request_udp_mapping(51820, 3600)
            .expect_err("UNSUPP_VERSION must error");
        assert!(
            matches!(err, PortMapperError::ProtocolNotSupported(_)),
            "UNSUPP_VERSION must classify as ProtocolNotSupported for orchestrator fall-through, got: {err:?}"
        );

        handle.join().expect("fake PCP gateway thread joins");
    }

    #[test]
    fn pcp_address_parser_round_trips_v4_mapped_and_native_v6() {
        // ::ffff:1.2.3.4 → IpAddr::V4(1.2.3.4).
        let mut v4_mapped = [0u8; 16];
        v4_mapped[10] = 0xff;
        v4_mapped[11] = 0xff;
        v4_mapped[12..16].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(
            parse_pcp_address(v4_mapped),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            "v4-mapped IPv6 must surface as IpAddr::V4"
        );
        // 2001:db8::1 → IpAddr::V6(2001:db8::1).
        let v6_native = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(
            parse_pcp_address(v6_native),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            "native IPv6 must surface as IpAddr::V6"
        );
    }

    // ---- Probe orchestrator tests ----

    /// Spawn a dual-protocol fake gateway that handles N requests on a
    /// single UDP socket. Each request is dispatched by inspecting
    /// `byte[0]` (PCP=2, NAT-PMP=0) and responded to according to the
    /// per-protocol handler closures. A handler returning `None` means
    /// "drop the packet silently" (used to simulate a gateway that does
    /// not speak that protocol). The orchestrator's PCP and NAT-PMP
    /// clients share the gateway address by design — real routers
    /// answer both protocols on port 5351 via version-byte demux.
    type Responder = Box<dyn Fn(&[u8]) -> Vec<u8> + Send + 'static>;

    fn spawn_dual_protocol_gateway(
        gateway_addr: SocketAddr,
        pcp_responder: Option<Responder>,
        nat_pmp_responder: Option<Responder>,
        expected_request_count: usize,
    ) -> JoinHandle<()> {
        let socket = UdpSocket::bind(gateway_addr).expect("bind dual-protocol fake gateway");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set fake gateway read timeout");
        std::thread::spawn(move || {
            let mut count = 0usize;
            while count < expected_request_count {
                let mut buf = [0u8; 256];
                let (len, src) = match socket.recv_from(&mut buf) {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                let req = buf[..len].to_vec();
                count += 1;
                let version = req.first().copied().unwrap_or(0xff);
                let response = match version {
                    2 => pcp_responder.as_ref().map(|f| f(&req)),
                    0 => nat_pmp_responder.as_ref().map(|f| f(&req)),
                    _ => None,
                };
                if let Some(resp) = response {
                    let _ = socket.send_to(&resp, src);
                }
                // None = drop silently (gateway that doesn't speak that protocol).
            }
        })
    }

    fn build_pcp_success_response(req: &[u8], ext_v4: Ipv4Addr, ext_port: u16) -> Vec<u8> {
        let mut nonce = [0u8; PCP_NONCE_LEN];
        nonce.copy_from_slice(&req[24..36]);
        let echoed_internal = u16::from_be_bytes([req[40], req[41]]);
        let mut resp = vec![0u8; PCP_MAP_RESPONSE_LEN];
        resp[0] = PCP_VERSION;
        resp[1] = PCP_R_BIT_RESPONSE_MASK | PCP_OPCODE_MAP;
        resp[3] = PCP_RESULT_SUCCESS;
        resp[4..8].copy_from_slice(&3600u32.to_be_bytes());
        resp[8..12].copy_from_slice(&7u32.to_be_bytes());
        resp[24..36].copy_from_slice(&nonce);
        resp[36] = PCP_PROTOCOL_UDP;
        resp[40..42].copy_from_slice(&echoed_internal.to_be_bytes());
        resp[42..44].copy_from_slice(&ext_port.to_be_bytes());
        resp[54] = 0xff;
        resp[55] = 0xff;
        resp[56..60].copy_from_slice(&ext_v4.octets());
        resp
    }

    fn build_pcp_error_response(req: &[u8], result_code: u8) -> Vec<u8> {
        let mut nonce = [0u8; PCP_NONCE_LEN];
        nonce.copy_from_slice(&req[24..36]);
        let mut resp = vec![0u8; PCP_MAP_RESPONSE_LEN];
        resp[0] = PCP_VERSION;
        resp[1] = PCP_R_BIT_RESPONSE_MASK | PCP_OPCODE_MAP;
        resp[3] = result_code;
        resp[24..36].copy_from_slice(&nonce);
        resp[36] = PCP_PROTOCOL_UDP;
        let echoed_internal = u16::from_be_bytes([req[40], req[41]]);
        resp[40..42].copy_from_slice(&echoed_internal.to_be_bytes());
        resp
    }

    fn build_nat_pmp_external_addr_response(ext_v4: Ipv4Addr) -> Vec<u8> {
        let mut resp = vec![0u8; 12];
        resp[0] = NAT_PMP_VERSION;
        resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_EXTERNAL_ADDR;
        resp[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
        resp[4..8].copy_from_slice(&42u32.to_be_bytes());
        resp[8..12].copy_from_slice(&ext_v4.octets());
        resp
    }

    fn build_nat_pmp_map_response(req: &[u8], ext_port: u16, lifetime: u32) -> Vec<u8> {
        let echoed_internal = u16::from_be_bytes([req[4], req[5]]);
        let mut resp = vec![0u8; 16];
        resp[0] = NAT_PMP_VERSION;
        resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        resp[2..4].copy_from_slice(&NAT_PMP_RESULT_SUCCESS.to_be_bytes());
        resp[4..8].copy_from_slice(&42u32.to_be_bytes());
        resp[8..10].copy_from_slice(&echoed_internal.to_be_bytes());
        resp[10..12].copy_from_slice(&ext_port.to_be_bytes());
        resp[12..16].copy_from_slice(&lifetime.to_be_bytes());
        resp
    }

    fn make_probe_test(gateway_addr: SocketAddr) -> PortMappingProbe {
        PortMappingProbe::new_for_test(gateway_addr)
            .with_initial_timeout(Duration::from_millis(50))
            .with_max_attempts(2)
    }

    fn probe_test_gateway_addr() -> SocketAddr {
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind probe gateway scout");
        let addr = listener.local_addr().expect("local_addr");
        drop(listener);
        addr
    }

    #[test]
    fn probe_returns_mapped_when_pcp_succeeds() {
        // Happy path: gateway speaks PCP, returns a lease.
        // Probe must return Mapped(lease) with protocol=Pcp and not
        // bother trying NAT-PMP.
        let gateway = probe_test_gateway_addr();
        let handle = spawn_dual_protocol_gateway(
            gateway,
            Some(Box::new(|req| {
                build_pcp_success_response(req, Ipv4Addr::new(198, 51, 100, 7), 54321)
            })),
            None, // NAT-PMP responder unused
            1,
        );
        let probe = make_probe_test(gateway);

        let outcome = probe
            .probe_udp_mapping(51820, 3600)
            .expect("probe succeeds when PCP responds");

        match outcome {
            ProbeOutcome::Mapped(lease) => {
                assert_eq!(lease.protocol, PortMappingProtocol::Pcp);
                assert_eq!(lease.external_port, 54321);
                assert_eq!(
                    lease.external_addr,
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))
                );
            }
            other => panic!("expected Mapped(Pcp), got {other:?}"),
        }

        handle.join().expect("gateway thread joins");
    }

    #[test]
    fn probe_falls_through_to_nat_pmp_when_pcp_silent() {
        // Realistic mid-tier router scenario: doesn't speak PCP at all
        // (silent on version=2 packets), does speak NAT-PMP. Probe
        // must time out on PCP and successfully fall through to
        // NAT-PMP, returning Mapped(lease, protocol=NatPmp).
        let gateway = probe_test_gateway_addr();
        let handle = spawn_dual_protocol_gateway(
            gateway,
            None, // PCP silent — drops version=2 packets
            Some(Box::new(|req| match req.get(1).copied() {
                Some(NAT_PMP_OP_EXTERNAL_ADDR) => {
                    build_nat_pmp_external_addr_response(Ipv4Addr::new(203, 0, 113, 9))
                }
                Some(NAT_PMP_OP_MAP_UDP) => build_nat_pmp_map_response(req, 12345, 3600),
                _ => Vec::new(),
            })),
            // PCP probes 2 times (configured max_attempts) before
            // giving up, then NAT-PMP gets 2 round-trips
            // (external_addr + map) — but each round-trip may itself
            // retry. We size the handler count to cover the realistic
            // worst case: 2 PCP attempts silently dropped + 2 NAT-PMP
            // round-trips.
            4,
        );
        let probe = make_probe_test(gateway);

        let outcome = probe
            .probe_udp_mapping(51820, 3600)
            .expect("probe succeeds when NAT-PMP responds");
        match outcome {
            ProbeOutcome::Mapped(lease) => {
                assert_eq!(
                    lease.protocol,
                    PortMappingProtocol::NatPmp,
                    "must fall through to NAT-PMP when PCP is silent"
                );
                assert_eq!(lease.external_port, 12345);
            }
            other => panic!("expected Mapped(NatPmp), got {other:?}"),
        }
        handle.join().expect("gateway thread joins");
    }

    #[test]
    fn probe_returns_no_gateway_support_when_both_protocols_unresponsive() {
        // Neither protocol responds (gateway is firewalled or doesn't
        // run a port-mapping service at all). Probe must return
        // NoGatewaySupport so the daemon can fall back to the
        // outbound-keepalive trick.
        let gateway = probe_test_gateway_addr();
        // Bind the socket but never respond.
        let socket = UdpSocket::bind(gateway).expect("bind silent gateway");
        let handle = std::thread::spawn(move || {
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .expect("set read timeout");
            // Drain a handful of packets and drop them — both probes will
            // hit max_attempts.
            for _ in 0..6 {
                let mut buf = [0u8; 256];
                if socket.recv_from(&mut buf).is_err() {
                    return;
                }
            }
        });
        let probe = make_probe_test(gateway);

        let outcome = probe
            .probe_udp_mapping(51820, 3600)
            .expect("probe returns Ok with NoGatewaySupport when both protocols silent");
        assert!(
            matches!(outcome, ProbeOutcome::NoGatewaySupport),
            "expected NoGatewaySupport, got {outcome:?}"
        );
        handle.join().expect("silent gateway thread joins");
    }

    #[test]
    fn probe_surfaces_hard_refusal_without_trying_second_protocol() {
        // PCP returns NOT_AUTHORIZED (result code 2). This means the
        // operator disabled port mapping in the router admin UI; NAT-PMP
        // almost certainly does the same. The orchestrator must surface
        // the error so the operator sees a useful diagnostic instead of
        // silently falling back to keepalive.
        //
        // The fake gateway only handles the one PCP request — if the
        // orchestrator wrongly falls through to NAT-PMP, the fake
        // gateway thread won't service the NAT-PMP request and the test
        // would still detect the wrong behaviour by inspecting the
        // returned error variant.
        let gateway = probe_test_gateway_addr();
        let handle = spawn_dual_protocol_gateway(
            gateway,
            Some(Box::new(|req| {
                build_pcp_error_response(req, PCP_RESULT_NOT_AUTHORIZED)
            })),
            None,
            1,
        );
        let probe = make_probe_test(gateway);

        let err = probe
            .probe_udp_mapping(51820, 3600)
            .expect_err("NOT_AUTHORIZED must surface as an error, not silent fall-through");
        assert!(
            matches!(err, PortMapperError::Refused(ref msg) if msg.to_lowercase().contains("not authorized")),
            "expected Refused with 'not authorized' message, got: {err:?}"
        );
        handle.join().expect("gateway thread joins");
    }

    #[test]
    fn probe_falls_through_on_unsupp_version_to_nat_pmp() {
        // PCP returns UNSUPP_VERSION (result code 1) — meaning the
        // gateway parsed our v2 packet enough to reject the version.
        // This is rare (most non-PCP gateways just don't respond at
        // all) but RFC 6887 §7.4 codifies it. The orchestrator must
        // classify it as ProtocolNotSupported and fall through, not as
        // a hard refusal.
        let gateway = probe_test_gateway_addr();
        let handle = spawn_dual_protocol_gateway(
            gateway,
            Some(Box::new(|req| {
                build_pcp_error_response(req, PCP_RESULT_UNSUPP_VERSION)
            })),
            Some(Box::new(|req| match req.get(1).copied() {
                Some(NAT_PMP_OP_EXTERNAL_ADDR) => {
                    build_nat_pmp_external_addr_response(Ipv4Addr::new(203, 0, 113, 9))
                }
                Some(NAT_PMP_OP_MAP_UDP) => build_nat_pmp_map_response(req, 7777, 3600),
                _ => Vec::new(),
            })),
            3,
        );
        let probe = make_probe_test(gateway);

        let outcome = probe
            .probe_udp_mapping(51820, 3600)
            .expect("UNSUPP_VERSION must fall through to NAT-PMP cleanly");
        match outcome {
            ProbeOutcome::Mapped(lease) => {
                assert_eq!(lease.protocol, PortMappingProtocol::NatPmp);
                assert_eq!(lease.external_port, 7777);
            }
            other => panic!("expected Mapped(NatPmp), got {other:?}"),
        }
        handle.join().expect("gateway thread joins");
    }
}
