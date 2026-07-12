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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use subtle::ConstantTimeEq;

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
#[derive(Clone, PartialEq, Eq)]
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
    ///
    /// **Security**: the nonce IS the credential for tearing down this
    /// mapping (RFC 6887 §15). The field is intentionally NOT exposed
    /// via `Debug` (see custom `fmt::Debug` impl below) so a stray
    /// `log::debug!("{:?}", lease)` cannot leak it. The bytes are
    /// zeroised when the lease is dropped.
    pub pcp_nonce: Option<[u8; 12]>,
}

// Custom Debug elides `pcp_nonce` bytes; only the presence flag is
// surfaced. Without this, a `{:?}` placeholder anywhere downstream
// would emit the 12-byte renew/delete credential into the log stream.
impl std::fmt::Debug for MappingLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MappingLease")
            .field("internal_port", &self.internal_port)
            .field("external_port", &self.external_port)
            .field("external_addr", &self.external_addr)
            .field("protocol", &self.protocol)
            .field("expires_at", &self.expires_at)
            .field("pcp_nonce", &self.pcp_nonce.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Drop for MappingLease {
    fn drop(&mut self) {
        // Zeroise the nonce on drop so a freed lease does not leave the
        // renew/delete credential floating in heap-reused memory.
        // Using `zeroize::Zeroize` keeps the wipe non-optimisable by
        // the compiler.
        if let Some(nonce) = self.pcp_nonce.as_mut() {
            use zeroize::Zeroize;
            nonce.zeroize();
        }
    }
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
    ///
    /// **Security**: the UDP socket is `connect()`'d to the gateway so
    /// the kernel filters incoming datagrams to only those from the
    /// configured gateway IP+port. An attacker on the LAN cannot
    /// spoof a NAT-PMP response from a different source IP to DoS the
    /// probe or feed us a forged mapping — those packets are silently
    /// dropped by the kernel before they reach this code. Matches the
    /// PCP client's discipline.
    ///
    /// Deliberately independent of `resilience::next_reconnect_delay_jittered_ms`:
    /// this is a receive-timeout retransmission ladder on RFC 6886 §3.1 timing
    /// (no inter-attempt delay exists to jitter) — see the FIS-0016
    /// classification.
    fn round_trip(&self, request: &[u8]) -> Result<Vec<u8>, PortMapperError> {
        // Bind to v4 0.0.0.0:0 because NAT-PMP is IPv4-only.
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(self.gateway)?;
        let mut current_timeout = self.initial_timeout;
        for _attempt in 0..self.max_attempts {
            socket.set_read_timeout(Some(current_timeout))?;
            socket.send(request)?;
            let mut buf = [0u8; 64];
            match socket.recv(&mut buf) {
                Ok(len) => return Ok(buf[..len].to_vec()),
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
            expires_at: expires_at_from_lifetime(lifetime_secs),
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
            expires_at: expires_at_from_lifetime(granted_lifetime),
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
    /// `lifetime=0` deletes and tear down our mapping. Draw directly
    /// from the kernel CSPRNG (`OsRng`). Fail-closed (no ThreadRng
    /// fallback) because ThreadRng also seeds from OsRng on first
    /// use; a host where OsRng is unavailable would panic inside
    /// ThreadRng anyway. Returning a typed error is the cleaner
    /// shape — the caller surfaces an `Io` PortMapperError that
    /// the daemon logs and the keepalive fallback covers.
    fn fresh_nonce() -> Result<[u8; PCP_NONCE_LEN], PortMapperError> {
        use rand::TryRngCore;
        let mut nonce = [0u8; PCP_NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut nonce).map_err(|e| {
            PortMapperError::Io(format!(
                "kernel CSPRNG (OsRng) refused entropy for PCP Mapping Nonce: {e}"
            ))
        })?;
        Ok(nonce)
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
        // RFC 6887 §11.2: the Mapping Nonce is the credential for
        // renewing or tearing down this mapping. A timing oracle that
        // leaks the nonce byte-by-byte would let an off-path attacker
        // craft a delete request. Compare in constant time even though
        // the UDP `connect()` source-IP filter already limits the
        // attacker surface — defense in depth.
        if echoed_nonce.ct_eq(&sent_nonce).unwrap_u8() != 1 {
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
    ///
    /// Deliberately independent of `resilience::next_reconnect_delay_jittered_ms`:
    /// receive-timeout ladder on documented RFC 6887 §8.1.1-deviating timing,
    /// not delay-before-retry backoff — see the FIS-0016 classification.
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
        let nonce = Self::fresh_nonce()?;
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
            expires_at: expires_at_from_lifetime(fields.granted_lifetime_secs),
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
            expires_at: expires_at_from_lifetime(fields.granted_lifetime_secs),
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

// ---- Default-gateway detection ----

/// Detect the host's IPv4 default gateway, which is the address the
/// probe orchestrator will point its PCP / NAT-PMP / uPnP clients at.
///
/// Per platform:
/// * **Linux** parses `/proc/net/route` and finds the row whose
///   `Destination` is `00000000` (the default route, RFC 4632 anycast
///   prefix `0.0.0.0/0`). The `Gateway` field is a little-endian hex
///   string for the IPv4 address.
/// * **macOS** runs `route -n get default` and scans the stdout for
///   the `gateway:` line.
/// * **Windows** calls `GetAdaptersAddresses` through the native
///   Windows boundary crate and picks the lowest-metric usable default
///   gateway on an operational non-loopback adapter.
///
/// We do NOT trust ARP output or shell-derived adapter text. The route table
/// (Linux/macOS) or Windows IP Helper API data is the authoritative source.
pub fn detect_default_gateway() -> Result<IpAddr, PortMapperError> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/net/route")
            .map_err(|e| PortMapperError::NoGateway(format!("reading /proc/net/route: {e}")))?;
        parse_proc_net_route_for_default(&content)
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .map_err(|e| PortMapperError::NoGateway(format!("spawning /sbin/route: {e}")))?;
        if !output.status.success() {
            return Err(PortMapperError::NoGateway(format!(
                "/sbin/route exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_route_get_default_output(&stdout)
    }
    #[cfg(target_os = "windows")]
    {
        rustynet_windows_native::detect_default_gateway().map_err(PortMapperError::NoGateway)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(PortMapperError::NoGateway(format!(
            "default-gateway autodetection not implemented for {}",
            std::env::consts::OS
        )))
    }
}

/// Pure parser for the `/proc/net/route` table. Public-in-module so the
/// test module can exercise it with synthesised tables (real device
/// route tables, malformed input, missing default route, etc.).
///
/// `/proc/net/route` format (tab/whitespace separated, header on line 0):
///   Iface  Destination  Gateway  Flags  RefCnt  Use  Metric  Mask  MTU  Window  IRTT
/// Both `Destination` and `Gateway` are 8-character lowercase hex
/// strings in **little-endian** byte order: `0102030A` represents the
/// address with bytes 0x0A, 0x03, 0x02, 0x01 → `10.3.2.1`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_proc_net_route_for_default(content: &str) -> Result<IpAddr, PortMapperError> {
    for (idx, line) in content.lines().enumerate() {
        if idx == 0 {
            // Skip the header row.
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let destination = fields[1];
        let gateway = fields[2];
        // Default route: destination = 0x00000000.
        if destination.eq_ignore_ascii_case("00000000") {
            return parse_hex_le_ipv4(gateway).map(IpAddr::V4);
        }
    }
    Err(PortMapperError::NoGateway(
        "no default route in /proc/net/route".to_owned(),
    ))
}

/// Parse an 8-character hex string in little-endian byte order into an
/// `Ipv4Addr`. `/proc/net/route` stores all addresses this way.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_hex_le_ipv4(hex: &str) -> Result<Ipv4Addr, PortMapperError> {
    if hex.len() != 8 {
        return Err(PortMapperError::NoGateway(format!(
            "expected 8-hex-char gateway, got {} chars: {hex}",
            hex.len()
        )));
    }
    let raw = u32::from_str_radix(hex, 16).map_err(|e| {
        PortMapperError::NoGateway(format!("failed to parse hex gateway {hex} as u32: {e}"))
    })?;
    let bytes = raw.to_le_bytes();
    Ok(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

/// Pure parser for `route -n get default` stdout on macOS.
///
/// Sample output:
/// ```text
///    route to: default
/// destination: default
///        mask: default
///     gateway: 192.168.1.1
///       interface: en0
///       flags: <UP,GATEWAY,DONE,STATIC,PRCLONED>
/// ```
/// The parser scans for the line whose leading non-whitespace token is
/// `gateway:` and parses the following whitespace-separated value as
/// an IPv4 or IPv6 address.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_route_get_default_output(stdout: &str) -> Result<IpAddr, PortMapperError> {
    for line in stdout.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("gateway:") {
            let value = rest.trim();
            if value.is_empty() {
                continue;
            }
            return value.parse::<IpAddr>().map_err(|e| {
                PortMapperError::NoGateway(format!("could not parse gateway value {value}: {e}"))
            });
        }
    }
    Err(PortMapperError::NoGateway(
        "no `gateway:` line in `route -n get default` output".to_owned(),
    ))
}

// ---- uPnP IGD (SSDP discovery + HTTP/SOAP) ----

/// SSDP multicast group address (UPnP Device Architecture v1.1 §1.2.2).
pub const UPNP_SSDP_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);

/// SSDP UDP port (UPnP Device Architecture v1.1 §1.2.2).
pub const UPNP_SSDP_PORT: u16 = 1900;

/// SSDP Search Target for the InternetGatewayDevice v1 root device.
pub const UPNP_ST_IGD_V1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";

/// SSDP Search Target for the InternetGatewayDevice v2 root device.
pub const UPNP_ST_IGD_V2: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:2";

/// Service type for WANIPConnection v1 (IGD:1).
pub const UPNP_SERVICE_WANIPCONNECTION_V1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";

/// Service type for WANIPConnection v2 (IGD:2).
pub const UPNP_SERVICE_WANIPCONNECTION_V2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";

/// Service type for WANPPPConnection (PPP-based WANs; rare on consumer
/// gear but still legal). Same SOAP surface as WANIPConnection.
pub const UPNP_SERVICE_WANPPPCONNECTION_V1: &str =
    "urn:schemas-upnp-org:service:WANPPPConnection:1";

/// Practical M-SEARCH MX header value (seconds). The UPnP spec says the
/// device picks a random delay between 0 and MX before replying — we
/// keep this short so a slow gateway does not pad the probe.
const UPNP_MSEARCH_MX_SECS: u8 = 2;

/// Practical SSDP discovery wait: how long we listen for responses.
const UPNP_SSDP_DEFAULT_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(3);

/// Hard cap on the number of distinct LOCATION URLs we accept from
/// SSDP M-SEARCH responses. A real LAN has at most one or two IGDs;
/// any host responding with more than this many distinct URLs is
/// either misconfigured or trying to DoS our `discover_one` path by
/// making us spend timeout × N seconds on bogus HTTP fetches.
pub const MAX_SSDP_DISCOVERED_DEVICES: usize = 4;

/// Build an SSDP M-SEARCH HTTP-over-UDP request body for an IGD search.
///
/// Wire format (UPnP Device Architecture v1.1 §1.3.2):
///
/// ```text
/// M-SEARCH * HTTP/1.1\r\n
/// HOST: 239.255.255.250:1900\r\n
/// MAN: "ssdp:discover"\r\n
/// MX: <seconds>\r\n
/// ST: <search-target>\r\n
/// \r\n
/// ```
///
/// CRLF line endings and the literal `MAN: "ssdp:discover"` value
/// (quotes included) are mandatory.
pub fn build_msearch_request(search_target: &str) -> Vec<u8> {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {UPNP_SSDP_MULTICAST_IPV4}:{UPNP_SSDP_PORT}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: {UPNP_MSEARCH_MX_SECS}\r\n\
         ST: {search_target}\r\n\
         USER-AGENT: rustynetd/0 UPnP/1.1\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Parse an SSDP response, returning the LOCATION header value if
/// present. The response is an HTTP-style document with `\r\n` line
/// endings; headers are case-insensitive (UPnP DA §1.3.3).
pub fn parse_ssdp_location(response: &str) -> Option<String> {
    // Skip the status line; first line is e.g. "HTTP/1.1 200 OK".
    for line in response.lines().skip(1) {
        // RFC 7230: headers are name<colon>value; the case of the name
        // does not matter. We split on the first colon and compare
        // case-insensitively.
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("LOCATION")
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}

/// Crude single-pass XML walker that finds the `<controlURL>` text
/// inside the first `<service>` block whose `<serviceType>` matches one
/// of `target_service_types`.
///
/// We deliberately avoid pulling in a full XML parser dep — the IGD
/// device description is well-formed and small (<10 KB), and the only
/// element we care about is a sibling text node of a known type marker.
/// The walker:
///
/// 1. Scans for `<service>` open tags.
/// 2. Within each `<service>...</service>` span, extracts the
///    `<serviceType>` and `<controlURL>` text.
/// 3. Returns the first `controlURL` whose serviceType matches.
///
/// Resolves relative `controlURL` values against `base_url` per
/// UPnP DA §1.6 (URL field rules).
pub fn parse_device_description_for_control_url(
    xml: &str,
    target_service_types: &[&str],
    base_url: &str,
) -> Option<String> {
    let mut cursor = 0;
    while let Some(open) = find_subslice(xml, b"<service>", cursor) {
        let close = find_subslice(xml, b"</service>", open).unwrap_or(xml.len());
        let block = &xml[open..close];
        let service_type = extract_inner_text(block, "serviceType")?;
        if target_service_types
            .iter()
            .any(|wanted| service_type.trim() == *wanted)
        {
            let control = extract_inner_text(block, "controlURL")?;
            let control_trimmed = control.trim();
            return Some(resolve_url_against_base(control_trimmed, base_url));
        }
        cursor = close + b"</service>".len();
    }
    None
}

fn find_subslice(haystack: &str, needle: &[u8], from: usize) -> Option<usize> {
    if from > haystack.len() {
        return None;
    }
    let bytes = haystack.as_bytes();
    bytes[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p + from)
}

fn extract_inner_text<'a>(block: &'a str, tag: &str) -> Option<&'a str> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let open_idx = block.find(&open)? + open.len();
    let close_idx = block[open_idx..].find(&close)? + open_idx;
    Some(&block[open_idx..close_idx])
}

/// Resolve a `<controlURL>` value against the device description's
/// LOCATION URL per UPnP DA §1.6 URL rules. Absolute URLs pass through;
/// path-relative URLs are joined against the LOCATION's
/// `scheme://host[:port]` prefix.
fn resolve_url_against_base(url: &str, base: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        return url.to_owned();
    }
    let scheme_end = match base.find("://") {
        Some(i) => i + 3,
        None => return url.to_owned(),
    };
    let path_start = base[scheme_end..]
        .find('/')
        .map(|i| i + scheme_end)
        .unwrap_or(base.len());
    let origin = &base[..path_start];
    if url.starts_with('/') {
        format!("{origin}{url}")
    } else {
        format!("{origin}/{url}")
    }
}

/// Build a SOAP envelope for an UPnP IGD action.
///
/// Format (UPnP DA §2.5 SOAP messaging; mirroring miniupnpc's wire
/// format which is the de-facto interoperable template):
///
/// ```xml
/// <?xml version="1.0"?>
/// <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"
///             s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
///   <s:Body>
///     <u:ActionName xmlns:u="<service-type-urn>">
///       <ArgName1>val1</ArgName1>
///       ...
///     </u:ActionName>
///   </s:Body>
/// </s:Envelope>
/// ```
///
/// `arguments` is a list of `(name, value)` pairs; values are XML-text
/// escaped (`&`, `<`, `>`, `"`, `'`) before inlining.
pub fn build_soap_envelope(
    service_type: &str,
    action: &str,
    arguments: &[(&str, String)],
) -> String {
    let mut args_xml = String::new();
    for (name, value) in arguments {
        args_xml.push_str(&format!("<{name}>{}</{name}>", xml_escape(value)));
    }
    format!(
        "<?xml version=\"1.0\"?>\r\n\
         <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\
         <s:Body>\
         <u:{action} xmlns:u=\"{service_type}\">\
         {args_xml}\
         </u:{action}>\
         </s:Body></s:Envelope>\r\n"
    )
}

/// Maximum lease lifetime we'll accept from any gateway, in seconds.
/// RFC 6887 §11.1 says "Recommended Lifetime SHOULD NOT exceed 24
/// hours" and RFC 6886 §3.3 implicitly bounds the field at u32::MAX
/// seconds (136 years). A hostile or buggy gateway returning a huge
/// lifetime would, without this cap, cause `Instant::now() + Duration`
/// to potentially overflow the platform's Instant representation and
/// panic the daemon. We clamp at 24 hours so the math always fits and
/// a degenerate gateway response cannot DoS the process.
pub const MAX_GATEWAY_LEASE_SECS: u32 = 24 * 60 * 60;

/// Compute the absolute expiry for a mapping lease, clamping the
/// gateway-supplied lifetime at [`MAX_GATEWAY_LEASE_SECS`] and using
/// `Instant::checked_add` to fail closed (never panic) on overflow.
/// Falls back to `Instant::now()` if the addition would overflow,
/// which forces an immediate refresh — much better than crashing.
fn expires_at_from_lifetime(lifetime_secs: u32) -> Instant {
    let clamped = lifetime_secs.min(MAX_GATEWAY_LEASE_SECS);
    Instant::now()
        .checked_add(Duration::from_secs(u64::from(clamped)))
        .unwrap_or_else(Instant::now)
}

/// Sanitise an attacker-controlled string before embedding it in an
/// error variant that may end up in operator logs.
///
/// Gateway-supplied fields (uPnP `errorDescription`, `errorCode`,
/// `NewExternalIPAddress`, etc.) come from packets a hostile LAN
/// device can send to us. Without sanitisation a malicious gateway
/// could embed CR/LF to inject misleading lines into the daemon's
/// log file, or terminal escape sequences to hijack the cursor of
/// an operator tailing the log.
///
/// Policy: truncate to a fixed cap and replace every control
/// character with a single `?` placeholder. The cap (200 bytes) is
/// generous for legitimate error descriptions; nothing useful in a
/// real uPnP fault is longer than this.
fn sanitize_log_excerpt(input: &str) -> String {
    const MAX_LEN: usize = 200;
    let truncated = if input.len() > MAX_LEN {
        // Truncate on a char boundary to keep `String::from_utf8` happy.
        let mut end = MAX_LEN;
        while !input.is_char_boundary(end) {
            end -= 1;
        }
        &input[..end]
    } else {
        input
    };
    truncated
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// XML-text escape — covers the five named entities required by XML 1.0
/// for character data.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Parse a SOAP response, returning either the inner action-response
/// body text (success) or a `PortMapperError::Refused` with the SOAP
/// fault code (failure).
///
/// UPnP IGD SOAP faults follow §2.5.16: a `<s:Fault>` element with a
/// nested `<UPnPError><errorCode>NUM</errorCode></UPnPError>`. The
/// well-known codes for AddPortMapping are 718 (ConflictInMappingEntry),
/// 724 (SamePortValuesRequired), 725 (OnlyPermanentLeasesSupported),
/// 726 (RemoteHostOnlySupportsWildcard), 727 (ExternalPortOnlySupportsWildcard),
/// 728 (NoPortMapsAvailable).
pub fn parse_soap_response(response: &str) -> Result<&str, PortMapperError> {
    // Locate the body. Look for `<s:Body>` or `<SOAP-ENV:Body>` etc.;
    // we treat the first `<Body` opening tag as the body delimiter.
    let body_start = response
        .find("<s:Body")
        .or_else(|| response.find("<SOAP-ENV:Body"))
        .or_else(|| response.find("<Body"))
        .ok_or_else(|| {
            PortMapperError::InvalidResponse("SOAP response missing Body element".to_owned())
        })?;
    let body = &response[body_start..];
    if body.contains("<s:Fault") || body.contains("Fault>") {
        // Try to extract UPnPError/errorCode for a structured message.
        // **Security**: both fields are attacker-controlled (a hostile
        // LAN gateway can put any string here). Sanitise before
        // embedding in an error variant that will end up in operator
        // logs — without this, the gateway can inject CR/LF or
        // terminal escapes that mislead anyone tailing the log.
        let raw_code = extract_inner_text(body, "errorCode")
            .unwrap_or("unknown")
            .trim();
        let raw_description = extract_inner_text(body, "errorDescription")
            .unwrap_or("(no errorDescription)")
            .trim();
        let code = sanitize_log_excerpt(raw_code);
        let description = sanitize_log_excerpt(raw_description);
        return Err(map_upnp_error_code(&code, &description));
    }
    Ok(body)
}

/// Translate an UPnP IGD SOAP error code (string) into a typed
/// `PortMapperError`. Codes from UPnP-gw-WANIPConnection-v1-Service
/// (Table 2-2). Unrecognised codes pass through as `Refused`.
fn map_upnp_error_code(code: &str, description: &str) -> PortMapperError {
    match code {
        "401" => PortMapperError::Refused(format!("uPnP gateway: invalid action ({description})")),
        "402" => {
            PortMapperError::Refused(format!("uPnP gateway: invalid arguments ({description})"))
        }
        "501" => PortMapperError::Refused(format!("uPnP gateway: action failed ({description})")),
        "606" => PortMapperError::Refused(format!(
            "uPnP gateway: action not authorized ({description})"
        )),
        "718" => PortMapperError::Refused(format!(
            "uPnP gateway: conflict — another client already holds this external port ({description})"
        )),
        "724" => PortMapperError::Refused(format!(
            "uPnP gateway: requires same internal and external port ({description})"
        )),
        "725" => PortMapperError::Refused(format!(
            "uPnP gateway: only permanent (zero-lifetime) leases supported ({description})"
        )),
        "726" => PortMapperError::Refused(format!(
            "uPnP gateway: RemoteHost wildcard required ({description})"
        )),
        "727" => PortMapperError::Refused(format!(
            "uPnP gateway: ExternalPort wildcard required ({description})"
        )),
        "728" => PortMapperError::Refused(format!(
            "uPnP gateway: no port maps available ({description})"
        )),
        other => {
            PortMapperError::Refused(format!("uPnP gateway: error code {other} ({description})"))
        }
    }
}

/// Minimal HTTP/1.1 client used by the uPnP code path. Implemented in
/// terms of `std::net::TcpStream` only — no async runtime, no
/// dependency on `hyper`/`reqwest`. Sufficient for short-lived,
/// fixed-format SOAP requests against on-LAN gateways.
///
/// The client does NOT support:
/// * Transfer-Encoding: chunked (well-behaved IGDs emit Content-Length).
/// * Keep-Alive (one request per TCP connection).
/// * TLS (uPnP IGD control points run plain HTTP).
///
/// If a future gateway emits a chunked response we degrade by reading
/// until the connection is closed, which works for one-shot
/// request/response.
pub fn http_get(url: &str, timeout: Duration) -> Result<String, PortMapperError> {
    let (host, port, path) = parse_http_url(url)?;
    let addr_string = format!("{host}:{port}");
    let stream = std::net::TcpStream::connect_timeout(
        &addr_string
            .to_socket_addrs()
            .map_err(|e| PortMapperError::Io(format!("resolving {addr_string}: {e}")))?
            .next()
            .ok_or_else(|| PortMapperError::Io(format!("no address for {addr_string}")))?,
        timeout,
    )
    .map_err(|e| PortMapperError::Io(format!("connecting to {addr_string}: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(PortMapperError::from)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(PortMapperError::from)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\n\
         HOST: {host}:{port}\r\n\
         USER-AGENT: rustynetd/0 UPnP/1.1\r\n\
         CONNECTION: close\r\n\
         \r\n"
    );
    perform_http_round_trip(stream, request.as_bytes())
}

/// HTTP/1.1 POST helper used to issue SOAP actions. Adds `Content-Type:
/// text/xml; charset="utf-8"` and the supplied `SOAPAction` header.
pub fn http_soap_post(
    url: &str,
    soap_action: &str,
    body: &str,
    timeout: Duration,
) -> Result<String, PortMapperError> {
    let (host, port, path) = parse_http_url(url)?;
    let addr_string = format!("{host}:{port}");
    let stream = std::net::TcpStream::connect_timeout(
        &addr_string
            .to_socket_addrs()
            .map_err(|e| PortMapperError::Io(format!("resolving {addr_string}: {e}")))?
            .next()
            .ok_or_else(|| PortMapperError::Io(format!("no address for {addr_string}")))?,
        timeout,
    )
    .map_err(|e| PortMapperError::Io(format!("connecting to {addr_string}: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(PortMapperError::from)?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(PortMapperError::from)?;
    let body_bytes = body.as_bytes();
    let mut request = format!(
        "POST {path} HTTP/1.1\r\n\
         HOST: {host}:{port}\r\n\
         CONTENT-TYPE: text/xml; charset=\"utf-8\"\r\n\
         CONTENT-LENGTH: {}\r\n\
         SOAPACTION: \"{soap_action}\"\r\n\
         USER-AGENT: rustynetd/0 UPnP/1.1\r\n\
         CONNECTION: close\r\n\
         \r\n",
        body_bytes.len()
    )
    .into_bytes();
    request.extend_from_slice(body_bytes);
    perform_http_round_trip(stream, &request)
}

/// Hard cap on the HTTP response size from a uPnP gateway. Device
/// descriptions for consumer IGDs are typically 2–8 KiB and SOAP
/// responses are smaller. A malicious or buggy gateway returning an
/// unbounded body could exhaust daemon memory; cap at 256 KiB so the
/// read-loop bails out cleanly. Practically every real IGD fits in
/// well under this limit (miniupnpd's default is ~16 KiB).
pub const UPNP_HTTP_MAX_BODY_BYTES: usize = 256 * 1024;

fn perform_http_round_trip(
    mut stream: std::net::TcpStream,
    request: &[u8],
) -> Result<String, PortMapperError> {
    use std::io::{Read, Write};
    stream
        .write_all(request)
        .map_err(|e| PortMapperError::Io(format!("HTTP write: {e}")))?;
    // Use `take(UPNP_HTTP_MAX_BODY_BYTES as u64 + 1)` so a body that
    // exceeds the cap reads one extra byte and we can detect it via
    // the length check below — defense against a malicious or buggy
    // gateway sending an unbounded response.
    let mut buf = Vec::with_capacity(4096);
    (&mut stream)
        .take(UPNP_HTTP_MAX_BODY_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| PortMapperError::Io(format!("HTTP read: {e}")))?;
    if buf.len() > UPNP_HTTP_MAX_BODY_BYTES {
        return Err(PortMapperError::InvalidResponse(format!(
            "HTTP response body exceeds {UPNP_HTTP_MAX_BODY_BYTES}-byte cap; refusing to consume"
        )));
    }
    let body = String::from_utf8_lossy(&buf).into_owned();
    let (status, body_text) = split_http_status_and_body(&body)?;
    if !(200..=299).contains(&status) && status != 500 {
        // 500 is acceptable here because SOAP faults are returned with
        // HTTP 500 per W3C SOAP 1.1 §4.4; the SOAP parser will surface
        // the fault details.
        return Err(PortMapperError::Refused(format!(
            "HTTP status {status} from gateway"
        )));
    }
    Ok(body_text.to_owned())
}

/// Parse an HTTP/1.1 response into (status_code, body_text). Headers
/// are not surfaced; the SOAP parser inspects the body string directly.
fn split_http_status_and_body(response: &str) -> Result<(u16, &str), PortMapperError> {
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((response, ""));
    let first_line = head
        .lines()
        .next()
        .ok_or_else(|| PortMapperError::InvalidResponse("empty HTTP response".to_owned()))?;
    // Status line: "HTTP/1.1 200 OK"
    let mut parts = first_line.splitn(3, ' ');
    let _version = parts.next();
    let code = parts.next().unwrap_or("0");
    let status = code.parse::<u16>().map_err(|e| {
        // **Security**: `code` is gateway-controlled. Sanitise before
        // logging via the error-string path.
        PortMapperError::InvalidResponse(format!(
            "could not parse HTTP status code {}: {e}",
            sanitize_log_excerpt(code)
        ))
    })?;
    Ok((status, body))
}

fn parse_http_url(url: &str) -> Result<(String, u16, String), PortMapperError> {
    // **Security**: reject any control character (CR, LF, NUL, tab, etc.)
    // anywhere in the URL. The LOCATION value comes from an untrusted
    // SSDP responder on the LAN, and the URL is interpolated into HTTP
    // headers (`HOST: {host}:{port}`) and request line (`GET {path}`).
    // CR/LF in those positions would let a hostile responder inject
    // headers into our outbound request. Real-world impact is bounded
    // (the responder controls the server anyway) but rejecting the
    // malformed URL closes the injection vector entirely.
    if url.chars().any(|c| c.is_control()) {
        return Err(PortMapperError::InvalidResponse(
            "uPnP URL contains a control character; refusing to issue request".to_owned(),
        ));
    }
    let stripped = url.strip_prefix("http://").ok_or_else(|| {
        PortMapperError::InvalidResponse(format!(
            "uPnP control URLs must be http:// (HTTPS not supported); got {url}"
        ))
    })?;
    let (authority, path) = stripped
        .split_once('/')
        .map(|(a, p)| (a, format!("/{p}")))
        .unwrap_or((stripped, "/".to_owned()));
    let (host, port) = if let Some(idx) = authority.rfind(':') {
        // Care: IPv6 literals like [::1]:80 contain colons inside [...].
        // Cheap heuristic: if authority starts with '[' and the matching
        // bracket exists before idx, treat the bracketed span as host.
        if authority.starts_with('[') {
            if let Some(bracket_end) = authority.find(']') {
                let host = &authority[1..bracket_end];
                let port_str = authority[bracket_end + 1..].trim_start_matches(':');
                let port = port_str.parse::<u16>().unwrap_or(80);
                (host.to_owned(), port)
            } else {
                return Err(PortMapperError::InvalidResponse(format!(
                    "uPnP control URL has unmatched IPv6 bracket: {url}"
                )));
            }
        } else {
            let host = &authority[..idx];
            let port = authority[idx + 1..].parse::<u16>().map_err(|e| {
                PortMapperError::InvalidResponse(format!(
                    "uPnP control URL has invalid port {}: {e}",
                    &authority[idx + 1..]
                ))
            })?;
            (host.to_owned(), port)
        }
    } else {
        (authority.to_owned(), 80u16)
    };
    Ok((host, port, path))
}

/// One device discovered via SSDP M-SEARCH. Carries the LOCATION URL of
/// the device description XML so the caller can fetch it and find the
/// WANIPConnection control URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsdpDiscoveredDevice {
    pub location_url: String,
    pub server: String,
    pub st: String,
}

/// Issue an SSDP M-SEARCH and collect responses for `wait_duration`.
///
/// `bind_address` is the local v4 address to bind to (use
/// `Ipv4Addr::UNSPECIFIED` in production). Returns every distinct
/// LOCATION header observed.
pub fn ssdp_discover_igd(
    bind_address: Ipv4Addr,
    wait_duration: Duration,
) -> Result<Vec<SsdpDiscoveredDevice>, PortMapperError> {
    let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(bind_address), 0))?;
    socket.set_read_timeout(Some(wait_duration))?;
    // Set the multicast TTL low — we only want to reach the on-LAN
    // gateway, never beyond.
    socket
        .set_multicast_ttl_v4(2)
        .map_err(PortMapperError::from)?;
    let multicast_dest = SocketAddr::new(IpAddr::V4(UPNP_SSDP_MULTICAST_IPV4), UPNP_SSDP_PORT);

    // Send one M-SEARCH for IGD v2, then one for v1. Most gateways
    // answer both with the same LOCATION; we send two queries so older
    // IGD:1-only gateways still respond.
    let v2_request = build_msearch_request(UPNP_ST_IGD_V2);
    let v1_request = build_msearch_request(UPNP_ST_IGD_V1);
    socket.send_to(&v2_request, multicast_dest)?;
    socket.send_to(&v1_request, multicast_dest)?;

    ssdp_collect_responses(&socket, wait_duration)
}

fn ssdp_collect_responses(
    socket: &UdpSocket,
    wait_duration: Duration,
) -> Result<Vec<SsdpDiscoveredDevice>, PortMapperError> {
    let mut devices: Vec<SsdpDiscoveredDevice> = Vec::new();
    // **Security**: `Instant::now() + wait_duration` would panic on
    // overflow if a caller passes a huge wait. Use `checked_add` with
    // `Instant::now()` fallback so the loop exits immediately on
    // overflow rather than crashing the daemon.
    let deadline = Instant::now()
        .checked_add(wait_duration)
        .unwrap_or_else(Instant::now);
    let mut buf = [0u8; 2048];
    loop {
        // **Security**: cap the device list size. An attacker on the
        // LAN flooding M-SEARCH responses with distinct LOCATION URLs
        // could otherwise force `discover_one` to spend
        // (per-device HTTP timeout) × N seconds on bogus fetches.
        if devices.len() >= MAX_SSDP_DISCOVERED_DEVICES {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        socket.set_read_timeout(Some(remaining))?;
        match socket.recv_from(&mut buf) {
            Ok((len, _src)) => {
                let response = String::from_utf8_lossy(&buf[..len]);
                let location = match parse_ssdp_location(&response) {
                    Some(loc) => loc,
                    None => continue,
                };
                let st = parse_ssdp_header(&response, "ST").unwrap_or_default();
                let server = parse_ssdp_header(&response, "SERVER").unwrap_or_default();
                if devices.iter().any(|d| d.location_url == location) {
                    continue;
                }
                devices.push(SsdpDiscoveredDevice {
                    location_url: location,
                    server,
                    st,
                });
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                break;
            }
            Err(other) => return Err(PortMapperError::from(other)),
        }
    }
    Ok(devices)
}

fn parse_ssdp_header(response: &str, name: &str) -> Option<String> {
    for line in response.lines().skip(1) {
        if let Some((n, v)) = line.split_once(':')
            && n.trim().eq_ignore_ascii_case(name)
        {
            return Some(v.trim().to_owned());
        }
    }
    None
}

/// uPnP IGD client. Implements the `PortMapper` trait against a
/// known control URL + service type (typically discovered via SSDP +
/// device-description fetch, but constructible directly for tests).
#[derive(Debug, Clone)]
pub struct UpnpIgdClient {
    control_url: String,
    service_type: String,
    timeout: Duration,
}

/// Production HTTP timeout for an on-LAN gateway SOAP call.
const UPNP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl UpnpIgdClient {
    /// Construct from a known control URL + service type. Use this
    /// when discovery has already happened (e.g. from a cached config
    /// or via [`UpnpIgdClient::discover_one`]).
    pub fn new(control_url: String, service_type: String) -> Self {
        Self {
            control_url,
            service_type,
            timeout: UPNP_DEFAULT_TIMEOUT,
        }
    }

    /// Override the HTTP timeout. Tests use a short value so failure
    /// paths trip quickly.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// One-shot discovery: do an SSDP M-SEARCH, fetch the first
    /// gateway's device description, parse for a WANIPConnection
    /// service, and return a ready-to-use client.
    ///
    /// Tries the v2 service first, then v1. The two are
    /// wire-compatible for the AddPortMapping/DeletePortMapping
    /// surface we use.
    pub fn discover_one(
        bind_address: Ipv4Addr,
        wait_duration: Duration,
    ) -> Result<Self, PortMapperError> {
        let devices = ssdp_discover_igd(bind_address, wait_duration)?;
        if devices.is_empty() {
            return Err(PortMapperError::ProtocolNotSupported(
                "no IGD responded to SSDP M-SEARCH within timeout".to_owned(),
            ));
        }
        // Try each discovered device until one yields a parseable
        // device description with a WANIPConnection service.
        for device in &devices {
            let description = match http_get(&device.location_url, UPNP_DEFAULT_TIMEOUT) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let candidates = [
                UPNP_SERVICE_WANIPCONNECTION_V2,
                UPNP_SERVICE_WANIPCONNECTION_V1,
                UPNP_SERVICE_WANPPPCONNECTION_V1,
            ];
            for service_type in candidates {
                if let Some(control_url) = parse_device_description_for_control_url(
                    &description,
                    &[service_type],
                    &device.location_url,
                ) {
                    return Ok(Self::new(control_url, service_type.to_owned()));
                }
            }
        }
        Err(PortMapperError::ProtocolNotSupported(
            "no IGD with WANIPConnection / WANPPPConnection found via SSDP".to_owned(),
        ))
    }

    fn soap_action_header(&self, action: &str) -> String {
        format!("{}#{action}", self.service_type)
    }

    /// Resolve the local IP the kernel routes to the gateway's
    /// control URL. We embed this as `NewInternalClient` in
    /// AddPortMapping so the gateway forwards inbound packets to the
    /// right host.
    ///
    /// We use UDP `connect()` rather than TCP because UDP `connect`
    /// only sets the kernel's per-socket default destination — it does
    /// not require the peer to be listening on the gateway port. The
    /// `local_addr()` after `connect()` returns the source IP the
    /// kernel would actually use to reach the gateway. This avoids
    /// burning an extra TCP accept slot on the gateway.
    fn resolve_local_internal_client(&self) -> Result<IpAddr, PortMapperError> {
        let (host, port, _) = parse_http_url(&self.control_url)?;
        let addr = format!("{host}:{port}")
            .to_socket_addrs()
            .map_err(|e| PortMapperError::Io(format!("resolving control URL: {e}")))?
            .next()
            .ok_or_else(|| {
                PortMapperError::Io("control URL resolved to no addresses".to_owned())
            })?;
        let bind = match addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(addr)?;
        Ok(socket.local_addr()?.ip())
    }
}

impl PortMapper for UpnpIgdClient {
    fn request_udp_mapping(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<MappingLease, PortMapperError> {
        if internal_port == 0 {
            return Err(PortMapperError::InvalidResponse(
                "internal_port must be non-zero for an uPnP mapping request".to_owned(),
            ));
        }
        let internal_client = self.resolve_local_internal_client()?;
        // UPnP IGD §2.4 AddPortMapping argument list (in order).
        let args: [(&str, String); 8] = [
            ("NewRemoteHost", String::new()), // empty = wildcard
            ("NewExternalPort", internal_port.to_string()),
            ("NewProtocol", "UDP".to_owned()),
            ("NewInternalPort", internal_port.to_string()),
            ("NewInternalClient", internal_client.to_string()),
            ("NewEnabled", "1".to_owned()),
            ("NewPortMappingDescription", "rustynetd".to_owned()),
            ("NewLeaseDuration", lease_duration_secs.to_string()),
        ];
        let body = build_soap_envelope(&self.service_type, "AddPortMapping", &args);
        let response = http_soap_post(
            &self.control_url,
            &self.soap_action_header("AddPortMapping"),
            &body,
            self.timeout,
        )?;
        let _body = parse_soap_response(&response)?;
        // Get the external IP via GetExternalIPAddress so we can
        // surface a complete MappingLease. If this fails the mapping
        // is still valid; we propagate the error because the lease's
        // external_addr is part of its identity.
        let external_addr = self.fetch_external_ip()?;
        Ok(MappingLease {
            internal_port,
            external_port: internal_port,
            external_addr,
            protocol: PortMappingProtocol::UpnpIgd,
            expires_at: expires_at_from_lifetime(lease_duration_secs),
            pcp_nonce: None,
        })
    }

    fn refresh_mapping(&self, lease: &MappingLease) -> Result<MappingLease, PortMapperError> {
        // Refresh is just AddPortMapping again with the same external
        // port and a new lease duration.
        let lifetime_secs = lease
            .expires_at
            .saturating_duration_since(Instant::now())
            .as_secs()
            .max(60)
            .try_into()
            .unwrap_or(u32::MAX);
        self.request_udp_mapping(lease.internal_port, lifetime_secs)
    }

    fn release_mapping(&self, lease: &MappingLease) -> Result<(), PortMapperError> {
        // UPnP IGD §2.4 DeletePortMapping arguments.
        let args: [(&str, String); 3] = [
            ("NewRemoteHost", String::new()),
            ("NewExternalPort", lease.external_port.to_string()),
            ("NewProtocol", "UDP".to_owned()),
        ];
        let body = build_soap_envelope(&self.service_type, "DeletePortMapping", &args);
        let response = http_soap_post(
            &self.control_url,
            &self.soap_action_header("DeletePortMapping"),
            &body,
            self.timeout,
        )?;
        let _body = parse_soap_response(&response)?;
        Ok(())
    }
}

impl UpnpIgdClient {
    /// Issue a GetExternalIPAddress SOAP call. Returns the WAN-side
    /// IP the gateway reports.
    pub fn fetch_external_ip(&self) -> Result<IpAddr, PortMapperError> {
        let body = build_soap_envelope(&self.service_type, "GetExternalIPAddress", &[]);
        let response = http_soap_post(
            &self.control_url,
            &self.soap_action_header("GetExternalIPAddress"),
            &body,
            self.timeout,
        )?;
        let body_text = parse_soap_response(&response)?;
        let ip = extract_inner_text(body_text, "NewExternalIPAddress")
            .map(str::trim)
            .ok_or_else(|| {
                PortMapperError::InvalidResponse(
                    "GetExternalIPAddress response did not contain NewExternalIPAddress".to_owned(),
                )
            })?;
        // **Security**: `ip` is gateway-controlled (extracted from the
        // SOAP response body). Sanitise before embedding in the error
        // string so a hostile gateway cannot inject log content via
        // a malformed `<NewExternalIPAddress>` value.
        ip.parse::<IpAddr>().map_err(|e| {
            PortMapperError::InvalidResponse(format!(
                "could not parse external IP {}: {e}",
                sanitize_log_excerpt(ip)
            ))
        })
    }
}

// ---- Daemon-side supervisor + mode flag ----

/// Operator-selectable port-mapping mode. Surfaced as the
/// `--port-mapping-mode={auto,keepalive,disabled}` daemon CLI flag.
///
/// * `Auto` — probe the gateway for PCP / NAT-PMP / uPnP on bring-up.
///   Use the granted lease when one of them succeeds; fall back to
///   keepalive when none do.
/// * `Keepalive` — skip the probe entirely and rely on the
///   outbound-keepalive trick (decision 2.3 in the dataplane plan):
///   WireGuard's PersistentKeepalive keeps a NAT mapping open
///   without any router cooperation. The right default for a home
///   server behind a cooperative cone NAT.
/// * `Disabled` — do not request a mapping and do not run keepalives.
///   Suitable for hosts with an explicit static port-forward or a
///   public IP address; running the probe would just waste a startup
///   round-trip.
///
/// `Keepalive` is the strict-secure-practical default: it works on
/// every cooperative cone NAT without any router probing. Operators
/// who want the probe layer to lift pair-success from ~70% to ~95%
/// switch to `Auto` explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PortMappingMode {
    Auto,
    #[default]
    Keepalive,
    Disabled,
}

impl PortMappingMode {
    /// Stable string label for the CLI flag, environment variable
    /// reporting, and the daemon's structured logs.
    pub const fn label(self) -> &'static str {
        match self {
            PortMappingMode::Auto => "auto",
            PortMappingMode::Keepalive => "keepalive",
            PortMappingMode::Disabled => "disabled",
        }
    }

    /// Parse a CLI/config-file value. Accepts the exact labels emitted
    /// by `label()`; anything else returns an error string suitable for
    /// the daemon's CLI parser to surface verbatim.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(PortMappingMode::Auto),
            "keepalive" => Ok(PortMappingMode::Keepalive),
            "disabled" => Ok(PortMappingMode::Disabled),
            other => Err(format!(
                "invalid port-mapping-mode value {other:?}: expected auto, keepalive, or disabled"
            )),
        }
    }
}

/// Outcome of the daemon-side bring-up call. Carries enough info for
/// structured logging and for the refresh loop to act on it.
#[derive(Debug)]
pub enum SupervisorBringUp {
    /// The probe succeeded and we hold a lease.
    Mapped { lease: MappingLease },
    /// The probe ran but no protocol responded — fall back to the
    /// outbound-keepalive trick. WireGuard's PersistentKeepalive
    /// stays scheduled regardless of port-mapping; the daemon's
    /// logging should surface `keepalive_fallback` so operators see
    /// the degraded path.
    KeepaliveFallback { reason: &'static str },
    /// Auto probing was disabled by configuration; the daemon should
    /// behave exactly as if no port-mapping had been attempted.
    Skipped { reason: &'static str },
}

/// Single-shot port-mapping bring-up, intended to be called from the
/// daemon's startup path. Encapsulates: gateway detection → probe
/// orchestrator → mode-aware classification of the outcome.
///
/// The supervisor does NOT run a refresh loop itself; the daemon owns
/// the timer infrastructure. Callers should reach back via
/// [`PortMappingSupervisor::refresh_existing_lease`] when the lease's
/// `expires_at - now()` falls below half the lifetime (the convention
/// recommended by both RFC 6886 and RFC 6887).
pub struct PortMappingSupervisor {
    mode: PortMappingMode,
    gateway_override: Option<IpAddr>,
    upnp_enabled: bool,
    upnp_bind_address: Ipv4Addr,
    upnp_wait: Duration,
}

impl PortMappingSupervisor {
    /// Construct a supervisor with the given mode and no overrides.
    /// uPnP is OFF by default; enable it via
    /// [`PortMappingSupervisor::with_upnp_enabled`] when the operator
    /// has opted in to multicast SSDP discovery.
    pub fn new(mode: PortMappingMode) -> Self {
        Self {
            mode,
            gateway_override: None,
            upnp_enabled: false,
            upnp_bind_address: Ipv4Addr::UNSPECIFIED,
            upnp_wait: UPNP_SSDP_DEFAULT_DISCOVERY_TIMEOUT,
        }
    }

    /// Override the gateway. Used on Windows (where autodetection is
    /// not yet implemented) and in tests pointing at an in-process
    /// fake gateway.
    #[must_use]
    pub fn with_gateway(mut self, gateway: IpAddr) -> Self {
        self.gateway_override = Some(gateway);
        self
    }

    /// Opt in to uPnP IGD as the third-tier probe.
    #[must_use]
    pub fn with_upnp_enabled(mut self, bind_address: Ipv4Addr, wait: Duration) -> Self {
        self.upnp_enabled = true;
        self.upnp_bind_address = bind_address;
        self.upnp_wait = wait;
        self
    }

    /// Perform the one-shot bring-up.
    pub fn bring_up(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<SupervisorBringUp, PortMapperError> {
        match self.mode {
            PortMappingMode::Disabled => Ok(SupervisorBringUp::Skipped {
                reason: "port-mapping-mode=disabled",
            }),
            PortMappingMode::Keepalive => Ok(SupervisorBringUp::Skipped {
                reason: "port-mapping-mode=keepalive (no probe; keepalive path active)",
            }),
            PortMappingMode::Auto => {
                let gateway = match self.gateway_override {
                    Some(addr) => addr,
                    None => match detect_default_gateway() {
                        Ok(addr) => addr,
                        Err(_) => {
                            // No autodetected gateway. We can still
                            // try uPnP (which uses multicast and does
                            // not need a gateway IP). If uPnP is
                            // disabled, fall back to keepalive.
                            if self.upnp_enabled {
                                return self.try_upnp_only(internal_port, lease_duration_secs);
                            }
                            return Ok(SupervisorBringUp::KeepaliveFallback {
                                reason: "default gateway not detected; falling back to keepalive",
                            });
                        }
                    },
                };
                let mut probe = PortMappingProbe::new(gateway);
                if self.upnp_enabled {
                    probe = probe.with_upnp_enabled(self.upnp_bind_address, self.upnp_wait);
                }
                match probe.probe_udp_mapping(internal_port, lease_duration_secs)? {
                    ProbeOutcome::Mapped(lease) => Ok(SupervisorBringUp::Mapped { lease }),
                    ProbeOutcome::NoGatewaySupport => Ok(SupervisorBringUp::KeepaliveFallback {
                        reason: "no gateway protocol responded; falling back to keepalive",
                    }),
                }
            }
        }
    }

    fn try_upnp_only(
        &self,
        internal_port: u16,
        lease_duration_secs: u32,
    ) -> Result<SupervisorBringUp, PortMapperError> {
        match UpnpIgdClient::discover_one(self.upnp_bind_address, self.upnp_wait) {
            Ok(client) => match client.request_udp_mapping(internal_port, lease_duration_secs) {
                Ok(lease) => Ok(SupervisorBringUp::Mapped { lease }),
                Err(PortMapperError::ProtocolNotSupported(_)) | Err(PortMapperError::Timeout) => {
                    Ok(SupervisorBringUp::KeepaliveFallback {
                        reason: "uPnP gateway did not honour the request; falling back to keepalive",
                    })
                }
                Err(other) => Err(other),
            },
            Err(PortMapperError::ProtocolNotSupported(_)) | Err(PortMapperError::Timeout) => {
                Ok(SupervisorBringUp::KeepaliveFallback {
                    reason: "no uPnP IGD responded; falling back to keepalive",
                })
            }
            Err(other) => Err(other),
        }
    }

    /// Refresh an existing lease in place. Returns a fresh lease with
    /// an updated `expires_at`. The daemon should call this when
    /// `lease.expires_at - now()` falls below ~half the lifetime.
    pub fn refresh_existing_lease(
        lease: &MappingLease,
        gateway_for_pcp_natpmp: Option<IpAddr>,
        upnp_control_url: Option<&str>,
    ) -> Result<MappingLease, PortMapperError> {
        match lease.protocol {
            PortMappingProtocol::Pcp => {
                let gateway = gateway_for_pcp_natpmp.ok_or_else(|| {
                    PortMapperError::NoGateway(
                        "PCP refresh needs a gateway IP; supply gateway_for_pcp_natpmp".to_owned(),
                    )
                })?;
                PcpClient::new(gateway).refresh_mapping(lease)
            }
            PortMappingProtocol::NatPmp => {
                let gateway = gateway_for_pcp_natpmp.ok_or_else(|| {
                    PortMapperError::NoGateway(
                        "NAT-PMP refresh needs a gateway IP; supply gateway_for_pcp_natpmp"
                            .to_owned(),
                    )
                })?;
                let v4 = match gateway {
                    IpAddr::V4(v4) => v4,
                    IpAddr::V6(_) => {
                        return Err(PortMapperError::ProtocolNotSupported(
                            "NAT-PMP requires an IPv4 gateway".to_owned(),
                        ));
                    }
                };
                NatPmpClient::new(v4).refresh_mapping(lease)
            }
            PortMappingProtocol::UpnpIgd => {
                let control_url = upnp_control_url.ok_or_else(|| {
                    PortMapperError::InvalidResponse(
                        "uPnP refresh needs the original controlURL; supply upnp_control_url"
                            .to_owned(),
                    )
                })?;
                UpnpIgdClient::new(
                    control_url.to_owned(),
                    UPNP_SERVICE_WANIPCONNECTION_V1.to_owned(),
                )
                .refresh_mapping(lease)
            }
        }
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
    /// If `Some`, the probe will attempt uPnP IGD as a third tier
    /// after PCP and NAT-PMP both fall through. Discovery is local-LAN
    /// multicast — the probe will issue SSDP M-SEARCH bound to the
    /// host's default interface. Set via
    /// [`PortMappingProbe::with_upnp_enabled`].
    upnp_bind_address: Option<Ipv4Addr>,
    upnp_wait: Duration,
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
            upnp_bind_address: None,
            upnp_wait: UPNP_SSDP_DEFAULT_DISCOVERY_TIMEOUT,
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
            upnp_bind_address: None,
            upnp_wait: UPNP_SSDP_DEFAULT_DISCOVERY_TIMEOUT,
        }
    }

    /// Enable uPnP IGD as a third-tier fallback after PCP and NAT-PMP.
    /// `bind_address` should be a local IPv4 the host can use to send
    /// the SSDP M-SEARCH multicast on (usually `Ipv4Addr::UNSPECIFIED`).
    /// `wait` is how long to listen for SSDP responses; UPnP DA §1.3.2
    /// says devices reply within MX seconds (default 2 s for our
    /// probe) — wait_duration should be ≥ MX + a small slack.
    #[must_use]
    pub fn with_upnp_enabled(mut self, bind_address: Ipv4Addr, wait: Duration) -> Self {
        self.upnp_bind_address = Some(bind_address);
        self.upnp_wait = wait;
        self
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
        // the only available protocol at the IANA-5351 tier.
        if self.gateway.ip().is_ipv4() {
            let nat_pmp = NatPmpClient::new_for_test(self.gateway)
                .with_initial_timeout(self.initial_timeout)
                .with_max_attempts(self.max_attempts);
            match nat_pmp.request_udp_mapping(internal_port, lease_duration_secs) {
                Ok(lease) => return Ok(ProbeOutcome::Mapped(lease)),
                Err(PortMapperError::ProtocolNotSupported(_)) | Err(PortMapperError::Timeout) => {
                    // fall through to uPnP if enabled.
                }
                Err(other) => return Err(other),
            }
        }

        // ---- uPnP IGD third (if enabled) ----
        if let Some(bind) = self.upnp_bind_address {
            match UpnpIgdClient::discover_one(bind, self.upnp_wait) {
                Ok(client) => {
                    match client.request_udp_mapping(internal_port, lease_duration_secs) {
                        Ok(lease) => return Ok(ProbeOutcome::Mapped(lease)),
                        Err(PortMapperError::ProtocolNotSupported(_))
                        | Err(PortMapperError::Timeout) => {
                            return Ok(ProbeOutcome::NoGatewaySupport);
                        }
                        Err(other) => return Err(other),
                    }
                }
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
    fn ssdp_header_lookup_case_insensitive_skips_first_line() {
        let response = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLocation: http://192.168.1.1:5000/desc.xml\r\n";
        // Case-insensitive name match; value is trimmed and keeps its own colons
        // (split_once on the first ':').
        assert_eq!(
            parse_ssdp_header(response, "location").as_deref(),
            Some("http://192.168.1.1:5000/desc.xml")
        );
        assert_eq!(
            parse_ssdp_header(response, "CACHE-CONTROL").as_deref(),
            Some("max-age=1800")
        );
        // Missing header -> None.
        assert_eq!(parse_ssdp_header(response, "SERVER"), None);
        // The first line (SSDP status/request line) is always skipped, so a
        // header sitting on line 0 is never matched.
        assert_eq!(parse_ssdp_header("FOO: bar\r\nBAZ: qux", "FOO"), None);
        assert_eq!(
            parse_ssdp_header("FOO: bar\r\nBAZ: qux", "BAZ").as_deref(),
            Some("qux")
        );
        assert_eq!(parse_ssdp_header("", "location"), None);
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
    fn decode_map_response_reject_paths_and_valid_decode() {
        let nonce: [u8; PCP_NONCE_LEN] = [0xAB; PCP_NONCE_LEN];
        let internal_port: u16 = 51820;

        // A well-formed 60-byte PCP MAP success response for `internal_port`.
        let build_valid = || {
            let mut buf = [0u8; PCP_MAP_RESPONSE_LEN];
            buf[0] = PCP_VERSION;
            buf[1] = PCP_R_BIT_RESPONSE_MASK | PCP_OPCODE_MAP;
            buf[3] = PCP_RESULT_SUCCESS;
            buf[4..8].copy_from_slice(&7200u32.to_be_bytes()); // lifetime
            buf[24..36].copy_from_slice(&nonce); // echoed mapping nonce
            buf[36] = PCP_PROTOCOL_UDP;
            buf[40..42].copy_from_slice(&internal_port.to_be_bytes()); // echoed internal port
            buf[42..44].copy_from_slice(&53420u16.to_be_bytes()); // external port
            // External address ::ffff:198.51.100.7 -> IPv4 198.51.100.7.
            buf[54] = 0xff;
            buf[55] = 0xff;
            buf[56..60].copy_from_slice(&[198, 51, 100, 7]);
            buf
        };

        // Happy path decodes all fields.
        let ok = PcpClient::decode_map_response(&build_valid(), nonce, internal_port).unwrap();
        assert_eq!(ok.external_port, 53420);
        assert_eq!(ok.granted_lifetime_secs, 7200);
        assert_eq!(ok.external_addr, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)));

        // Each byte-level reject path fails closed.
        assert!(
            PcpClient::decode_map_response(
                &[0u8; PCP_MAP_RESPONSE_LEN - 1],
                nonce,
                internal_port
            )
            .is_err(),
            "short buffer"
        );
        let mut cases: Vec<[u8; PCP_MAP_RESPONSE_LEN]> = Vec::new();
        {
            let mut b = build_valid();
            b[0] = PCP_VERSION + 1; // wrong version
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[1] = PCP_OPCODE_MAP; // R-bit not set (looks like a request)
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[1] = PCP_R_BIT_RESPONSE_MASK | 2; // wrong opcode
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[3] = 2; // non-success result code
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[24] ^= 0xFF; // nonce mismatch
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[36] = 6; // protocol mismatch (TCP, not UDP)
            cases.push(b);
        }
        {
            let mut b = build_valid();
            b[40..42].copy_from_slice(&9999u16.to_be_bytes()); // echoed internal-port mismatch
            cases.push(b);
        }
        for (i, b) in cases.iter().enumerate() {
            assert!(
                PcpClient::decode_map_response(b, nonce, internal_port).is_err(),
                "reject case {i} should fail"
            );
        }
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

    // ---- Default-gateway parser tests ----

    #[test]
    fn parse_hex_le_ipv4_decodes_little_endian_correctly() {
        // 0x0102030A in little-endian byte order = bytes 0x0A, 0x03,
        // 0x02, 0x01 = 10.3.2.1.
        assert_eq!(
            parse_hex_le_ipv4("0102030A").expect("valid hex"),
            Ipv4Addr::new(10, 3, 2, 1)
        );
        // 0x0101A8C0 = bytes 0xC0, 0xA8, 0x01, 0x01 = 192.168.1.1.
        assert_eq!(
            parse_hex_le_ipv4("0101A8C0").expect("valid hex"),
            Ipv4Addr::new(192, 168, 1, 1)
        );
        // All zeros = 0.0.0.0 (default route destination).
        assert_eq!(
            parse_hex_le_ipv4("00000000").expect("valid hex"),
            Ipv4Addr::UNSPECIFIED
        );
    }

    #[test]
    fn parse_hex_le_ipv4_rejects_wrong_length_and_non_hex() {
        assert!(
            parse_hex_le_ipv4("12345").is_err(),
            "short string must be rejected"
        );
        assert!(
            parse_hex_le_ipv4("ZZZZZZZZ").is_err(),
            "non-hex characters must be rejected"
        );
    }

    #[test]
    fn parse_proc_net_route_finds_default_route_via_destination_zero() {
        // Realistic /proc/net/route sample — two routes, the first is
        // the default. Real entries are tab-separated.
        let sample = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
ens3\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0
ens3\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";
        let gateway = parse_proc_net_route_for_default(sample).expect("default route found");
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_proc_net_route_returns_no_gateway_when_default_missing() {
        // No row with destination=00000000 — every interface is on
        // its directly-attached subnet only, no default route.
        let sample = "\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT
ens3\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0
";
        let err = parse_proc_net_route_for_default(sample)
            .expect_err("must error when default route is absent");
        assert!(
            matches!(err, PortMapperError::NoGateway(ref msg) if msg.contains("no default route")),
            "expected NoGateway error mentioning the missing default route, got: {err:?}"
        );
    }

    #[test]
    fn parse_proc_net_route_handles_blank_and_short_lines_without_panic() {
        // Lines with <3 fields must not panic.
        let sample = "\
Iface\tDestination\tGateway\tFlags
\t
\t\t
ens3\t00000000\t0101A8C0\t0003
";
        let gateway = parse_proc_net_route_for_default(sample).expect("default route found");
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_route_get_default_output_finds_ipv4_gateway() {
        let sample = "\
   route to: default
destination: default
       mask: default
    gateway: 192.168.1.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONED>
";
        let gateway = parse_route_get_default_output(sample).expect("parses gateway line");
        assert_eq!(gateway, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parse_route_get_default_output_finds_ipv6_gateway() {
        // macOS surfaces IPv6 gateways the same way; the parser must
        // pass-through to IpAddr::parse and accept v6 too.
        let sample = "\
   route to: default
destination: default
       mask: default
    gateway: fe80::1%en0
";
        // fe80::1%en0 — note the scope-id suffix is not parseable by
        // std::net::IpAddr. The parser surfaces a NoGateway error
        // here; the daemon will surface a clear diagnostic. We pin
        // this behaviour so any change to scope-id handling trips
        // this test rather than silently regressing.
        let err = parse_route_get_default_output(sample)
            .expect_err("scope-id-suffixed IPv6 must surface a clear parser error");
        assert!(
            matches!(err, PortMapperError::NoGateway(ref msg) if msg.contains("parse gateway")),
            "expected NoGateway with parser context, got: {err:?}"
        );

        // Without the scope-id suffix, the parse succeeds.
        let sample_no_scope = "    gateway: 2001:db8::1\n";
        let gateway = parse_route_get_default_output(sample_no_scope).expect("v6 parses");
        match gateway {
            IpAddr::V6(_) => {}
            other => panic!("expected IpAddr::V6, got {other:?}"),
        }
    }

    #[test]
    fn parse_route_get_default_output_returns_no_gateway_when_line_missing() {
        // Output that does not contain a `gateway:` line — e.g. host
        // has no default route, or output format changed in a new
        // macOS version.
        let sample = "\
   route to: default
destination: default
       mask: default
  interface: en0
";
        let err =
            parse_route_get_default_output(sample).expect_err("absent gateway line must error");
        assert!(
            matches!(err, PortMapperError::NoGateway(ref msg) if msg.contains("`gateway:` line")),
            "expected NoGateway with diagnostic message, got: {err:?}"
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_detect_default_gateway_returns_some() {
        let gateway = detect_default_gateway().expect("Windows host should have a default gateway");
        assert!(gateway.is_ipv4(), "NAT-PMP/uPnP gateway should be IPv4");
    }

    // ---- uPnP IGD parser / wire-format tests ----

    #[test]
    fn upnp_msearch_request_has_required_headers_and_crlf() {
        let buf = build_msearch_request(UPNP_ST_IGD_V2);
        let text = std::str::from_utf8(&buf).expect("ascii");
        assert!(text.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(text.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(text.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(text.contains("MX: 2\r\n"));
        assert!(text.contains(&format!("ST: {UPNP_ST_IGD_V2}\r\n")));
        assert!(text.ends_with("\r\n\r\n"), "M-SEARCH ends with blank line");
    }

    #[test]
    fn upnp_parse_ssdp_location_is_case_insensitive() {
        let response = "HTTP/1.1 200 OK\r\n\
                        CACHE-CONTROL: max-age=120\r\n\
                        location: http://192.168.1.1:49152/rootDesc.xml\r\n\
                        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                        \r\n";
        let loc = parse_ssdp_location(response).expect("location parsed");
        assert_eq!(loc, "http://192.168.1.1:49152/rootDesc.xml");
    }

    #[test]
    fn upnp_parse_ssdp_location_returns_none_when_absent() {
        let response = "HTTP/1.1 200 OK\r\n\
                        CACHE-CONTROL: max-age=120\r\n\
                        ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
                        \r\n";
        assert!(parse_ssdp_location(response).is_none());
    }

    fn sample_igd_device_description() -> &'static str {
        // Hand-trimmed example matching the shape every consumer
        // IGD emits — root InternetGatewayDevice → WANDevice →
        // WANConnectionDevice → WANIPConnection service.
        r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>HomeRouter</friendlyName>
    <deviceList>
      <device>
        <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
        <serviceList>
          <service>
            <serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
            <controlURL>/upnp/control/WANCommonIFC1</controlURL>
          </service>
        </serviceList>
        <deviceList>
          <device>
            <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
                <controlURL>/upnp/control/WANIPConn1</controlURL>
                <eventSubURL>/upnp/event/WANIPConn1</eventSubURL>
                <SCPDURL>/upnp/WANIPConn1.xml</SCPDURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>"#
    }

    #[test]
    fn upnp_parse_device_description_returns_wan_ip_connection_control_url() {
        let url = parse_device_description_for_control_url(
            sample_igd_device_description(),
            &[UPNP_SERVICE_WANIPCONNECTION_V1],
            "http://192.168.1.1:49152/rootDesc.xml",
        )
        .expect("WANIPConnection control URL found");
        // Relative paths must be resolved against the LOCATION's
        // scheme://host[:port] prefix per UPnP DA §1.6.
        assert_eq!(url, "http://192.168.1.1:49152/upnp/control/WANIPConn1");
    }

    #[test]
    fn upnp_parse_device_description_passes_through_absolute_control_url() {
        let xml = r#"<service>
          <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
          <controlURL>http://gateway.local:49152/Control</controlURL>
        </service>"#;
        let url = parse_device_description_for_control_url(
            xml,
            &[UPNP_SERVICE_WANIPCONNECTION_V1],
            "http://192.168.1.1:49152/rootDesc.xml",
        )
        .expect("absolute URL kept verbatim");
        assert_eq!(url, "http://gateway.local:49152/Control");
    }

    #[test]
    fn upnp_parse_device_description_skips_non_matching_services() {
        // If we ask for WANIPConnection:2 in a doc that only exposes
        // WANIPConnection:1, we must get None — not a false match on
        // the v1 service URL.
        let url = parse_device_description_for_control_url(
            sample_igd_device_description(),
            &[UPNP_SERVICE_WANIPCONNECTION_V2],
            "http://192.168.1.1:49152/rootDesc.xml",
        );
        assert!(url.is_none(), "v2 must not match v1");
    }

    #[test]
    fn upnp_build_soap_envelope_pins_namespaces_and_action() {
        let body = build_soap_envelope(
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "AddPortMapping",
            &[
                ("NewRemoteHost", String::new()),
                ("NewExternalPort", "51820".to_owned()),
                ("NewProtocol", "UDP".to_owned()),
            ],
        );
        assert!(body.contains("xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""));
        assert!(body.contains("<s:Body>"));
        assert!(body.contains(
            "<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"
        ));
        assert!(body.contains("<NewRemoteHost></NewRemoteHost>"));
        assert!(body.contains("<NewExternalPort>51820</NewExternalPort>"));
        assert!(body.contains("<NewProtocol>UDP</NewProtocol>"));
        assert!(body.contains("</u:AddPortMapping>"));
        assert!(body.contains("</s:Envelope>"));
    }

    #[test]
    fn upnp_soap_envelope_xml_escapes_special_characters() {
        let body = build_soap_envelope("urn:test", "X", &[("Field", "a&b<c>d\"e'f".to_owned())]);
        assert!(body.contains("a&amp;b&lt;c&gt;d&quot;e&apos;f"));
    }

    #[test]
    fn upnp_http_round_trip_rejects_oversize_response_body() {
        // Security pin: a malicious or buggy gateway returning an
        // unbounded body cannot exhaust daemon memory. The HTTP
        // client caps at UPNP_HTTP_MAX_BODY_BYTES and surfaces
        // InvalidResponse when the cap is breached.
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind oversize server");
        let addr = listener.local_addr().expect("local_addr");
        let body_bytes = UPNP_HTTP_MAX_BODY_BYTES + 32;
        let handle = std::thread::spawn(move || {
            let (mut stream, _peer) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            let mut buf = vec![0u8; 4096];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {body_bytes}\r\n\r\n"
            );
            let _ = stream.write_all(header.as_bytes());
            let payload = vec![b'X'; body_bytes];
            let _ = stream.write_all(&payload);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        let url = format!("http://{addr}/x");
        let err =
            http_get(&url, Duration::from_secs(3)).expect_err("oversize response must be rejected");
        match err {
            PortMapperError::InvalidResponse(msg) => {
                assert!(msg.contains("cap"), "expected cap diagnostic, got: {msg}")
            }
            other => panic!("expected InvalidResponse(cap...), got: {other:?}"),
        }
        handle.join().ok();
    }

    #[test]
    fn mapping_lease_debug_output_redacts_pcp_nonce() {
        // Security pin: a PCP lease accidentally logged with `{:?}`
        // MUST NOT emit the 12-byte Mapping Nonce — that nonce is
        // the credential for tearing the mapping down (RFC 6887 §15).
        let lease = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            protocol: PortMappingProtocol::Pcp,
            expires_at: Instant::now() + Duration::from_secs(1800),
            pcp_nonce: Some([0xAB; PCP_NONCE_LEN]),
        };
        let debug_string = format!("{lease:?}");
        assert!(
            debug_string.contains("<redacted>"),
            "Debug output must redact the PCP nonce; got: {debug_string}"
        );
        // The hex of the nonce must not appear in the debug output.
        assert!(
            !debug_string.contains("ab, ab, ab") && !debug_string.to_lowercase().contains("0xab"),
            "Debug output must NOT leak the nonce bytes; got: {debug_string}"
        );
    }

    #[test]
    fn sanitize_log_excerpt_replaces_control_chars_and_caps_length() {
        // CR/LF mapped to `?` so a hostile gateway cannot inject log
        // lines via SOAP fault descriptions.
        let evil = "Bad\r\nFAKE: log line";
        let clean = sanitize_log_excerpt(evil);
        assert!(!clean.contains('\r'));
        assert!(!clean.contains('\n'));
        assert_eq!(clean, "Bad??FAKE: log line");

        // Terminal escape sequence redacted.
        let escape = "Hello\x1b[2JWorld";
        let clean = sanitize_log_excerpt(escape);
        assert!(!clean.contains('\x1b'));

        // Length cap.
        let huge = "x".repeat(1000);
        let clean = sanitize_log_excerpt(&huge);
        assert!(
            clean.len() <= 200,
            "sanitiser must cap length; got {}",
            clean.len()
        );

        // ASCII printable passes through unchanged within the cap.
        let plain = "OnlyPermanentLeasesSupported";
        assert_eq!(sanitize_log_excerpt(plain), plain);
    }

    #[test]
    fn upnp_soap_fault_with_injected_newlines_in_description_is_sanitised() {
        // Pin: a hostile gateway response that embeds CR/LF in the
        // SOAP `<errorDescription>` MUST NOT cause those characters
        // to appear verbatim in the error message we propagate to
        // operator logs.
        let resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/xml\r\n\r\n\
            <?xml version=\"1.0\"?>\
            <s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">\
            <s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>\
            <detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">\
            <errorCode>501</errorCode>\
            <errorDescription>Boom\r\nFAKE: log line\x1b[2J</errorDescription>\
            </UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        let err = parse_soap_response(resp).expect_err("fault should be surfaced");
        let msg = err.to_string();
        assert!(
            !msg.contains('\r') && !msg.contains('\n') && !msg.contains('\x1b'),
            "sanitisation must strip CR/LF/ESC from gateway-controlled error description; got: {msg:?}"
        );
    }

    #[test]
    fn ssdp_collect_responses_caps_devices_at_max_to_block_flood_dos() {
        // Security pin: a hostile LAN host could flood SSDP M-SEARCH
        // responses with many distinct LOCATION URLs. Without the
        // cap, the subsequent discover_one would spend
        // (HTTP-timeout) × N seconds on bogus device-description
        // fetches. The cap (`MAX_SSDP_DISCOVERED_DEVICES`) bounds
        // the work.
        let listener = UdpSocket::bind("127.0.0.1:0").expect("bind probe gateway scout");
        let recv_addr = listener.local_addr().expect("local_addr");

        // Spawn a "hostile" sender that floods many distinct
        // responses at the probe socket.
        let flood_count = MAX_SSDP_DISCOVERED_DEVICES + 10;
        let sender_handle = std::thread::spawn(move || {
            let sender = UdpSocket::bind("127.0.0.1:0").expect("bind hostile sender");
            for i in 0..flood_count {
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.{}/rootDesc.xml\r\n\r\n",
                    i + 1
                );
                let _ = sender.send_to(resp.as_bytes(), recv_addr);
            }
        });

        let devices = ssdp_collect_responses(&listener, Duration::from_millis(500))
            .expect("collect succeeds");
        assert!(
            devices.len() <= MAX_SSDP_DISCOVERED_DEVICES,
            "device list must be capped at {}; got {}",
            MAX_SSDP_DISCOVERED_DEVICES,
            devices.len()
        );

        sender_handle.join().ok();
    }

    #[test]
    fn expires_at_from_lifetime_clamps_huge_values_and_never_panics() {
        // Security pin: a hostile gateway returning `granted_lifetime
        // = u32::MAX` would, before the clamp, compute
        // `Instant::now() + Duration::from_secs(4_294_967_295)` which
        // could panic on platforms where the Instant representation
        // cannot hold the result. The clamp at MAX_GATEWAY_LEASE_SECS
        // keeps the arithmetic safely inside the representable range.
        let now = Instant::now();
        let huge = expires_at_from_lifetime(u32::MAX);
        let zero = expires_at_from_lifetime(0);
        let small = expires_at_from_lifetime(60);

        // Huge clamps to MAX_GATEWAY_LEASE_SECS (24h).
        let huge_dur = huge.saturating_duration_since(now);
        assert!(
            huge_dur.as_secs() <= u64::from(MAX_GATEWAY_LEASE_SECS) + 1,
            "u32::MAX lifetime must clamp to MAX_GATEWAY_LEASE_SECS; got {}s",
            huge_dur.as_secs()
        );
        // Zero is `now` (or a few microseconds later from the
        // checked_add side-trip).
        assert!(zero.saturating_duration_since(now) <= Duration::from_millis(50));
        // Small passes through.
        let small_dur = small.saturating_duration_since(now);
        assert!(small_dur.as_secs() >= 59 && small_dur.as_secs() <= 61);
    }

    #[test]
    fn upnp_parse_http_url_rejects_url_with_control_characters() {
        // Security pin: a hostile SSDP responder claiming to be the
        // IGD could hand us a LOCATION URL with embedded CR/LF to
        // inject extra HTTP headers into our outbound request. The
        // parser must refuse the URL entirely.
        let cr_lf = "http://gateway.local:49152/desc\r\nX-Injected: evil";
        let err = parse_http_url(cr_lf).expect_err("control chars must be rejected");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("control")),
            "expected InvalidResponse with 'control' diagnostic, got: {err:?}"
        );

        let null_byte = "http://gateway.local/\0";
        assert!(parse_http_url(null_byte).is_err(), "null byte rejected");

        let tab = "http://gateway.local/a\tb";
        assert!(parse_http_url(tab).is_err(), "tab rejected");
    }

    #[test]
    fn nat_pmp_round_trip_uses_connect_to_filter_wrong_source_packets() {
        // Security pin: the NAT-PMP client uses UDP `connect()` so the
        // kernel filters incoming datagrams to only those from the
        // configured gateway. An attacker on the LAN sending spoofed
        // NAT-PMP packets from a wrong source IP cannot DoS the probe.
        //
        // We can't easily test the kernel filter directly. Instead,
        // pin the wire shape: the client must send a request on a
        // connected socket (so `set_read_timeout` + `recv` is enough;
        // no `recv_from`). We assert this by verifying that the
        // existing happy-path test against a fake gateway still
        // works (proves connect+send+recv flow is right) and that
        // packets from a non-gateway source are not delivered to us.
        let (client, gateway_addr) = make_test_client();
        let (_handle, _rx) = spawn_fake_gateway(
            gateway_addr,
            Ipv4Addr::new(198, 51, 100, 7),
            54321,
            7200,
            NAT_PMP_RESULT_SUCCESS,
            2,
        );
        // Send a spoof packet from a different loopback port BEFORE
        // the legitimate gateway responds — when the client uses
        // connect(), the kernel discards this packet.
        let spoof = UdpSocket::bind("127.0.0.1:0").expect("bind spoof");
        let mut spoof_resp = vec![0u8; 16];
        spoof_resp[0] = NAT_PMP_VERSION;
        spoof_resp[1] = NAT_PMP_OP_RESPONSE_BIT | NAT_PMP_OP_MAP_UDP;
        // bogus result code so the spoof would be detectable if the
        // client accepted it.
        spoof_resp[2..4].copy_from_slice(&255u16.to_be_bytes());
        // We can't know the client's ephemeral port without
        // observation; this test is mostly here as a structural pin.
        let _ = spoof.send_to(&spoof_resp, "127.0.0.1:0");

        let lease = client
            .request_udp_mapping(51820, 3600)
            .expect("client gets a clean lease, not the spoof");
        assert_eq!(lease.external_port, 54321);
    }

    #[test]
    fn upnp_parse_soap_response_extracts_action_body() {
        let resp = r#"HTTP/1.1 200 OK
Content-Type: text/xml

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
</u:AddPortMappingResponse>
</s:Body>
</s:Envelope>"#;
        let body = parse_soap_response(resp).expect("success body");
        assert!(body.contains("AddPortMappingResponse"));
    }

    #[test]
    fn upnp_parse_soap_response_returns_typed_error_for_conflict() {
        // UPnP IGD §2.4.16 ConflictInMappingEntry = 718.
        let resp = r#"HTTP/1.1 500 Internal Server Error
Content-Type: text/xml

<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<s:Fault>
<faultcode>s:Client</faultcode>
<faultstring>UPnPError</faultstring>
<detail>
<UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
<errorCode>718</errorCode>
<errorDescription>ConflictInMappingEntry</errorDescription>
</UPnPError>
</detail>
</s:Fault>
</s:Body>
</s:Envelope>"#;
        let err = parse_soap_response(resp).expect_err("must surface SOAP fault");
        match err {
            PortMapperError::Refused(msg) => {
                assert!(
                    msg.contains("718") || msg.to_lowercase().contains("conflict"),
                    "error message should reference 718 or 'conflict', got: {msg}"
                );
            }
            other => panic!("expected Refused, got: {other:?}"),
        }
    }

    #[test]
    fn upnp_parse_http_url_handles_typical_control_url() {
        let (host, port, path) =
            parse_http_url("http://192.168.1.1:49152/upnp/control/WANIPConn1").expect("parses");
        assert_eq!(host, "192.168.1.1");
        assert_eq!(port, 49152);
        assert_eq!(path, "/upnp/control/WANIPConn1");
    }

    #[test]
    fn upnp_parse_http_url_defaults_port_when_absent() {
        let (host, port, path) = parse_http_url("http://gateway.local/path").expect("parses");
        assert_eq!(host, "gateway.local");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");
    }

    #[test]
    fn upnp_parse_http_url_handles_ipv6_literal_with_port() {
        let (host, port, path) = parse_http_url("http://[fe80::1]:49152/path").expect("parses");
        assert_eq!(host, "fe80::1");
        assert_eq!(port, 49152);
        assert_eq!(path, "/path");
    }

    #[test]
    fn upnp_parse_http_url_rejects_https() {
        // uPnP IGD control points are HTTP-only; we don't ship a TLS
        // path. A gateway that hands us an https:// URL should produce
        // a clear error, not a silent connect failure.
        let err = parse_http_url("https://gateway.local/x").expect_err("https rejected");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("http")),
            "expected InvalidResponse mentioning http, got: {err:?}"
        );
    }

    /// Spawn a TCP HTTP server that answers exactly one request, then
    /// closes. The handler closure receives the raw request string and
    /// returns the raw response bytes.
    fn spawn_one_shot_http_server<F>(handler: F) -> (SocketAddr, JoinHandle<()>)
    where
        F: FnOnce(&str) -> Vec<u8> + Send + 'static,
    {
        use std::io::{Read, Write};
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind one-shot HTTP server");
        let addr = listener.local_addr().expect("local addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _peer) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            let response = handler(&request);
            let _ = stream.write_all(&response);
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        (addr, handle)
    }

    #[test]
    fn upnp_http_get_round_trips_against_in_process_server() {
        let (addr, handle) = spawn_one_shot_http_server(|_req| {
            let body = "hello from gateway";
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        });
        let url = format!("http://{addr}/test");
        let body = http_get(&url, Duration::from_secs(2)).expect("GET succeeds");
        assert!(body.contains("hello from gateway"), "body extracted");
        handle.join().expect("server thread joins");
    }

    #[test]
    fn upnp_soap_post_round_trips_against_in_process_server() {
        let (addr, handle) = spawn_one_shot_http_server(|request| {
            // Verify the request shape.
            assert!(
                request.contains("POST /Control HTTP/1.1"),
                "POST to /Control"
            );
            assert!(
                request.contains("SOAPACTION: \"urn:test#DoStuff\""),
                "SOAPACTION header present"
            );
            assert!(
                request.contains("CONTENT-TYPE: text/xml"),
                "Content-Type set"
            );
            assert!(
                request.contains("<u:DoStuff xmlns:u=\"urn:test\">"),
                "envelope contains action"
            );
            let body = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:DoStuffResponse xmlns:u="urn:test">
<Result>OK</Result>
</u:DoStuffResponse>
</s:Body>
</s:Envelope>"#;
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes()
        });
        let url = format!("http://{addr}/Control");
        let body = build_soap_envelope("urn:test", "DoStuff", &[]);
        let response = http_soap_post(&url, "urn:test#DoStuff", &body, Duration::from_secs(2))
            .expect("SOAP POST succeeds");
        let body_xml = parse_soap_response(&response).expect("SOAP success body");
        assert!(body_xml.contains("<Result>OK</Result>"));
        handle.join().expect("server thread joins");
    }

    #[test]
    fn upnp_client_request_udp_mapping_against_in_process_gateway() {
        // Spawn a TCP server that handles two SOAP requests in
        // sequence: AddPortMapping followed by GetExternalIPAddress.
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind in-process gateway");
        let addr = listener.local_addr().expect("local_addr");
        let handle = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _peer) = match listener.accept() {
                    Ok(s) => s,
                    Err(_) => return,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = if request.contains("AddPortMapping") {
                    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
</u:AddPortMappingResponse>
</s:Body>
</s:Envelope>"#
                } else {
                    r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
<NewExternalIPAddress>198.51.100.42</NewExternalIPAddress>
</u:GetExternalIPAddressResponse>
</s:Body>
</s:Envelope>"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.shutdown(std::net::Shutdown::Write);
            }
        });
        let control_url = format!("http://{addr}/Control");
        let client = UpnpIgdClient::new(control_url, UPNP_SERVICE_WANIPCONNECTION_V1.to_owned())
            .with_timeout(Duration::from_secs(2));
        let lease = client
            .request_udp_mapping(51820, 3600)
            .expect("uPnP mapping succeeds against in-process gateway");
        assert_eq!(lease.internal_port, 51820);
        assert_eq!(lease.external_port, 51820);
        assert_eq!(lease.protocol, PortMappingProtocol::UpnpIgd);
        assert_eq!(
            lease.external_addr,
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))
        );
        handle.join().expect("gateway thread joins");
    }

    #[test]
    fn upnp_client_release_mapping_against_in_process_gateway() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind in-process gateway");
        let addr = listener.local_addr().expect("local_addr");
        let handle = std::thread::spawn(move || {
            let (mut stream, _peer) = match listener.accept() {
                Ok(s) => s,
                Err(_) => return,
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("read timeout");
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                request.contains("DeletePortMapping"),
                "DeletePortMapping action observed"
            );
            assert!(
                request.contains("<NewExternalPort>51820</NewExternalPort>"),
                "external port carried in body"
            );
            let body = r#"<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body>
<u:DeletePortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
</u:DeletePortMappingResponse>
</s:Body>
</s:Envelope>"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.shutdown(std::net::Shutdown::Write);
        });
        let control_url = format!("http://{addr}/Control");
        let client = UpnpIgdClient::new(control_url, UPNP_SERVICE_WANIPCONNECTION_V1.to_owned())
            .with_timeout(Duration::from_secs(2));
        let lease = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            protocol: PortMappingProtocol::UpnpIgd,
            expires_at: Instant::now() + Duration::from_secs(1800),
            pcp_nonce: None,
        };
        client
            .release_mapping(&lease)
            .expect("uPnP release succeeds");
        handle.join().expect("gateway thread joins");
    }

    // ---- Supervisor + mode tests ----

    #[test]
    fn port_mapping_mode_parse_round_trips_canonical_labels() {
        assert_eq!(
            PortMappingMode::parse("auto").unwrap(),
            PortMappingMode::Auto
        );
        assert_eq!(
            PortMappingMode::parse("keepalive").unwrap(),
            PortMappingMode::Keepalive
        );
        assert_eq!(
            PortMappingMode::parse("disabled").unwrap(),
            PortMappingMode::Disabled
        );
        assert_eq!(PortMappingMode::Auto.label(), "auto");
        assert_eq!(PortMappingMode::Keepalive.label(), "keepalive");
        assert_eq!(PortMappingMode::Disabled.label(), "disabled");
    }

    #[test]
    fn port_mapping_mode_parse_rejects_unknown_value() {
        let err = PortMappingMode::parse("yes-please").expect_err("unknown value");
        assert!(err.contains("invalid"));
        assert!(err.contains("auto"));
        assert!(err.contains("keepalive"));
        assert!(err.contains("disabled"));
    }

    #[test]
    fn port_mapping_mode_default_is_keepalive() {
        // Keepalive must be the default because it works on every
        // cooperative cone NAT without any router probing. Operators
        // who want the probe layer to lift them from ~70% to ~95%
        // pair-success switch to `auto` explicitly.
        assert_eq!(PortMappingMode::default(), PortMappingMode::Keepalive);
    }

    #[test]
    fn supervisor_disabled_returns_skipped_without_probing() {
        // Skipped must short-circuit before any network IO. We use an
        // unrouteable gateway IP — if the supervisor tries to probe
        // it, the test will time out instead of returning Skipped.
        let supervisor = PortMappingSupervisor::new(PortMappingMode::Disabled)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let outcome = supervisor
            .bring_up(51820, 3600)
            .expect("Disabled returns Ok(Skipped) synchronously");
        assert!(
            matches!(outcome, SupervisorBringUp::Skipped { .. }),
            "Disabled must produce Skipped, got {outcome:?}"
        );
    }

    #[test]
    fn supervisor_keepalive_returns_skipped_without_probing() {
        let supervisor = PortMappingSupervisor::new(PortMappingMode::Keepalive)
            .with_gateway(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let outcome = supervisor.bring_up(51820, 3600).expect("synchronous");
        assert!(
            matches!(outcome, SupervisorBringUp::Skipped { reason } if reason.contains("keepalive")),
            "Keepalive must produce Skipped(..keepalive..), got {outcome:?}"
        );
    }

    #[test]
    fn supervisor_refresh_existing_lease_routes_by_protocol() {
        // PCP lease with no stored nonce → refresh path rejects with
        // InvalidResponse (validates that the supervisor dispatches
        // to PcpClient::refresh which then checks the nonce, rather
        // than falling through to NAT-PMP). We do not actually do any
        // network IO here because the nonce check fires before send.
        let lease = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            protocol: PortMappingProtocol::Pcp,
            expires_at: Instant::now() + Duration::from_secs(300),
            pcp_nonce: None,
        };
        let err = PortMappingSupervisor::refresh_existing_lease(
            &lease,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            None,
        )
        .expect_err("PCP refresh without nonce must fail");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("Mapping Nonce")),
            "expected nonce-missing InvalidResponse, got: {err:?}"
        );
    }

    #[test]
    fn supervisor_refresh_existing_lease_requires_gateway_for_pcp_and_natpmp() {
        let pcp_lease = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            protocol: PortMappingProtocol::Pcp,
            expires_at: Instant::now() + Duration::from_secs(300),
            pcp_nonce: Some([0; PCP_NONCE_LEN]),
        };
        let err = PortMappingSupervisor::refresh_existing_lease(&pcp_lease, None, None)
            .expect_err("missing gateway");
        assert!(
            matches!(err, PortMapperError::NoGateway(ref msg) if msg.contains("gateway")),
            "expected NoGateway, got: {err:?}"
        );

        let natpmp_lease = MappingLease {
            protocol: PortMappingProtocol::NatPmp,
            ..pcp_lease
        };
        let err = PortMappingSupervisor::refresh_existing_lease(&natpmp_lease, None, None)
            .expect_err("missing gateway");
        assert!(
            matches!(err, PortMapperError::NoGateway(_)),
            "expected NoGateway, got: {err:?}"
        );
    }

    #[test]
    fn supervisor_refresh_existing_lease_requires_control_url_for_upnp() {
        let lease = MappingLease {
            internal_port: 51820,
            external_port: 51820,
            external_addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            protocol: PortMappingProtocol::UpnpIgd,
            expires_at: Instant::now() + Duration::from_secs(300),
            pcp_nonce: None,
        };
        let err = PortMappingSupervisor::refresh_existing_lease(&lease, None, None)
            .expect_err("missing control URL");
        assert!(
            matches!(err, PortMapperError::InvalidResponse(ref msg) if msg.contains("controlURL")),
            "expected InvalidResponse mentioning controlURL, got: {err:?}"
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
