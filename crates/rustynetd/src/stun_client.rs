#![forbid(unsafe_code)]

use rand::RngCore;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

trait StunQuerySocket {
    fn set_read_timeout(&self, duration: Option<Duration>) -> std::io::Result<()>;
    fn local_addr(&self) -> std::io::Result<SocketAddr>;
    fn send_to(&self, buf: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

impl StunQuerySocket for UdpSocket {
    fn set_read_timeout(&self, duration: Option<Duration>) -> std::io::Result<()> {
        UdpSocket::set_read_timeout(self, duration)
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

/// One in-flight batched query: which configured server it belongs to,
/// the resolved target it was sent to, and the tx-id its response must echo.
struct PendingStunQuery {
    server_index: usize,
    target: SocketAddr,
    tx_id: [u8; 12],
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

    /// Fire every binding request up front from the one socket (each with
    /// its own tx-id), then run a single receive loop until the gather
    /// deadline, demuxing each datagram by source address (must equal a
    /// queried target — a strictness increase over the old per-server serial
    /// path, which accepted any source that echoed the tx-id) plus the
    /// existing tx-id echo check. Results assemble in server order (not
    /// arrival order) with the same dedup predicate, so an all-responsive
    /// fixture produces byte-identical output to the old serial version.
    fn gather_mapped_endpoints_batched<S: StunQuerySocket>(&self, socket: &S) -> Vec<StunResult> {
        let Ok(local_addr) = socket.local_addr() else {
            return Vec::new();
        };
        let mut pending: Vec<PendingStunQuery> = Vec::new();
        for (server_index, server) in self.servers.iter().enumerate() {
            let Ok(server_addrs) = server.to_socket_addrs() else {
                continue;
            };
            let Some(target) = server_addrs.into_iter().next() else {
                continue;
            };
            let tx_id = self.generate_tx_id();
            let request = self.build_binding_request(&tx_id);
            if socket.send_to(&request, target).is_err() {
                continue;
            }
            pending.push(PendingStunQuery {
                server_index,
                target,
                tx_id,
            });
        }
        if pending.is_empty() {
            return Vec::new();
        }

        let deadline = Instant::now() + self.timeout;
        let mut slots: Vec<Option<StunResult>> = vec![None; self.servers.len()];
        let mut buf = [0u8; 1024];
        while !pending.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            if socket.set_read_timeout(Some(remaining)).is_err() {
                break;
            }
            // Timeout (deadline reached) and hard socket errors both end the
            // gather; whatever responded so far is the result.
            let Ok((len, source)) = socket.recv_from(&mut buf) else {
                break;
            };
            let Some(position) = pending.iter().position(|query| query.target == source) else {
                // Response from an unqueried source: reject, keep collecting.
                continue;
            };
            let Ok(mapped_endpoint) =
                self.parse_binding_response(&buf[..len], &pending[position].tx_id)
            else {
                // Malformed or wrong tx-id from a real target: drop the
                // datagram, keep the query pending until the deadline.
                continue;
            };
            let query = pending.swap_remove(position);
            slots[query.server_index] = Some(StunResult {
                mapped_endpoint,
                server: query.target,
                local_addr,
            });
        }

        let mut results = Vec::new();
        for result in slots.into_iter().flatten() {
            if !results
                .iter()
                .any(|existing: &StunResult| existing.mapped_endpoint == result.mapped_endpoint)
            {
                results.push(result);
            }
        }
        results
    }

    /// Gather public mapped endpoints using a backend-owned authoritative
    /// round-trip transport instead of a daemon-owned socket.
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
            let tx_id = self.generate_tx_id();
            let request = self.build_binding_request(&tx_id);
            // FIS-0018: the authoritative round-trip transport is a hard
            // singleton (queries must stay sequential), so the fix is budget
            // accounting: each server gets total/N so an unresponsive server
            // can no longer eat the others' budget — total gather wall-clock
            // stays <= one `self.timeout`. N=1 receives the full timeout,
            // byte-identical to the old behavior.
            let Ok(response) = round_trip(target, &request, self.per_server_slice()) else {
                continue;
            };
            if response.remote_addr != target {
                continue;
            }
            let Ok(mapped_endpoint) = self.parse_binding_response(&response.response, &tx_id)
            else {
                continue;
            };
            if !results
                .iter()
                .any(|existing: &StunResult| existing.mapped_endpoint == mapped_endpoint)
            {
                results.push(StunResult {
                    mapped_endpoint,
                    server: target,
                    local_addr: response.local_addr,
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

        let tx_id = self.generate_tx_id();
        let request = self.build_binding_request(&tx_id);

        socket
            .send_to(&request, target)
            .map_err(|e| e.to_string())?;

        let mut buf = [0u8; 1024];
        let (len, _src) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;

        let mapped_endpoint = self.parse_binding_response(&buf[..len], &tx_id)?;

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

    fn generate_tx_id(&self) -> [u8; 12] {
        let mut tx_id = [0u8; 12];
        rand::rng().fill_bytes(&mut tx_id);
        tx_id
    }

    fn build_binding_request(&self, tx_id: &[u8; 12]) -> Vec<u8> {
        let mut packet = Vec::with_capacity(20);
        packet.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes()); // Length
        packet.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(tx_id);
        packet
    }

    fn parse_binding_response(&self, buf: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
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
                && let Ok(addr) = self.parse_xor_mapped_address(attr_value, tx_id)
            {
                xor_mapped_addr = Some(addr);
            } else if attr_type == STUN_ATTR_MAPPED_ADDRESS
                && let Ok(addr) = self.parse_mapped_address(attr_value)
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

    fn parse_xor_mapped_address(&self, val: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
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

    fn parse_mapped_address(&self, val: &[u8]) -> Result<SocketAddr, String> {
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
        assert_eq!(observed, vec![Duration::from_millis(300); 3]);
    }

    #[test]
    fn round_trip_gather_single_server_receives_full_timeout() {
        let client = StunClient::new(
            vec!["127.0.0.1:5001".to_owned()],
            Duration::from_millis(900),
        );
        let mut observed = Vec::new();
        let _ = client.gather_mapped_endpoints_with_round_trip(|_target, _req, timeout| {
            observed.push(timeout);
            Err("unresponsive".to_owned())
        });
        assert_eq!(observed, vec![Duration::from_millis(900)]);
    }
}
