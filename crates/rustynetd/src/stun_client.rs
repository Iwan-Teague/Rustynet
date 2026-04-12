#![forbid(unsafe_code)]

use rand::RngCore;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

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
    /// This method returns full `SocketAddr` (IP + port) as observed by each STUN server.
    /// Unlike `gather_public_ips`, this method returns the actual mapped port, not a guess.
    ///
    /// # Arguments
    /// * `socket` - Optional socket to use for queries. If provided, the mapped endpoint
    ///   reflects the NAT mapping for that specific socket. If `None`, creates
    ///   ephemeral sockets per query (legacy behavior, not recommended).
    ///
    /// # Returns
    /// A vector of `StunResult` containing the full mapped endpoint information.
    pub fn gather_mapped_endpoints(&self, socket: Option<&UdpSocket>) -> Vec<StunResult> {
        let mut results = Vec::new();
        for server in &self.servers {
            match self.query_stun_server_full(server, socket) {
                Ok(result) => {
                    // Deduplicate by mapped endpoint
                    if !results
                        .iter()
                        .any(|r: &StunResult| r.mapped_endpoint == result.mapped_endpoint)
                    {
                        results.push(result);
                    }
                }
                Err(_) => continue,
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
            let Ok(response) = round_trip(target, &request, self.timeout) else {
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

    /// Legacy method that returns only IPs.
    ///
    /// **DEPRECATED**: Use `gather_mapped_endpoints` instead. This method guesses the port
    /// by using the local listen port, which is incorrect for NATs that don't preserve ports.
    pub fn gather_public_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for server in &self.servers {
            if let Ok(addr) = self.query_stun_server(server)
                && !ips.contains(&addr.ip())
            {
                ips.push(addr.ip());
            }
        }
        ips
    }

    /// Query a STUN server and return full result with metadata.
    fn query_stun_server_full(
        &self,
        server: &str,
        provided_socket: Option<&UdpSocket>,
    ) -> Result<StunResult, String> {
        let server_addrs = server.to_socket_addrs().map_err(|e| e.to_string())?;
        let target = server_addrs.into_iter().next().ok_or("no server address")?;

        if let Some(socket) = provided_socket {
            return self.query_stun_server_with_socket(target, socket);
        }

        let owned_socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        self.query_stun_server_with_socket(target, &owned_socket)
    }

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

    fn query_stun_server(&self, server: &str) -> Result<SocketAddr, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        socket
            .set_read_timeout(Some(self.timeout))
            .map_err(|e| e.to_string())?;

        let server_addrs = server.to_socket_addrs().map_err(|e| e.to_string())?;
        let target = server_addrs.into_iter().next().ok_or("no server address")?;

        let tx_id = self.generate_tx_id();
        let request = self.build_binding_request(&tx_id);

        socket
            .send_to(&request, target)
            .map_err(|e| e.to_string())?;

        let mut buf = [0u8; 1024];
        let (len, _src) = socket.recv_from(&mut buf).map_err(|e| e.to_string())?;

        self.parse_binding_response(&buf[..len], &tx_id)
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
            return Err("response too short".to_string());
        }
        let type_ = u16::from_be_bytes([buf[0], buf[1]]);
        if type_ != STUN_BINDING_RESPONSE {
            return Err(format!("unexpected response type: 0x{type_:04x}"));
        }
        let length = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err("invalid magic cookie".to_string());
        }
        if &buf[8..20] != tx_id {
            return Err("transaction id mismatch".to_string());
        }
        if buf.len() < 20 + length {
            return Err("truncated response".to_string());
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
                return Err("stun attribute exceeds message boundary".to_string());
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
            Err("no mapped address attribute found".to_string())
        }
    }

    fn parse_xor_mapped_address(&self, val: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr, String> {
        if val.len() < 8 {
            return Err("xor mapped addr too short".to_string());
        }
        let _reserved = val[0];
        let family = val[1];
        let port_xor = u16::from_be_bytes([val[2], val[3]]);
        let port = port_xor ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        if family == 0x01 {
            // IPv4
            if val.len() < 8 {
                return Err("ipv4 too short".to_string());
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
                return Err("ipv6 too short".to_string());
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
            return Err("mapped addr too short".to_string());
        }
        let _reserved = val[0];
        let family = val[1];
        let port = u16::from_be_bytes([val[2], val[3]]);

        if family == 0x01 {
            // IPv4
            if val.len() < 8 {
                return Err("ipv4 too short".to_string());
            }
            let ip = std::net::Ipv4Addr::new(val[4], val[5], val[6], val[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        } else if family == 0x02 {
            // IPv6
            // Not supported
            Err("ipv6 mapped addr not supported".to_string())
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
}
