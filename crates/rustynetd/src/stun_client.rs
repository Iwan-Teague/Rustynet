#![forbid(unsafe_code)]

use rand::RngCore;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

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
    ///              reflects the NAT mapping for that specific socket. If `None`, creates
    ///              ephemeral sockets per query (legacy behavior, not recommended).
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

    /// Legacy method that returns only IPs.
    ///
    /// **DEPRECATED**: Use `gather_mapped_endpoints` instead. This method guesses the port
    /// by using the local listen port, which is incorrect for NATs that don't preserve ports.
    pub fn gather_public_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();
        for server in &self.servers {
            if let Ok(addr) = self.query_stun_server(server) {
                if !ips.contains(&addr.ip()) {
                    ips.push(addr.ip());
                }
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

        // Use provided socket or create ephemeral
        let owned_socket: Option<UdpSocket>;
        let socket: &UdpSocket = match provided_socket {
            Some(s) => s,
            None => {
                owned_socket = Some(UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?);
                owned_socket.as_ref().unwrap()
            }
        };

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
        rand::thread_rng().fill_bytes(&mut tx_id);
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
                break;
            }
            let attr_value = &buf[pos + 4..attr_end];

            if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS {
                if let Ok(addr) = self.parse_xor_mapped_address(attr_value) {
                    xor_mapped_addr = Some(addr);
                }
            } else if attr_type == STUN_ATTR_MAPPED_ADDRESS {
                if let Ok(addr) = self.parse_mapped_address(attr_value) {
                    mapped_addr = Some(addr);
                }
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

    fn parse_xor_mapped_address(&self, val: &[u8]) -> Result<SocketAddr, String> {
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
            // IPv6 XOR uses the first 32 bits of Transaction ID
            // But we need the tx_id passed in or stored.
            // For now, skipping IPv6 support in this simple client.
            Err("ipv6 stun not supported yet".to_string())
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
        // ip 1.2.3.4 = 0x01020304, XOR with 0x2112A442 = 0x2110A746
        let val = [
            0x00, // reserved
            0x01, // IPv4
            0x37, 0x3C, // XOR'd port (5678 XOR 0x2112)
            0x21, 0x10, 0xA7, 0x46, // XOR'd IP (1.2.3.4 XOR 0x2112A442)
        ];

        let result = client.parse_xor_mapped_address(&val).unwrap();
        assert_eq!(result.port(), 5678);
        assert_eq!(result.ip().to_string(), "1.2.3.4");
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
}
