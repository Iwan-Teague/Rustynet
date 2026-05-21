//! D5.5 / cross-network preflight diagnostic.
//!
//! `rustynet ops cross-network-preflight` is an operator-runnable
//! readiness check that answers: "if I run a cross-network test
//! against this host right now, will it plausibly succeed, and
//! through which path?" It runs standalone (no daemon required;
//! parses the same env vars / CLI flags the daemon would) so the
//! operator can sanity-check infrastructure BEFORE invoking
//! `scripts/e2e/live_linux_cross_network_*.sh`.
//!
//! What the preflight observes:
//!
//! 1. **Local host candidates** — `getifaddrs(2)` enumeration via
//!    `dataplane_candidates::enumerate_local_host_candidates`, kept
//!    only when the scope is `Global` or `Private` (the same filter
//!    `gather_candidate_set` applies).
//! 2. **STUN srflx observations per server** — for each configured
//!    STUN server, perform an RFC 5389 Binding Request from a
//!    fresh UDP socket and record the observed `XOR-MAPPED-ADDRESS`.
//!    A timeout / unreachable server is recorded as a per-server
//!    failure but does NOT abort the preflight; partial responses
//!    are still diagnostically valuable.
//! 3. **NAT-class heuristic** — if 2+ STUN servers respond, compare
//!    the observed external `(addr, port)` pairs:
//!    - all agree → `cone_nat_likely` (direct path stands a chance)
//!    - addresses agree but ports differ → `port_restricted_likely`
//!      (direct path possible but marginal — may need the D5.5
//!      pair-race in production)
//!    - addresses differ → `symmetric_likely` (direct path WILL NOT
//!      work from this host; the test must use the relay path)
//! 4. **Relay reachability** — if the operator provides
//!    `--relay-endpoint <addr:port>`, attempt a TCP connect to it
//!    with a short timeout. Reports `reachable` / `timed_out` /
//!    `refused` / `dns_failed`.
//!
//! The preflight emits a structured one-line summary (key=value
//! pairs, matching the existing `rustynet netcheck` / `rustynet
//! status` shape) plus an optional `--json` mode for machine
//! consumption. The final verdict is one of:
//!
//! - `direct_likely` — at least one configured STUN server
//!   responded AND the NAT-class heuristic is `cone_nat_likely`.
//! - `mixed_nat_could_work` — `port_restricted_likely`; direct
//!   might work via parallel pair race.
//! - `relay_required` — `symmetric_likely`; direct will not work.
//! - `stun_broken` — zero STUN servers responded.
//! - `no_stun_configured` — operator passed no STUN servers.
//!
//! Security framing: the preflight does NOT load the daemon's
//! private key, signing material, or any membership state. It only
//! exercises plaintext probes against operator-supplied endpoints
//! and reads its own UDP socket's mapped addresses back from the
//! responses. The check is safe to run on any host; the worst-case
//! information disclosure is to the configured STUN/relay servers,
//! which already see this traffic during normal cross-network
//! operation.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use rustynetd::dataplane_candidates::{AddressScope, enumerate_local_host_candidates};
use rustynetd::stun_client::StunClient;

/// Operator-supplied inputs to the preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossNetworkPreflightConfig {
    /// STUN servers in `host:port` form. May be empty.
    pub stun_servers: Vec<String>,
    /// Optional relay endpoint (`ip:port` form) to TCP-probe.
    pub relay_endpoint: Option<String>,
    /// Per-STUN-server query timeout. Default 2 s.
    pub stun_timeout_ms: u64,
    /// Per-relay TCP-connect timeout. Default 3 s.
    pub relay_timeout_ms: u64,
    /// Emit the report as JSON instead of the one-line key=value
    /// summary. Mutually compatible with `--output-path`.
    pub json: bool,
    /// Write the JSON report to this path in addition to printing
    /// to stdout. Optional.
    pub output_path: Option<PathBuf>,
}

impl Default for CrossNetworkPreflightConfig {
    fn default() -> Self {
        Self {
            stun_servers: Vec::new(),
            relay_endpoint: None,
            stun_timeout_ms: 2_000,
            relay_timeout_ms: 3_000,
            json: false,
            output_path: None,
        }
    }
}

/// Per-server STUN observation. `mapped_endpoint` is the
/// `XOR-MAPPED-ADDRESS` from the response; `error` is set when the
/// server did not respond or returned a malformed reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunServerObservation {
    pub server: String,
    pub family: &'static str,
    pub mapped_endpoint: Option<SocketAddr>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalHostObservation {
    pub interface: String,
    pub addr: IpAddr,
    pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayProbeObservation {
    pub endpoint: String,
    pub status: &'static str,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

/// Stable, finite-vocabulary NAT-class heuristic verdict. See the
/// module docs for the per-variant meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatClassHeuristic {
    ConeNatLikely,
    PortRestrictedLikely,
    SymmetricLikely,
    InsufficientData,
}

impl NatClassHeuristic {
    pub fn as_str(self) -> &'static str {
        match self {
            NatClassHeuristic::ConeNatLikely => "cone_nat_likely",
            NatClassHeuristic::PortRestrictedLikely => "port_restricted_likely",
            NatClassHeuristic::SymmetricLikely => "symmetric_likely",
            NatClassHeuristic::InsufficientData => "insufficient_data",
        }
    }
}

/// Top-level verdict — operator-facing one-word answer to "will the
/// cross-network test plausibly succeed?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreflightVerdict {
    DirectLikely,
    MixedNatCouldWork,
    RelayRequired,
    StunBroken,
    NoStunConfigured,
}

impl PreflightVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            PreflightVerdict::DirectLikely => "direct_likely",
            PreflightVerdict::MixedNatCouldWork => "mixed_nat_could_work",
            PreflightVerdict::RelayRequired => "relay_required",
            PreflightVerdict::StunBroken => "stun_broken",
            PreflightVerdict::NoStunConfigured => "no_stun_configured",
        }
    }
}

/// Aggregated preflight report. Both the one-line summary and the
/// JSON form are derived from this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossNetworkPreflightReport {
    pub schema_version: u32,
    pub stun_observations: Vec<StunServerObservation>,
    pub local_host_candidates: Vec<LocalHostObservation>,
    pub relay_probe: Option<RelayProbeObservation>,
    pub nat_class: NatClassHeuristic,
    pub verdict: PreflightVerdict,
    pub guidance: String,
}

/// Run the preflight and return a typed report. Pure function over
/// the network I/O it performs — does not mutate any on-disk state.
pub fn run_cross_network_preflight(
    config: &CrossNetworkPreflightConfig,
) -> CrossNetworkPreflightReport {
    let stun_observations = probe_stun_servers(config);
    let local_host_candidates = collect_local_host_candidates();
    let relay_probe = config.relay_endpoint.as_deref().map(|endpoint| {
        probe_relay_endpoint(endpoint, Duration::from_millis(config.relay_timeout_ms))
    });
    let nat_class = classify_nat(&stun_observations);
    let (verdict, guidance) = derive_verdict(&stun_observations, nat_class, config);
    CrossNetworkPreflightReport {
        schema_version: 1,
        stun_observations,
        local_host_candidates,
        relay_probe,
        nat_class,
        verdict,
        guidance,
    }
}

fn collect_local_host_candidates() -> Vec<LocalHostObservation> {
    enumerate_local_host_candidates()
        .into_iter()
        .filter(|c| matches!(c.scope, AddressScope::Global | AddressScope::Private))
        .map(|c| LocalHostObservation {
            interface: c.interface,
            addr: c.addr,
            scope: format!("{:?}", c.scope),
        })
        .collect()
}

fn probe_stun_servers(config: &CrossNetworkPreflightConfig) -> Vec<StunServerObservation> {
    let mut out = Vec::new();
    if config.stun_servers.is_empty() {
        return out;
    }
    let timeout = Duration::from_millis(config.stun_timeout_ms);
    // Bind ONE socket per family and reuse it across every STUN
    // server query. This mirrors how the production daemon uses
    // the authoritative WG transport socket — one socket, same
    // external mapping across every reflection. Without this
    // shared-socket shape, a cone-NAT host would look like a
    // port-restricted NAT because each fresh UDP bind gets a
    // different ephemeral source port.
    let v4_socket = UdpSocket::bind("0.0.0.0:0").ok();
    let v6_socket = UdpSocket::bind("[::]:0").ok();
    if let Some(sock) = v4_socket.as_ref() {
        let _ = sock.set_read_timeout(Some(timeout));
    }
    if let Some(sock) = v6_socket.as_ref() {
        let _ = sock.set_read_timeout(Some(timeout));
    }
    for server in &config.stun_servers {
        for (family_label, socket) in [("v4", v4_socket.as_ref()), ("v6", v6_socket.as_ref())] {
            let Some(socket) = socket else {
                out.push(StunServerObservation {
                    server: server.clone(),
                    family: family_label,
                    mapped_endpoint: None,
                    error: Some(format!("could not bind {family_label} probe socket")),
                });
                continue;
            };
            // Filter by server family BEFORE binding, mirroring
            // gather_srflx_for_family's resolver-family check, so a
            // v4-only server URL passed to the v6 probe path
            // doesn't time out.
            if !server_resolves_in_family(server, family_label) {
                out.push(StunServerObservation {
                    server: server.clone(),
                    family: family_label,
                    mapped_endpoint: None,
                    error: Some(format!(
                        "server does not resolve in the {family_label} family"
                    )),
                });
                continue;
            }
            let client = StunClient::new(vec![server.clone()], timeout);
            let results = client.gather_mapped_endpoints(Some(socket));
            if let Some(result) = results.into_iter().next() {
                out.push(StunServerObservation {
                    server: server.clone(),
                    family: family_label,
                    mapped_endpoint: Some(result.mapped_endpoint),
                    error: None,
                });
            } else {
                out.push(StunServerObservation {
                    server: server.clone(),
                    family: family_label,
                    mapped_endpoint: None,
                    error: Some(format!(
                        "no {family_label} STUN response within {} ms",
                        config.stun_timeout_ms
                    )),
                });
            }
        }
    }
    out
}

fn server_resolves_in_family(server: &str, family_label: &str) -> bool {
    let Ok(addrs) = server.to_socket_addrs() else {
        return false;
    };
    for addr in addrs {
        match (family_label, addr) {
            ("v4", SocketAddr::V4(_)) | ("v6", SocketAddr::V6(_)) => return true,
            _ => continue,
        }
    }
    false
}

fn probe_relay_endpoint(endpoint: &str, timeout: Duration) -> RelayProbeObservation {
    let addrs: Vec<SocketAddr> = match endpoint.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(err) => {
            return RelayProbeObservation {
                endpoint: endpoint.to_owned(),
                status: "dns_failed",
                latency_ms: None,
                error: Some(err.to_string()),
            };
        }
    };
    let Some(addr) = addrs.first() else {
        return RelayProbeObservation {
            endpoint: endpoint.to_owned(),
            status: "dns_failed",
            latency_ms: None,
            error: Some("address resolution returned zero entries".to_owned()),
        };
    };
    let started = Instant::now();
    match TcpStream::connect_timeout(addr, timeout) {
        Ok(stream) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            // Close immediately. We only care whether the TCP
            // handshake completed; the relay protocol itself runs
            // over UDP and a separate session token.
            drop(stream);
            RelayProbeObservation {
                endpoint: endpoint.to_owned(),
                status: "reachable",
                latency_ms: Some(latency_ms),
                error: None,
            }
        }
        Err(err) => {
            let status = match err.kind() {
                std::io::ErrorKind::TimedOut => "timed_out",
                std::io::ErrorKind::ConnectionRefused => "refused",
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                    "unreachable"
                }
                _ => "tcp_failed",
            };
            RelayProbeObservation {
                endpoint: endpoint.to_owned(),
                status,
                latency_ms: None,
                error: Some(err.to_string()),
            }
        }
    }
}

fn classify_nat(observations: &[StunServerObservation]) -> NatClassHeuristic {
    // Group successful observations by family so we don't compare
    // v4 and v6 srflx (different families produce different
    // mapped endpoints by definition).
    let mut by_family: BTreeMap<&'static str, Vec<SocketAddr>> = BTreeMap::new();
    for obs in observations {
        if let Some(addr) = obs.mapped_endpoint {
            by_family.entry(obs.family).or_default().push(addr);
        }
    }
    // We need ≥2 observations in some family to draw a conclusion.
    let Some((_, addrs)) = by_family.iter().max_by_key(|(_, v)| v.len()) else {
        return NatClassHeuristic::InsufficientData;
    };
    if addrs.len() < 2 {
        return NatClassHeuristic::InsufficientData;
    }
    let first = addrs[0];
    let all_same_ip = addrs.iter().all(|a| a.ip() == first.ip());
    let all_same_port = addrs.iter().all(|a| a.port() == first.port());
    match (all_same_ip, all_same_port) {
        (true, true) => NatClassHeuristic::ConeNatLikely,
        (true, false) => NatClassHeuristic::PortRestrictedLikely,
        (false, _) => NatClassHeuristic::SymmetricLikely,
    }
}

fn derive_verdict(
    observations: &[StunServerObservation],
    nat_class: NatClassHeuristic,
    config: &CrossNetworkPreflightConfig,
) -> (PreflightVerdict, String) {
    if config.stun_servers.is_empty() {
        return (
            PreflightVerdict::NoStunConfigured,
            "configure RUSTYNET_TRAVERSAL_STUN_SERVERS or pass --stun-servers; cross-network direct probing requires at least one reachable STUN reflector".to_owned(),
        );
    }
    let any_success = observations.iter().any(|o| o.mapped_endpoint.is_some());
    if !any_success {
        return (
            PreflightVerdict::StunBroken,
            "every configured STUN server failed to respond within the per-server timeout; check egress connectivity, the STUN port (typically UDP/3478), and DNS resolution".to_owned(),
        );
    }
    match nat_class {
        NatClassHeuristic::ConeNatLikely => (
            PreflightVerdict::DirectLikely,
            "all responsive STUN servers reported the same external endpoint; cone-NAT (or no NAT) likely; direct path stands a good chance against a peer with similar posture".to_owned(),
        ),
        NatClassHeuristic::PortRestrictedLikely => (
            PreflightVerdict::MixedNatCouldWork,
            "STUN servers reported the same external IP but different external ports; port-restricted NAT likely; direct path may succeed via parallel pair race against a cooperative peer".to_owned(),
        ),
        NatClassHeuristic::SymmetricLikely => (
            PreflightVerdict::RelayRequired,
            "STUN servers reported different external IPs; symmetric NAT likely; the cross-network test should use the relay-remote-exit suite, not the direct-remote-exit suite".to_owned(),
        ),
        NatClassHeuristic::InsufficientData => (
            PreflightVerdict::MixedNatCouldWork,
            "only one STUN server responded; pass two or more STUN servers to classify NAT behaviour reliably; the daemon will still attempt direct via the parallel pair race".to_owned(),
        ),
    }
}

/// Render the report as a one-line key=value summary matching the
/// existing `rustynet status` / `rustynet netcheck` shape so the
/// existing `--json` JSON-from-key-value renderer can convert it.
pub fn render_one_line_summary(report: &CrossNetworkPreflightReport) -> String {
    let stun_responsive = report
        .stun_observations
        .iter()
        .filter(|o| o.mapped_endpoint.is_some())
        .count();
    let stun_total = report.stun_observations.len();
    let host_candidate_count = report.local_host_candidates.len();
    let relay = match report.relay_probe.as_ref() {
        Some(probe) => format!(
            "relay_probe={status} relay_latency_ms={latency} relay_endpoint={endpoint}",
            status = probe.status,
            latency = probe
                .latency_ms
                .map(|v| v.to_string())
                .unwrap_or_else(|| "none".to_owned()),
            endpoint = sanitize_value(probe.endpoint.as_str()),
        ),
        None => "relay_probe=not_configured relay_latency_ms=none relay_endpoint=none".to_owned(),
    };
    let mapped = report
        .stun_observations
        .iter()
        .find_map(|o| o.mapped_endpoint.map(|sa| sa.to_string()))
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "cross-network-preflight: verdict={verdict} nat_class={nat} stun_responsive={resp}/{total} stun_mapped_endpoint={mapped} host_candidates={hosts} {relay}",
        verdict = report.verdict.as_str(),
        nat = report.nat_class.as_str(),
        resp = stun_responsive,
        total = stun_total,
        mapped = sanitize_value(mapped.as_str()),
        hosts = host_candidate_count,
    )
}

fn sanitize_value(value: &str) -> String {
    // Strip whitespace/newlines so the key=value line stays
    // parseable by the existing `rustynet status` consumer.
    value.replace([' ', '\t', '\n', '\r'], "_")
}

/// Render the report as deterministic JSON. The schema is pinned at
/// `schema_version=1`. Operator tooling can grep on `verdict` for
/// machine-readable verdicts.
pub fn render_json_report(report: &CrossNetworkPreflightReport) -> String {
    use serde_json::json;
    let stun_observations: Vec<_> = report
        .stun_observations
        .iter()
        .map(|o| {
            json!({
                "server": o.server,
                "family": o.family,
                "mapped_endpoint": o.mapped_endpoint.map(|sa| sa.to_string()),
                "error": o.error,
            })
        })
        .collect();
    let local_host_candidates: Vec<_> = report
        .local_host_candidates
        .iter()
        .map(|c| {
            json!({
                "interface": c.interface,
                "addr": c.addr.to_string(),
                "scope": c.scope,
            })
        })
        .collect();
    let relay_probe = match report.relay_probe.as_ref() {
        Some(probe) => json!({
            "endpoint": probe.endpoint,
            "status": probe.status,
            "latency_ms": probe.latency_ms,
            "error": probe.error,
        }),
        None => serde_json::Value::Null,
    };
    let value = json!({
        "schema_version": report.schema_version,
        "verdict": report.verdict.as_str(),
        "nat_class": report.nat_class.as_str(),
        "guidance": report.guidance,
        "stun_observations": stun_observations,
        "local_host_candidates": local_host_candidates,
        "relay_probe": relay_probe,
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
}

/// Operator-facing entry point. Returns the rendered output suitable
/// for printing; the typed report is also returned for callers
/// (e.g. CI gates) that want to inspect the verdict in-process.
pub fn execute_cross_network_preflight(
    config: CrossNetworkPreflightConfig,
) -> Result<String, String> {
    let report = run_cross_network_preflight(&config);
    let output = if config.json {
        render_json_report(&report)
    } else {
        render_one_line_summary(&report)
    };
    if let Some(path) = config.output_path.as_deref() {
        // Always write the JSON to the output path regardless of
        // the on-stdout format choice — the file is machine
        // consumption.
        let json = render_json_report(&report);
        std::fs::write(path, format!("{json}\n"))
            .map_err(|err| format!("write preflight report to {}: {err}", path.display()))?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};

    fn spawn_xor_mapped_echo(bind: &str) -> SocketAddr {
        let socket = UdpSocket::bind(bind).expect("bind echo");
        let addr = socket.local_addr().expect("local addr");
        std::thread::spawn(move || {
            socket.set_read_timeout(Some(Duration::from_secs(3))).ok();
            let mut buf = [0u8; 1024];
            while let Ok((len, src)) = socket.recv_from(&mut buf) {
                if len < 20 {
                    continue;
                }
                let mut tx_id = [0u8; 12];
                tx_id.copy_from_slice(&buf[8..20]);
                let resp = build_xor_mapped_response(&tx_id, src);
                let _ = socket.send_to(&resp, src);
            }
        });
        addr
    }

    fn build_xor_mapped_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        const STUN_MAGIC: u32 = 0x2112_a442;
        const STUN_BINDING_RESPONSE: u16 = 0x0101;
        const STUN_ATTR_XOR_MAPPED: u16 = 0x0020;
        let (family_byte, addr_len, xor_addr) = match mapped {
            SocketAddr::V4(v4) => {
                let raw = v4.ip().octets();
                let xor = [raw[0] ^ 0x21, raw[1] ^ 0x12, raw[2] ^ 0xa4, raw[3] ^ 0x42];
                (0x01u8, 4u16, xor.to_vec())
            }
            SocketAddr::V6(v6) => {
                let raw = v6.ip().octets();
                let mut mask = [0u8; 16];
                mask[0..4].copy_from_slice(&STUN_MAGIC.to_be_bytes());
                mask[4..16].copy_from_slice(tx_id);
                let mut xor = [0u8; 16];
                for i in 0..16 {
                    xor[i] = raw[i] ^ mask[i];
                }
                (0x02u8, 16u16, xor.to_vec())
            }
        };
        let xor_port = mapped.port() ^ ((STUN_MAGIC >> 16) as u16);
        let attr_len = 4 + addr_len;
        let total_len = 4 + attr_len;
        let mut pkt = Vec::with_capacity(20 + total_len as usize);
        pkt.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        pkt.extend_from_slice(&total_len.to_be_bytes());
        pkt.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        pkt.extend_from_slice(tx_id);
        pkt.extend_from_slice(&STUN_ATTR_XOR_MAPPED.to_be_bytes());
        pkt.extend_from_slice(&attr_len.to_be_bytes());
        pkt.push(0);
        pkt.push(family_byte);
        pkt.extend_from_slice(&xor_port.to_be_bytes());
        pkt.extend_from_slice(&xor_addr);
        pkt
    }

    #[test]
    fn no_stun_configured_yields_no_stun_configured_verdict() {
        let config = CrossNetworkPreflightConfig::default();
        let report = run_cross_network_preflight(&config);
        assert_eq!(report.verdict, PreflightVerdict::NoStunConfigured);
        assert!(report.stun_observations.is_empty());
        assert!(report.guidance.contains("STUN"));
    }

    #[test]
    fn unreachable_stun_yields_stun_broken_verdict() {
        // RFC 5737 documentation prefix — guaranteed unreachable.
        let config = CrossNetworkPreflightConfig {
            stun_servers: vec!["192.0.2.1:3478".to_owned()],
            stun_timeout_ms: 250,
            ..Default::default()
        };
        let report = run_cross_network_preflight(&config);
        assert_eq!(report.verdict, PreflightVerdict::StunBroken);
        assert!(
            report
                .stun_observations
                .iter()
                .all(|o| o.mapped_endpoint.is_none())
        );
    }

    #[test]
    fn cone_nat_likely_when_all_stun_servers_agree() {
        let a = spawn_xor_mapped_echo("127.0.0.1:0");
        let b = spawn_xor_mapped_echo("127.0.0.1:0");
        let config = CrossNetworkPreflightConfig {
            stun_servers: vec![a.to_string(), b.to_string()],
            stun_timeout_ms: 1000,
            ..Default::default()
        };
        let report = run_cross_network_preflight(&config);
        // Both echo servers reflect the requester's own source port,
        // which is the same socket — so observed (ip, port) match
        // across the two STUN responses. Cone-NAT shape.
        assert_eq!(report.nat_class, NatClassHeuristic::ConeNatLikely);
        assert_eq!(report.verdict, PreflightVerdict::DirectLikely);
        assert_eq!(
            report
                .stun_observations
                .iter()
                .filter(|o| o.mapped_endpoint.is_some())
                .count(),
            2,
            "both echo servers should respond (one v4 hit each); got: {:?}",
            report.stun_observations
        );
    }

    #[test]
    fn one_responsive_one_unreachable_yields_mixed_nat_could_work() {
        let a = spawn_xor_mapped_echo("127.0.0.1:0");
        let config = CrossNetworkPreflightConfig {
            stun_servers: vec![a.to_string(), "192.0.2.1:3478".to_owned()],
            stun_timeout_ms: 250,
            ..Default::default()
        };
        let report = run_cross_network_preflight(&config);
        // Only one responded → InsufficientData → MixedNatCouldWork.
        assert_eq!(report.nat_class, NatClassHeuristic::InsufficientData);
        assert_eq!(report.verdict, PreflightVerdict::MixedNatCouldWork);
    }

    #[test]
    fn relay_probe_reachable_when_tcp_connect_succeeds() {
        // Spin a TCP listener so the relay probe sees a reachable
        // endpoint. We don't need to speak the relay protocol —
        // only the TCP handshake completion is checked.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
        let addr = listener.local_addr().expect("local addr");
        std::thread::spawn(move || {
            // Accept one connection and close. Keeps the test
            // deterministic without leaking the listener.
            let _ = listener.accept();
        });
        let config = CrossNetworkPreflightConfig {
            relay_endpoint: Some(addr.to_string()),
            relay_timeout_ms: 1000,
            ..Default::default()
        };
        let report = run_cross_network_preflight(&config);
        let probe = report.relay_probe.expect("relay probe present");
        assert_eq!(probe.status, "reachable");
        assert!(probe.latency_ms.is_some());
    }

    #[test]
    fn relay_probe_status_is_dns_failed_on_unparseable_endpoint() {
        let config = CrossNetworkPreflightConfig {
            relay_endpoint: Some("not-a-valid-endpoint:not-a-port".to_owned()),
            relay_timeout_ms: 250,
            ..Default::default()
        };
        let report = run_cross_network_preflight(&config);
        let probe = report.relay_probe.expect("relay probe present");
        assert_eq!(probe.status, "dns_failed");
        assert!(probe.latency_ms.is_none());
    }

    #[test]
    fn render_one_line_summary_emits_stable_keys() {
        let report = CrossNetworkPreflightReport {
            schema_version: 1,
            stun_observations: vec![],
            local_host_candidates: vec![],
            relay_probe: None,
            nat_class: NatClassHeuristic::InsufficientData,
            verdict: PreflightVerdict::NoStunConfigured,
            guidance: "test".to_owned(),
        };
        let line = render_one_line_summary(&report);
        for key in [
            "cross-network-preflight:",
            "verdict=",
            "nat_class=",
            "stun_responsive=",
            "stun_mapped_endpoint=",
            "host_candidates=",
            "relay_probe=",
            "relay_latency_ms=",
            "relay_endpoint=",
        ] {
            assert!(
                line.contains(key),
                "summary missing required key {key:?}; got: {line}"
            );
        }
    }

    #[test]
    fn render_json_report_round_trips_through_serde() {
        let report = CrossNetworkPreflightReport {
            schema_version: 1,
            stun_observations: vec![StunServerObservation {
                server: "stun.example.test:3478".to_owned(),
                family: "v4",
                mapped_endpoint: Some(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                    51820,
                )),
                error: None,
            }],
            local_host_candidates: vec![LocalHostObservation {
                interface: "wg0".to_owned(),
                addr: IpAddr::V6(Ipv6Addr::new(0x2606, 0, 0, 0, 0, 0, 0, 1)),
                scope: "Global".to_owned(),
            }],
            relay_probe: Some(RelayProbeObservation {
                endpoint: "relay.example.test:51820".to_owned(),
                status: "reachable",
                latency_ms: Some(42),
                error: None,
            }),
            nat_class: NatClassHeuristic::ConeNatLikely,
            verdict: PreflightVerdict::DirectLikely,
            guidance: "cone NAT".to_owned(),
        };
        let json = render_json_report(&report);
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("rendered JSON must parse");
        assert_eq!(parsed["schema_version"], 1);
        assert_eq!(parsed["verdict"], "direct_likely");
        assert_eq!(parsed["nat_class"], "cone_nat_likely");
        assert_eq!(
            parsed["stun_observations"][0]["mapped_endpoint"],
            "203.0.113.5:51820"
        );
        assert_eq!(parsed["relay_probe"]["status"], "reachable");
        assert_eq!(parsed["relay_probe"]["latency_ms"], 42);
    }

    #[test]
    fn nat_class_classifies_symmetric_when_mapped_ips_differ() {
        let obs = vec![
            StunServerObservation {
                server: "a".to_owned(),
                family: "v4",
                mapped_endpoint: Some("198.51.100.5:51820".parse().unwrap()),
                error: None,
            },
            StunServerObservation {
                server: "b".to_owned(),
                family: "v4",
                mapped_endpoint: Some("203.0.113.7:51820".parse().unwrap()),
                error: None,
            },
        ];
        assert_eq!(classify_nat(&obs), NatClassHeuristic::SymmetricLikely);
    }

    #[test]
    fn nat_class_classifies_port_restricted_when_ports_differ_but_ips_match() {
        let obs = vec![
            StunServerObservation {
                server: "a".to_owned(),
                family: "v4",
                mapped_endpoint: Some("203.0.113.5:51820".parse().unwrap()),
                error: None,
            },
            StunServerObservation {
                server: "b".to_owned(),
                family: "v4",
                mapped_endpoint: Some("203.0.113.5:51999".parse().unwrap()),
                error: None,
            },
        ];
        assert_eq!(classify_nat(&obs), NatClassHeuristic::PortRestrictedLikely);
    }

    #[test]
    fn schema_version_is_pinned_at_one() {
        let config = CrossNetworkPreflightConfig::default();
        let report = run_cross_network_preflight(&config);
        assert_eq!(report.schema_version, 1);
    }
}
