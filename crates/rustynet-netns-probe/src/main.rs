#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]
//! LAB TOOLING — not a shipped Rustynet product component.
//!
//! Rust-native replacement for the former Python netns probes used by the
//! `--node` cross-network suite's internet simulator:
//!   - `stun-responder`     ← `scripts/vm_lab/stun_responder.py`
//!   - `nat-classify`       ← `scripts/vm_lab/nat_probe.py`
//!   - `nat-filter-init`    ← `scripts/vm_lab/nat_filter_probe.py init`
//!   - `nat-filter-probe`   ← `scripts/vm_lab/nat_filter_probe.py probe`
//!
//! Why Rust: the cross-network suite deployed `.py` scripts and hard-required
//! `python3` on every lab guest, so the `--node` engine was not Python-free.
//! This binary is `std`-only (no external crates) so it builds OFFLINE on the
//! no-egress lab guests with zero cargo-cache additions, and it is NOT built by
//! `release.yml` (never ships in the product).
//!
//! Wire compatibility: the STUN encode/decode below is byte-identical to
//! `crates/rustynetd/src/stun_client.rs` (same magic cookie, same
//! XOR-MAPPED-ADDRESS layout per RFC 5389 §15.2) so the real client parses the
//! responder's replies unchanged. `#[cfg(test)]` pins the wire format against
//! fixed vectors so it cannot silently diverge (the Python versions had no such
//! pin). STDOUT lines are byte-identical to the Python scripts so the shell
//! Rust NAT gate (`stage/cross_network/netns.rs::run_nat_gates`, which replaced
//! the former `netns_nat_classify.sh` / `netns_nat_filter.sh` wrappers in CN-2)
//! parses them unchanged.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant};

const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_MAPPED_ADDRESS: u16 = 0x0001;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match mode {
        "stun-responder" => run_stun_responder(rest),
        "nat-classify" => run_nat_classify(rest),
        "nat-filter-init" => run_nat_filter_init(rest),
        "nat-filter-probe" => run_nat_filter_probe(rest),
        "-h" | "--help" | "help" | "" => {
            eprintln!(
                "rustynet-netns-probe (lab tooling)\n\
                 usage: rustynet-netns-probe <mode> [options]\n\
                 modes: stun-responder | nat-classify | nat-filter-init | nat-filter-probe"
            );
            return ExitCode::from(if mode.is_empty() { 2 } else { 0 });
        }
        other => Err(format!("unknown mode '{other}'")),
    };
    match result {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::FAILURE
        }
    }
}

// ─── tiny flag parser (std-only) ─────────────────────────────────────────────

/// Pull `--name value` (repeatable) and `--flag` (boolean) out of argv.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Flags {
    values: Vec<(String, String)>,
    bools: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], bool_flags: &[&str]) -> Result<Self, String> {
        let mut values = Vec::new();
        let mut bools = Vec::new();
        let mut i = 0;
        while let Some(a) = args.get(i) {
            if let Some(name) = a.strip_prefix("--") {
                if bool_flags.contains(&name) {
                    bools.push(name.to_owned());
                    i += 1;
                } else {
                    let v = args
                        .get(i + 1)
                        .ok_or_else(|| format!("flag --{name} requires a value"))?;
                    values.push((name.to_owned(), v.clone()));
                    i += 2;
                }
            } else {
                return Err(format!("unexpected argument '{a}'"));
            }
        }
        Ok(Flags { values, bools })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .rev()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
    fn get_all(&self, name: &str) -> Vec<&str> {
        self.values
            .iter()
            .filter(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
            .collect()
    }
    fn has(&self, name: &str) -> bool {
        self.bools.iter().any(|b| b == name)
    }
    fn get_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.get(name).unwrap_or(default)
    }
}

fn parse_f64(s: &str, what: &str) -> Result<f64, String> {
    s.parse::<f64>().map_err(|_| format!("invalid {what}: {s}"))
}
fn parse_u16(s: &str, what: &str) -> Result<u16, String> {
    s.parse::<u16>().map_err(|_| format!("invalid {what}: {s}"))
}
fn secs(v: f64) -> Duration {
    Duration::from_secs_f64(v.max(0.0))
}

/// Resolve `HOST:PORT` (HOST may be an IPv6 literal without brackets, matching
/// the Python `rsplit(":", 1)`).
fn parse_endpoint(value: &str) -> Result<SocketAddr, String> {
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| format!("expected HOST:PORT, got '{value}'"))?;
    let port: u16 = port.parse().map_err(|_| format!("bad port in '{value}'"))?;
    (host, port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve '{value}': {e}"))?
        .next()
        .ok_or_else(|| format!("no address for '{value}'"))
}

// ─── STUN wire (byte-identical to stun_client.rs) ────────────────────────────

/// Build a binding request: type(2) len(2)=0 cookie(4) tx_id(12).
fn build_binding_request(tx_id: &[u8; 12]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20);
    p.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    p.extend_from_slice(tx_id);
    p
}

/// Build a binding response carrying XOR-MAPPED-ADDRESS of `mapped`.
fn build_binding_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
    let xport = mapped.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    let mut attr_val = Vec::new();
    attr_val.push(0u8); // reserved
    match mapped.ip() {
        IpAddr::V4(v4) => {
            attr_val.push(0x01); // family IPv4
            attr_val.extend_from_slice(&xport.to_be_bytes());
            let raw = v4.octets();
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let x: [u8; 4] = [
                raw[0] ^ cookie[0],
                raw[1] ^ cookie[1],
                raw[2] ^ cookie[2],
                raw[3] ^ cookie[3],
            ];
            attr_val.extend_from_slice(&x);
        }
        IpAddr::V6(v6) => {
            attr_val.push(0x02); // family IPv6
            attr_val.extend_from_slice(&xport.to_be_bytes());
            // 16-byte key = magic cookie || tx_id (RFC 5389 §15.2)
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(tx_id);
            let raw = v6.octets();
            let mut x = [0u8; 16];
            for (x_byte, (raw_byte, key_byte)) in x.iter_mut().zip(raw.iter().zip(key.iter())) {
                *x_byte = raw_byte ^ key_byte;
            }
            attr_val.extend_from_slice(&x);
        }
    }
    let mut attr = Vec::new();
    attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    attr.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
    attr.extend_from_slice(&attr_val);

    let mut msg = Vec::new();
    msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(tx_id);
    msg.extend_from_slice(&attr);
    msg
}

/// Return the 12-byte transaction id if `buf` is a valid binding request.
fn valid_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < 20 {
        return None;
    }
    let [
        msg_0,
        msg_1,
        _,
        _,
        cookie_0,
        cookie_1,
        cookie_2,
        cookie_3,
        ..,
    ] = buf
    else {
        return None;
    };
    let msg_type = u16::from_be_bytes([*msg_0, *msg_1]);
    let cookie = u32::from_be_bytes([*cookie_0, *cookie_1, *cookie_2, *cookie_3]);
    if msg_type != STUN_BINDING_REQUEST || cookie != STUN_MAGIC_COOKIE {
        return None;
    }
    let mut tx = [0u8; 12];
    let src = buf.get(8..20)?;
    tx.copy_from_slice(src);
    Some(tx)
}

/// Parse the first (XOR-)MAPPED-ADDRESS attribute (IPv4) → (ip, port).
/// Byte-pinned to stun_client.rs parse_binding_response semantics: the
/// attribute walk is bounded by the DECLARED message length (bytes past it
/// are trailing garbage and must never fabricate a mapping), an attribute
/// that overruns that boundary fails the parse, and only family 0x01
/// (IPv4) is understood — anything else is rejected instead of misread.
fn parse_mapped_address(buf: &[u8]) -> Result<(Ipv4Addr, u16), String> {
    if buf.len() < 20 {
        return Err("response too short".to_owned());
    }
    let Some([_, _, declared_0, declared_1]) = buf.get(..4) else {
        return Err("response too short".to_owned());
    };
    let declared_len = u16::from_be_bytes([*declared_0, *declared_1]) as usize;
    let end = 20usize
        .checked_add(declared_len)
        .ok_or_else(|| "declared length overflow".to_owned())?;
    if buf.len() < end {
        return Err("truncated response".to_owned());
    }
    let mut i = 20usize;
    while i + 4 <= end {
        let Some(rest) = buf.get(i..) else {
            break;
        };
        let Some([type_0, type_1, len_0, len_1]) = rest.get(..4) else {
            break;
        };
        let attr_type = u16::from_be_bytes([*type_0, *type_1]);
        let attr_len = u16::from_be_bytes([*len_0, *len_1]) as usize;
        let start = i + 4;
        let attr_end = start
            .checked_add(attr_len)
            .ok_or_else(|| "stun attribute exceeds message boundary".to_owned())?;
        if attr_end > end {
            return Err("stun attribute exceeds message boundary".to_owned());
        }
        let Some(val) = buf.get(start..attr_end) else {
            continue;
        };
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS
            && let Some([_reserved, 0x01, port_0, port_1, ip_0, ip_1, ip_2, ip_3]) = val.get(..8)
        {
            let port = u16::from_be_bytes([*port_0, *port_1]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                *ip_0 ^ cookie[0],
                *ip_1 ^ cookie[1],
                *ip_2 ^ cookie[2],
                *ip_3 ^ cookie[3],
            );
            return Ok((ip, port));
        }
        if attr_type == STUN_ATTR_MAPPED_ADDRESS
            && let Some([_reserved, 0x01, port_0, port_1, ip_0, ip_1, ip_2, ip_3]) = val.get(..8)
        {
            let port = u16::from_be_bytes([*port_0, *port_1]);
            let ip = Ipv4Addr::new(*ip_0, *ip_1, *ip_2, *ip_3);
            return Ok((ip, port));
        }
        i += 4 + attr_len + ((4 - attr_len % 4) % 4);
    }
    Err("no mapped-address attribute in response".to_owned())
}

fn random_tx_id() -> [u8; 12] {
    // Non-crypto uniqueness is all a STUN tx_id needs here (lab tooling). Mix a
    // few entropy-ish sources without pulling in `rand` (keeps this std-only /
    // offline-buildable).
    let mut tx = [0u8; 12];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mut seed = now ^ (pid << 64) ^ (&tx as *const _ as u128);
    for b in tx.iter_mut() {
        // xorshift-ish
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *b = (seed & 0xff) as u8;
    }
    tx
}

// ─── mode: stun-responder ────────────────────────────────────────────────────

fn run_stun_responder(args: &[String]) -> Result<ExitCode, String> {
    let f = Flags::parse(args, &[])?;
    let bind = f.get_or("bind", "0.0.0.0").to_owned();
    let port = parse_u16(f.get_or("port", "3478"), "port")?;
    let ip: IpAddr = bind
        .parse()
        .map_err(|_| format!("invalid --bind address: {bind}"))?;
    let sock = UdpSocket::bind(SocketAddr::new(ip, port))
        .map_err(|e| format!("bind {bind}:{port}: {e}"))?;
    println!("stun-responder: listening on {bind}:{port}");
    let _ = std::io::stdout().flush();
    let mut buf = [0u8; 1024];
    loop {
        let (n, addr) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(packet) = buf.get(..n) else {
            continue;
        };
        let Some(tx) = valid_binding_request(packet) else {
            continue;
        };
        let resp = build_binding_response(&tx, addr);
        let _ = sock.send_to(&resp, addr);
    }
}

// ─── mode: nat-classify (was nat_probe.py) ───────────────────────────────────

/// Envelope check byte-pinned to stun_client.rs parse_binding_response:
/// only a binding response carrying our magic cookie AND echoing our
/// transaction id counts as ours. Anything else on the socket (stray lab
/// traffic, or a late duplicate from a previous query) must be discarded,
/// never parsed as a mapping.
fn is_our_binding_response(buf: &[u8], tx_id: &[u8; 12]) -> bool {
    if buf.len() < 20 {
        return false;
    }
    let [
        msg_0,
        msg_1,
        _,
        _,
        cookie_0,
        cookie_1,
        cookie_2,
        cookie_3,
        ..,
    ] = buf
    else {
        return false;
    };
    let msg_type = u16::from_be_bytes([*msg_0, *msg_1]);
    if msg_type != STUN_BINDING_RESPONSE {
        return false;
    }
    let cookie = u32::from_be_bytes([*cookie_0, *cookie_1, *cookie_2, *cookie_3]);
    cookie == STUN_MAGIC_COOKIE && buf.get(8..20).is_some_and(|src| src == tx_id.as_slice())
}

fn stun_round_trip(
    sock: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<(Ipv4Addr, u16), String> {
    let tx = random_tx_id();
    let deadline = Instant::now() + timeout;
    sock.send_to(&build_binding_request(&tx), server)
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 1500];
    // Demux like the stun_client.rs gather core: drop every datagram that is
    // not OUR binding response (wrong type / cookie / tx-id echo) and keep
    // listening until the deadline. Accepting the first datagram unvalidated
    // let stale or stray traffic fabricate NAT mappings.
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timed_out_err = || "recv: no matching binding response before timeout".to_owned();
        if remaining.is_zero() {
            return Err(timed_out_err());
        }
        sock.set_read_timeout(Some(remaining))
            .map_err(|e| format!("set timeout: {e}"))?;
        let (n, _from) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return Err(timed_out_err());
            }
            Err(e) => return Err(format!("recv: {e}")),
        };
        let Some(packet) = buf.get(..n) else {
            continue;
        };
        if !is_our_binding_response(packet, &tx) {
            continue;
        }
        return parse_mapped_address(packet);
    }
}

fn run_nat_classify(args: &[String]) -> Result<ExitCode, String> {
    let f = Flags::parse(args, &[])?;
    let timeout = secs(parse_f64(f.get_or("timeout", "3.0"), "timeout")?);
    let server_strs = f.get_all("stun");
    if server_strs.len() < 2 {
        eprintln!("need at least two --stun servers");
        return Ok(ExitCode::from(2));
    }
    let mut servers = Vec::new();
    for s in &server_strs {
        servers.push(parse_endpoint(s)?);
    }
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind ephemeral socket: {e}"))?;
    let mut mapped = Vec::new();
    for srv in &servers {
        match stun_round_trip(&sock, *srv, timeout) {
            Ok(m) => mapped.push(m),
            Err(e) => {
                eprintln!("probe failed: {e}");
                return Ok(ExitCode::FAILURE);
            }
        }
    }
    for (idx, (ip, port)) in mapped.iter().enumerate() {
        println!("mapped[{idx}]={ip}:{port}");
    }
    let distinct_ports: std::collections::BTreeSet<u16> = mapped.iter().map(|(_, p)| *p).collect();
    let behaviour = if distinct_ports.len() == 1 {
        "endpoint-independent"
    } else {
        "endpoint-dependent"
    };
    println!("mapping={behaviour}");
    Ok(ExitCode::SUCCESS)
}

// ─── mode: nat-filter-init / nat-filter-probe (was nat_filter_probe.py) ──────

fn write_text_atomic(path: &str, text: &str) -> Result<(), String> {
    let tmp = format!("{path}.tmp.{}", std::process::id());
    std::fs::write(&tmp, text).map_err(|e| format!("write {tmp}: {e}"))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("rename into {path}: {e}"))
}

fn run_nat_filter_init(args: &[String]) -> Result<ExitCode, String> {
    let f = Flags::parse(args, &["count-stun-response"])?;
    let bind_host = f.get_or("bind-host", "0.0.0.0").to_owned();
    let bind_port = parse_u16(f.get_or("bind-port", "51820"), "bind-port")?;
    let timeout = secs(parse_f64(f.get_or("timeout", "1.0"), "timeout")?);
    let listen_secs = parse_f64(f.get_or("listen-secs", "3.0"), "listen-secs")?;
    let bind_ip: IpAddr = bind_host
        .parse()
        .map_err(|_| format!("invalid --bind-host: {bind_host}"))?;
    let sock = UdpSocket::bind(SocketAddr::new(bind_ip, bind_port))
        .map_err(|e| format!("bind {bind_host}:{bind_port}: {e}"))?;

    let mut mapped = sock
        .local_addr()
        .map(|a| (a.ip().to_string(), a.port()))
        .unwrap_or_else(|_| (bind_host.clone(), bind_port));
    let mut received = false;
    let mut received_from = String::new();
    let mut detail = "none";

    if let Some(stun) = f.get("stun") {
        let server = parse_endpoint(stun)?;
        let tx = random_tx_id();
        sock.set_read_timeout(Some(timeout))
            .map_err(|e| format!("set timeout: {e}"))?;
        sock.send_to(&build_binding_request(&tx), server)
            .map_err(|e| format!("stun_failed={e}"))?;
        // Loop until our tx_id's binding response arrives (mirrors the Python).
        let (m, from) = loop {
            let mut buf = [0u8; 1024];
            let (n, addr) = sock
                .recv_from(&mut buf)
                .map_err(|e| format!("stun_failed={e}"))?;
            if n < 20 {
                continue;
            }
            let Some(packet) = buf.get(..n) else {
                continue;
            };
            let Some(
                [
                    msg_0,
                    msg_1,
                    _,
                    _,
                    cookie_0,
                    cookie_1,
                    cookie_2,
                    cookie_3,
                    ..,
                ],
            ) = packet.get(..8)
            else {
                continue;
            };
            let msg_type = u16::from_be_bytes([*msg_0, *msg_1]);
            let cookie = u32::from_be_bytes([*cookie_0, *cookie_1, *cookie_2, *cookie_3]);
            if msg_type == STUN_BINDING_RESPONSE
                && cookie == STUN_MAGIC_COOKIE
                && packet.get(8..20).is_some_and(|src| src == tx.as_slice())
            {
                let m = parse_mapped_address(packet).map_err(|e| format!("stun_failed={e}"))?;
                break ((m.0.to_string(), m.1), addr);
            }
        };
        mapped = m;
        if let Some(mf) = f.get("mapped-file") {
            write_text_atomic(mf, &format!("{}:{}\n", mapped.0, mapped.1))?;
        }
        if f.has("count-stun-response") {
            received = true;
            received_from = format!("{}:{}", from.ip(), from.port());
            detail = "stun_response";
        }
    } else if let Some(mf) = f.get("mapped-file") {
        write_text_atomic(mf, &format!("{}:{}\n", mapped.0, mapped.1))?;
    }

    let deadline = Instant::now() + secs(listen_secs);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait = remaining.min(timeout);
        if wait.is_zero() {
            break;
        }
        sock.set_read_timeout(Some(wait))
            .map_err(|e| format!("set timeout: {e}"))?;
        let mut buf = [0u8; 2048];
        match sock.recv_from(&mut buf) {
            Ok((_n, addr)) => {
                received = true;
                received_from = format!("{}:{}", addr.ip(), addr.port());
                detail = "udp_probe";
                break;
            }
            Err(_) => continue,
        }
    }

    println!(
        "mapped={}:{} received={} from={} detail={}",
        mapped.0,
        mapped.1,
        if received { "yes" } else { "no" },
        if received_from.is_empty() {
            "-"
        } else {
            &received_from
        },
        detail
    );
    let _ = std::io::stdout().flush();
    Ok(ExitCode::SUCCESS)
}

fn run_nat_filter_probe(args: &[String]) -> Result<ExitCode, String> {
    let f = Flags::parse(args, &[])?;
    let target_s = f
        .get("target")
        .ok_or_else(|| "nat-filter-probe requires --target HOST:PORT".to_owned())?;
    let bind_s = f
        .get("bind")
        .ok_or_else(|| "nat-filter-probe requires --bind HOST:PORT".to_owned())?;
    let count: u32 = f
        .get_or("count", "3")
        .parse()
        .map_err(|_| "invalid --count".to_owned())?;
    let delay = secs(parse_f64(f.get_or("delay", "0.05"), "delay")?);
    let payload = f.get_or("payload", "rustynet-nat-filter-probe").to_owned();
    let target = parse_endpoint(target_s)?;
    let bind = parse_endpoint(bind_s)?;
    let sock = UdpSocket::bind(bind).map_err(|e| format!("bind {bind}: {e}"))?;
    for _ in 0..count {
        sock.send_to(payload.as_bytes(), target)
            .map_err(|e| format!("send: {e}"))?;
        std::thread::sleep(delay);
    }
    println!(
        "sent={} bind={}:{} target={}:{}",
        count,
        bind.ip(),
        bind.port(),
        target.ip(),
        target.port()
    );
    let _ = std::io::stdout().flush();
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    // Pin the STUN wire format so it cannot silently diverge from
    // crates/rustynetd/src/stun_client.rs (the Python probes had no such pin).

    #[test]
    fn binding_request_is_20_bytes_with_cookie() {
        let tx = [0xABu8; 12];
        let req = build_binding_request(&tx);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), STUN_BINDING_REQUEST);
        assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0); // length
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            STUN_MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &tx);
    }

    #[test]
    fn v4_response_round_trips_through_parser() {
        let tx = [0x11u8; 12];
        let mapped = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51820);
        let resp = build_binding_response(&tx, mapped);
        // header: type + len + cookie + tx
        assert_eq!(
            u16::from_be_bytes([resp[0], resp[1]]),
            STUN_BINDING_RESPONSE
        );
        assert_eq!(
            u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]),
            STUN_MAGIC_COOKIE
        );
        let (ip, port) = parse_mapped_address(&resp).expect("parse");
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(port, 51820);
    }

    #[test]
    fn xor_mapped_port_masks_high_cookie_word() {
        // Fixed vector: the XOR-MAPPED port field is port ^ (cookie>>16).
        let tx = [0u8; 12];
        let resp = build_binding_response(
            &tx,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0x1234),
        );
        // attribute starts at offset 20: type(2) len(2) reserved(1) family(1) xport(2)...
        let xport = u16::from_be_bytes([resp[26], resp[27]]);
        assert_eq!(xport, 0x1234 ^ ((STUN_MAGIC_COOKIE >> 16) as u16));
    }

    #[test]
    fn valid_binding_request_rejects_wrong_cookie() {
        let mut req = build_binding_request(&[9u8; 12]);
        req[4] ^= 0xff; // corrupt cookie
        assert!(valid_binding_request(&req).is_none());
        assert!(valid_binding_request(&build_binding_request(&[9u8; 12])).is_some());
    }

    #[test]
    fn v6_response_uses_16_byte_key() {
        let tx = [0x22u8; 12];
        let mapped = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            9999,
        );
        let resp = build_binding_response(&tx, mapped);
        // family byte (offset 25) == 0x02 (IPv6); attr value length == 20 (1+1+2+16)
        assert_eq!(resp[25], 0x02);
        assert_eq!(u16::from_be_bytes([resp[22], resp[23]]), 20);
    }

    #[test]
    fn endpoint_parse_handles_ipv4() {
        let ep = parse_endpoint("198.18.0.254:3478").expect("parse");
        assert_eq!(ep.port(), 3478);
        assert_eq!(ep.ip(), IpAddr::V4(Ipv4Addr::new(198, 18, 0, 254)));
    }

    /// A datagram may carry bytes past its declared STUN message length
    /// (trailing garbage or an injected attribute). The parser must bound its
    /// attribute walk by the declared length — byte-pinned to stun_client.rs
    /// parse_binding_response ("stun attribute exceeds message boundary") —
    /// so appended bytes can never fabricate a mapping.
    #[test]
    fn mapped_address_parser_rejects_bytes_beyond_declared_length() {
        // Header declares length 0, yet a well-formed MAPPED-ADDRESS attr
        // follows at offset 20.
        let mut buf = Vec::new();
        buf.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // declared msg len = 0
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&[7u8; 12]);
        let mut attr = vec![0u8, 1]; // MAPPED-ADDRESS
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0); // reserved
        attr.push(0x01); // family IPv4
        attr.extend_from_slice(&1234u16.to_be_bytes());
        attr.extend_from_slice(&[203, 0, 113, 9]);
        buf.extend_from_slice(&attr);
        assert!(
            parse_mapped_address(&buf).is_err(),
            "attribute beyond the declared length must not be parsed as a mapping"
        );
    }

    /// XOR-MAPPED-ADDRESS with family 0x02 (IPv6) cannot be represented by
    /// this v4-only classifier; misreading its first address bytes as an
    /// IPv4 address would report a fabricated endpoint (the reference
    /// rejects unknown families fail-closed).
    #[test]
    fn mapped_address_parser_rejects_non_ipv4_family() {
        let tx = [0x33u8; 12];
        let v6 = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            51820,
        );
        let resp = build_binding_response(&tx, v6);
        if let Ok((ip, _)) = parse_mapped_address(&resp) {
            panic!("ipv6 xor-mapped attr misparsed as ipv4 {ip}");
        }
    }

    /// nat-classify shares one socket across servers and must demux like the
    /// reference gather core: a valid-looking binding response that does not
    /// echo OUR transaction id (stray traffic, or a late duplicate from a
    /// previous query) is discarded, and the matching response is awaited.
    #[test]
    fn nat_classify_round_trip_discards_datagrams_not_echoing_our_tx_id() {
        let responder = UdpSocket::bind("127.0.0.1:0").expect("bind responder");
        let stranger = UdpSocket::bind("127.0.0.1:0").expect("bind stranger");
        let client = UdpSocket::bind("127.0.0.1:0").expect("bind client");
        let responder_addr = responder.local_addr().expect("responder addr");
        let client_addr = client.local_addr().expect("client addr");

        // Pre-load the client path with a stray, structurally VALID binding
        // response whose tx id belongs to some other transaction.
        let stale_tx = [0xEEu8; 12];
        let stale = build_binding_response(
            &stale_tx,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66)), 11111),
        );
        stranger.send_to(&stale, client_addr).expect("send stale");

        // Responder answers the real request with the true mapping.
        let responder_sock = responder.try_clone().expect("clone responder");
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            if let Ok((n, from)) = responder_sock.recv_from(&mut buf)
                && let Some(tx) = valid_binding_request(&buf[..n])
            {
                let resp = build_binding_response(
                    &tx,
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 22222),
                );
                let _ = responder_sock.send_to(&resp, from);
            }
        });

        let (ip, port) =
            stun_round_trip(&client, responder_addr, Duration::from_secs(2)).expect("round trip");
        assert_eq!(ip, Ipv4Addr::new(203, 0, 113, 7));
        assert_eq!(port, 22222);
    }
}

// AQ-08 step 8 differential harness: every `old_*` function below is the
// verbatim pre-patch implementation (HEAD 207d991cc) whose indexing sites
// this step rewrote, renamed only. Each test runs the new and the old
// implementation over golden buffers plus seeded single-byte mutations and
// truncations and requires identical outputs.
#[cfg(test)]
mod aq08_step8_differential {
    use super::*;

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state >> 33
    }

    fn seeded_tx(state: &mut u64) -> [u8; 12] {
        let mut tx = [0u8; 12];
        for b in tx.iter_mut() {
            *b = (lcg(state) & 0xff) as u8;
        }
        tx
    }

    fn mutate(buf: &[u8], state: &mut u64) -> Vec<u8> {
        let mut m = buf.to_vec();
        if lcg(state) & 1 == 0 {
            if m.is_empty() {
                return m;
            }
            let idx = (lcg(state) as usize) % m.len();
            m[idx] = (lcg(state) & 0xff) as u8;
        } else {
            let cut = (lcg(state) as usize) % (m.len() + 1);
            m.truncate(cut);
        }
        m
    }

    fn old_flags_parse(args: &[String], bool_flags: &[&str]) -> Result<Flags, String> {
        let mut values = Vec::new();
        let mut bools = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let a = &args[i];
            if let Some(name) = a.strip_prefix("--") {
                if bool_flags.contains(&name) {
                    bools.push(name.to_owned());
                    i += 1;
                } else {
                    let v = args
                        .get(i + 1)
                        .ok_or_else(|| format!("flag --{name} requires a value"))?;
                    values.push((name.to_owned(), v.clone()));
                    i += 2;
                }
            } else {
                return Err(format!("unexpected argument '{a}'"));
            }
        }
        Ok(Flags { values, bools })
    }

    fn old_build_binding_response(tx_id: &[u8; 12], mapped: SocketAddr) -> Vec<u8> {
        let xport = mapped.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let mut attr_val = Vec::new();
        attr_val.push(0u8); // reserved
        match mapped.ip() {
            IpAddr::V4(v4) => {
                attr_val.push(0x01); // family IPv4
                attr_val.extend_from_slice(&xport.to_be_bytes());
                let raw = v4.octets();
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                let x: [u8; 4] = [
                    raw[0] ^ cookie[0],
                    raw[1] ^ cookie[1],
                    raw[2] ^ cookie[2],
                    raw[3] ^ cookie[3],
                ];
                attr_val.extend_from_slice(&x);
            }
            IpAddr::V6(v6) => {
                attr_val.push(0x02); // family IPv6
                attr_val.extend_from_slice(&xport.to_be_bytes());
                // 16-byte key = magic cookie || tx_id (RFC 5389 §15.2)
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                key[4..].copy_from_slice(tx_id);
                let raw = v6.octets();
                let mut x = [0u8; 16];
                for i in 0..16 {
                    x[i] = raw[i] ^ key[i];
                }
                attr_val.extend_from_slice(&x);
            }
        }
        let mut attr = Vec::new();
        attr.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&(attr_val.len() as u16).to_be_bytes());
        attr.extend_from_slice(&attr_val);

        let mut msg = Vec::new();
        msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
        msg.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(tx_id);
        msg.extend_from_slice(&attr);
        msg
    }

    fn old_valid_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
        if buf.len() < 20 {
            return None;
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if msg_type != STUN_BINDING_REQUEST || cookie != STUN_MAGIC_COOKIE {
            return None;
        }
        let mut tx = [0u8; 12];
        tx.copy_from_slice(&buf[8..20]);
        Some(tx)
    }

    fn old_parse_mapped_address(buf: &[u8]) -> Result<(Ipv4Addr, u16), String> {
        if buf.len() < 20 {
            return Err("response too short".to_owned());
        }
        let declared_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let end = 20usize
            .checked_add(declared_len)
            .ok_or_else(|| "declared length overflow".to_owned())?;
        if buf.len() < end {
            return Err("truncated response".to_owned());
        }
        let mut i = 20usize;
        while i + 4 <= end {
            let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
            let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
            let start = i + 4;
            let attr_end = start
                .checked_add(attr_len)
                .ok_or_else(|| "stun attribute exceeds message boundary".to_owned())?;
            if attr_end > end {
                return Err("stun attribute exceeds message boundary".to_owned());
            }
            let val = &buf[start..attr_end];
            if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && val.len() >= 8 && val[1] == 0x01 {
                let port =
                    u16::from_be_bytes([val[2], val[3]]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                let ip = Ipv4Addr::new(
                    val[4] ^ cookie[0],
                    val[5] ^ cookie[1],
                    val[6] ^ cookie[2],
                    val[7] ^ cookie[3],
                );
                return Ok((ip, port));
            }
            if attr_type == STUN_ATTR_MAPPED_ADDRESS && val.len() >= 8 && val[1] == 0x01 {
                let port = u16::from_be_bytes([val[2], val[3]]);
                let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
                return Ok((ip, port));
            }
            i += 4 + attr_len + ((4 - attr_len % 4) % 4);
        }
        Err("no mapped-address attribute in response".to_owned())
    }

    fn old_is_our_binding_response(buf: &[u8], tx_id: &[u8; 12]) -> bool {
        if buf.len() < 20 {
            return false;
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        if msg_type != STUN_BINDING_RESPONSE {
            return false;
        }
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        cookie == STUN_MAGIC_COOKIE && buf[8..20] == *tx_id
    }

    fn seeded_addr(state: &mut u64) -> SocketAddr {
        if lcg(state) & 1 == 0 {
            SocketAddr::from((
                [
                    (lcg(state) & 0xff) as u8,
                    (lcg(state) & 0xff) as u8,
                    (lcg(state) & 0xff) as u8,
                    (lcg(state) & 0xff) as u8,
                ],
                (lcg(state) & 0xffff) as u16,
            ))
        } else {
            let mut o = [0u16; 8];
            for h in o.iter_mut() {
                *h = (lcg(state) & 0xffff) as u16;
            }
            SocketAddr::from((
                std::net::Ipv6Addr::new(o[0], o[1], o[2], o[3], o[4], o[5], o[6], o[7]),
                (lcg(state) & 0xffff) as u16,
            ))
        }
    }

    #[test]
    fn build_binding_response_differential() {
        let mut state = 0x0a08_0001u64;
        for _ in 0..3000 {
            let tx = seeded_tx(&mut state);
            let addr = seeded_addr(&mut state);
            assert_eq!(
                build_binding_response(&tx, addr),
                old_build_binding_response(&tx, addr),
                "build_binding_response diverged for {addr}"
            );
        }
    }

    #[test]
    fn valid_binding_request_differential() {
        let mut state = 0x0a08_0002u64;
        let tx = seeded_tx(&mut state);
        let golden = build_binding_request(&tx);
        assert_eq!(valid_binding_request(&golden), Some(tx));
        for _ in 0..3000 {
            let m = mutate(&golden, &mut state);
            assert_eq!(
                valid_binding_request(&m),
                old_valid_binding_request(&m),
                "valid_binding_request diverged on {m:?}"
            );
        }
    }

    #[test]
    fn parse_mapped_address_differential() {
        let mut state = 0x0a08_0003u64;
        let tx = seeded_tx(&mut state);
        let mapped: SocketAddr = "198.18.0.9:3478".parse().unwrap();
        let golden_xor = build_binding_response(&tx, mapped);
        assert_eq!(
            parse_mapped_address(&golden_xor),
            Ok(("198.18.0.9".parse().unwrap(), 3478))
        );
        // Plain (non-XOR) MAPPED-ADDRESS golden.
        let mut golden_plain = Vec::new();
        golden_plain.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        golden_plain.extend_from_slice(&12u16.to_be_bytes());
        golden_plain.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        golden_plain.extend_from_slice(&tx);
        let mut attr = Vec::new();
        attr.extend_from_slice(&STUN_ATTR_MAPPED_ADDRESS.to_be_bytes());
        attr.extend_from_slice(&8u16.to_be_bytes());
        attr.push(0u8);
        attr.push(0x01);
        attr.extend_from_slice(&3478u16.to_be_bytes());
        attr.extend_from_slice(&[203, 0, 113, 7]);
        golden_plain.extend_from_slice(&attr);
        assert_eq!(
            parse_mapped_address(&golden_plain),
            Ok(("203.0.113.7".parse().unwrap(), 3478))
        );
        assert_eq!(
            old_parse_mapped_address(&golden_plain),
            Ok(("203.0.113.7".parse().unwrap(), 3478))
        );
        for golden in [&golden_xor, &golden_plain] {
            for _ in 0..3000 {
                let m = mutate(golden, &mut state);
                assert_eq!(
                    parse_mapped_address(&m),
                    old_parse_mapped_address(&m),
                    "parse_mapped_address diverged on {m:?}"
                );
            }
        }
        // IPv6 response must be rejected identically by both.
        let tx6 = seeded_tx(&mut state);
        let v6 = build_binding_response(&tx6, "[2001:db8::1]:3478".parse().unwrap());
        assert_eq!(parse_mapped_address(&v6), old_parse_mapped_address(&v6));
    }

    #[test]
    fn is_our_binding_response_differential() {
        let mut state = 0x0a08_0004u64;
        let tx = seeded_tx(&mut state);
        let golden = build_binding_response(&tx, "198.18.0.9:3478".parse().unwrap());
        assert!(is_our_binding_response(&golden, &tx));
        for _ in 0..3000 {
            let m = mutate(&golden, &mut state);
            assert_eq!(
                is_our_binding_response(&m, &tx),
                old_is_our_binding_response(&m, &tx),
                "is_our_binding_response diverged on {m:?}"
            );
        }
    }

    #[test]
    fn flags_parse_differential() {
        let mut state = 0x0a08_0005u64;
        let bool_flags = ["auto", "odd"];
        let tokens = [
            "--profile",
            "quick",
            "--auto",
            "--bind",
            "1.2.3.4:9",
            "--odd",
            "--lonely",
        ];
        for _ in 0..2000 {
            let mut args: Vec<String> = Vec::new();
            for _ in 0..((lcg(&mut state) % 6) as usize) {
                args.push(tokens[(lcg(&mut state) as usize) % tokens.len()].to_owned());
            }
            assert_eq!(
                Flags::parse(&args, &bool_flags),
                old_flags_parse(&args, &bool_flags),
                "Flags::parse diverged on {args:?}"
            );
        }
        assert_eq!(
            Flags::parse(&[], &bool_flags),
            old_flags_parse(&[], &bool_flags)
        );
    }
}
