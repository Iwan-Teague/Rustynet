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
//! wrappers (`netns_nat_classify.sh`, `netns_nat_filter.sh`) parse them unchanged.

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
    let rest = &args[args.len().min(1)..];
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
struct Flags {
    values: Vec<(String, String)>,
    bools: Vec<String>,
}

impl Flags {
    fn parse(args: &[String], bool_flags: &[&str]) -> Result<Self, String> {
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

/// Return the 12-byte transaction id if `buf` is a valid binding request.
fn valid_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
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

/// Parse the first (XOR-)MAPPED-ADDRESS attribute (IPv4) → (ip, port).
/// Mirrors the Python attribute walk incl. 4-byte alignment padding.
fn parse_mapped_address(buf: &[u8]) -> Result<(Ipv4Addr, u16), String> {
    let mut i = 20usize;
    while i + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let attr_len = u16::from_be_bytes([buf[i + 2], buf[i + 3]]) as usize;
        let start = i + 4;
        let end = (start + attr_len).min(buf.len());
        let val = &buf[start..end];
        if attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && val.len() >= 8 {
            let port = u16::from_be_bytes([val[2], val[3]]) ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
            let ip = Ipv4Addr::new(
                val[4] ^ cookie[0],
                val[5] ^ cookie[1],
                val[6] ^ cookie[2],
                val[7] ^ cookie[3],
            );
            return Ok((ip, port));
        }
        if attr_type == STUN_ATTR_MAPPED_ADDRESS && val.len() >= 8 {
            let port = u16::from_be_bytes([val[2], val[3]]);
            let ip = Ipv4Addr::new(val[4], val[5], val[6], val[7]);
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
        let Some(tx) = valid_binding_request(&buf[..n]) else {
            continue;
        };
        let resp = build_binding_response(&tx, addr);
        let _ = sock.send_to(&resp, addr);
    }
}

// ─── mode: nat-classify (was nat_probe.py) ───────────────────────────────────

fn stun_round_trip(
    sock: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<(Ipv4Addr, u16), String> {
    let tx = random_tx_id();
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("set timeout: {e}"))?;
    sock.send_to(&build_binding_request(&tx), server)
        .map_err(|e| format!("send: {e}"))?;
    let mut buf = [0u8; 1024];
    let (n, _from) = sock.recv_from(&mut buf).map_err(|e| format!("recv: {e}"))?;
    parse_mapped_address(&buf[..n])
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
            let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
            let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            if msg_type == STUN_BINDING_RESPONSE && cookie == STUN_MAGIC_COOKIE && buf[8..20] == tx
            {
                let m = parse_mapped_address(&buf[..n]).map_err(|e| format!("stun_failed={e}"))?;
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
}
