#![allow(dead_code)]
//! Linux exit-node egress leak witness (AQ-46) for the standard orchestrator.
//!
//! While the exit killswitch (commit `5093ac97`) scopes its DNS/DoT drops to
//! the egress interface and emits no IPv6 accept, that ruleset is NOT PROVEN
//! until lab-witnessed: this validator captures the exit's egress NIC with
//! `tcpdump` during a bounded window while host-origin DNS/DoT/IPv6 probes and
//! a client positive control run, then classifies every packet. The egress NIC
//! must carry zero host-origin udp/53, tcp/53, tcp/853, or IPv6, while
//! masqueraded client ICMP to 192.0.2.1 and WireGuard udp on the listen port
//! are present — any leak class, or a vacuous capture, fails closed.
//!
//! All remote execution is argv-only through the [`RemoteShellHost`] seam:
//! the tcpdump filter is passed as separate argv tokens and every probe target
//! is a compile-time constant, so no remote value is ever concatenated into a
//! shell string.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_validation::discover_single_generated_nft_table;
use std::sync::Arc;

/// Test-net documentation target the host-origin DNS probes are fired at.
/// RFC 5737 / RFC 5737-adjacent reserved space: nothing answers, so the probes
/// are expected to fail locally — their exit codes are recorded, not errors.
pub const WITNESS_DNS_TARGET: &str = "192.0.2.53";
/// Test-net target for the masqueraded client ICMP positive control.
pub const WITNESS_ICMP_TARGET: &str = "192.0.2.1";
/// Documentation-only IPv6 target for the host-origin IPv6 attempt.
pub const WITNESS_IPV6_TARGET: &str = "2001:db8::53";
/// DoT port witnessed alongside udp/tcp 53.
pub const WITNESS_DOT_PORT: u16 = 853;

/// Live capture window in seconds. The tcpdump side is bounded by
/// `timeout` regardless of this value, so a stalled transport cannot hang
/// the stage.
pub const CAPTURE_WINDOW_SECS: u64 = 20;
/// Settle delay after tcpdump starts before probes fire, so early packets
/// are inside the window.
pub const CAPTURE_SETTLE_SECS: u64 = 3;
/// `timeout --kill-after` grace applied after the capture window.
const CAPTURE_KILL_AFTER_SECS: u64 = 5;
/// Per-probe `timeout` bound in seconds. On a correctly-protected exit the
/// scoped `tcp dport { 53, 853 } drop` silently eats SYNs instead of
/// rejecting them, so an unbounded `/dev/tcp` connect would hang for the
/// default `tcp_syn_retries=6` (~129s) and push every later probe — and the
/// client positive control — outside the capture window.
pub const PROBE_TIMEOUT_SECS: u64 = 4;

/// Per-class packet tallies for the egress capture. Every count zero except
/// `forwarded_icmp`/`wireguard` is the pass shape.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct LeakWitnessCounts {
    pub host_dns_udp: u32,
    pub host_dns_tcp: u32,
    pub host_dot: u32,
    pub ipv6: u32,
    pub forwarded_icmp: u32,
    pub wireguard: u32,
}

impl LeakWitnessCounts {
    pub fn as_json_fields(&self) -> String {
        format!(
            "host_dns_udp={} host_dns_tcp={} host_dot={} ipv6={} forwarded_icmp={} wireguard={}",
            self.host_dns_udp,
            self.host_dns_tcp,
            self.host_dot,
            self.ipv6,
            self.forwarded_icmp,
            self.wireguard
        )
    }
}

/// Full witness report for one capture window: posture + capture context,
/// per-class counts, probe exit codes, raw capture text, and the fail-closed
/// verdict reasons (empty means the witness passed).
#[derive(Debug, Clone)]
pub struct LeakWitnessReport {
    pub exit_alias: String,
    pub egress_iface: String,
    pub egress_addr: String,
    pub killswitch_table: String,
    pub wg_listen_port: u16,
    pub capture_filter: String,
    pub counts: LeakWitnessCounts,
    pub probe_exit_codes: Vec<(String, i32)>,
    pub capture_stdout: String,
    pub capture_stderr: String,
    pub failures: Vec<String>,
}

pub fn exit_egress_leak_witness_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Detect the default egress interface from `ip route show default`.
fn detect_linux_egress_interface(shell: &dyn RemoteShellHost) -> Result<String, String> {
    let out = shell
        .run_argv(&["ip", "route", "show", "default"], &[], &[])
        .map_err(|err| format!("failed to query default route for egress interface: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == "dev")
            && let Some(iface) = parts.get(pos + 1)
        {
            return Ok(iface.to_string());
        }
    }
    Err("default egress interface not found in `ip route show default` output".to_owned())
}

/// Fail-closed posture precondition: the active generated killswitch table
/// must carry the egress-scoped DNS/DoT drop rules the scoped ruleset emits
/// when `protected_dns` is on — udp dport {53,853} drop AND tcp dport
/// {53,853} drop, both scoped to `oifname "<egress>"` with
/// `meta nfproto ipv4`. A missing rule is named in the error (never a
/// silent pass over absent posture). Returns the table listing, which the
/// witness also reads the WireGuard listen port from.
fn verify_scoped_dns_drop_rules(
    shell: &dyn RemoteShellHost,
    egress_iface: &str,
    table: &str,
) -> Result<String, String> {
    let argv: [&str; 7] = ["sudo", "-n", "nft", "list", "table", "inet", table];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to list killswitch table {table}: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "nft list table inet {table} exited {}; posture unverifiable, failing closed",
            out.code
        ));
    }
    let oifname = format!("oifname \"{egress_iface}\"");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut found_udp = false;
    let mut found_tcp = false;
    for line in stdout.lines() {
        let collapsed = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !collapsed.contains(&oifname)
            || !collapsed.contains("meta nfproto ipv4")
            || !collapsed.contains("drop")
        {
            continue;
        }
        if collapsed.contains("udp dport")
            && collapsed.contains('{')
            && collapsed.contains("53,")
            && collapsed.contains("853")
            && collapsed.contains('}')
        {
            found_udp = true;
        }
        if collapsed.contains("tcp dport")
            && collapsed.contains('{')
            && collapsed.contains("53,")
            && collapsed.contains("853")
            && collapsed.contains('}')
        {
            found_tcp = true;
        }
    }
    if !found_udp {
        return Err(format!(
            "posture precondition failed: killswitch table inet {table} is missing the \
             egress-scoped drop rule `oifname \"{egress_iface}\" meta nfproto ipv4 udp dport \
             {{ 53, 853 }} drop` (protected_dns posture absent) — failing closed"
        ));
    }
    if !found_tcp {
        return Err(format!(
            "posture precondition failed: killswitch table inet {table} is missing the \
             egress-scoped drop rule `oifname \"{egress_iface}\" meta nfproto ipv4 tcp dport \
             {{ 53, 853 }} drop` (protected_dns posture absent) — failing closed"
        ));
    }
    Ok(stdout.into_owned())
}

/// Detect the exit's own IPv4 address on the egress interface — the source
/// address host-origin leaks and masqueraded client traffic both carry.
fn detect_egress_ipv4(shell: &dyn RemoteShellHost, iface: &str) -> Result<String, String> {
    let argv = ["ip", "-4", "addr", "show", "dev", iface];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to read addresses on {iface}: {err}"))?;
    if out.code != 0 {
        return Err(format!("`ip -4 addr show dev {iface}` exited {}", out.code));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(pos) = parts.iter().position(|p| *p == "inet")
            && let Some(addr_cidr) = parts.get(pos + 1)
        {
            if let Some(addr) = addr_cidr.split('/').next() {
                if !addr.is_empty() {
                    return Ok(addr.to_string());
                }
            }
        }
    }
    Err(format!(
        "no IPv4 `inet <addr>/` entry found on egress interface {iface}"
    ))
}

/// The WireGuard listen port, read from the killswitch table the posture
/// check already listed. Rustynet's data plane does not expose its WireGuard
/// socket to the `wg` tool (`wg show` prints nothing on a live exit, run
/// linux-u12b), but the daemon's killswitch allows the port it listens on as a
/// pair on the egress interface (phase10 `wg_listen_port_allow_tokens`):
/// `oifname "<egress>" meta nfproto ipv4 udp dport <port> accept` and the same
/// with `sport`. The port is the one value that has both halves. Zero or
/// several such ports fail closed: WireGuard presence would be unwitnessable.
fn wg_listen_port_from_killswitch_listing(
    listing: &str,
    egress_iface: &str,
) -> Result<u16, String> {
    let oifname = format!("oifname \"{egress_iface}\"");
    let mut dports: Vec<u16> = Vec::new();
    let mut sports: Vec<u16> = Vec::new();
    for line in listing.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let collapsed = tokens.join(" ");
        if !collapsed.contains(&oifname)
            || !collapsed.contains("meta nfproto ipv4 udp")
            || tokens.last() != Some(&"accept")
        {
            continue;
        }
        for (idx, token) in tokens.iter().enumerate() {
            let bucket = match *token {
                "dport" => &mut dports,
                "sport" => &mut sports,
                _ => continue,
            };
            if idx.checked_sub(1).and_then(|prev| tokens.get(prev)) == Some(&"udp")
                && let Some(port) = tokens.get(idx + 1).and_then(|p| p.parse::<u16>().ok())
                && port != 0
                && tokens.get(idx + 2) == Some(&"accept")
            {
                bucket.push(port);
            }
        }
    }
    let mut paired: Vec<u16> = dports.into_iter().filter(|p| sports.contains(p)).collect();
    paired.sort_unstable();
    paired.dedup();
    match paired.as_slice() {
        [port] => Ok(*port),
        [] => Err(format!(
            "could not determine the WireGuard listen port: the killswitch table has no \
             `oifname \"{egress_iface}\" meta nfproto ipv4 udp dport/sport <port> accept` pair — \
             WireGuard presence is unwitnessable, failing closed"
        )),
        several => Err(format!(
            "could not determine the WireGuard listen port: the killswitch table carries \
             several udp dport/sport accept pairs on {egress_iface} ({several:?}) — ambiguous, \
             failing closed"
        )),
    }
}

/// The MAC address of the exit's egress NIC, from `ip -brief link show dev
/// <iface>` (third field). The IPv6 clause of the capture filter is scoped to
/// frames this NIC sends: tcpdump captures promiscuously, and on a bridged LAN
/// (lenovo-bot's guests) it also sees other devices' IPv6 neighbour
/// solicitations, which run lenovo-u16l counted as three IPv6 "leaks" from an
/// exit that has no IPv6 address at all. Fails closed on anything that is not a
/// plain `xx:xx:xx:xx:xx:xx` MAC.
fn detect_egress_mac(shell: &dyn RemoteShellHost, iface: &str) -> Result<String, String> {
    let argv = ["ip", "-brief", "link", "show", "dev", iface];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("failed to read the link address of {iface}: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "`ip -brief link show dev {iface}` exited {}",
            out.code
        ));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mac = stdout
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or_default()
        .to_ascii_lowercase();
    if is_plain_mac(&mac) {
        Ok(mac)
    } else {
        Err(format!(
            "could not read a MAC address for egress interface {iface} (got {mac:?}) — the \
             IPv6 witness cannot be scoped to frames this exit sends, failing closed"
        ))
    }
}

fn is_plain_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();
    parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The tcpdump capture filter, as separate argv tokens (never a shell string):
/// IPv4 host-origin DNS/DoT ports, ICMP (masqueraded client control) and the
/// WireGuard listen port, plus IPv6 SENT BY the egress NIC (`egress_mac`).
///
/// The port clauses are IPv4-only on purpose. `classify_capture` counts every
/// captured IPv6 line as a leak, and `udp port 53` alone also matches IPv6, so
/// on a bridged LAN a neighbour's IPv6 DNS would count against this exit. The
/// exit's own IPv6 is still captured, by the MAC-scoped clause. pcap `and` and
/// `or` have equal precedence and group left to right, hence the explicit
/// parentheses.
fn capture_filter_tokens(wg_port: u16, egress_mac: &str) -> Vec<String> {
    vec![
        "(".to_owned(),
        "ip".to_owned(),
        "and".to_owned(),
        "(".to_owned(),
        "udp".to_owned(),
        "port".to_owned(),
        "53".to_owned(),
        "or".to_owned(),
        "tcp".to_owned(),
        "port".to_owned(),
        "53".to_owned(),
        "or".to_owned(),
        "tcp".to_owned(),
        "port".to_owned(),
        WITNESS_DOT_PORT.to_string(),
        "or".to_owned(),
        "icmp".to_owned(),
        "or".to_owned(),
        "udp".to_owned(),
        "port".to_owned(),
        wg_port.to_string(),
        ")".to_owned(),
        ")".to_owned(),
        "or".to_owned(),
        "(".to_owned(),
        "ip6".to_owned(),
        "and".to_owned(),
        "ether".to_owned(),
        "src".to_owned(),
        egress_mac.to_owned(),
        ")".to_owned(),
    ]
}

/// A stdout line that is tcpdump banner/chatter, never a packet: the same
/// whitelist the chaos daemon-fault tally uses
/// (`^(tcpdump:|listening on|capture_provenance=|$)`), so banner text can
/// never be counted as a packet.
fn is_capture_banner_line(line: &str) -> bool {
    let t = line.trim();
    t.is_empty()
        || t.starts_with("tcpdump:")
        || t.starts_with("listening on")
        || t.starts_with("capture_provenance=")
}

/// stderr line classification mirroring the chaos daemon-fault whitelist:
/// `dropped privs to `, `listening on `, and the numeric packet tallies
/// (`N packets captured` / `N packets received by filter` / `N packets
/// dropped by kernel`) are benign; anything else is a tcpdump error.
/// tcpdump 4.99+ prints the captured/received tally lines with a wall-clock
/// prefix (`12:00:20.000000 5 packets captured`), so a leading
/// `<HH:MM:SS.uS>` timestamp token is stripped before the tally check —
/// nothing else about the whitelist is widened.
/// The `tcpdump: listening on` banner form is treated as benign only because
/// the caller separately requires the `listening on ` banner to be present —
/// every other `tcpdump: ...` line (real errors) stays non-benign and fails
/// the stage.
fn is_benign_tcpdump_stderr_line(line: &str) -> bool {
    let t = line.trim();
    // tcpdump 4.99 prints this notice to stderr on every run without -v
    // (run katana-u13 failed the witness on exactly this line); matched
    // exactly, as the chaos daemon-fault tally does (b73c39aa9).
    if t.is_empty()
        || t.starts_with("dropped privs to ")
        || t.starts_with("listening on ")
        || t.starts_with("tcpdump: listening on ")
        || t == "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode"
    {
        return true;
    }
    let t = match strip_tcpdump_summary_timestamp(t) {
        Some(rest) => rest,
        None => t,
    };
    let toks: Vec<&str> = t.split_whitespace().collect();
    if toks.len() < 3 {
        return false;
    }
    let first = toks[0];
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) || toks[1] != "packets" {
        return false;
    }
    match toks[2] {
        "captured" => true,
        "received" => toks.len() >= 5 && toks[3] == "by" && toks[4] == "filter",
        "dropped" => toks.len() >= 5 && toks[3] == "by" && toks[4] == "kernel",
        _ => false,
    }
}

/// If `line` starts with a tcpdump summary timestamp token
/// (`HH:MM:SS.microseconds`, digits separated by `:` and `.` only), return
/// the remainder after it; otherwise None.
fn strip_tcpdump_summary_timestamp(line: &str) -> Option<&str> {
    let (head, rest) = line.split_once(' ')?;
    if head.is_empty()
        || !head
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b':' || b == b'.')
        || !head.contains(':')
        || !head.contains('.')
    {
        return None;
    }
    Some(rest)
}

/// Split a tcpdump `addr.port` endpoint token (or bare IPv4) into its parts.
/// IPv6 literals (containing `:`) return None — they are classified by the
/// `IP6` marker before endpoint parsing.
fn split_v4_addr_port(token: &str) -> Option<(&str, Option<u16>)> {
    if token.contains(':') {
        return None;
    }
    let segs: Vec<&str> = token.split('.').collect();
    match segs.len() {
        4 => Some((token, None)),
        5 => {
            let port_str = segs[4];
            if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let port: u16 = port_str.parse().ok()?;
            let addr_len = token.len() - port_str.len() - 1;
            Some((&token[..addr_len], Some(port)))
        }
        _ => None,
    }
}

/// Parse the `<src> > <dst>` endpoint pair out of a tcpdump -nn IPv4 packet
/// line (the span between the `IP ` marker and the `: ` details delimiter).
fn parse_v4_packet_endpoints(line: &str) -> Option<(String, Option<u16>, String, Option<u16>)> {
    let marker = line.find(" IP ")?;
    let rest = &line[marker + 4..];
    let end = rest.find(": ")?;
    let endpoints = &rest[..end];
    let (src_tok, dst_tok) = endpoints.split_once(" > ")?;
    let (src_ip, src_port) = split_v4_addr_port(src_tok.trim())?;
    let (dst_ip, dst_port) = split_v4_addr_port(dst_tok.trim())?;
    Some((src_ip.to_owned(), src_port, dst_ip.to_owned(), dst_port))
}

/// Classify every packet line of the capture into the witness classes.
/// Banner lines are skipped (never counted); anything unparseable is ignored
/// by classification but the capture-level checks (banner present, stderr
/// clean) fail the stage independently.
fn classify_capture(stdout: &str, egress_addr: &str, wg_port: u16) -> LeakWitnessCounts {
    let mut counts = LeakWitnessCounts::default();
    for line in stdout.lines() {
        if is_capture_banner_line(line) {
            continue;
        }
        let trimmed = line.trim_start();
        if trimmed.starts_with("IP6 ") || trimmed.contains(" IP6 ") {
            counts.ipv6 += 1;
            continue;
        }
        let Some((src_ip, src_port, dst_ip, dst_port)) = parse_v4_packet_endpoints(line) else {
            continue;
        };
        if src_ip == egress_addr {
            if dst_port == Some(WITNESS_DOT_PORT) {
                counts.host_dot += 1;
                continue;
            }
            if dst_port == Some(53) {
                if line.contains("Flags") {
                    counts.host_dns_tcp += 1;
                } else {
                    counts.host_dns_udp += 1;
                }
                continue;
            }
            if dst_ip == WITNESS_ICMP_TARGET && line.contains("ICMP") {
                counts.forwarded_icmp += 1;
                continue;
            }
        }
        if src_port == Some(wg_port) || dst_port == Some(wg_port) {
            counts.wireguard += 1;
        }
    }
    counts
}

/// Fail-closed verdict over the per-class counts: any leak class above zero
/// fails naming the class and count; a missing masqueraded ICMP control or
/// missing WireGuard traffic makes the witness vacuous and fails.
pub fn evaluate_leak_witness(
    counts: &LeakWitnessCounts,
    egress_iface: &str,
    wg_port: u16,
) -> Vec<String> {
    let mut failures = Vec::new();
    if counts.host_dns_udp > 0 {
        failures.push(format!(
            "egress leak: {} host-origin udp/53 packet(s) left {egress_iface}",
            counts.host_dns_udp
        ));
    }
    if counts.host_dns_tcp > 0 {
        failures.push(format!(
            "egress leak: {} host-origin tcp/53 packet(s) left {egress_iface}",
            counts.host_dns_tcp
        ));
    }
    if counts.host_dot > 0 {
        failures.push(format!(
            "egress leak: {} host-origin tcp/853 (DoT) packet(s) left {egress_iface}",
            counts.host_dot
        ));
    }
    if counts.ipv6 > 0 {
        failures.push(format!(
            "egress leak: {} IPv6 packet(s) left {egress_iface} (killswitch emits no IPv6 \
             accept; any IPv6 egress is a leak)",
            counts.ipv6
        ));
    }
    if counts.forwarded_icmp == 0 {
        failures.push(format!(
            "vacuous witness: no masqueraded client ICMP to {WITNESS_ICMP_TARGET} from the \
             exit egress address was captured — the forwarded-traffic positive control is \
             absent, the zero-leak counts prove nothing"
        ));
    }
    if counts.wireguard == 0 {
        failures.push(format!(
            "vacuous witness: no WireGuard udp/{wg_port} traffic was captured — the tunnel \
             control is absent, the zero-leak counts prove nothing"
        ));
    }
    failures
}

/// Run the host-origin probes on the exit, recording every exit code (the
/// probes are expected to fail locally — the codes are evidence, transport
/// failures are recorded as -1). `dig` is preferred for udp/53 when present
/// (exit code 127 = missing); the fallback is a constant bash `/dev/udp`
/// poke with no interpolation, so the argv seam stays intact on distros
/// without dnsutils/bind-utils. The bash pokes are bounded by `timeout`
/// (`PROBE_TIMEOUT_SECS`) because a silent drop never completes the
/// connect, and every probe must land inside the capture window.
fn run_host_origin_probes(shell: &dyn RemoteShellHost) -> Vec<(String, i32)> {
    let mut codes: Vec<(String, i32)> = Vec::new();
    let dig_target = format!("@{WITNESS_DNS_TARGET}");
    let dot_url = format!("https://{WITNESS_DNS_TARGET}:{WITNESS_DOT_PORT}");
    let dig_argv = [
        "dig",
        "+time=2",
        "+tries=1",
        dig_target.as_str(),
        "rustynet-witness.invalid",
        "A",
    ];
    match shell.run_argv(&dig_argv, &[], &[]) {
        Ok(out) => {
            codes.push(("host_dns_udp_dig".to_owned(), out.code));
            if out.code == 127 {
                let fallback: Vec<String> = vec![
                    "timeout".to_owned(),
                    PROBE_TIMEOUT_SECS.to_string(),
                    "bash".to_owned(),
                    "-c".to_owned(),
                    "exec 3<> /dev/udp/192.0.2.53/53".to_owned(),
                ];
                let argv_refs: Vec<&str> = fallback.iter().map(String::as_str).collect();
                let code = shell
                    .run_argv(&argv_refs, &[], &[])
                    .map(|out| out.code)
                    .unwrap_or(-1);
                codes.push(("host_dns_udp_devudp_fallback".to_owned(), code));
            }
        }
        Err(_) => codes.push(("host_dns_udp_dig".to_owned(), -1)),
    }
    let tcp_argv: Vec<String> = vec![
        "timeout".to_owned(),
        PROBE_TIMEOUT_SECS.to_string(),
        "bash".to_owned(),
        "-c".to_owned(),
        "exec 3<> /dev/tcp/192.0.2.53/53".to_owned(),
    ];
    let tcp_argv_refs: Vec<&str> = tcp_argv.iter().map(String::as_str).collect();
    let tcp_code = shell
        .run_argv(&tcp_argv_refs, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_dns_tcp_devtcp".to_owned(), tcp_code));
    let dot_argv = [
        "curl",
        "--connect-timeout",
        "3",
        "-sS",
        "-o",
        "/dev/null",
        dot_url.as_str(),
    ];
    let dot_code = shell
        .run_argv(&dot_argv, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_dot_curl".to_owned(), dot_code));
    let v6_argv = ["ping", "-6", "-c", "1", "-W", "2", WITNESS_IPV6_TARGET];
    let v6_code = shell
        .run_argv(&v6_argv, &[], &[])
        .map(|out| out.code)
        .unwrap_or(-1);
    codes.push(("host_ipv6_ping".to_owned(), v6_code));
    codes
}

/// Run the full Linux exit egress leak witness: posture precondition, egress
/// context, bounded tcpdump capture window with concurrent probes, packet
/// classification, and the fail-closed verdict. Setup/transport failures are
/// `Err`; verdict failures are carried in `LeakWitnessReport::failures`.
pub fn run_linux_exit_egress_leak_witness(
    shell: Arc<dyn RemoteShellHost>,
    alias: &str,
    client: Option<(Arc<dyn RemoteShellHost>, Vec<String>)>,
    window_secs: u64,
    settle_secs: u64,
) -> Result<LeakWitnessReport, String> {
    let egress_iface = detect_linux_egress_interface(&*shell)?;
    let killswitch_table =
        discover_single_generated_nft_table(&*shell, "inet", "rustynet_g", "active killswitch")?;
    let killswitch_listing =
        verify_scoped_dns_drop_rules(&*shell, &egress_iface, &killswitch_table)?;
    let egress_addr = detect_egress_ipv4(&*shell, &egress_iface)?;
    let egress_mac = detect_egress_mac(&*shell, &egress_iface)?;
    let wg_listen_port =
        wg_listen_port_from_killswitch_listing(&killswitch_listing, &egress_iface)?;

    let filter_tokens = capture_filter_tokens(wg_listen_port, &egress_mac);
    let timeout_secs = window_secs + CAPTURE_KILL_AFTER_SECS;
    let mut capture_argv: Vec<String> = vec![
        "sudo".to_owned(),
        "-n".to_owned(),
        "timeout".to_owned(),
        format!("--kill-after={CAPTURE_KILL_AFTER_SECS}"),
        timeout_secs.to_string(),
        "tcpdump".to_owned(),
        "-i".to_owned(),
        egress_iface.clone(),
        "-nn".to_owned(),
        "-l".to_owned(),
    ];
    capture_argv.extend(filter_tokens.iter().cloned());

    let capture_shell = Arc::clone(&shell);
    let capture_handle = std::thread::spawn(move || {
        let argv_refs: Vec<&str> = capture_argv.iter().map(String::as_str).collect();
        capture_shell.run_argv(&argv_refs, &[], &[])
    });

    std::thread::sleep(std::time::Duration::from_secs(settle_secs));

    let mut probe_exit_codes = Vec::new();
    // The masqueraded client ICMP control fires FIRST, before the host-origin
    // probes: on a correctly-protected exit the silent dns/tcp drops make the
    // `/dev/tcp` probes burn their full `timeout` budget, so firing the client
    // last risked landing it after the capture window closed.
    if let Some((client_shell, client_ping_argv)) = &client {
        let argv_refs: Vec<&str> = client_ping_argv.iter().map(String::as_str).collect();
        let code = client_shell
            .run_argv(&argv_refs, &[], &[])
            .map(|out| out.code)
            .unwrap_or(-1);
        probe_exit_codes.push(("client_icmp_positive_control".to_owned(), code));
    }
    probe_exit_codes.extend(run_host_origin_probes(&*shell));

    let mut failures = Vec::new();
    let (capture_stdout, capture_stderr, capture_code) = match capture_handle.join() {
        Ok(Ok(status)) => (
            String::from_utf8_lossy(&status.stdout).to_string(),
            String::from_utf8_lossy(&status.stderr).to_string(),
            status.code,
        ),
        Ok(Err(err)) => {
            failures.push(format!(
                "{alias}: tcpdump capture run failed ({err}) — capture unusable, failing closed"
            ));
            (String::new(), String::new(), -1)
        }
        Err(_) => {
            return Err(format!(
                "{alias}: tcpdump capture thread panicked — capture unusable, failing closed"
            ));
        }
    };
    if !capture_stderr.contains("listening on ") {
        failures.push(format!(
            "{alias}: tcpdump did not start on {egress_iface} (exit code {capture_code}; no \
             `listening on` banner in stderr) — capture unusable, failing closed"
        ));
    }
    let non_benign: Vec<&str> = capture_stderr
        .lines()
        .filter(|line| !is_benign_tcpdump_stderr_line(line))
        .collect();
    if !non_benign.is_empty() {
        let shown: Vec<String> = non_benign
            .iter()
            .take(3)
            .map(|line| format!("\"{line}\""))
            .collect();
        failures.push(format!(
            "{alias}: tcpdump stderr carried {} non-benign line(s) (tcpdump error?): {}",
            non_benign.len(),
            shown.join(" ")
        ));
    }

    let counts = classify_capture(&capture_stdout, &egress_addr, wg_listen_port);
    failures.extend(evaluate_leak_witness(
        &counts,
        &egress_iface,
        wg_listen_port,
    ));

    Ok(LeakWitnessReport {
        exit_alias: alias.to_owned(),
        egress_iface,
        egress_addr,
        killswitch_table,
        wg_listen_port,
        capture_filter: filter_tokens.join(" "),
        counts,
        probe_exit_codes,
        capture_stdout,
        capture_stderr,
        failures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_EGRESS_IFACE: &str = "enp0s9";
    const TEST_EGRESS_ADDR: &str = "192.0.2.240";
    const TEST_WG_PORT: u16 = 51820;
    const TEST_EGRESS_MAC: &str = "52:54:00:0a:00:31";

    fn program_egress_mac(mock: &MockShellHost) {
        mock.program_run_response(
            &["ip", "-brief", "link", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "{TEST_EGRESS_IFACE}           UP             {TEST_EGRESS_MAC} <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
            )),
        );
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn exit_code(code: i32, stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn capture_status(stdout: &str, stderr: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 124,
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn nft_table_ok() -> String {
        "table inet rustynet_g7 {\n\
         \x20 chain egress {\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 tcp dport { 53, 853 } drop\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
         \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
         \x20 }\n\
         }\n"
        .to_owned()
    }

    /// Masqueraded client ICMP (out + in) and a WireGuard keepalive — the
    /// ONLY traffic a correctly-scoped egress should carry. Host-origin
    /// DNS/DoT probes are dropped by the killswitch BEFORE the driver, so
    /// tcpdump never sees them; their presence in a capture is the leak
    /// signal, never part of the clean shape.
    fn clean_capture() -> String {
        format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n\
             12:00:01.100000 IP 192.0.2.1 > {TEST_EGRESS_ADDR}: ICMP echo reply, id 1, seq 1, length 64\n\
             12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        )
    }

    fn tcpdump_stderr_ok() -> String {
        "tcpdump: listening on 'enp0s9', link-type EN10MB (Ethernet), snapshot length 262144 bytes\n\
         12:00:20.000000 5 packets captured\n\
         5 packets received by filter\n\
         0 packets dropped by kernel\n"
        .to_owned()
    }

    fn capture_argv_for_test(window_secs: u64) -> Vec<String> {
        let mut argv: Vec<String> = vec![
            "sudo".to_owned(),
            "-n".to_owned(),
            "timeout".to_owned(),
            format!("--kill-after={CAPTURE_KILL_AFTER_SECS}"),
            (window_secs + CAPTURE_KILL_AFTER_SECS).to_string(),
            "tcpdump".to_owned(),
            "-i".to_owned(),
            TEST_EGRESS_IFACE.to_owned(),
            "-nn".to_owned(),
            "-l".to_owned(),
        ];
        argv.extend(capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC));
        argv
    }

    fn argv_refs(argv: &[String]) -> Vec<&str> {
        argv.iter().map(String::as_str).collect()
    }

    /// Program the posture/context conversation (egress, table, posture,
    /// addr, wg port) and the expected-to-fail host-origin probes plus the
    /// client positive control. The tcpdump capture and `dig` responses are
    /// left to each test (FIFO programming).
    fn program_setup(mock: &MockShellHost, with_dig_success_path: bool) {
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(&nft_table_ok()),
        );
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "2: {TEST_EGRESS_IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    \
                 inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\n"
            )),
        );
        program_egress_mac(mock);
        if with_dig_success_path {
            // dig present (code 1 = timed out after packets left — expected
            // to fail locally; the capture is what decides)
            mock.program_run_response(
                &[
                    "dig",
                    "+time=2",
                    "+tries=1",
                    "@192.0.2.53",
                    "rustynet-witness.invalid",
                    "A",
                ],
                exit_code(1, ""),
            );
        }
        mock.program_run_response(
            &[
                "timeout",
                "4",
                "bash",
                "-c",
                "exec 3<> /dev/tcp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "curl",
                "--connect-timeout",
                "3",
                "-sS",
                "-o",
                "/dev/null",
                "https://192.0.2.53:853",
            ],
            exit_code(6, ""),
        );
        mock.program_run_response(
            &["ping", "-6", "-c", "1", "-W", "2", "2001:db8::53"],
            exit_code(1, ""),
        );
        // client positive control
        mock.program_run_response(&["ping", "-c", "4", "-W", "2", "192.0.2.1"], exit_ok(""));
    }

    fn program_capture(mock: &MockShellHost, capture_stdout: &str, capture_stderr: &str) {
        let tcpdump_argv = capture_argv_for_test(0);
        mock.program_run_response(
            &argv_refs(&tcpdump_argv),
            capture_status(capture_stdout, capture_stderr),
        );
    }

    fn run_witness(mock: &Arc<MockShellHost>) -> Result<LeakWitnessReport, String> {
        run_linux_exit_egress_leak_witness(
            Arc::clone(mock) as Arc<dyn RemoteShellHost>,
            "exit-1",
            Some((
                Arc::clone(mock) as Arc<dyn RemoteShellHost>,
                vec![
                    "ping".to_owned(),
                    "-c".to_owned(),
                    "4".to_owned(),
                    "-W".to_owned(),
                    "2".to_owned(),
                    "192.0.2.1".to_owned(),
                ],
            )),
            0,
            0,
        )
    }

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Windows
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Ios
        ));
        assert!(!exit_egress_leak_witness_runtime_implemented(
            VmGuestPlatform::Android
        ));
    }

    #[test]
    fn clean_capture_with_both_controls_passes() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("clean witness must not err on setup");
        assert!(report.failures.is_empty(), "{:?}", report.failures);
        assert_eq!(report.counts.forwarded_icmp, 1);
        assert_eq!(report.counts.wireguard, 1);
        assert_eq!(report.counts.host_dns_udp, 0);
        assert_eq!(report.counts.host_dns_tcp, 0);
        assert_eq!(report.counts.host_dot, 0);
        assert_eq!(report.counts.ipv6, 0);
        assert_eq!(report.wg_listen_port, TEST_WG_PORT);
        assert_eq!(report.egress_addr, TEST_EGRESS_ADDR);
        assert_eq!(report.killswitch_table, "rustynet_g7");
    }

    #[test]
    fn posture_rule_absent_fails_naming_the_rule() {
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        let incomplete = "table inet rustynet_g7 {\n\
             \x20 chain egress {\n\
             \x20  oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n\
             \x20  oifname \"enp0s9\" meta nfproto ipv4 accept\n\
             \x20 }\n\
             }\n";
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(incomplete),
        );
        let err = run_witness(&mock).expect_err("missing tcp drop rule must fail closed");
        assert!(
            err.contains("tcp dport") && err.contains("53") && err.contains("853"),
            "error must name the missing rule, got: {err}"
        );
        assert!(err.contains("posture precondition failed"), "{err}");
    }

    #[test]
    fn host_origin_udp_dns_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40002 > 192.0.2.53.53: 2+ A? leak.invalid. (30)\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_udp, 1);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("udp/53") && f.contains("1 host-origin")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn host_origin_tcp_dot_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40003 > 192.0.2.53.853: Flags [S], seq 1, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dot, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("tcp/853 (DoT)")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn host_origin_tcp_dns_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(&format!(
            "12:00:03.000000 IP {TEST_EGRESS_ADDR}.40004 > 192.0.2.53.53: Flags [S], seq 1, length 0\n"
        ));
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.host_dns_tcp, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("tcp/53")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn single_ipv6_packet_fails() {
        let mut capture = clean_capture();
        capture.push_str(
            "12:00:03.000000 IP6 2001:db8::240 > 2001:db8::53: ICMP6, echo request, length 64\n",
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.ipv6, 1);
        assert!(
            report.failures.iter().any(|f| f.contains("IPv6 packet(s)")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn missing_forwarded_icmp_is_vacuous_fail() {
        let capture = format!(
            "12:00:02.000000 IP {TEST_EGRESS_ADDR}.{TEST_WG_PORT} > 192.0.2.5.{TEST_WG_PORT}: UDP, length 32\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.forwarded_icmp, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no masqueraded client ICMP")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn missing_wireguard_is_vacuous_fail() {
        let capture = format!(
            "12:00:01.000000 IP {TEST_EGRESS_ADDR} > 192.0.2.1: ICMP echo request, id 1, seq 1, length 64\n"
        );
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, &capture, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts.wireguard, 0);
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("vacuous witness: no WireGuard udp/51820")),
            "{:?}",
            report.failures
        );
    }

    #[test]
    fn tcpdump_banner_only_stdout_counts_zero_packets() {
        let banner_only = "listening on enp0s9\nlink-type EN10MB\ncapture_provenance=test\n\
             tcpdump: data link type EN10MB\n\n";
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, banner_only, &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        assert_eq!(report.counts, LeakWitnessCounts::default());
        // zero counts are NOT a pass: both vacuous controls must fire, and
        // no banner line may be counted as a packet or an error
        assert!(
            report
                .failures
                .iter()
                .all(|f| f.contains("vacuous witness")),
            "banner lines must never be counted as packets or errors: {:?}",
            report.failures
        );
        assert_eq!(report.failures.len(), 2, "{:?}", report.failures);
    }

    #[test]
    fn tcpdump_without_listening_banner_fails_closed() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, true);
        program_capture(&mock, "", "tcpdump: enp0s9: No such device exists\n");
        let report = run_witness(&mock).expect("setup must succeed");
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("tcpdump did not start")),
            "{:?}",
            report.failures
        );
        assert!(
            report
                .failures
                .iter()
                .any(|f| f.contains("non-benign line")),
            "tcpdump error lines must surface, not be whitelisted: {:?}",
            report.failures
        );
    }

    #[test]
    fn missing_dig_falls_back_to_devudp_poke() {
        let mock = Arc::new(MockShellHost::new());
        program_setup(&mock, false);
        mock.program_run_response(
            &[
                "dig",
                "+time=2",
                "+tries=1",
                "@192.0.2.53",
                "rustynet-witness.invalid",
                "A",
            ],
            exit_code(127, ""),
        );
        mock.program_run_response(
            &[
                "timeout",
                "4",
                "bash",
                "-c",
                "exec 3<> /dev/udp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        program_capture(&mock, &clean_capture(), &tcpdump_stderr_ok());
        let report = run_witness(&mock).expect("setup must succeed");
        let labels: Vec<&str> = report
            .probe_exit_codes
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        assert!(
            labels.contains(&"host_dns_udp_dig")
                && labels.contains(&"host_dns_udp_devudp_fallback"),
            "{labels:?}"
        );
        assert!(
            report
                .probe_exit_codes
                .iter()
                .any(|(label, code)| label == "host_dns_udp_devudp_fallback" && *code == 1),
            "{:?}",
            report.probe_exit_codes
        );
    }

    #[test]
    fn devtcp_probe_is_timeout_bounded() {
        // Witness: the `/dev/tcp` poke must run under `timeout` — a silent
        // drop never completes the connect, so an unbounded poke would hang
        // far past the capture window. Programmed ONLY for the wrapped argv;
        // a regression to the bare `bash -c` argv matches nothing, the mock
        // errors, and the recorded -1 fails this assert.
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &[
                "dig",
                "+time=2",
                "+tries=1",
                "@192.0.2.53",
                "rustynet-witness.invalid",
                "A",
            ],
            exit_code(1, ""),
        );
        mock.program_run_response(
            &[
                "timeout",
                &PROBE_TIMEOUT_SECS.to_string(),
                "bash",
                "-c",
                "exec 3<> /dev/tcp/192.0.2.53/53",
            ],
            exit_code(1, ""),
        );
        let codes = run_host_origin_probes(mock.as_ref());
        assert!(
            codes
                .iter()
                .any(|(label, code)| label == "host_dns_tcp_devtcp" && *code == 1),
            "tcp poke did not match the timeout-wrapped argv: {codes:?}"
        );
    }

    #[test]
    fn witness_fails_closed_on_wg_port_absent() {
        let mock = Arc::new(MockShellHost::new());
        mock.program_run_response(
            &["ip", "route", "show", "default"],
            exit_ok(&format!("default via 192.0.2.1 dev {TEST_EGRESS_IFACE}\n")),
        );
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\n"),
        );
        let without_wg_pair: String = nft_table_ok()
            .lines()
            .filter(|line| !line.contains("51820"))
            .map(|line| format!("{line}\n"))
            .collect();
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "table", "inet", "rustynet_g7"],
            exit_ok(&without_wg_pair),
        );
        mock.program_run_response(
            &["ip", "-4", "addr", "show", "dev", TEST_EGRESS_IFACE],
            exit_ok(&format!(
                "    inet {TEST_EGRESS_ADDR}/24 brd 192.0.2.255 scope global {TEST_EGRESS_IFACE}\n"
            )),
        );
        program_egress_mac(&mock);
        let err = run_witness(&mock).expect_err("undeterminable WG port must fail closed");
        assert!(err.contains("WireGuard listen port"), "{err}");
    }

    #[test]
    fn tcpdump_verbose_notice_is_benign_but_real_errors_are_not() {
        assert!(is_benign_tcpdump_stderr_line(
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode"
        ));
        assert!(!is_benign_tcpdump_stderr_line(
            "tcpdump: ens3: No such device exists"
        ));
        assert!(!is_benign_tcpdump_stderr_line(
            "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode; extra"
        ));
    }

    // Run lenovo-u16l: on a bridged LAN tcpdump (promiscuous) also sees other
    // devices' IPv6; only frames this exit's NIC sends may count as leaks.
    #[test]
    fn ipv6_clause_is_scoped_to_frames_the_egress_nic_sends() {
        let tokens = capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC).join(" ");
        assert!(
            tokens.contains(&format!("( ip6 and ether src {TEST_EGRESS_MAC} )")),
            "{tokens}"
        );
        assert!(
            !tokens.contains("or ip6 or"),
            "an unscoped ip6 clause must not remain: {tokens}"
        );
    }

    // `udp port 53`, `tcp port 53|853` and the WireGuard port clause match
    // IPv6 too, and every captured IPv6 line counts as a leak, so unscoped
    // they would still let a neighbour's IPv6 DNS fail the witness on a
    // bridged LAN. They must sit in one IPv4-only group (pcap `and`/`or` are
    // equal precedence, so the grouping is locked here token for token).
    #[test]
    fn port_clauses_are_ipv4_only() {
        let tokens = capture_filter_tokens(TEST_WG_PORT, TEST_EGRESS_MAC).join(" ");
        assert_eq!(
            tokens,
            format!(
                "( ip and ( udp port 53 or tcp port 53 or tcp port {WITNESS_DOT_PORT} or icmp \
                 or udp port {TEST_WG_PORT} ) ) or ( ip6 and ether src {TEST_EGRESS_MAC} )"
            )
        );
    }

    #[test]
    fn egress_mac_must_be_a_plain_mac() {
        assert!(is_plain_mac("52:54:00:0a:00:31"));
        assert!(!is_plain_mac(""));
        assert!(!is_plain_mac("<BROADCAST,MULTICAST,UP,LOWER_UP>"));
        assert!(!is_plain_mac("52:54:00:0a:00"));
        assert!(!is_plain_mac("52:54:00:0a:00:3g"));
    }

    #[test]
    fn wg_port_comes_from_the_killswitch_dport_sport_pair_on_the_egress_iface() {
        let iface = "enp0s9";
        assert_eq!(
            wg_listen_port_from_killswitch_listing(&nft_table_ok(), iface),
            Ok(51820)
        );
        // Only one half of the pair: not a WireGuard allow, fail closed.
        let dport_only = "oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n";
        assert!(wg_listen_port_from_killswitch_listing(dport_only, iface).is_err());
        // A pair on another interface does not count.
        let other_iface = "oifname \"wg9\" meta nfproto ipv4 udp dport 51820 accept\n\
                           oifname \"wg9\" meta nfproto ipv4 udp sport 51820 accept\n";
        assert!(wg_listen_port_from_killswitch_listing(other_iface, iface).is_err());
        // Two different pairs: ambiguous, fail closed.
        let two_pairs = "oifname \"enp0s9\" meta nfproto ipv4 udp dport 51820 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp sport 51820 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp dport 41641 accept\n\
                         oifname \"enp0s9\" meta nfproto ipv4 udp sport 41641 accept\n";
        let err = wg_listen_port_from_killswitch_listing(two_pairs, iface).expect_err("ambiguous");
        assert!(err.contains("several"), "{err}");
        // The DNS/DoT drop set on the same interface never reads as a port.
        let drops_only = "oifname \"enp0s9\" meta nfproto ipv4 udp dport { 53, 853 } drop\n";
        assert!(wg_listen_port_from_killswitch_listing(drops_only, iface).is_err());
    }

    #[test]
    fn evaluate_leak_witness_counts_clean_shape() {
        let counts = LeakWitnessCounts {
            host_dns_udp: 0,
            host_dns_tcp: 0,
            host_dot: 0,
            ipv6: 0,
            forwarded_icmp: 3,
            wireguard: 7,
        };
        assert!(evaluate_leak_witness(&counts, TEST_EGRESS_IFACE, TEST_WG_PORT).is_empty());
        let leaky = LeakWitnessCounts {
            host_dns_udp: 2,
            ..LeakWitnessCounts::default()
        };
        let failures = evaluate_leak_witness(&leaky, TEST_EGRESS_IFACE, TEST_WG_PORT);
        assert_eq!(failures.len(), 3, "{failures:?}");
    }
}
