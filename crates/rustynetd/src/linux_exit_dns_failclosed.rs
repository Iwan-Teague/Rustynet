#![allow(clippy::result_large_err)]

//! Linux exit-mode DNS fail-closed artefact producer.
//!
//! Companion of `evaluate_linux_exit_dns_failclosed_artifact_dir` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`. The producer emits the
//! exit-mode DNS leak-proof artefacts beside the existing
//! `linux_dns_failclosed_check.json` report:
//!
//! - `firewall_block_rules.json`
//! - `udp_block_pcap.txt`
//! - `tcp_block_pcap.txt`
//! - `dns_block_probe.json` — the ACTIVE off-tunnel probe that makes the empty
//!   pcaps non-vacuous (we drove a real DNS query at the LAN path and it was
//!   dropped), recording whether any response leaked back
//! - `tunnel_path_resolves.json`
//!
//! Runtime probes use argv-only `Command` invocation. Operator-provided
//! interface and hostname values are validated before reaching argv.

use crate::linux_dns_failclosed::{
    build_linux_dns_failclosed_report, collect_linux_dns_failclosed_snapshot,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::thread::sleep;
use std::time::Duration;

pub const LINUX_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION: u32 = 1;
pub const DNS_BLOCK_LAN_UDP_RULE: &str = "rustynet-dns-block-lan-udp";
pub const DNS_BLOCK_LAN_TCP_RULE: &str = "rustynet-dns-block-lan-tcp";
pub const DEFAULT_TUNNEL_DNS_HOSTNAME: &str = "exit-1.rustynet";
pub const DEFAULT_LINUX_KILLSWITCH_TABLE: &str = "rustynet_g1";

/// A throwaway query name for the active blocked-path probe. It is intentionally
/// in the reserved `.invalid` TLD (RFC 6761) so that even if the probe were to
/// escape (a leak we are trying to catch) it can never resolve to a real host.
/// Mirrors the macOS producer's `DNS_BLOCK_PROBE_QUERY`.
pub const DNS_BLOCK_PROBE_QUERY: &str = "rustynet-dns-leak-probe.invalid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExitDnsFailclosedOptions {
    pub lan_iface: String,
    pub tunnel_dns_hostname: String,
    pub killswitch_table: String,
    pub tcpdump_secs: u64,
}

impl LinuxExitDnsFailclosedOptions {
    pub fn new(lan_iface: String, tunnel_dns_hostname: String, killswitch_table: String) -> Self {
        Self {
            lan_iface,
            tunnel_dns_hostname,
            killswitch_table,
            tcpdump_secs: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDnsBlockRule {
    pub name: String,
    pub action: String,
    pub direction: String,
    pub enabled: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDnsBlockRulesReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub rules: Vec<LinuxDnsBlockRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxTunnelPathResolvesReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub resolved: bool,
    pub hostname: String,
    pub addresses: Vec<String>,
    pub reason: String,
}

/// Result of the ACTIVE blocked-path DNS probe. The empty-pcap leak proof is
/// only meaningful if traffic was actually generated toward the off-tunnel DNS
/// path during the capture window — otherwise an empty capture merely says "no
/// DNS happened to be sent", a vacuous PASS. This report records that an
/// off-tunnel DNS query WAS attempted and whether any DNS response came back
/// (any response = the LAN DNS path is open = a leak, regardless of rcode).
/// Schema mirrors the macOS `MacosDnsBlockProbeReport`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDnsBlockProbeReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub probe_attempted: bool,
    pub probe_target: String,
    pub probe_query: String,
    pub udp_response_received: bool,
    pub tcp_response_received: bool,
    pub reason: String,
}

pub fn write_linux_exit_dns_failclosed_artifacts(
    output_dir: &Path,
    options: &LinuxExitDnsFailclosedOptions,
) -> Result<(), String> {
    validate_iface_name(options.lan_iface.as_str())?;
    validate_hostname(options.tunnel_dns_hostname.as_str())?;
    validate_nft_table_name(options.killswitch_table.as_str())?;
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create {} failed: {err}", output_dir.display()))?;

    let dns_check = build_linux_dns_failclosed_report(collect_linux_dns_failclosed_snapshot());
    write_json(
        &output_dir.join("linux_dns_failclosed_check.json"),
        &dns_check,
        "linux_dns_failclosed_check.json",
    )?;

    let rules_stdout =
        capture_nft_killswitch_table(options.killswitch_table.as_str()).unwrap_or_default();
    let rules_report = build_linux_dns_block_rules_report(rules_stdout.as_str());
    write_json(
        &output_dir.join("firewall_block_rules.json"),
        &rules_report,
        "firewall_block_rules.json",
    )?;

    // Derive an off-tunnel DNS target (the LAN default gateway) so the probe
    // sends a real port-53 datagram toward a directly-reachable, NON-tunnel
    // destination. If the killswitch is enforced the packet is dropped on
    // egress (empty pcap); if it is not, the attempt appears in the capture.
    // Failing loud when the gateway cannot be derived keeps the proof honest
    // (no silent fall back to a probe that can't egress).
    let probe_target = derive_linux_default_gateway()?;
    validate_probe_target(probe_target.as_str())?;

    let (udp_pcap, udp_probe_output) = capture_dns_block_path(
        options.lan_iface.as_str(),
        "udp",
        probe_target.as_str(),
        DNS_BLOCK_PROBE_QUERY,
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("udp_block_pcap.txt"), udp_pcap)
        .map_err(|err| format!("write udp_block_pcap.txt failed: {err}"))?;

    let (tcp_pcap, tcp_probe_output) = capture_dns_block_path(
        options.lan_iface.as_str(),
        "tcp",
        probe_target.as_str(),
        DNS_BLOCK_PROBE_QUERY,
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("tcp_block_pcap.txt"), tcp_pcap)
        .map_err(|err| format!("write tcp_block_pcap.txt failed: {err}"))?;

    let probe_report = build_linux_dns_block_probe_report(
        probe_target.as_str(),
        DNS_BLOCK_PROBE_QUERY,
        true,
        udp_probe_output.as_str(),
        tcp_probe_output.as_str(),
    );
    write_json(
        &output_dir.join("dns_block_probe.json"),
        &probe_report,
        "dns_block_probe.json",
    )?;

    let resolve_stdout =
        capture_tunnel_dns_resolution(options.tunnel_dns_hostname.as_str()).unwrap_or_default();
    let resolve_report = build_tunnel_path_resolves_report(
        options.tunnel_dns_hostname.as_str(),
        resolve_stdout.as_str(),
    );
    write_json(
        &output_dir.join("tunnel_path_resolves.json"),
        &resolve_report,
        "tunnel_path_resolves.json",
    )?;
    Ok(())
}

pub fn build_linux_dns_block_rules_report(nft_table_stdout: &str) -> LinuxDnsBlockRulesReport {
    let rules = [
        (DNS_BLOCK_LAN_UDP_RULE, "udp"),
        (DNS_BLOCK_LAN_TCP_RULE, "tcp"),
    ]
    .into_iter()
    .map(|(name, protocol)| parse_dns_block_rule(nft_table_stdout, name, protocol))
    .collect::<Vec<_>>();
    let overall_ok = rules
        .iter()
        .all(|rule| rule.enabled == "true" && rule.action == "drop");
    LinuxDnsBlockRulesReport {
        schema_version: LINUX_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
        overall_ok,
        rules,
    }
}

pub fn build_tunnel_path_resolves_report(
    hostname: &str,
    resolver_stdout: &str,
) -> LinuxTunnelPathResolvesReport {
    let addresses = resolver_stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| {
            line.parse::<std::net::IpAddr>().is_ok()
                || line
                    .split_ascii_whitespace()
                    .any(|token| token.parse::<std::net::IpAddr>().is_ok())
        })
        .flat_map(|line| {
            line.split_ascii_whitespace()
                .filter(|token| token.parse::<std::net::IpAddr>().is_ok())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let resolved = !addresses.is_empty();
    LinuxTunnelPathResolvesReport {
        schema_version: LINUX_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
        overall_ok: resolved,
        resolved,
        hostname: hostname.to_owned(),
        addresses,
        reason: if resolved {
            "resolved through platform resolver".to_owned()
        } else {
            "no tunnel DNS answer observed".to_owned()
        },
    }
}

/// True when `dig` output shows a DNS message header was parsed — i.e. a
/// response came back from the queried server. ANY rcode (NOERROR, NXDOMAIN,
/// SERVFAIL, REFUSED) means the DNS round-trip COMPLETED over the off-tunnel
/// path, which is a leak. `dig` only prints the `;; ->>HEADER<<-` line when it
/// actually parses a response, so its presence is a deterministic, rcode-
/// agnostic "the path is open" signal (a timeout/no-response never prints it).
/// Mirrors the macOS `dns_probe_response_received`.
pub fn dns_probe_response_received(dig_output: &str) -> bool {
    dig_output.to_ascii_lowercase().contains("->>header<<-")
}

/// Build the blocked-path probe report. `overall_ok` (the leak-proof PASS
/// condition) requires that the probe was actually attempted AND that NEITHER
/// the UDP nor the TCP probe received any DNS response. Fail-closed: a probe
/// that did not run, or any observed response, is NOT ok. Mirrors the macOS
/// `build_macos_dns_block_probe_report`.
pub fn build_linux_dns_block_probe_report(
    probe_target: &str,
    probe_query: &str,
    attempted: bool,
    udp_dig_output: &str,
    tcp_dig_output: &str,
) -> LinuxDnsBlockProbeReport {
    let udp_response_received = attempted && dns_probe_response_received(udp_dig_output);
    let tcp_response_received = attempted && dns_probe_response_received(tcp_dig_output);
    let overall_ok = attempted && !udp_response_received && !tcp_response_received;
    let reason = if !attempted {
        "blocked-path DNS probe did not execute; an empty pcap is vacuous without an active probe"
            .to_owned()
    } else if udp_response_received || tcp_response_received {
        "off-tunnel DNS probe received a response (udp_response_received or tcp_response_received): LAN DNS path is OPEN (leak)".to_owned()
    } else {
        "off-tunnel DNS probe received no UDP or TCP response: consistent with the killswitch dropping LAN DNS egress".to_owned()
    };
    LinuxDnsBlockProbeReport {
        schema_version: LINUX_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
        overall_ok,
        probe_attempted: attempted,
        probe_target: probe_target.to_owned(),
        probe_query: probe_query.to_owned(),
        udp_response_received,
        tcp_response_received,
        reason,
    }
}

/// Extract the `via <gateway>` value from `ip route get <dst>` output. Linux
/// renders the resolved route as e.g.
/// `1.1.1.1 via 192.168.1.1 dev enp0s1 src 192.168.1.10 uid 1000`; an on-link
/// destination omits the `via` token entirely (no usable gateway). Pure so it
/// is host-testable regardless of the build target.
pub fn parse_linux_route_gateway(route_output: &str) -> Option<String> {
    let mut tokens = route_output.split_whitespace();
    while let Some(token) = tokens.next() {
        if token == "via" {
            if let Some(gw) = tokens.next() {
                let trimmed = gw.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_owned());
                }
            }
        }
    }
    None
}

/// Validate the derived probe target is a literal IP address. An on-link
/// default route or a malformed parse must fail loud rather than produce an
/// unsendable probe. Mirrors the macOS `validate_probe_target`.
fn validate_probe_target(value: &str) -> Result<(), String> {
    value
        .parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("derived DNS probe target {value:?} is not a usable IP address"))
}

fn parse_dns_block_rule(nft_table_stdout: &str, name: &str, protocol: &str) -> LinuxDnsBlockRule {
    let matched = nft_table_stdout.lines().map(str::trim).find(|line| {
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        normalized.contains(protocol)
            && normalized.contains("dport 53")
            && normalized.contains("oifname !=")
            && normalized.contains("drop")
    });
    match matched {
        Some(_) => LinuxDnsBlockRule {
            name: name.to_owned(),
            action: "drop".to_owned(),
            direction: "out".to_owned(),
            enabled: "true".to_owned(),
        },
        None => LinuxDnsBlockRule {
            name: name.to_owned(),
            action: "missing".to_owned(),
            direction: "unknown".to_owned(),
            enabled: "false".to_owned(),
        },
    }
}

fn write_json<T: Serialize>(path: &Path, value: &T, label: &str) -> Result<(), String> {
    let encoded = serde_json::to_string_pretty(value)
        .map_err(|err| format!("serialize {label} failed: {err}"))?;
    fs::write(path, encoded).map_err(|err| format!("write {label} failed: {err}"))
}

fn validate_iface_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("LAN interface name contains unsupported characters".to_owned());
    }
    Ok(())
}

fn validate_hostname(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 253
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
    {
        return Err("tunnel DNS hostname contains unsupported characters".to_owned());
    }
    Ok(())
}

fn validate_nft_table_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_'))
        || !value.starts_with("rustynet")
    {
        return Err("nft killswitch table name is outside reviewed RustyNet shape".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn capture_nft_killswitch_table(table: &str) -> Result<String, String> {
    let output = Command::new("/usr/sbin/nft")
        .args(["list", "table", "inet", table])
        .output()
        .map_err(|err| format!("nft list table inet {table} failed to start: {err}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "linux"))]
fn capture_nft_killswitch_table(_table: &str) -> Result<String, String> {
    Ok(String::new())
}

/// A routable off-tunnel target used purely to resolve the LAN default route.
/// `ip route get <dst>` returns the `via <gateway>` next hop for a routable
/// public destination; the gateway (not this address) is what the probe is
/// pointed at. A documentation-range address (RFC 5737) keeps the route lookup
/// deterministic without depending on a real external host being reachable.
#[cfg(target_os = "linux")]
const LINUX_ROUTE_PROBE_DST: &str = "192.0.2.1";

#[cfg(target_os = "linux")]
fn run_ip_route(args: &[&str]) -> Result<String, String> {
    let output = Command::new("/usr/sbin/ip")
        .args(args)
        .output()
        .or_else(|_| Command::new("/sbin/ip").args(args).output())
        .or_else(|_| Command::new("ip").args(args).output())
        .map_err(|err| format!("ip {} failed to start: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "ip {} failed: status={} stderr={}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "linux")]
fn derive_linux_default_gateway() -> Result<String, String> {
    let stdout = run_ip_route(&["route", "get", LINUX_ROUTE_PROBE_DST])?;
    parse_linux_route_gateway(stdout.as_str())
        .ok_or_else(|| "could not derive default gateway from `ip route get`".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn derive_linux_default_gateway() -> Result<String, String> {
    Err("default-gateway derivation is only supported on Linux".to_owned())
}

/// Capture DNS/53 egress on `iface` while ACTIVELY sending one off-tunnel DNS
/// probe (to `server`) mid-window. Returns the tcpdump text plus the `dig`
/// output. The probe makes an empty pcap meaningful: a real port-53 datagram
/// was driven toward a reachable, non-tunnel destination, so an empty capture
/// proves the killswitch dropped it rather than "nothing tried DNS". Mirrors
/// the macOS `capture_dns_block_path`.
#[cfg(target_os = "linux")]
fn capture_dns_block_path(
    iface: &str,
    protocol: &str,
    server: &str,
    query: &str,
    duration: Duration,
) -> Result<(String, String), String> {
    let mut child = Command::new("/usr/sbin/tcpdump")
        .args(["-n", "-i", iface, protocol, "and", "port", "53"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("tcpdump {protocol}/53 failed to start: {err}"))?;
    // Let tcpdump settle into the capture before generating the probe so the
    // attempt cannot race ahead of the sniffer.
    sleep(Duration::from_millis(500));
    let probe_output = run_dig_probe(protocol, server, query)?;
    // Keep capturing for the remainder of the window to catch any delayed or
    // retried egress the probe might have triggered.
    sleep(duration);
    if child
        .try_wait()
        .map_err(|err| format!("tcpdump {protocol}/53 poll failed: {err}"))?
        .is_none()
    {
        child
            .kill()
            .map_err(|err| format!("tcpdump {protocol}/53 stop failed: {err}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("tcpdump {protocol}/53 output failed: {err}"))?;
    Ok((
        String::from_utf8_lossy(&output.stdout).into_owned(),
        probe_output,
    ))
}

/// Run a single `dig` DNS probe (argv-only) for `query` against `server` over
/// the requested transport. Combines stdout + stderr so the caller can detect a
/// parsed response header (`;; ->>HEADER<<-`, any rcode) versus a timeout.
/// Mirrors the macOS `run_dig_probe`.
#[cfg(target_os = "linux")]
fn run_dig_probe(protocol: &str, server: &str, query: &str) -> Result<String, String> {
    let transport = if protocol == "tcp" { "+tcp" } else { "+notcp" };
    let at_server = format!("@{server}");
    let output = Command::new("/usr/bin/dig")
        .args([
            "+time=2",
            "+tries=1",
            transport,
            at_server.as_str(),
            query,
            "A",
        ])
        .output()
        .map_err(|err| format!("dig {protocol} probe failed to start: {err}"))?;
    let mut combined = String::from_utf8_lossy(&output.stdout).into_owned();
    combined.push_str(String::from_utf8_lossy(&output.stderr).as_ref());
    Ok(combined)
}

#[cfg(not(target_os = "linux"))]
fn capture_dns_block_path(
    _iface: &str,
    _protocol: &str,
    _server: &str,
    _query: &str,
    _duration: Duration,
) -> Result<(String, String), String> {
    Ok((String::new(), String::new()))
}

#[cfg(target_os = "linux")]
fn capture_tunnel_dns_resolution(hostname: &str) -> Result<String, String> {
    let output = Command::new("/usr/bin/getent")
        .args(["ahosts", hostname])
        .output()
        .map_err(|err| format!("getent ahosts failed to start: {err}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "linux"))]
fn capture_tunnel_dns_resolution(_hostname: &str) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nft_report_accepts_reviewed_udp_and_tcp_drop_rules() {
        let body = r#"
table inet rustynet_g1 {
  chain killswitch {
    type filter hook output priority filter; policy drop;
    udp dport 53 oifname != "rustynet0" drop
    tcp dport 53 oifname != "rustynet0" drop
  }
}
"#;
        let report = build_linux_dns_block_rules_report(body);
        assert!(report.overall_ok);
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.rules.len(), 2);
        assert!(report.rules.iter().all(|rule| rule.action == "drop"));
        assert!(report.rules.iter().all(|rule| rule.direction == "out"));
    }

    #[test]
    fn nft_report_fails_closed_when_rule_missing() {
        let report = build_linux_dns_block_rules_report("");
        assert!(!report.overall_ok);
        assert!(
            report
                .rules
                .iter()
                .any(|rule| rule.name == DNS_BLOCK_LAN_UDP_RULE && rule.enabled == "false")
        );
    }

    #[test]
    fn tunnel_resolve_report_accepts_getent_answer() {
        let report = build_tunnel_path_resolves_report(
            "exit-1.rustynet",
            "100.64.0.1 STREAM exit-1.rustynet\n100.64.0.1 DGRAM\n",
        );
        assert!(report.overall_ok);
        assert!(report.resolved);
        assert_eq!(report.addresses, vec!["100.64.0.1", "100.64.0.1"]);
    }

    #[test]
    fn tunnel_resolve_report_fails_closed_without_answer() {
        let report = build_tunnel_path_resolves_report("exit-1.rustynet", "");
        assert!(!report.overall_ok);
        assert!(!report.resolved);
    }

    #[test]
    fn input_validation_rejects_shell_metacharacters() {
        assert!(validate_iface_name("enp0s1").is_ok());
        assert!(validate_hostname("exit-1.rustynet").is_ok());
        assert!(validate_nft_table_name("rustynet_g1").is_ok());
        assert!(validate_iface_name("enp0s1;rm").is_err());
        assert!(validate_hostname("exit-1.rustynet;rm").is_err());
        assert!(validate_nft_table_name("rustynet_g1;rm").is_err());
        assert!(validate_nft_table_name("other_g1").is_err());
    }

    #[test]
    fn dns_probe_response_detects_completed_round_trip() {
        // `dig` prints `;; ->>HEADER<<-` only when it parses a response, for ANY
        // rcode — NXDOMAIN/SERVFAIL/NOERROR all mean the off-tunnel DNS path is
        // open and therefore a leak.
        let nxdomain = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 4242\n";
        let noerror = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7\n";
        assert!(dns_probe_response_received(nxdomain));
        assert!(dns_probe_response_received(noerror));
    }

    #[test]
    fn dns_probe_response_absent_on_timeout() {
        // A blocked probe yields no parsed header — only a timeout banner.
        let timed_out = ";; communications error to 192.168.0.1#53: timed out\n;; no servers could be reached\n";
        assert!(!dns_probe_response_received(timed_out));
        assert!(!dns_probe_response_received(""));
    }

    #[test]
    fn dns_block_probe_report_ok_only_when_attempted_and_silent() {
        let blocked =
            ";; communications error to 10.0.0.1#53: timed out\n;; no servers could be reached\n";
        let ok = build_linux_dns_block_probe_report(
            "10.0.0.1",
            DNS_BLOCK_PROBE_QUERY,
            true,
            blocked,
            blocked,
        );
        assert!(ok.overall_ok);
        assert!(ok.probe_attempted);
        assert_eq!(ok.schema_version, 1);
        assert!(!ok.udp_response_received && !ok.tcp_response_received);
    }

    #[test]
    fn dns_block_probe_report_fails_closed_on_response() {
        let answered = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n";
        let blocked = ";; no servers could be reached\n";
        // A response on EITHER transport is a leak.
        let leak_udp = build_linux_dns_block_probe_report(
            "10.0.0.1",
            DNS_BLOCK_PROBE_QUERY,
            true,
            answered,
            blocked,
        );
        assert!(!leak_udp.overall_ok);
        assert!(leak_udp.udp_response_received);
        let leak_tcp = build_linux_dns_block_probe_report(
            "10.0.0.1",
            DNS_BLOCK_PROBE_QUERY,
            true,
            blocked,
            answered,
        );
        assert!(!leak_tcp.overall_ok);
        assert!(leak_tcp.tcp_response_received);
    }

    #[test]
    fn dns_block_probe_report_fails_closed_when_not_attempted() {
        // An empty pcap without a proven active probe is vacuous → not ok.
        let report =
            build_linux_dns_block_probe_report("10.0.0.1", DNS_BLOCK_PROBE_QUERY, false, "", "");
        assert!(!report.overall_ok);
        assert!(!report.probe_attempted);
        assert!(report.reason.contains("vacuous"));
    }

    #[test]
    fn route_gateway_parser_extracts_ip_and_rejects_onlink() {
        // Real `ip route get 192.0.2.1` shape on Linux with a default gateway.
        let via = "192.0.2.1 via 192.168.1.1 dev enp0s1 src 192.168.1.10 uid 1000 \n    cache\n";
        assert_eq!(
            parse_linux_route_gateway(via).as_deref(),
            Some("192.168.1.1")
        );
        assert!(validate_probe_target("192.168.1.1").is_ok());
        // An on-link / directly-reachable destination omits the `via` token —
        // no usable gateway, so the parser yields None and the caller fails loud.
        let onlink = "192.0.2.1 dev enp0s1 src 192.168.1.10 uid 1000 \n    cache\n";
        assert_eq!(parse_linux_route_gateway(onlink), None);
        assert_eq!(parse_linux_route_gateway(""), None);
        // A non-IP token (should never happen from `ip route`, but defense in
        // depth) is rejected by the probe-target validator.
        assert!(validate_probe_target("link#12").is_err());
    }
}
