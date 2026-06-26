#![allow(clippy::result_large_err)]

//! macOS exit-mode DNS fail-closed artefact producer.
//!
//! Companion of `evaluate_macos_exit_dns_failclosed_artifact_dir` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`. This producer emits the
//! exit-mode DNS leak-proof artefacts that sit beside the existing
//! `macos_dns_failclosed_check.json` report:
//!
//! - `pf_block_rules.json`
//! - `udp_block_pcap.txt`
//! - `tcp_block_pcap.txt`
//! - `dns_block_probe.json` — the ACTIVE off-tunnel probe that makes the empty
//!   pcaps non-vacuous (we drove a real DNS query at the LAN path and it was
//!   dropped), recording whether any response leaked back
//! - `tunnel_path_resolves.json`
//!
//! All host probes use argv-only `Command` invocation. No shell string
//! construction is used for operator-controlled interface or hostname
//! values.

use crate::macos_dns_failclosed::{
    build_macos_dns_failclosed_report, collect_macos_dns_failclosed_snapshot,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
#[cfg(target_os = "macos")]
use std::process::{Command, Stdio};
#[cfg(target_os = "macos")]
use std::thread::sleep;
use std::time::Duration;

pub const MACOS_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION: u32 = 1;
pub const DNS_BLOCK_LAN_UDP_RULE: &str = "rustynet-dns-block-lan-udp";
pub const DNS_BLOCK_LAN_TCP_RULE: &str = "rustynet-dns-block-lan-tcp";
pub const DEFAULT_TUNNEL_DNS_HOSTNAME: &str = "exit-1.rustynet";

/// A throwaway query name for the active blocked-path probe. It is intentionally
/// in the reserved `.invalid` TLD (RFC 6761) so that even if the probe were to
/// escape (a leak we are trying to catch) it can never resolve to a real host.
pub const DNS_BLOCK_PROBE_QUERY: &str = "rustynet-dns-leak-probe.invalid";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosExitDnsFailclosedOptions {
    pub lan_iface: String,
    pub tunnel_dns_hostname: String,
    pub tcpdump_secs: u64,
}

impl MacosExitDnsFailclosedOptions {
    pub fn new(lan_iface: String, tunnel_dns_hostname: String) -> Self {
        Self {
            lan_iface,
            tunnel_dns_hostname,
            tcpdump_secs: 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosPfBlockRule {
    pub name: String,
    pub action: String,
    pub direction: String,
    pub enabled: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosPfBlockRulesReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub rules: Vec<MacosPfBlockRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosTunnelPathResolvesReport {
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDnsBlockProbeReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub probe_attempted: bool,
    pub probe_target: String,
    pub probe_query: String,
    pub udp_response_received: bool,
    pub tcp_response_received: bool,
    pub reason: String,
}

pub fn write_macos_exit_dns_failclosed_artifacts(
    output_dir: &Path,
    options: &MacosExitDnsFailclosedOptions,
) -> Result<(), String> {
    // Resolve the capture interface: when the caller passes `auto` (or an
    // empty value) derive the live egress NIC from the routing table rather
    // than trusting a hardcoded `en0`. A wrong/dead interface makes tcpdump
    // observe nothing, turning the DNS-leak proof into a vacuous PASS — a
    // false security guarantee. Deriving + failing loud when undetermined
    // keeps the leak evidence honest.
    let lan_iface = resolve_capture_lan_iface(options.lan_iface.as_str())?;
    validate_hostname(options.tunnel_dns_hostname.as_str())?;
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create {} failed: {err}", output_dir.display()))?;

    let dns_check = build_macos_dns_failclosed_report(collect_macos_dns_failclosed_snapshot());
    write_json(
        &output_dir.join("macos_dns_failclosed_check.json"),
        &dns_check,
        "macos_dns_failclosed_check.json",
    )?;

    let pf_rules_stdout = capture_pf_rules_stdout().unwrap_or_default();
    let pf_rules = build_macos_pf_block_rules_report(pf_rules_stdout.as_str());
    write_json(
        &output_dir.join("pf_block_rules.json"),
        &pf_rules,
        "pf_block_rules.json",
    )?;

    // Derive an off-tunnel DNS target (the LAN default gateway) so the probe
    // sends a real port-53 datagram toward a directly-reachable, NON-tunnel
    // destination. If the killswitch is enforced the packet is dropped on
    // egress (empty pcap); if it is not, the attempt appears in the capture.
    // Failing loud when the gateway cannot be derived keeps the proof honest
    // (no silent fall back to a probe that can't egress).
    let probe_target = derive_macos_default_gateway()?;
    validate_probe_target(probe_target.as_str())?;

    let (udp_pcap, udp_probe_output) = capture_dns_block_path(
        lan_iface.as_str(),
        "udp",
        probe_target.as_str(),
        DNS_BLOCK_PROBE_QUERY,
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("udp_block_pcap.txt"), udp_pcap)
        .map_err(|err| format!("write udp_block_pcap.txt failed: {err}"))?;

    let (tcp_pcap, tcp_probe_output) = capture_dns_block_path(
        lan_iface.as_str(),
        "tcp",
        probe_target.as_str(),
        DNS_BLOCK_PROBE_QUERY,
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("tcp_block_pcap.txt"), tcp_pcap)
        .map_err(|err| format!("write tcp_block_pcap.txt failed: {err}"))?;

    let probe_report = build_macos_dns_block_probe_report(
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

pub fn build_macos_pf_block_rules_report(pfctl_rules_stdout: &str) -> MacosPfBlockRulesReport {
    let rules = [DNS_BLOCK_LAN_UDP_RULE, DNS_BLOCK_LAN_TCP_RULE]
        .into_iter()
        .map(|name| parse_pf_block_rule(pfctl_rules_stdout, name))
        .collect::<Vec<_>>();
    let overall_ok = rules
        .iter()
        .all(|rule| rule.enabled == "true" && rule.action == "block");
    MacosPfBlockRulesReport {
        schema_version: MACOS_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
        overall_ok,
        rules,
    }
}

pub fn build_tunnel_path_resolves_report(
    hostname: &str,
    resolver_stdout: &str,
) -> MacosTunnelPathResolvesReport {
    let addresses = resolver_stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("ip_address:"))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let resolved = !addresses.is_empty();
    MacosTunnelPathResolvesReport {
        schema_version: MACOS_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
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
pub fn dns_probe_response_received(dig_output: &str) -> bool {
    dig_output.to_ascii_lowercase().contains("->>header<<-")
}

/// Build the blocked-path probe report. `overall_ok` (the leak-proof PASS
/// condition) requires that the probe was actually attempted AND that NEITHER
/// the UDP nor the TCP probe received any DNS response. Fail-closed: a probe
/// that did not run, or any observed response, is NOT ok.
pub fn build_macos_dns_block_probe_report(
    probe_target: &str,
    probe_query: &str,
    attempted: bool,
    udp_dig_output: &str,
    tcp_dig_output: &str,
) -> MacosDnsBlockProbeReport {
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
    MacosDnsBlockProbeReport {
        schema_version: MACOS_EXIT_DNS_FAILCLOSED_SCHEMA_VERSION,
        overall_ok,
        probe_attempted: attempted,
        probe_target: probe_target.to_owned(),
        probe_query: probe_query.to_owned(),
        udp_response_received,
        tcp_response_received,
        reason,
    }
}

/// Extract the `gateway:` value from `route -n get default` output. Pure so it
/// is host-testable regardless of the build target.
pub fn parse_macos_route_gateway(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("gateway:").map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// Validate the derived probe target is a literal IP address. A point-to-point
/// default route renders `gateway: link#N` (no usable unicast target), so a
/// non-IP gateway must fail loud rather than produce an unsendable probe.
fn validate_probe_target(value: &str) -> Result<(), String> {
    value
        .parse::<std::net::IpAddr>()
        .map(|_| ())
        .map_err(|_| format!("derived DNS probe target {value:?} is not a usable IP address"))
}

fn parse_pf_block_rule(pfctl_rules_stdout: &str, name: &str) -> MacosPfBlockRule {
    let matched = pfctl_rules_stdout
        .lines()
        .map(str::trim)
        .find(|line| line.contains(name));
    match matched {
        Some(line) => {
            let is_block = line.starts_with("block") || line.contains(" block ");
            let is_drop = line.contains("drop");
            let is_out = line.contains(" out ") || line.ends_with(" out");
            MacosPfBlockRule {
                name: name.to_owned(),
                action: if is_block {
                    "block".to_owned()
                } else {
                    "unknown".to_owned()
                },
                direction: if is_out {
                    "out".to_owned()
                } else if line.contains(" in ") || line.ends_with(" in") {
                    "in".to_owned()
                } else {
                    "any".to_owned()
                },
                // Only a genuine active `block drop out` rule counts as an
                // enforced DNS block. If the label appears on a non-blocking,
                // non-drop, or wrong-direction line (a shadowing `pass`, a
                // commented/log rule, or a stray match), it must NOT read as
                // enabled — fail closed so a config-text match can't masquerade
                // as enforcement.
                enabled: if is_block && is_drop && is_out {
                    "true".to_owned()
                } else {
                    "false".to_owned()
                },
            }
        }
        None => MacosPfBlockRule {
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

/// Resolve the LAN egress interface to capture on. `auto` (or an empty
/// value) triggers live derivation from the routing table; any other value
/// is taken as an explicit interface name (still validated). Fails loud
/// rather than silently falling back to a guessed default.
fn resolve_capture_lan_iface(requested: &str) -> Result<String, String> {
    let trimmed = requested.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        let derived = derive_macos_egress_interface()?;
        validate_iface_name(derived.as_str())?;
        return Ok(derived);
    }
    validate_iface_name(trimmed)?;
    Ok(trimmed.to_owned())
}

/// Extract the `interface:` value from `route -n get <dst>` output. Pure so
/// it is host-testable regardless of the build target.
pub fn parse_macos_route_interface(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("interface:").map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

#[cfg(target_os = "macos")]
fn derive_macos_egress_interface() -> Result<String, String> {
    let stdout = run_route(&["-n", "get", "default"])?;
    parse_macos_route_interface(stdout.as_str()).ok_or_else(|| {
        "could not derive default egress interface from `route -n get default`".to_owned()
    })
}

#[cfg(not(target_os = "macos"))]
fn derive_macos_egress_interface() -> Result<String, String> {
    Err("egress interface auto-derivation is only supported on macOS".to_owned())
}

#[cfg(target_os = "macos")]
fn run_route(args: &[&str]) -> Result<String, String> {
    let output = Command::new("/sbin/route")
        .args(args)
        .output()
        .map_err(|err| format!("route {} failed to start: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "route {} failed: status={} stderr={}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn validate_iface_name(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 32
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err("lan interface name contains unsupported characters".to_owned());
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

/// Bounded retry budget for live anchor discovery. The killswitch anchor's
/// generation rotates on every (re-)apply, so a single-shot `pfctl -s Anchors`
/// sample can land in the rotation window with no matching anchor present. Poll
/// up to this many attempts, sleeping `DNS_ANCHOR_POLL_INTERVAL` between tries,
/// returning as soon as one matches. The bound is a fixed `for` range so the
/// loop always terminates; once exhausted it fails closed with the original
/// "no active …" error (no silent empty ruleset that would mask an absent block).
#[cfg(target_os = "macos")]
const DNS_ANCHOR_POLL_ATTEMPTS: u32 = 15;
#[cfg(target_os = "macos")]
const DNS_ANCHOR_POLL_INTERVAL: Duration = Duration::from_secs(1);

#[cfg(target_os = "macos")]
fn capture_pf_rules_stdout() -> Result<String, String> {
    use crate::macos_exit_killswitch_precedence::{
        AnchorPollOutcome, classify_anchor_poll_sample, validate_pf_anchor_name,
    };
    // The macOS exit dataplane loads its filter rules — including the labeled
    // LAN DNS-block rules `render_pf_rules` emits — into a generation-numbered
    // anchor `com.apple/rustynet_g<N>`, NOT the main ruleset. A bare
    // `pfctl -s rules` therefore never observes them. Enumerate the live
    // anchors, select the highest-generation rustynet anchor, and dump ITS
    // rules. The anchor generation rotates on every (re-)apply, so a single
    // sample can race the rotation window; poll a bounded number of times,
    // returning the instant one matches. Fail loud once the budget is spent:
    // the producer must observe the real filter rules rather than silently
    // reporting an empty ruleset that would mask an absent DNS block.
    let mut anchor: Option<String> = None;
    for attempt in 0..DNS_ANCHOR_POLL_ATTEMPTS {
        let anchors = run_pfctl(&["-s", "Anchors"])?;
        let has_more_attempts = attempt + 1 < DNS_ANCHOR_POLL_ATTEMPTS;
        match classify_anchor_poll_sample(anchors.as_str(), has_more_attempts) {
            AnchorPollOutcome::Found(found) => {
                anchor = Some(found);
                break;
            }
            AnchorPollOutcome::Retry => sleep(DNS_ANCHOR_POLL_INTERVAL),
            AnchorPollOutcome::GiveUp => break,
        }
    }
    let anchor = anchor.ok_or_else(|| {
        "no active com.apple/rustynet_g<N> pf anchor found; daemon killswitch path not active"
            .to_owned()
    })?;
    validate_pf_anchor_name(anchor.as_str())?;
    run_pfctl(&["-a", anchor.as_str(), "-s", "rules"])
}

#[cfg(target_os = "macos")]
fn run_pfctl(args: &[&str]) -> Result<String, String> {
    let output = Command::new("/sbin/pfctl")
        .args(args)
        .output()
        .map_err(|err| format!("pfctl {} failed to start: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "pfctl {} failed: status={} stderr={}",
            args.join(" "),
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn capture_pf_rules_stdout() -> Result<String, String> {
    Ok(String::new())
}

#[cfg(target_os = "macos")]
fn derive_macos_default_gateway() -> Result<String, String> {
    let stdout = run_route(&["-n", "get", "default"])?;
    parse_macos_route_gateway(stdout.as_str())
        .ok_or_else(|| "could not derive default gateway from `route -n get default`".to_owned())
}

#[cfg(not(target_os = "macos"))]
fn derive_macos_default_gateway() -> Result<String, String> {
    Err("default-gateway derivation is only supported on macOS".to_owned())
}

/// Capture DNS/53 egress on `iface` while ACTIVELY sending one off-tunnel DNS
/// probe (to `server`) mid-window. Returns the tcpdump text plus the `dig`
/// output. The probe makes an empty pcap meaningful: a real port-53 datagram
/// was driven toward a reachable, non-tunnel destination, so an empty capture
/// proves the killswitch dropped it rather than "nothing tried DNS".
#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

#[cfg(not(target_os = "macos"))]
fn capture_dns_block_path(
    _iface: &str,
    _protocol: &str,
    _server: &str,
    _query: &str,
    _duration: Duration,
) -> Result<(String, String), String> {
    Ok((String::new(), String::new()))
}

#[cfg(target_os = "macos")]
fn capture_tunnel_dns_resolution(hostname: &str) -> Result<String, String> {
    let output = Command::new("/usr/bin/dscacheutil")
        .args(["-q", "host", "-a", "name", hostname])
        .output()
        .map_err(|err| format!("dscacheutil host lookup failed to start: {err}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn capture_tunnel_dns_resolution(_hostname: &str) -> Result<String, String> {
    Ok(String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_report_accepts_reviewed_udp_and_tcp_rules() {
        let body = r#"
block drop out quick on en0 inet proto udp from any to 192.168.1.0/24 port = domain label "rustynet-dns-block-lan-udp"
block drop out quick on en0 inet proto tcp from any to 192.168.1.0/24 port = domain label "rustynet-dns-block-lan-tcp"
"#;
        let report = build_macos_pf_block_rules_report(body);
        assert!(report.overall_ok);
        assert_eq!(report.schema_version, 1);
        assert_eq!(report.rules.len(), 2);
        assert!(report.rules.iter().all(|rule| rule.action == "block"));
        assert!(report.rules.iter().all(|rule| rule.direction == "out"));
    }

    #[test]
    fn pf_report_fails_closed_when_rule_missing() {
        let report = build_macos_pf_block_rules_report("");
        assert!(!report.overall_ok);
        assert!(
            report
                .rules
                .iter()
                .any(|rule| rule.name == DNS_BLOCK_LAN_UDP_RULE && rule.enabled == "false")
        );
    }

    #[test]
    fn pf_report_accepts_rendered_anchor_rule_shape() {
        // Mirrors what `pfctl -a com.apple/rustynet_g<N> -s rules` emits for
        // the rules render_pf_rules (phase10.rs) now produces: `block drop out
        // quick inet proto udp/tcp to any port 53 label "rustynet-dns-block-
        // lan-*"`, after pfctl normalization (`port 53` -> `port = 53`, an
        // explicit `from any to any`). The labels are the canonical
        // DNS_BLOCK_LAN_*_RULE constants shared with render_pf_rules.
        let body = format!(
            "block drop out quick inet proto udp from any to any port = 53 label \"{DNS_BLOCK_LAN_UDP_RULE}\"\n\
             block drop out quick inet proto tcp from any to any port = 53 label \"{DNS_BLOCK_LAN_TCP_RULE}\"\n\
             block drop out quick all\n",
        );
        let report = build_macos_pf_block_rules_report(body.as_str());
        assert!(report.overall_ok, "labeled rendered rules must pass");
        assert_eq!(report.rules.len(), 2);
        assert!(report.rules.iter().all(|rule| rule.action == "block"));
        assert!(report.rules.iter().all(|rule| rule.direction == "out"));
    }

    #[test]
    fn pf_report_rejects_label_less_block_rules() {
        // The pre-fix failure mode: the live rules (or a bare main-ruleset
        // `pfctl -s rules` dump that never sees the anchor) carry NO label, so
        // the producer cannot identify them and must fail closed. This is what
        // made the live capture stage abort before the fix.
        let body = "block drop out quick inet proto udp from any to any port = 53\n\
             block drop out quick inet proto tcp from any to any port = 53\n\
             block drop out quick all\n";
        let report = build_macos_pf_block_rules_report(body);
        assert!(
            !report.overall_ok,
            "label-less block rules must not satisfy the DNS-block contract"
        );
    }

    #[test]
    fn tunnel_resolve_report_accepts_dscacheutil_answer() {
        let report = build_tunnel_path_resolves_report(
            "exit-1.rustynet",
            "name: exit-1.rustynet\nip_address: 100.64.0.1\n",
        );
        assert!(report.overall_ok);
        assert!(report.resolved);
        assert_eq!(report.addresses, vec!["100.64.0.1"]);
    }

    #[test]
    fn tunnel_resolve_report_fails_closed_without_answer() {
        let report = build_tunnel_path_resolves_report("exit-1.rustynet", "");
        assert!(!report.overall_ok);
        assert!(!report.resolved);
    }

    #[test]
    fn route_interface_parser_extracts_egress_nic() {
        // Real `route -n get default` block shape on macOS 26.x.
        let out = "   route to: default\ndestination: default\n       gateway: 192.168.0.1\n     interface: en0\n         flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n";
        assert_eq!(parse_macos_route_interface(out).as_deref(), Some("en0"));
    }

    #[test]
    fn route_interface_parser_handles_bridged_nic_and_missing() {
        // A bridged/secondary NIC must be derived faithfully (not assumed en0).
        let bridged = "       gateway: 10.0.0.1\n     interface: en1\n";
        assert_eq!(parse_macos_route_interface(bridged).as_deref(), Some("en1"));
        // No interface line -> None so the caller fails loud rather than guessing.
        assert_eq!(parse_macos_route_interface("   route to: default\n"), None);
        assert_eq!(parse_macos_route_interface("     interface:   \n"), None);
    }

    #[test]
    fn resolve_capture_lan_iface_takes_explicit_value() {
        assert_eq!(resolve_capture_lan_iface("en3").unwrap(), "en3");
        assert!(resolve_capture_lan_iface("en0;rm").is_err());
    }

    #[test]
    fn input_validation_rejects_shell_metacharacters() {
        assert!(validate_iface_name("en0").is_ok());
        assert!(validate_hostname("exit-1.rustynet").is_ok());
        assert!(validate_iface_name("en0;rm").is_err());
        assert!(validate_hostname("exit-1.rustynet;rm").is_err());
    }

    #[test]
    fn pf_report_rejects_label_on_pass_or_inbound_rule() {
        // A shadowing/misconfigured rule that merely CARRIES the label but is
        // not an active `block drop out` rule must not read as enforced. The
        // hardened parser fails closed for a `pass` line and for an inbound
        // block — both would otherwise have reported enabled=true previously.
        let pass_shadow = format!(
            "pass out quick inet proto udp from any to any port = 53 label \"{DNS_BLOCK_LAN_UDP_RULE}\"\n\
             block drop in quick inet proto tcp from any to any port = 53 label \"{DNS_BLOCK_LAN_TCP_RULE}\"\n",
        );
        let report = build_macos_pf_block_rules_report(pass_shadow.as_str());
        assert!(
            !report.overall_ok,
            "a label on a pass/inbound rule must not satisfy the DNS-block contract"
        );
        assert!(
            report.rules.iter().all(|rule| rule.enabled == "false"),
            "neither non-block rule may report enabled=true"
        );
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
        let ok = build_macos_dns_block_probe_report(
            "10.0.0.1",
            DNS_BLOCK_PROBE_QUERY,
            true,
            blocked,
            blocked,
        );
        assert!(ok.overall_ok);
        assert!(ok.probe_attempted);
        assert!(!ok.udp_response_received && !ok.tcp_response_received);
    }

    #[test]
    fn dns_block_probe_report_fails_closed_on_response() {
        let answered = ";; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 1\n";
        let blocked = ";; no servers could be reached\n";
        // A response on EITHER transport is a leak.
        let leak_udp = build_macos_dns_block_probe_report(
            "10.0.0.1",
            DNS_BLOCK_PROBE_QUERY,
            true,
            answered,
            blocked,
        );
        assert!(!leak_udp.overall_ok);
        assert!(leak_udp.udp_response_received);
        let leak_tcp = build_macos_dns_block_probe_report(
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
            build_macos_dns_block_probe_report("10.0.0.1", DNS_BLOCK_PROBE_QUERY, false, "", "");
        assert!(!report.overall_ok);
        assert!(!report.probe_attempted);
    }

    #[test]
    fn route_gateway_parser_extracts_ip_and_rejects_link() {
        let out = "   route to: default\ndestination: default\n       gateway: 192.168.0.1\n     interface: en0\n";
        assert_eq!(
            parse_macos_route_gateway(out).as_deref(),
            Some("192.168.0.1")
        );
        assert!(validate_probe_target("192.168.0.1").is_ok());
        // A point-to-point link gateway has no unicast target and must fail loud.
        let link = "       gateway: link#12\n     interface: utun4\n";
        assert_eq!(parse_macos_route_gateway(link).as_deref(), Some("link#12"));
        assert!(validate_probe_target("link#12").is_err());
        assert_eq!(parse_macos_route_gateway("   route to: default\n"), None);
    }
}
