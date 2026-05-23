#![allow(clippy::result_large_err)]

//! macOS exit-mode DNS fail-closed artefact producer.
//!
//! Companion of `evaluate_macos_exit_dns_failclosed_artifact_dir` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`. This producer emits the
//! four exit-mode DNS leak-proof artefacts that sit beside the existing
//! `macos_dns_failclosed_check.json` report:
//!
//! - `pf_block_rules.json`
//! - `udp_block_pcap.txt`
//! - `tcp_block_pcap.txt`
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

pub fn write_macos_exit_dns_failclosed_artifacts(
    output_dir: &Path,
    options: &MacosExitDnsFailclosedOptions,
) -> Result<(), String> {
    validate_iface_name(options.lan_iface.as_str())?;
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

    let udp_pcap = capture_dns_pcap_text(
        options.lan_iface.as_str(),
        "udp",
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("udp_block_pcap.txt"), udp_pcap)
        .map_err(|err| format!("write udp_block_pcap.txt failed: {err}"))?;

    let tcp_pcap = capture_dns_pcap_text(
        options.lan_iface.as_str(),
        "tcp",
        Duration::from_secs(options.tcpdump_secs),
    )?;
    fs::write(output_dir.join("tcp_block_pcap.txt"), tcp_pcap)
        .map_err(|err| format!("write tcp_block_pcap.txt failed: {err}"))?;

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

fn parse_pf_block_rule(pfctl_rules_stdout: &str, name: &str) -> MacosPfBlockRule {
    let matched = pfctl_rules_stdout
        .lines()
        .map(str::trim)
        .find(|line| line.contains(name));
    match matched {
        Some(line) => MacosPfBlockRule {
            name: name.to_owned(),
            action: if line.starts_with("block") || line.contains(" block ") {
                "block".to_owned()
            } else {
                "unknown".to_owned()
            },
            direction: if line.contains(" out ") || line.ends_with(" out") {
                "out".to_owned()
            } else if line.contains(" in ") || line.ends_with(" in") {
                "in".to_owned()
            } else {
                "any".to_owned()
            },
            enabled: "true".to_owned(),
        },
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

#[cfg(target_os = "macos")]
fn capture_pf_rules_stdout() -> Result<String, String> {
    let output = Command::new("/sbin/pfctl")
        .args(["-s", "rules"])
        .output()
        .map_err(|err| format!("pfctl -s rules failed to start: {err}"))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn capture_pf_rules_stdout() -> Result<String, String> {
    Ok(String::new())
}

#[cfg(target_os = "macos")]
fn capture_dns_pcap_text(
    iface: &str,
    protocol: &str,
    duration: Duration,
) -> Result<String, String> {
    let mut child = Command::new("/usr/sbin/tcpdump")
        .args(["-n", "-i", iface, protocol, "and", "port", "53"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| format!("tcpdump {protocol}/53 failed to start: {err}"))?;
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
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "macos"))]
fn capture_dns_pcap_text(
    _iface: &str,
    _protocol: &str,
    _duration: Duration,
) -> Result<String, String> {
    Ok(String::new())
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
    fn input_validation_rejects_shell_metacharacters() {
        assert!(validate_iface_name("en0").is_ok());
        assert!(validate_hostname("exit-1.rustynet").is_ok());
        assert!(validate_iface_name("en0;rm").is_err());
        assert!(validate_hostname("exit-1.rustynet;rm").is_err());
    }
}
