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

#[cfg(target_os = "linux")]
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

#[cfg(not(target_os = "linux"))]
fn capture_dns_pcap_text(
    _iface: &str,
    _protocol: &str,
    _duration: Duration,
) -> Result<String, String> {
    Ok(String::new())
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
}
