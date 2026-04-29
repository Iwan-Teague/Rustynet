#![allow(clippy::result_large_err)]

//! macOS DNS fail-closed verifier.
//!
//! macOS parity for `linux_dns_failclosed`. Reads `/etc/resolv.conf`
//! (macOS populates this via mDNSResponder in most configurations) and
//! confirms every nameserver is loopback-only. Off-loopback nameservers
//! mean DNS queries that should stay inside the mesh can leak.
//!
//! The macOS resolver stack is more complex than Linux (mDNSResponder,
//! scutil, /etc/resolv.conf). This verifier reads /etc/resolv.conf as
//! the lowest-common-denominator that libc-using processes consult. A
//! future slice can extend to `scutil --dns` for the full picture.
//!
//! Wired through the CLI as `rustynetd macos-dns-failclosed-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches `DnsFailclosed` here.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const REVIEWED_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDnsFailclosedSnapshot {
    pub resolv_conf_path: String,
    pub resolv_conf_present: bool,
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub loopback_resolver_advertised: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDnsFailclosedReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: MacosDnsFailclosedSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator: every nameserver must be loopback.
pub fn evaluate_macos_dns_failclosed(nameservers: &[String]) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    for ns in nameservers {
        let addr: Option<IpAddr> = ns.trim().parse().ok();
        match addr {
            Some(ip) if ip.is_loopback() => {}
            Some(ip) => {
                reasons.push(format!(
                    "nameserver {ip} is not loopback; DNS queries may leak outside the mesh"
                ));
            }
            None => {
                reasons.push(format!("nameserver entry {ns:?} is not a valid IP address"));
            }
        }
    }
    reasons
}

pub fn parse_resolv_conf(body: &str) -> (Vec<String>, Vec<String>) {
    let mut nameservers: Vec<String> = Vec::new();
    let mut search_domains: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ns = rest.trim().to_string();
            if !ns.is_empty() {
                nameservers.push(ns);
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_string());
            }
        } else if let Some(rest) = line.strip_prefix("domain") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_string());
            }
        }
    }
    (nameservers, search_domains)
}

pub fn collect_macos_dns_failclosed_snapshot() -> MacosDnsFailclosedSnapshot {
    let resolv_conf_path = REVIEWED_RESOLV_CONF_PATH.to_string();
    match std::fs::read_to_string(REVIEWED_RESOLV_CONF_PATH) {
        Ok(body) => {
            let (nameservers, search_domains) = parse_resolv_conf(&body);
            MacosDnsFailclosedSnapshot {
                resolv_conf_path,
                resolv_conf_present: true,
                nameservers,
                search_domains,
                loopback_resolver_advertised: true,
            }
        }
        Err(_) => MacosDnsFailclosedSnapshot {
            resolv_conf_path,
            resolv_conf_present: false,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            loopback_resolver_advertised: false,
        },
    }
}

pub fn build_macos_dns_failclosed_report(
    snapshot: MacosDnsFailclosedSnapshot,
) -> MacosDnsFailclosedReport {
    let mut drift_reasons: Vec<String> = Vec::new();
    if !snapshot.resolv_conf_present {
        drift_reasons.push(format!(
            "{} is not present; DNS fail-closed posture cannot be verified",
            snapshot.resolv_conf_path
        ));
    } else {
        let ns_drift = evaluate_macos_dns_failclosed(&snapshot.nameservers);
        drift_reasons.extend(ns_drift);
    }
    let overall_ok = drift_reasons.is_empty();
    MacosDnsFailclosedReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluator_accepts_loopback_only() {
        let ns = vec!["127.0.0.1".to_string(), "::1".to_string()];
        assert!(evaluate_macos_dns_failclosed(&ns).is_empty());
    }

    #[test]
    fn evaluator_rejects_external_nameserver() {
        let ns = vec!["8.8.8.8".to_string()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("8.8.8.8")),
            "external NS must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_malformed_entry() {
        let ns = vec!["not-an-ip".to_string()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("not a valid IP")),
            "malformed must surface: {reasons:?}"
        );
    }

    #[test]
    fn parser_extracts_nameservers_and_search() {
        let body = "# comment\nnameserver 127.0.0.1\nsearch local\nnameserver ::1\n";
        let (ns, domains) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1", "::1"]);
        assert_eq!(domains, vec!["local"]);
    }

    #[test]
    fn parser_ignores_comments_and_blank_lines() {
        let body = "\n# ignored\nnameserver 127.0.0.1\n";
        let (ns, _) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1"]);
    }

    #[test]
    fn report_serde_round_trips() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_string(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_string()],
            search_domains: vec![],
            loopback_resolver_advertised: true,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosDnsFailclosedReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn build_report_loopback_only_is_ok() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_string(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_string()],
            search_domains: vec![],
            loopback_resolver_advertised: true,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
    }

    #[test]
    fn build_report_missing_resolv_conf_is_drift() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_string(),
            resolv_conf_present: false,
            nameservers: vec![],
            search_domains: vec![],
            loopback_resolver_advertised: false,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("cannot be verified")),
            "missing resolv.conf must surface: {:?}",
            report.drift_reasons
        );
    }
}
