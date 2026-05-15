#![allow(clippy::result_large_err)]

//! Linux DNS fail-closed verifier.
//!
//! Linux parity for `windows_dns_failclosed`. Confirms the host's
//! resolver is bound to loopback only — no external DNS server is
//! configured to receive queries that should stay inside the mesh.
//! When the resolver path on the host points anywhere off-loopback,
//! a queries-to-mesh-names side-channel exists and the verifier
//! reports drift.
//!
//! On Linux there are several resolver stacks (systemd-resolved,
//! resolvconf, dnsmasq, plain `/etc/resolv.conf`). This verifier
//! reads `/etc/resolv.conf` directly because that's the lowest-
//! common-denominator file every libc-using process consults. A
//! future slice can extend the verifier to query
//! `resolvectl status` for systemd-resolved-managed hosts; the
//! resolv.conf check stays as the floor.
//!
//! The pure evaluator takes a parsed list of nameserver addresses
//! and confirms every one is loopback (127.0.0.0/8 for IPv4, ::1/128
//! for IPv6). Off-loopback nameservers count as drift.
//!
//! Wired through the CLI as `rustynetd linux-dns-failclosed-check`.
//! The orchestrator's `LinuxDaemonProbe` adapter dispatches the
//! `DnsFailclosed` op to this subcommand.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const REVIEWED_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDnsFailclosedSnapshot {
    pub resolv_conf_path: String,
    pub resolv_conf_present: bool,
    /// Raw nameserver lines from `/etc/resolv.conf`, in source order.
    pub nameservers: Vec<String>,
    /// Optional capture of `search` / `domain` lines for forensic
    /// completeness; not evaluated for drift today.
    pub search_domains: Vec<String>,
    /// Whether the daemon's loopback resolver is bound — currently
    /// inferred from the `RUSTYNET_DNS_RESOLVER_BIND_ADDR=127.0.0.1:…`
    /// env-var contract; this snapshot field is a placeholder for a
    /// future probe of the actual listening socket.
    pub loopback_resolver_advertised: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDnsFailclosedReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: LinuxDnsFailclosedSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator: walks the nameserver list and confirms every
/// entry is a loopback address. Returns every drift reason in one
/// pass. The collector does the file-IO / parsing; the evaluator
/// stays platform-agnostic and unit-testable.
pub fn evaluate_linux_dns_failclosed_snapshot(
    snapshot: &LinuxDnsFailclosedSnapshot,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    if !snapshot.resolv_conf_present {
        reasons.push(format!(
            "resolv.conf not readable at {}: cannot confirm DNS fail-closed posture",
            snapshot.resolv_conf_path
        ));
        return reasons;
    }
    if snapshot.nameservers.is_empty() {
        reasons.push(format!(
            "{} contains no nameserver entries; cannot confirm fail-closed posture",
            snapshot.resolv_conf_path
        ));
        return reasons;
    }
    for raw in &snapshot.nameservers {
        match raw.parse::<IpAddr>() {
            Ok(addr) if is_loopback_address(&addr) => {}
            Ok(addr) => {
                reasons.push(format!(
                    "nameserver {addr} is non-loopback; mesh DNS queries leak off-host"
                ));
            }
            Err(err) => {
                reasons.push(format!(
                    "nameserver entry {raw:?} is not a parseable IP address: {err}"
                ));
            }
        }
    }
    reasons
}

fn is_loopback_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

pub fn build_linux_dns_failclosed_report(
    snapshot: LinuxDnsFailclosedSnapshot,
) -> LinuxDnsFailclosedReport {
    let drift_reasons = evaluate_linux_dns_failclosed_snapshot(&snapshot);
    let overall_ok = drift_reasons.is_empty();
    LinuxDnsFailclosedReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Parse `/etc/resolv.conf`-style content. Strips comments (`#` /
/// `;`), extracts each `nameserver <addr>` and `search <domain ...>`
/// line. Tolerant of leading whitespace + blank lines so the parser
/// matches what glibc accepts.
pub fn parse_resolv_conf(body: &str) -> (Vec<String>, Vec<String>) {
    let mut nameservers: Vec<String> = Vec::new();
    let mut search_domains: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let value = rest.trim();
            if !value.is_empty() {
                nameservers.push(value.to_string());
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("search") {
            for token in rest.split_ascii_whitespace() {
                search_domains.push(token.to_string());
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("domain") {
            let value = rest.trim();
            if !value.is_empty() {
                search_domains.push(value.to_string());
            }
        }
    }
    (nameservers, search_domains)
}

/// Cross-platform collector. On Linux reads `/etc/resolv.conf` and
/// parses it; off-Linux emits a snapshot with `resolv_conf_present =
/// false` and a clear blocker reason.
pub fn collect_linux_dns_failclosed_snapshot() -> LinuxDnsFailclosedSnapshot {
    collect_linux_dns_failclosed_snapshot_inner()
}

#[cfg(target_os = "linux")]
fn collect_linux_dns_failclosed_snapshot_inner() -> LinuxDnsFailclosedSnapshot {
    let body = match std::fs::read_to_string(REVIEWED_RESOLV_CONF_PATH) {
        Ok(b) => b,
        Err(_) => {
            return LinuxDnsFailclosedSnapshot {
                resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
                resolv_conf_present: false,
                nameservers: Vec::new(),
                search_domains: Vec::new(),
                // Off-host loopback advertise: assume the daemon's
                // RUSTYNET_DNS_RESOLVER_BIND_ADDR env var advertises
                // 127.0.0.1; the snapshot field stays a contract
                // marker until a future slice probes the live socket.
                loopback_resolver_advertised: true,
            };
        }
    };
    let (nameservers, search_domains) = parse_resolv_conf(body.as_str());
    LinuxDnsFailclosedSnapshot {
        resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
        resolv_conf_present: true,
        nameservers,
        search_domains,
        loopback_resolver_advertised: true,
    }
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_dns_failclosed_snapshot_inner() -> LinuxDnsFailclosedSnapshot {
    LinuxDnsFailclosedSnapshot {
        resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
        resolv_conf_present: false,
        nameservers: Vec::new(),
        search_domains: Vec::new(),
        loopback_resolver_advertised: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback_only_snapshot() -> LinuxDnsFailclosedSnapshot {
        LinuxDnsFailclosedSnapshot {
            resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_string(), "::1".to_string()],
            search_domains: vec!["rustynet".to_string()],
            loopback_resolver_advertised: true,
        }
    }

    #[test]
    fn parser_extracts_nameservers_and_search_domains() {
        let body = "\
# generated by systemd-resolved
nameserver 127.0.0.53
nameserver ::1
search lan rustynet
domain example.lan
";
        let (ns, sd) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.53".to_string(), "::1".to_string()]);
        assert!(sd.contains(&"lan".to_string()));
        assert!(sd.contains(&"rustynet".to_string()));
        assert!(sd.contains(&"example.lan".to_string()));
    }

    #[test]
    fn parser_skips_comments_and_blank_lines() {
        let body = "\n; classic semicolon comment\n# hash comment\n   \nnameserver 127.0.0.1\n";
        let (ns, _sd) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1".to_string()]);
    }

    #[test]
    fn evaluator_accepts_loopback_only_nameservers() {
        let reasons = evaluate_linux_dns_failclosed_snapshot(&loopback_only_snapshot());
        assert!(reasons.is_empty(), "loopback-only must pass: {reasons:?}");
    }

    #[test]
    fn evaluator_rejects_external_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers.push("8.8.8.8".to_string());
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("8.8.8.8") && r.contains("non-loopback")),
            "external DNS must surface as drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_lan_resolver_address() {
        // RFC1918 LAN router DNS is the most common drift in practice.
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["192.168.1.1".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("192.168.1.1") && r.contains("non-loopback")),
            "RFC1918 DNS must surface as drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unparseable_nameserver_entry() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["not-an-address".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("not a parseable IP")),
            "garbage entries must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_resolv_conf() {
        let snap = LinuxDnsFailclosedSnapshot {
            resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
            resolv_conf_present: false,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            loopback_resolver_advertised: true,
        };
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("not readable")),
            "missing file must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_empty_nameservers_list() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers.clear();
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("no nameserver entries")),
            "empty list must surface: {reasons:?}"
        );
    }

    #[test]
    fn build_report_marks_overall_ok_for_loopback_only_snapshot() {
        let report = build_linux_dns_failclosed_report(loopback_only_snapshot());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_linux_dns_failclosed_report(loopback_only_snapshot());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxDnsFailclosedReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec![
            "8.8.8.8".to_string(),
            "192.168.1.1".to_string(),
            "garbage".to_string(),
        ];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(reasons.len() >= 3, "expected three drifts: {reasons:?}");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collector_off_linux_marks_resolv_conf_absent() {
        let snap = collect_linux_dns_failclosed_snapshot();
        assert!(!snap.resolv_conf_present);
        assert!(snap.nameservers.is_empty());
        let report = build_linux_dns_failclosed_report(snap);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("not readable")),
            "off-Linux must surface unreadable resolv.conf"
        );
    }

    // ---- L4: race + edge-case fail-closed coverage --------------------

    /// systemd-resolved's stub listener uses 127.0.0.53 (still loopback).
    /// The evaluator must accept this as valid — the queries never leave
    /// the host even though the address isn't the bare 127.0.0.1.
    #[test]
    fn evaluator_accepts_systemd_resolved_stub_127_0_0_53() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["127.0.0.53".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.is_empty(),
            "127.0.0.53 (systemd-resolved stub) must pass: {reasons:?}"
        );
    }

    /// IPv4 unspecified 0.0.0.0 must be flagged — a resolver binding to
    /// the wildcard accepts off-host traffic and is not loopback-only.
    #[test]
    fn evaluator_rejects_ipv4_unspecified_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["0.0.0.0".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("0.0.0.0") && r.contains("non-loopback")),
            "0.0.0.0 must surface as drift: {reasons:?}"
        );
    }

    /// IPv6 unspecified :: must be flagged for the same reason.
    #[test]
    fn evaluator_rejects_ipv6_unspecified_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["::".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("non-loopback")),
            ":: must surface as drift: {reasons:?}"
        );
    }

    /// IPv4 link-local 169.254.0.0/16 — common DHCP / cloud-metadata
    /// path. Off-loopback, must drift.
    #[test]
    fn evaluator_rejects_ipv4_link_local_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["169.254.169.254".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("169.254.169.254") && r.contains("non-loopback")),
            "IPv4 link-local must surface as drift: {reasons:?}"
        );
    }

    /// IPv6 link-local fe80::/10 — NetworkManager / RA-installed
    /// resolver case. Off-loopback, must drift.
    #[test]
    fn evaluator_rejects_ipv6_link_local_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["fe80::1".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("fe80") && r.contains("non-loopback")),
            "IPv6 link-local must surface as drift: {reasons:?}"
        );
    }

    /// IPv4-mapped IPv6 (::ffff:8.8.8.8) — same wire address as 8.8.8.8
    /// but written as v6. Must not be treated as loopback.
    #[test]
    fn evaluator_rejects_ipv4_mapped_external_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["::ffff:8.8.8.8".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("non-loopback")),
            "IPv4-mapped external must surface as drift: {reasons:?}"
        );
    }

    /// IPv6 loopback expressed in long form must be accepted.
    #[test]
    fn evaluator_accepts_ipv6_loopback_long_form() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["0:0:0:0:0:0:0:1".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.is_empty(),
            "0:0:0:0:0:0:0:1 must pass as loopback: {reasons:?}"
        );
    }

    /// Loopback range 127.0.0.0/8: 127.255.255.254 is still loopback by
    /// Rust's `is_loopback`. Pin the contract so a future refactor that
    /// narrows to 127.0.0.1 only doesn't silently shift behavior.
    #[test]
    fn evaluator_accepts_full_127_slash_8_loopback_range() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec![
            "127.0.0.1".to_string(),
            "127.0.0.53".to_string(),
            "127.255.255.254".to_string(),
        ];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.is_empty(),
            "127.0.0.0/8 must all pass as loopback: {reasons:?}"
        );
    }

    /// One loopback + one external → external is flagged, loopback is
    /// not. Race shape: NetworkManager appended a public resolver after
    /// systemd-resolved's stub line during precedence resolution.
    #[test]
    fn evaluator_flags_only_off_loopback_entry_when_mixed() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["127.0.0.53".to_string(), "1.1.1.1".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert_eq!(
            reasons.len(),
            1,
            "exactly one drift expected for one external entry: {reasons:?}"
        );
        assert!(
            reasons[0].contains("1.1.1.1") && reasons[0].contains("non-loopback"),
            "drift must name the off-loopback entry: {reasons:?}"
        );
    }

    /// IPv6 link-local with zone-id (fe80::1%eth0) is not a parseable
    /// IpAddr in Rust std — confirm the evaluator surfaces it as a
    /// parse failure rather than silently accepting.
    #[test]
    fn evaluator_rejects_zoneid_suffixed_link_local() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["fe80::1%eth0".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("not a parseable IP")),
            "zone-id-suffixed entry must surface as parse failure: {reasons:?}"
        );
    }

    /// IPv6 bracketed form `[::1]` is a URL form, not resolv.conf form.
    /// Confirm we reject it as unparseable rather than silently
    /// accepting after a brackets-strip.
    #[test]
    fn evaluator_rejects_bracketed_ipv6_nameserver() {
        let mut snap = loopback_only_snapshot();
        snap.nameservers = vec!["[::1]".to_string()];
        let reasons = evaluate_linux_dns_failclosed_snapshot(&snap);
        assert!(
            reasons.iter().any(|r| r.contains("not a parseable IP")),
            "bracketed form must surface as parse failure: {reasons:?}"
        );
    }

    /// Parser tolerates leading whitespace before `nameserver` — common
    /// in resolvconf-managed files where /run/resolvconf snippets get
    /// concatenated with mixed indentation.
    #[test]
    fn parser_tolerates_leading_whitespace_before_nameserver() {
        let body = "    nameserver 127.0.0.1\n\t nameserver ::1\n";
        let (ns, _sd) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1".to_string(), "::1".to_string()]);
    }

    /// Parser ignores resolv.conf option lines (`options`, `sortlist`,
    /// `lookup`, `family`) — they are not nameserver-bearing and must
    /// not appear in the nameserver list.
    #[test]
    fn parser_ignores_options_and_sortlist_lines() {
        let body = "\
options edns0 timeout:1 attempts:2
sortlist 192.168.1.0/24
lookup file bind
family inet4
nameserver 127.0.0.1
";
        let (ns, sd) = parse_resolv_conf(body);
        assert_eq!(
            ns,
            vec!["127.0.0.1".to_string()],
            "options/sortlist/lookup/family must not pollute nameservers"
        );
        assert!(sd.is_empty(), "search_domains must stay empty: {sd:?}");
    }

    /// Parser treats a nameserver line with no address as a no-op
    /// rather than panicking or pushing an empty string. Mirrors what
    /// glibc does (skips the bad line).
    #[test]
    fn parser_drops_bare_nameserver_keyword_with_no_address() {
        let body = "nameserver\nnameserver 127.0.0.1\n";
        let (ns, _sd) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1".to_string()]);
    }

    /// Parser does not strip in-line comments after the address — glibc
    /// also treats the rest of the line as part of the value, so the
    /// evaluator must surface "127.0.0.1 # comment" as an unparseable
    /// entry rather than silently keeping only the IP. This pins the
    /// contract so an over-eager parser refactor doesn't introduce a
    /// silent-accept path for "127.0.0.1 # add backup 8.8.8.8".
    #[test]
    fn parser_keeps_inline_comment_attached_to_address() {
        let body = "nameserver 127.0.0.1 # via systemd-resolved\n";
        let (ns, _sd) = parse_resolv_conf(body);
        assert_eq!(ns.len(), 1);
        let reasons = evaluate_linux_dns_failclosed_snapshot(&LinuxDnsFailclosedSnapshot {
            resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_string(),
            resolv_conf_present: true,
            nameservers: ns,
            search_domains: Vec::new(),
            loopback_resolver_advertised: true,
        });
        assert!(
            reasons.iter().any(|r| r.contains("not a parseable IP")),
            "inline-comment-attached entry must surface as parse failure: {reasons:?}"
        );
    }

    /// Snapshot test: pin schema_version on report builds. Bumping it
    /// must be a deliberate change with a paired migration test, not a
    /// silent drift.
    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = build_linux_dns_failclosed_report(loopback_only_snapshot());
        assert_eq!(
            report.schema_version, 1,
            "schema_version bump must be deliberate"
        );
    }
}
