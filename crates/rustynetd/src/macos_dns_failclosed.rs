#![allow(clippy::result_large_err)]

//! macOS DNS fail-closed verifier.
//!
//! macOS parity for `linux_dns_failclosed`. Reads `/etc/resolv.conf`
//! (macOS populates this via mDNSResponder in most configurations) and
//! confirms every nameserver is loopback-only. Off-loopback nameservers
//! mean DNS queries that should stay inside the mesh can leak.
//!
//! The macOS resolver stack is more complex than Linux (mDNSResponder,
//! scutil, /etc/resolv.conf). This verifier reads TWO independent
//! sources:
//!
//! * `/etc/resolv.conf` — the lowest-common-denominator that
//!   libc-using processes consult. Supplies `nameservers` /
//!   `search_domains`.
//! * `scutil --dns` — the resolver configuration macOS itself
//!   actually uses (mDNSResponder's view). Supplies
//!   `loopback_resolver_advertised`, derived from the PRIMARY
//!   (unscoped `resolver #1`) block's nameserver entries.
//!
//! The two sources matter because they can disagree: `/etc/resolv.conf`
//! is a compatibility shim that can advertise a loopback stub while the
//! configuration mDNSResponder resolves against points off-box. Deriving
//! `loopback_resolver_advertised` from the parsed `resolv.conf`
//! nameservers would be a tautology — it would restate the check at
//! `:87` and could never independently change a verdict (QH-39). It is
//! therefore derived from `scutil --dns` and from nothing else, and
//! fails closed when `scutil` cannot be read.
//!
//! Wired through the CLI as `rustynetd macos-dns-failclosed-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches `DnsFailclosed` here.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const REVIEWED_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Absolute path to `scutil`, the macOS resolver-configuration query
/// tool. Absolute so no `PATH` entry can substitute a different binary.
pub const REVIEWED_SCUTIL_PATH: &str = "/usr/sbin/scutil";

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

/// Snapshot-level evaluator. This is the enforcement point used by
/// report generation so missing/unverifiable resolver state fails
/// closed instead of vacuously passing an empty nameserver list.
pub fn evaluate_macos_dns_failclosed_snapshot(
    snapshot: &MacosDnsFailclosedSnapshot,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    if !snapshot.resolv_conf_present {
        reasons.push(format!(
            "{} is not present; DNS fail-closed posture cannot be verified",
            snapshot.resolv_conf_path
        ));
        return reasons;
    }
    if snapshot.nameservers.is_empty() {
        reasons.push(format!(
            "{} contains no nameserver entries; cannot confirm DNS fail-closed posture",
            snapshot.resolv_conf_path
        ));
        return reasons;
    }
    if !snapshot.loopback_resolver_advertised {
        reasons.push(format!(
            "macOS loopback resolver is not advertised by {REVIEWED_SCUTIL_PATH} --dns (primary resolver is off-loopback, empty, or unreadable); DNS fail-closed posture cannot be verified"
        ));
    }
    reasons.extend(evaluate_macos_dns_failclosed(&snapshot.nameservers));
    reasons
}

pub fn parse_resolv_conf(body: &str) -> (Vec<String>, Vec<String>) {
    let mut nameservers: Vec<String> = Vec::new();
    let mut search_domains: Vec<String> = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver") {
            let ns = rest.trim().to_owned();
            if !ns.is_empty() {
                nameservers.push(ns);
            }
        } else if let Some(rest) = line.strip_prefix("search") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("domain") {
            for domain in rest.split_whitespace() {
                search_domains.push(domain.to_owned());
            }
        }
    }
    (nameservers, search_domains)
}

/// Parse the nameservers of the PRIMARY resolver out of `scutil --dns`
/// output.
///
/// `scutil --dns` prints a `DNS configuration` section (the unscoped
/// resolvers, in priority order — `resolver #1` is the one a plain
/// query uses) followed by a `DNS configuration (for scoped queries)`
/// section holding per-interface resolvers. Only the primary unscoped
/// resolver decides where an ordinary lookup goes, so only its
/// `nameserver[N] : <addr>` lines are returned.
pub fn parse_scutil_primary_resolver_nameservers(body: &str) -> Vec<String> {
    let mut nameservers: Vec<String> = Vec::new();
    let mut in_scoped_section = false;
    let mut resolver_ordinal = 0usize;
    for line in body.lines() {
        let line = line.trim();
        if line.starts_with("DNS configuration (for scoped queries)") {
            in_scoped_section = true;
            continue;
        }
        if in_scoped_section {
            continue;
        }
        if line.starts_with("resolver #") {
            resolver_ordinal += 1;
            continue;
        }
        if resolver_ordinal != 1 {
            continue;
        }
        if let Some(rest) = line.strip_prefix("nameserver[")
            && let Some((_index, value)) = rest.split_once(':')
        {
            let value = value.trim();
            if !value.is_empty() {
                nameservers.push(value.to_owned());
            }
        }
    }
    nameservers
}

/// True only when macOS's own resolver configuration advertises at
/// least one primary nameserver AND every one of them is loopback.
///
/// This is an INDEPENDENT observation of `/etc/resolv.conf`: it is what
/// makes the `loopback_resolver_advertised` drift branch able to change
/// a verdict on its own (a `resolv.conf` reading `127.0.0.1` while
/// `scutil` resolves against a public server now fails).
pub fn loopback_resolver_advertised_from_scutil(primary_nameservers: &[String]) -> bool {
    !primary_nameservers.is_empty()
        && primary_nameservers.iter().all(|ns| {
            ns.trim()
                .parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        })
}

/// Pure snapshot builder over the two raw observations. `None` means
/// "could not be read", which fails closed in both cases: an unreadable
/// `resolv.conf` sets `resolv_conf_present=false`, and unreadable
/// `scutil` output sets `loopback_resolver_advertised=false`.
///
/// Production and tests share this function, so the drift branches are
/// reachable by the same path the daemon takes.
pub fn build_macos_dns_failclosed_snapshot(
    resolv_conf_body: Option<&str>,
    scutil_dns_body: Option<&str>,
) -> MacosDnsFailclosedSnapshot {
    let resolv_conf_path = REVIEWED_RESOLV_CONF_PATH.to_owned();
    let loopback_resolver_advertised = scutil_dns_body.is_some_and(|body| {
        loopback_resolver_advertised_from_scutil(&parse_scutil_primary_resolver_nameservers(body))
    });
    match resolv_conf_body {
        Some(body) => {
            let (nameservers, search_domains) = parse_resolv_conf(body);
            MacosDnsFailclosedSnapshot {
                resolv_conf_path,
                resolv_conf_present: true,
                nameservers,
                search_domains,
                loopback_resolver_advertised,
            }
        }
        None => MacosDnsFailclosedSnapshot {
            resolv_conf_path,
            resolv_conf_present: false,
            nameservers: Vec::new(),
            search_domains: Vec::new(),
            loopback_resolver_advertised,
        },
    }
}

/// Read `scutil --dns`. `None` on any failure (missing binary, non-zero
/// exit) so the caller fails closed rather than assuming loopback.
/// Reads the live `scutil --dns` output through the reviewed fixed path.
/// Exposed for the M1 startup-recovery guard in `macos_dns_sc_protect`.
pub fn read_scutil_dns() -> Option<String> {
    let output = std::process::Command::new(REVIEWED_SCUTIL_PATH)
        .arg("--dns")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub fn collect_macos_dns_failclosed_snapshot() -> MacosDnsFailclosedSnapshot {
    let resolv_conf_body = std::fs::read_to_string(REVIEWED_RESOLV_CONF_PATH).ok();
    let scutil_dns_body = read_scutil_dns();
    build_macos_dns_failclosed_snapshot(resolv_conf_body.as_deref(), scutil_dns_body.as_deref())
}

pub fn build_macos_dns_failclosed_report(
    snapshot: MacosDnsFailclosedSnapshot,
) -> MacosDnsFailclosedReport {
    let drift_reasons = evaluate_macos_dns_failclosed_snapshot(&snapshot);
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
        let ns = vec!["127.0.0.1".to_owned(), "::1".to_owned()];
        assert!(evaluate_macos_dns_failclosed(&ns).is_empty());
    }

    #[test]
    fn evaluator_rejects_external_nameserver() {
        let ns = vec!["8.8.8.8".to_owned()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("8.8.8.8")),
            "external NS must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_malformed_entry() {
        let ns = vec!["not-an-ip".to_owned()];
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
        let body = "\n# ignored\n; classic comment\nnameserver 127.0.0.1\n";
        let (ns, _) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1"]);
    }

    #[test]
    fn report_serde_round_trips() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_owned()],
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
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_owned()],
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
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
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

    #[test]
    fn build_report_empty_nameserver_list_fails_closed() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec![],
            search_domains: vec![],
            loopback_resolver_advertised: true,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("no nameserver entries")),
            "empty nameserver list must fail closed: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn build_report_rejects_missing_loopback_resolver_advertisement() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_owned()],
            search_domains: vec![],
            loopback_resolver_advertised: false,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("loopback resolver is not advertised")),
            "missing loopback resolver marker must fail closed: {:?}",
            report.drift_reasons
        );
    }

    // ----- QH-39: loopback_resolver_advertised is a real observation ------

    /// Representative `scutil --dns` output. The primary (unscoped)
    /// resolver's nameserver is the field under test; the scoped section
    /// deliberately carries an off-loopback server, which must NOT be
    /// read as the primary resolver.
    fn scutil_output(primary_nameserver: &str) -> String {
        format!(
            "DNS configuration\n\n\
             resolver #1\n  \
             search domain[0] : mesh.local\n  \
             nameserver[0] : {primary_nameserver}\n  \
             flags    : Request A records\n  \
             reach    : 0x00000002 (Reachable)\n\n\
             resolver #2\n  \
             domain   : local\n  \
             options  : mdns\n  \
             nameserver[0] : 8.8.8.8\n\n\
             DNS configuration (for scoped queries)\n\n\
             resolver #1\n  \
             nameserver[0] : 1.1.1.1\n  \
             if_index : 4 (en0)\n"
        )
    }

    const LOOPBACK_RESOLV_CONF: &str = "nameserver 127.0.0.1\nsearch mesh.local\n";

    #[test]
    fn scutil_parser_reads_only_the_primary_unscoped_resolver() {
        let parsed = parse_scutil_primary_resolver_nameservers(&scutil_output("127.0.0.1"));
        assert_eq!(
            parsed,
            vec!["127.0.0.1"],
            "only resolver #1 of the unscoped section is the primary resolver"
        );
    }

    #[test]
    fn scutil_parser_returns_empty_for_output_with_no_resolvers() {
        assert!(parse_scutil_primary_resolver_nameservers("DNS configuration\n\n").is_empty());
    }

    #[test]
    fn advertisement_requires_a_nonempty_all_loopback_primary_resolver() {
        assert!(loopback_resolver_advertised_from_scutil(&[
            "127.0.0.1".to_owned(),
            "::1".to_owned()
        ]));
        // Empty must NOT read as "advertised" — that is the fail-closed
        // case for a host whose resolver configuration is unset.
        assert!(!loopback_resolver_advertised_from_scutil(&[]));
        // A mixed set is not a loopback-only resolver.
        assert!(!loopback_resolver_advertised_from_scutil(&[
            "127.0.0.1".to_owned(),
            "8.8.8.8".to_owned()
        ]));
        assert!(!loopback_resolver_advertised_from_scutil(&[
            "not-an-ip".to_owned()
        ]));
    }

    #[test]
    fn snapshot_builder_observes_a_loopback_resolver_as_advertised() {
        let snapshot = build_macos_dns_failclosed_snapshot(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
        );
        assert!(snapshot.resolv_conf_present);
        assert!(
            snapshot.loopback_resolver_advertised,
            "a loopback primary resolver must be observed as advertised"
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            report.overall_ok,
            "drift_reasons: {:?}",
            report.drift_reasons
        );
    }

    /// THE negative case QH-39 asked for: resolver drift alone must fail
    /// the check.
    ///
    /// `/etc/resolv.conf` is fully compliant here (loopback-only), so the
    /// `:87` nameserver rule passes and cannot be what fails this. Only
    /// the independent `scutil --dns` observation differs — macOS is
    /// actually resolving against a public server. Before this fix the
    /// collector hardcoded `loopback_resolver_advertised = true` and this
    /// host reported `overall_ok: true`.
    #[test]
    fn snapshot_builder_fails_closed_when_scutil_shows_off_loopback_resolver() {
        let snapshot = build_macos_dns_failclosed_snapshot(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("8.8.8.8")),
        );
        assert!(
            !snapshot.loopback_resolver_advertised,
            "an off-loopback primary resolver must not be observed as advertised"
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            !report.overall_ok,
            "resolver drift must fail the check even when resolv.conf is clean"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("loopback resolver is not advertised")),
            "the drift branch must be the reason: {:?}",
            report.drift_reasons
        );
        assert!(
            !report
                .drift_reasons
                .iter()
                .any(|r| r.contains("is not loopback")),
            "resolv.conf is clean here; the nameserver rule must not be what failed: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn snapshot_builder_fails_closed_when_scutil_is_unreadable() {
        let snapshot = build_macos_dns_failclosed_snapshot(Some(LOOPBACK_RESOLV_CONF), None);
        assert!(
            !snapshot.loopback_resolver_advertised,
            "unreadable scutil output must fail closed, never assume loopback"
        );
        assert!(!build_macos_dns_failclosed_report(snapshot).overall_ok);
    }

    #[test]
    fn snapshot_builder_never_hardcodes_the_advertisement_flag() {
        // Pins the QH-39 regression directly: the flag must track the
        // scutil observation, not the readability of resolv.conf.
        let advertised = build_macos_dns_failclosed_snapshot(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
        )
        .loopback_resolver_advertised;
        let not_advertised = build_macos_dns_failclosed_snapshot(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("8.8.8.8")),
        )
        .loopback_resolver_advertised;
        assert_ne!(
            advertised, not_advertised,
            "the same resolv.conf with different resolver state must produce different flags"
        );
    }

    #[test]
    fn snapshot_builder_reports_missing_resolv_conf_independently_of_scutil() {
        let snapshot = build_macos_dns_failclosed_snapshot(None, Some(&scutil_output("127.0.0.1")));
        assert!(!snapshot.resolv_conf_present);
        assert!(
            snapshot.loopback_resolver_advertised,
            "the two sources are independent; scutil still observed a loopback resolver"
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn report_schema_version_pinned_at_one() {
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_owned()],
            search_domains: Vec::new(),
            loopback_resolver_advertised: true,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape must be int=1: {body}"
        );
    }

    #[test]
    fn evaluator_rejects_ipv4_link_local_cloud_metadata_address() {
        // 169.254.169.254 is the IMDS / cloud-metadata link-local
        // address. If the macOS resolver lists it, an exfiltration
        // path via DNS-tunneling-on-metadata is plausible. Pin the
        // mesh-only contract.
        let ns = vec!["169.254.169.254".to_owned()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("169.254.169.254")),
            "IPv4 link-local must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_ipv6_link_local_address() {
        // fe80::1 is the IPv6 link-local equivalent — typically an
        // RA-installed resolver. Pin its rejection so a future
        // "router-recommended" config doesn't silently leak.
        let ns = vec!["fe80::1".to_owned()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("fe80")),
            "IPv6 link-local must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_ipv4_mapped_ipv6_external_address() {
        // ::ffff:8.8.8.8 is an IPv4-mapped IPv6 address. macOS's
        // resolver may surface either form depending on stack
        // configuration. Pin that the IPv4-mapped path is NOT
        // misclassified as loopback by IpAddr::is_loopback.
        let ns = vec!["::ffff:8.8.8.8".to_owned()];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            !reasons.is_empty(),
            "IPv4-mapped IPv6 external must surface as drift, not silently pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_full_loopback_range() {
        // 127.0.0.0/8 is a loopback range; any address in it must
        // pass. Pin the boundary 127.255.255.254 explicitly so a
        // future tightening to 127.0.0.1-only would trip this test.
        let ns = vec![
            "127.0.0.1".to_owned(),
            "127.0.0.53".to_owned(), // systemd-resolved stub on linux peers
            "127.255.255.254".to_owned(),
        ];
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.is_empty(),
            "full 127.0.0.0/8 loopback range must pass: {reasons:?}"
        );
    }

    #[test]
    fn parser_handles_multiple_search_and_domain_directives() {
        // resolv.conf can carry multiple search directives or a
        // domain directive — the parser appends both into a single
        // search_domains list in source order. Pin so a future
        // refactor that dedups or reorders surfaces a deliberate
        // change.
        let body = "search internal.example com.example\ndomain example.org\nnameserver 127.0.0.1\nsearch alpha\n";
        let (ns, domains) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1"]);
        assert_eq!(
            domains,
            vec!["internal.example", "com.example", "example.org", "alpha"]
        );
    }

    #[test]
    fn parser_drops_bare_nameserver_directive_with_no_address() {
        // `nameserver` with no following address is malformed; the
        // parser must drop it silently (it's not a value the
        // evaluator can validate). Pin the current behavior.
        let body = "nameserver\nnameserver 127.0.0.1\n";
        let (ns, _) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1"]);
    }

    #[test]
    fn parser_keeps_inline_comment_attached_to_nameserver() {
        let body = "nameserver 127.0.0.1 # reviewed loopback\n";
        let (ns, _) = parse_resolv_conf(body);
        assert_eq!(ns, vec!["127.0.0.1 # reviewed loopback"]);
        let reasons = evaluate_macos_dns_failclosed(&ns);
        assert!(
            reasons.iter().any(|r| r.contains("not a valid IP")),
            "inline comment must not silently strip into accepted loopback: {reasons:?}"
        );
    }

    #[test]
    fn build_report_aggregates_multiple_nameserver_drift_reasons() {
        // Two off-loopback nameservers must surface as two reasons,
        // not collapse to one. Pin the no-dedup contract.
        let snapshot = MacosDnsFailclosedSnapshot {
            resolv_conf_path: "/etc/resolv.conf".to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()],
            search_domains: Vec::new(),
            loopback_resolver_advertised: false,
        };
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
        let off_loopback: Vec<&String> = report
            .drift_reasons
            .iter()
            .filter(|r| r.contains("is not loopback"))
            .collect();
        assert_eq!(
            off_loopback.len(),
            2,
            "expected 2 reasons (no dedup), got: {:?}",
            report.drift_reasons
        );
    }
}
