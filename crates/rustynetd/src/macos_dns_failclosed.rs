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
//! Those two sources alone were not enough to make green mean closed
//! (macOS DNS fail-closed adversarial review, finding S6): a host whose
//! pf DNS block rules were flushed, or whose enabled network services
//! quietly re-acquired DHCP-provided resolvers, could still report
//! `overall_ok: true`. The verifier therefore reads TWO additional
//! independent observations, both fail-closed, and ANDs them into the
//! verdict:
//!
//! * pf DNS block floor — `pfctl -s Anchors` plus `pfctl -a <anchor>
//!   -s rules` over every rustynet-owned anchor; at least one must
//!   carry BOTH labeled DNS block rules
//!   (`rustynet-dns-block-lan-udp` / `rustynet-dns-block-lan-tcp`).
//!   Unreadable `pfctl` output or zero rustynet-owned anchors fails
//!   closed.
//! * per-service loopback DNS pin — `networksetup
//!   -listallnetworkservices` plus `networksetup -getdnsservers
//!   <service>` over every ENABLED hardware network service; each must
//!   report loopback-only DNS. Unreadable `networksetup` output fails
//!   closed.
//!
//! Wired through the CLI as `rustynetd macos-dns-failclosed-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches `DnsFailclosed` here.

use crate::macos_dns_sc_protect::{
    NETWORKSETUP_BINARY_PATH, NetworksetupDnsServers, is_loopback_dns_server_list,
    networksetup_getdns_args, networksetup_listall_args, parse_networksetup_getdns_output,
    parse_networksetup_service_list,
};
use crate::macos_exit_dns_failclosed::{DNS_BLOCK_LAN_TCP_RULE, DNS_BLOCK_LAN_UDP_RULE};
use crate::macos_exit_killswitch_precedence::{
    MACOS_RUSTYNET_ANCHOR_PREFIX, validate_pf_anchor_name,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const REVIEWED_RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Absolute path to `scutil`, the macOS resolver-configuration query
/// tool. Absolute so no `PATH` entry can substitute a different binary.
pub const REVIEWED_SCUTIL_PATH: &str = "/usr/sbin/scutil";

/// Absolute path to `pfctl`, the pf rule-set query tool. Absolute so no
/// `PATH` entry can substitute a different binary.
pub const REVIEWED_PFCTL_PATH: &str = "/sbin/pfctl";

/// Anchor-name prefixes a pf anchor must carry for this verifier to
/// treat its rules as rustynet-owned: the generation-scoped killswitch
/// anchors (`com.apple/rustynet_g<N>`) and the rustynet blind-exit
/// anchor family (`com.rustynet/...`). Rules under any other anchor are
/// not ours to assert on.
pub const MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES: [&str; 2] =
    [MACOS_RUSTYNET_ANCHOR_PREFIX, "com.rustynet/"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDnsFailclosedSnapshot {
    pub resolv_conf_path: String,
    pub resolv_conf_present: bool,
    pub nameservers: Vec<String>,
    pub search_domains: Vec<String>,
    pub loopback_resolver_advertised: bool,
    /// pf DNS block floor: `pfctl` anchor/rule reads succeeded. `false`
    /// means the floor is unverifiable and fails closed.
    pub pfctl_readable: bool,
    /// pf DNS block floor: at least one rustynet-owned anchor carries
    /// BOTH labeled DNS block rules. Implies `pfctl_readable`.
    pub pf_block_rules_present: bool,
    /// pf DNS block floor: rustynet-owned anchors whose rules were read.
    pub pf_anchors_scanned: Vec<String>,
    /// Per-service loopback DNS pin: `networksetup` reads succeeded.
    /// `false` means the pin is unverifiable and fails closed.
    pub networksetup_readable: bool,
    /// Per-service loopback DNS pin: enabled services reporting
    /// loopback-only DNS.
    pub pinned_services: Vec<String>,
    /// Per-service loopback DNS pin: enabled services NOT reporting
    /// loopback-only DNS (including services with no configured
    /// servers — those inherit DHCP resolvers and can leak).
    pub unpinned_services: Vec<String>,
    /// Scoped `*.rustynet` resolver: `/etc/resolver/rustynet` is present
    /// and readable (M5). Required by the ScopedResolverOnly posture;
    /// ignored by the FullyProtected evaluation, which demands the full
    /// machine-wide posture (the full posture installs the scoped file,
    /// but its contract is the general resolver state).
    #[serde(default)]
    pub scoped_resolver_present: bool,
}

/// Raw pf DNS block floor observation (S6 layer 3), as collected from
/// `pfctl`. `None`-equivalent (read failure) is represented by the
/// `Option` at the builder boundary, not by a variant here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PfDnsBlockFloorObservation {
    pub anchors_scanned: Vec<String>,
    pub block_rules_present: bool,
}

/// Raw per-service loopback DNS pin observation (S6 layer 4), as
/// collected from `networksetup`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworksetupDnsPinObservation {
    pub pinned_services: Vec<String>,
    pub unpinned_services: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosDnsFailclosedReport {
    pub schema_version: u32,
    /// The DNS posture the report was evaluated FOR, as
    /// [`crate::phase10::DnsPosture::as_str`] (self-describing: the CLI
    /// evaluator rejects a report whose posture does not match the role
    /// the node is supposed to hold). Defaults to `fully_protected` when
    /// deserializing a schema-1 payload that predates the field.
    #[serde(default = "default_report_posture")]
    pub posture: String,
    pub overall_ok: bool,
    pub snapshot: MacosDnsFailclosedSnapshot,
    pub drift_reasons: Vec<String>,
}

fn default_report_posture() -> String {
    crate::phase10::DnsPosture::FullyProtected
        .as_str()
        .to_owned()
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
    // S6 layer 3: the pf DNS block floor. An unreadable `pfctl` sets
    // `pf_block_rules_present=false`, so one reason covers both shapes.
    if !snapshot.pf_block_rules_present {
        reasons.push(format!(
            "pf DNS block floor not verified: no rustynet-owned pf anchor (prefixes {}) observed carrying both labeled DNS block rules ({DNS_BLOCK_LAN_UDP_RULE} / {DNS_BLOCK_LAN_TCP_RULE}); anchors scanned: {:?}; pfctl unreadable or rules absent; DNS fail-closed posture cannot be verified",
            MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES.join(", "),
            snapshot.pf_anchors_scanned
        ));
    }
    // S6 layer 4: the per-service loopback DNS pin.
    if !snapshot.networksetup_readable {
        reasons.push(
            "networksetup service enumeration unreadable; per-service loopback DNS pin cannot be verified; DNS fail-closed posture cannot be verified"
                .to_owned(),
        );
    }
    for service in &snapshot.unpinned_services {
        reasons.push(format!(
            "network service {service:?} does not report loopback-only DNS via networksetup -getdnsservers; DNS fail-closed posture cannot be verified"
        ));
    }
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

/// True when an anchor name reported by `pfctl -s Anchors` names a
/// rustynet-owned anchor: one of `MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES`
/// AND a structurally valid pf anchor name
/// (`validate_pf_anchor_name`). Anything else is not ours to assert on.
pub fn is_rustynet_owned_pf_anchor(name: &str) -> bool {
    if !MACOS_RUSTYNET_OWNED_ANCHOR_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        return false;
    }
    validate_pf_anchor_name(name).is_ok()
}

/// Parse `pfctl -s Anchors` output into the rustynet-owned anchor
/// names. Non-owned or structurally invalid lines are skipped; blank
/// lines are skipped.
pub fn parse_pf_anchor_names(pfctl_anchors_output: &str) -> Vec<String> {
    let mut anchors = Vec::new();
    for line in pfctl_anchors_output.lines() {
        let name = line.trim();
        if name.is_empty() {
            continue;
        }
        if is_rustynet_owned_pf_anchor(name) {
            anchors.push(name.to_owned());
        }
    }
    anchors
}

/// True when a `pfctl -a <anchor> -s rules` dump contains BOTH labeled
/// DNS block rules, each as a real block rule: the quoted label token,
/// a `block` action, and a :53 port form. `pfctl` normalizes the port
/// to `port = 53`; the service-name forms (`port domain`) are accepted
/// the same way.
pub fn anchor_rules_contain_both_dns_block_labels(rules: &str) -> bool {
    fn line_is_labeled_block_rule(line: &str, label: &str) -> bool {
        let lowered = line.to_lowercase();
        lowered.contains(&format!("label \"{label}\""))
            && lowered.starts_with("block")
            && (lowered.contains("port 53")
                || lowered.contains("port = 53")
                || lowered.contains("port domain")
                || lowered.contains("port = domain"))
    }
    rules
        .lines()
        .any(|line| line_is_labeled_block_rule(line, DNS_BLOCK_LAN_UDP_RULE))
        && rules
            .lines()
            .any(|line| line_is_labeled_block_rule(line, DNS_BLOCK_LAN_TCP_RULE))
}

/// Pure snapshot builder over all four raw observations. `None` means
/// "could not be read", which fails closed in every case: an unreadable
/// `resolv.conf` sets `resolv_conf_present=false`, unreadable `scutil`
/// output sets `loopback_resolver_advertised=false`, an unreadable pf
/// floor sets `pf_block_rules_present=false` (with
/// `pfctl_readable=false`), and an unreadable `networksetup` sets
/// `networksetup_readable=false`.
///
/// Production and tests share this function, so the drift branches are
/// reachable by the same path the daemon takes.
pub fn build_macos_dns_failclosed_snapshot_with_host_layers(
    resolv_conf_body: Option<&str>,
    scutil_dns_body: Option<&str>,
    pf_observation: Option<&PfDnsBlockFloorObservation>,
    networksetup_observation: Option<&NetworksetupDnsPinObservation>,
) -> MacosDnsFailclosedSnapshot {
    let resolv_conf_path = REVIEWED_RESOLV_CONF_PATH.to_owned();
    let loopback_resolver_advertised = scutil_dns_body.is_some_and(|body| {
        loopback_resolver_advertised_from_scutil(&parse_scutil_primary_resolver_nameservers(body))
    });
    let (resolv_conf_present, nameservers, search_domains) = match resolv_conf_body {
        Some(body) => {
            let (nameservers, search_domains) = parse_resolv_conf(body);
            (true, nameservers, search_domains)
        }
        None => (false, Vec::new(), Vec::new()),
    };
    let mut snapshot = MacosDnsFailclosedSnapshot {
        resolv_conf_path,
        resolv_conf_present,
        nameservers,
        search_domains,
        loopback_resolver_advertised,
        pfctl_readable: false,
        pf_block_rules_present: false,
        pf_anchors_scanned: Vec::new(),
        networksetup_readable: false,
        pinned_services: Vec::new(),
        unpinned_services: Vec::new(),
        // Scoped layer: the pure builders cannot observe /etc and FAIL
        // CLOSED (absent); the live collector overwrites it below.
        scoped_resolver_present: false,
    };
    snapshot.pfctl_readable = pf_observation.is_some();
    snapshot.pf_block_rules_present = pf_observation.is_some_and(|o| o.block_rules_present);
    snapshot.pf_anchors_scanned = pf_observation
        .map(|o| o.anchors_scanned.clone())
        .unwrap_or_default();
    snapshot.networksetup_readable = networksetup_observation.is_some();
    snapshot.pinned_services = networksetup_observation
        .map(|o| o.pinned_services.clone())
        .unwrap_or_default();
    snapshot.unpinned_services = networksetup_observation
        .map(|o| o.unpinned_services.clone())
        .unwrap_or_default();
    snapshot
}

/// Pure snapshot builder over the two raw resolver observations. The
/// host-level layers (pf DNS block floor, per-service loopback DNS pin)
/// are not observable here and FAIL CLOSED (`pfctl_readable=false`,
/// `networksetup_readable=false`); production snapshots are built with
/// `build_macos_dns_failclosed_snapshot_with_host_layers`, which the
/// collector feeds with live `pfctl`/`networksetup` observations.
pub fn build_macos_dns_failclosed_snapshot(
    resolv_conf_body: Option<&str>,
    scutil_dns_body: Option<&str>,
) -> MacosDnsFailclosedSnapshot {
    build_macos_dns_failclosed_snapshot_with_host_layers(
        resolv_conf_body,
        scutil_dns_body,
        None,
        None,
    )
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

/// Read-only query through the reviewed fixed `pfctl` binary. `None` on
/// any failure (missing binary, non-zero exit) so the caller fails
/// closed rather than assuming the floor holds.
fn read_pfctl(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(REVIEWED_PFCTL_PATH)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Read-only query through the reviewed fixed `networksetup` binary.
/// `None` on any failure (missing binary, non-zero exit) so the caller
/// fails closed rather than assuming the pin holds.
fn read_networksetup(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new(NETWORKSETUP_BINARY_PATH)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Union the rustynet-owned pf anchor names from a top-level `pfctl -s Anchors`
/// dump and (when available) a nested `pfctl -a com.apple -s Anchors` dump,
/// preserving order and deduplicating. The nested dump surfaces the
/// `com.apple/rustynet_g{N}` DNS-block-floor anchors that the top-level dump
/// omits (they are sub-anchors of Apple's `com.apple` parent). Both dumps are
/// filtered through `parse_pf_anchor_names`, so only prefix-matched, structurally
/// valid rustynet-owned anchors survive.
pub fn merge_rustynet_anchor_names(top_output: &str, nested_output: Option<&str>) -> Vec<String> {
    let mut anchors = parse_pf_anchor_names(top_output);
    if let Some(nested_output) = nested_output {
        for anchor in parse_pf_anchor_names(nested_output) {
            if !anchors.contains(&anchor) {
                anchors.push(anchor);
            }
        }
    }
    anchors
}

/// Observe the pf DNS block floor (S6 layer 3): enumerate anchors via
/// `pfctl -s Anchors`, then read every rustynet-owned anchor's rules via
/// `pfctl -a <anchor> -s rules`, reporting whether SOME anchor carries
/// BOTH labeled DNS block rules. `None` on any read failure — including
/// a single rustynet-owned anchor whose rules cannot be read — so the
/// caller fails closed. Zero rustynet-owned anchors is a readable-but-
/// absent floor (`block_rules_present=false`), also a failure
/// downstream.
pub fn read_pf_dns_block_floor() -> Option<PfDnsBlockFloorObservation> {
    // The rustynet DNS-block floor anchor is `com.apple/rustynet_g{N}` — NESTED
    // under Apple's `com.apple` parent anchor. `pfctl -s Anchors` lists only
    // TOP-LEVEL anchor names (e.g. `com.apple`, `com.rustynet`), so the nested
    // floor anchor is invisible to it; the daemon loads and verifies that anchor
    // by its full path (`pfctl -a com.apple/rustynet_g{N} -s rules`, see
    // phase10::verify_live_pf_dns_floor). Enumerate BOTH the top-level set (which
    // still catches the top-level `com.rustynet/` family) AND `com.apple`'s
    // sub-anchors, so this check observes the same floor the daemon installed.
    //
    // Fail-closed is preserved: a failed top-level query still returns `None`
    // (unverifiable); the nested query is best-effort because an UNFOUND floor
    // yields `block_rules_present = false` (a failure downstream) — a missing
    // nested query can therefore never make the check PASS, only limit which
    // anchors are scanned; and every per-anchor rule read stays `?`-fail-closed.
    let top_output = read_pfctl(&["-s", "Anchors"])?;
    let nested_output = read_pfctl(&["-a", "com.apple", "-s", "Anchors"]);
    let anchors = merge_rustynet_anchor_names(&top_output, nested_output.as_deref());
    let mut anchors_scanned = Vec::new();
    let mut block_rules_present = false;
    for anchor in anchors {
        let rules = read_pfctl(&["-a", &anchor, "-s", "rules"])?;
        if anchor_rules_contain_both_dns_block_labels(&rules) {
            block_rules_present = true;
        }
        anchors_scanned.push(anchor);
    }
    Some(PfDnsBlockFloorObservation {
        anchors_scanned,
        block_rules_present,
    })
}

/// Observe the per-service loopback DNS pin (S6 layer 4): enumerate the
/// ENABLED hardware network services via `networksetup
/// -listallnetworkservices`, then read each service's DNS servers via
/// `networksetup -getdnsservers <service>`. A service with NO servers
/// configured is UNPINNED — it inherits resolver state from DHCP and
/// can leak. `None` on any read or parse failure so the caller fails
/// closed.
pub fn read_networksetup_dns_pin() -> Option<NetworksetupDnsPinObservation> {
    let list_output = read_networksetup(&networksetup_listall_args())?;
    let services = parse_networksetup_service_list(&list_output).ok()?;
    let mut pinned_services = Vec::new();
    let mut unpinned_services = Vec::new();
    for service in &services {
        let args = networksetup_getdns_args(service).ok()?;
        let dns_output = read_networksetup(&args)?;
        let servers = match parse_networksetup_getdns_output(&dns_output).ok()? {
            NetworksetupDnsServers::None => Vec::new(),
            NetworksetupDnsServers::Servers(servers) => servers,
        };
        if is_loopback_dns_server_list(&servers) {
            pinned_services.push(service.clone());
        } else {
            unpinned_services.push(service.clone());
        }
    }
    Some(NetworksetupDnsPinObservation {
        pinned_services,
        unpinned_services,
    })
}

pub fn collect_macos_dns_failclosed_snapshot() -> MacosDnsFailclosedSnapshot {
    let resolv_conf_body = std::fs::read_to_string(REVIEWED_RESOLV_CONF_PATH).ok();
    let scutil_dns_body = read_scutil_dns();
    let pf_observation = read_pf_dns_block_floor();
    let networksetup_observation = read_networksetup_dns_pin();
    let mut snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
        resolv_conf_body.as_deref(),
        scutil_dns_body.as_deref(),
        pf_observation.as_ref(),
        networksetup_observation.as_ref(),
    );
    snapshot.scoped_resolver_present =
        std::fs::read_to_string(crate::linux_dns_protect::MACOS_SCOPED_RESOLVER_PATH).is_ok();
    snapshot
}

pub fn build_macos_dns_failclosed_report(
    snapshot: MacosDnsFailclosedSnapshot,
) -> MacosDnsFailclosedReport {
    build_macos_dns_failclosed_report_for_posture(
        snapshot,
        crate::phase10::DnsPosture::FullyProtected,
    )
}

/// Build a report evaluated FOR a specific DNS posture (M5). The posture is
/// THREADED by the caller from the role/exit posture the daemon holds —
/// never inferred from the snapshot being checked (that would make the
/// check a tautology). The report embeds the posture so a consumer can
/// verify the evaluation matches the role it asked about.
pub fn build_macos_dns_failclosed_report_for_posture(
    snapshot: MacosDnsFailclosedSnapshot,
    posture: crate::phase10::DnsPosture,
) -> MacosDnsFailclosedReport {
    let drift_reasons = evaluate_macos_dns_failclosed_snapshot_for_posture(&snapshot, posture);
    let overall_ok = drift_reasons.is_empty();
    MacosDnsFailclosedReport {
        schema_version: 2,
        posture: posture.as_str().to_owned(),
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Parse the wire form of a DNS posture (accepts both the `as_str` form
/// and the CLI flag spelling). `None` = unrecognized (callers must fail
/// closed, never default).
pub fn parse_macos_dns_posture(value: &str) -> Option<crate::phase10::DnsPosture> {
    match value.trim() {
        "fully_protected" | "fully-protected" => Some(crate::phase10::DnsPosture::FullyProtected),
        "scoped_resolver_only" | "scoped-resolver-only" => {
            Some(crate::phase10::DnsPosture::ScopedResolverOnly)
        }
        _ => None,
    }
}

/// Posture-aware snapshot evaluation (M5,
/// MacosClientDnsFailclosedDiagnosisReview_2026-09-02 A7). The
/// FullyProtected contract is the existing seven-condition check,
/// UNCHANGED. The ScopedResolverOnly contract (plain mesh client): the
/// scoped `*.rustynet` resolver MUST be present (its absence means mesh
/// names leak to the LAN resolver), NO service may pin the loopback
/// resolver as its general DNS (a pin without the full posture's live
/// primary + pf floor is the forbidden half state), and the system
/// configuration must be readable (an unreadable state cannot prove the
/// absence of a pin). The machine's own resolv.conf/scutil/pf state is
/// deliberately NOT demanded — this posture leaves the machine's general
/// DNS untouched by design. `Untouched` always drifts: a running node
/// always holds one of the two protective postures.
pub fn evaluate_macos_dns_failclosed_snapshot_for_posture(
    snapshot: &MacosDnsFailclosedSnapshot,
    posture: crate::phase10::DnsPosture,
) -> Vec<String> {
    match posture {
        crate::phase10::DnsPosture::FullyProtected => {
            evaluate_macos_dns_failclosed_snapshot(snapshot)
        }
        crate::phase10::DnsPosture::Untouched => vec![
            "no DNS posture is applied; a running mesh node must hold either the fully-protected or scoped-resolver-only posture"
                .to_owned(),
        ],
        crate::phase10::DnsPosture::ScopedResolverOnly => {
            let mut reasons: Vec<String> = Vec::new();
            if !snapshot.scoped_resolver_present {
                reasons.push(format!(
                    "scoped resolver {} is missing; *.rustynet queries leak to the LAN resolver; scoped DNS posture cannot be verified",
                    crate::linux_dns_protect::MACOS_SCOPED_RESOLVER_PATH
                ));
            }
            // Fail closed: an unreadable enumeration cannot prove the
            // absence of a stranded loopback pin.
            if !snapshot.networksetup_readable {
                reasons.push(
                    "networksetup service enumeration unreadable; the absence of stranded loopback pins cannot be verified; scoped DNS posture cannot be verified"
                        .to_owned(),
                );
            }
            // A service PINNED to loopback outside the full posture is
            // residue: it advertises a resolver this posture does not
            // justify. Non-loopback or DHCP-inherited general DNS is the
            // machine's own business and is NOT drift here.
            for service in &snapshot.pinned_services {
                reasons.push(format!(
                    "network service {service:?} pins loopback DNS without the fully-protected posture (stranded residue); scoped DNS posture cannot be verified"
                ));
            }
            reasons
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fully compliant snapshot: loopback resolver state AND all host
    /// layers observed healthy. Tests mutate single fields from here so
    /// each test isolates one drift branch.
    fn compliant_snapshot() -> MacosDnsFailclosedSnapshot {
        MacosDnsFailclosedSnapshot {
            resolv_conf_path: REVIEWED_RESOLV_CONF_PATH.to_owned(),
            resolv_conf_present: true,
            nameservers: vec!["127.0.0.1".to_owned()],
            search_domains: Vec::new(),
            loopback_resolver_advertised: true,
            pfctl_readable: true,
            pf_block_rules_present: true,
            pf_anchors_scanned: vec!["com.apple/rustynet_g1".to_owned()],
            networksetup_readable: true,
            pinned_services: vec!["Wi-Fi".to_owned()],
            unpinned_services: Vec::new(),
            scoped_resolver_present: true,
        }
    }

    /// A compliant pf DNS block floor observation, as `read_pf_dns_block_floor`
    /// would produce on an enforced host.
    fn compliant_pf_observation() -> PfDnsBlockFloorObservation {
        PfDnsBlockFloorObservation {
            anchors_scanned: vec!["com.apple/rustynet_g1".to_owned()],
            block_rules_present: true,
        }
    }

    /// A compliant per-service DNS pin observation, as
    /// `read_networksetup_dns_pin` would produce on an enforced host.
    fn compliant_networksetup_observation() -> NetworksetupDnsPinObservation {
        NetworksetupDnsPinObservation {
            pinned_services: vec!["Wi-Fi".to_owned()],
            unpinned_services: Vec::new(),
        }
    }

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
        let snapshot = compliant_snapshot();
        let report = build_macos_dns_failclosed_report(snapshot);
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosDnsFailclosedReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn build_report_loopback_only_is_ok() {
        let report = build_macos_dns_failclosed_report(compliant_snapshot());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
    }

    #[test]
    fn build_report_missing_resolv_conf_is_drift() {
        let mut snapshot = compliant_snapshot();
        snapshot.resolv_conf_present = false;
        snapshot.nameservers = Vec::new();
        snapshot.loopback_resolver_advertised = false;
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
        let mut snapshot = compliant_snapshot();
        snapshot.nameservers = Vec::new();
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
        let mut snapshot = compliant_snapshot();
        snapshot.loopback_resolver_advertised = false;
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
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            Some(&compliant_pf_observation()),
            Some(&compliant_networksetup_observation()),
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

    // ----- M5 posture-aware evaluation (review A7) -----------------------

    #[test]
    fn fully_protected_complete_snapshot_passes() {
        let report = build_macos_dns_failclosed_report_for_posture(
            compliant_snapshot(),
            crate::phase10::DnsPosture::FullyProtected,
        );
        assert!(report.overall_ok, "drift: {:?}", report.drift_reasons);
        assert_eq!(report.posture, "fully_protected");
    }

    #[test]
    fn fully_protected_missing_pf_floor_drifts() {
        let mut snapshot = compliant_snapshot();
        snapshot.pf_block_rules_present = false;
        let report = build_macos_dns_failclosed_report_for_posture(
            snapshot,
            crate::phase10::DnsPosture::FullyProtected,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("pf DNS block floor not verified")),
            "drift must name the missing floor: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn scoped_resolver_only_clean_snapshot_passes() {
        let mut snapshot = compliant_snapshot();
        // A plain client leaves the machine's general DNS untouched: the
        // primary is NOT loopback, services carry their own (non-loopback)
        // DNS, and there is no pf floor. ONLY the scoped resolver matters.
        snapshot.resolv_conf_present = false;
        snapshot.nameservers = Vec::new();
        snapshot.loopback_resolver_advertised = false;
        snapshot.pfctl_readable = false;
        snapshot.pf_block_rules_present = false;
        snapshot.pinned_services = Vec::new();
        snapshot.unpinned_services = Vec::new();
        let report = build_macos_dns_failclosed_report_for_posture(
            snapshot,
            crate::phase10::DnsPosture::ScopedResolverOnly,
        );
        assert!(report.overall_ok, "drift: {:?}", report.drift_reasons);
        assert_eq!(report.posture, "scoped_resolver_only");
    }

    #[test]
    fn scoped_resolver_only_missing_scoped_file_drifts() {
        let mut snapshot = compliant_snapshot();
        snapshot.pinned_services = Vec::new();
        snapshot.scoped_resolver_present = false;
        let report = build_macos_dns_failclosed_report_for_posture(
            snapshot,
            crate::phase10::DnsPosture::ScopedResolverOnly,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("/etc/resolver/rustynet is missing")),
            "drift must name the missing scoped resolver: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn scoped_resolver_only_with_stray_general_pin_drifts() {
        let mut snapshot = compliant_snapshot();
        snapshot.scoped_resolver_present = true;
        // Stranded residue: a service pinned to loopback outside the full
        // posture advertises a resolver this posture never justifies.
        snapshot.pinned_services = vec!["Wi-Fi".to_owned()];
        let report = build_macos_dns_failclosed_report_for_posture(
            snapshot,
            crate::phase10::DnsPosture::ScopedResolverOnly,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| { reason.contains("Wi-Fi") && reason.contains("stranded residue") }),
            "drift must name the stranded pin: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn untouched_posture_always_drifts() {
        let report = build_macos_dns_failclosed_report_for_posture(
            compliant_snapshot(),
            crate::phase10::DnsPosture::Untouched,
        );
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("no DNS posture is applied"))
        );
    }

    #[test]
    fn parse_macos_dns_posture_accepts_both_spellings_and_fails_closed() {
        assert_eq!(
            parse_macos_dns_posture("fully-protected"),
            Some(crate::phase10::DnsPosture::FullyProtected)
        );
        assert_eq!(
            parse_macos_dns_posture("scoped_resolver_only"),
            Some(crate::phase10::DnsPosture::ScopedResolverOnly)
        );
        assert_eq!(parse_macos_dns_posture("untouched"), None);
        assert_eq!(parse_macos_dns_posture(""), None);
        assert_eq!(parse_macos_dns_posture("bogus"), None);
    }

    #[test]
    fn report_schema_version_pinned_at_two() {
        let report = build_macos_dns_failclosed_report(compliant_snapshot());
        assert_eq!(report.schema_version, 2);
        assert_eq!(report.posture, "fully_protected");
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":2"),
            "schema_version JSON shape must be int=2: {body}"
        );
        assert!(
            body.contains("\"posture\":\"fully_protected\""),
            "the report must embed its evaluated posture: {body}"
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
        let mut snapshot = compliant_snapshot();
        snapshot.nameservers = vec!["8.8.8.8".to_owned(), "1.1.1.1".to_owned()];
        snapshot.loopback_resolver_advertised = false;
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

    // ----- S6: the pf DNS block floor and the per-service DNS pin ------

    #[test]
    fn pf_anchor_parser_selects_only_rustynet_owned_anchors() {
        let output = "com.apple/rustynet_g2\n\
                      com.apple/Anchor\n\
                      com.rustynet/blind_exit\n\
                      com.apple/rustynet_g10/sub\n\
                      rustynet_g1\n\
                      ../escape\n\
                      com.apple/rustynet_g/../evil\n\
                      \n\
                      com.apple/other\n";
        let parsed = parse_pf_anchor_names(output);
        assert_eq!(
            parsed,
            vec![
                "com.apple/rustynet_g2",
                "com.rustynet/blind_exit",
                "com.apple/rustynet_g10/sub",
            ],
            "only prefix-matched, structurally valid anchor names are ours"
        );
    }

    #[test]
    fn floor_scan_unions_top_level_and_nested_com_apple_anchors() {
        // `pfctl -s Anchors` lists only top-level anchors (com.apple, com.rustynet);
        // the DNS-block floor lives NESTED at com.apple/rustynet_g{N}, surfaced by
        // `pfctl -a com.apple -s Anchors`. read_pf_dns_block_floor unions both — the
        // regression that false-failed a FULLY-PROTECTED node whose floor WAS present.
        let top = "com.apple
com.rustynet
";
        let nested = "com.apple/rustynet_g5
com.apple/250.ApplicationFirewall
";
        let anchors = merge_rustynet_anchor_names(top, Some(nested));
        assert!(
            anchors.contains(&"com.apple/rustynet_g5".to_owned()),
            "the nested com.apple/rustynet_g floor anchor must be scanned; got {anchors:?}"
        );
        // bare top-level com.apple / com.rustynet are NOT rustynet-owned floor anchors.
        assert!(
            !anchors
                .iter()
                .any(|a| a == "com.apple" || a == "com.rustynet")
        );
        // A top-level com.rustynet/ family anchor is still found without the nested dump.
        let top_only = merge_rustynet_anchor_names(
            "com.rustynet/blind_exit
",
            None,
        );
        assert_eq!(top_only, vec!["com.rustynet/blind_exit".to_owned()]);
        // Dedup: an anchor present in both dumps appears once.
        let deduped = merge_rustynet_anchor_names(
            "com.apple/rustynet_g5
",
            Some(
                "com.apple/rustynet_g5
",
            ),
        );
        assert_eq!(deduped, vec!["com.apple/rustynet_g5".to_owned()]);
    }

    #[test]
    fn anchor_rules_require_both_labeled_block_rules() {
        let udp = "block drop out quick inet proto udp from any to ! 127.0.0.0/8 port = 53 label \"rustynet-dns-block-lan-udp\"";
        let tcp = "block drop out quick inet proto tcp from any to ! 127.0.0.0/8 port = 53 label \"rustynet-dns-block-lan-tcp\"";
        assert!(anchor_rules_contain_both_dns_block_labels(&format!(
            "{udp}\n{tcp}\n"
        )));
        // pfctl's service-name port form must be accepted too.
        let tcp_domain = tcp.replace("port = 53", "port domain");
        assert!(anchor_rules_contain_both_dns_block_labels(&format!(
            "{udp}\n{tcp_domain}\n"
        )));
        // Only one label present: the floor is NOT verified.
        assert!(
            !anchor_rules_contain_both_dns_block_labels(&format!("{udp}\n")),
            "a single labeled rule must not satisfy the both-labels floor"
        );
        // Both labels but the TCP one is a pass rule, not a block rule.
        let tcp_pass = tcp.replace("block drop", "pass out");
        assert!(
            !anchor_rules_contain_both_dns_block_labels(&format!("{udp}\n{tcp_pass}\n")),
            "a labeled pass rule must not satisfy the block-rule floor"
        );
        // Labels mentioned in a comment-ish context (not a block rule line).
        assert!(
            !anchor_rules_contain_both_dns_block_labels(
                "# label \"rustynet-dns-block-lan-udp\" label \"rustynet-dns-block-lan-tcp\"\n"
            ),
            "labels outside block rules must not satisfy the floor"
        );
    }

    #[test]
    fn all_four_layers_ok_report_is_green() {
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            Some(&compliant_pf_observation()),
            Some(&compliant_networksetup_observation()),
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            report.overall_ok,
            "all four layers compliant must be green: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn missing_pf_block_rules_fails_the_report() {
        let pf = PfDnsBlockFloorObservation {
            anchors_scanned: vec!["com.apple/rustynet_g1".to_owned()],
            block_rules_present: false,
        };
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            Some(&pf),
            Some(&compliant_networksetup_observation()),
        );
        assert!(snapshot.pfctl_readable, "pfctl read succeeded here");
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            !report.overall_ok,
            "a flushed pf anchor must fail the check even with clean resolv.conf"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("pf DNS block floor not verified")),
            "the pf floor branch must be the reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn unpinned_networksetup_service_fails_the_report() {
        let pin = NetworksetupDnsPinObservation {
            pinned_services: Vec::new(),
            unpinned_services: vec!["Wi-Fi".to_owned()],
        };
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            Some(&compliant_pf_observation()),
            Some(&pin),
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            !report.overall_ok,
            "a service reporting non-loopback DNS must fail the check"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("Wi-Fi") && r.contains("loopback-only DNS")),
            "the unpinned-service branch must be the reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn pfctl_unreadable_fails_closed() {
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            None,
            Some(&compliant_networksetup_observation()),
        );
        assert!(
            !snapshot.pfctl_readable,
            "unreadable pfctl must be observable as such"
        );
        assert!(
            !snapshot.pf_block_rules_present,
            "unreadable pfctl must never read as a verified floor"
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            !report.overall_ok,
            "unreadable pfctl must fail closed, never pass"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("pf DNS block floor not verified")),
            "the pf floor branch must cover the unreadable case: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn networksetup_unreadable_fails_closed() {
        let snapshot = build_macos_dns_failclosed_snapshot_with_host_layers(
            Some(LOOPBACK_RESOLV_CONF),
            Some(&scutil_output("127.0.0.1")),
            Some(&compliant_pf_observation()),
            None,
        );
        assert!(
            !snapshot.networksetup_readable,
            "unreadable networksetup must be observable as such"
        );
        let report = build_macos_dns_failclosed_report(snapshot);
        assert!(
            !report.overall_ok,
            "unreadable networksetup must fail closed, never pass"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("networksetup service enumeration unreadable")),
            "the networksetup branch must be the reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn two_observation_builder_fails_closed_on_host_layers_by_default() {
        // The two-source builder cannot observe the pf floor or the DNS
        // pin, so both must read as UNVERIFIED (never as pass).
        let snapshot = build_macos_dns_failclosed_snapshot(Some(LOOPBACK_RESOLV_CONF), None);
        assert!(!snapshot.pfctl_readable);
        assert!(!snapshot.pf_block_rules_present);
        assert!(!snapshot.networksetup_readable);
        assert!(snapshot.pinned_services.is_empty());
        assert!(snapshot.unpinned_services.is_empty());
        assert!(!build_macos_dns_failclosed_report(snapshot).overall_ok);
    }
}
