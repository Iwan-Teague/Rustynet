#![allow(clippy::result_large_err)]

//! Windows DNS fail-closed verifier.
//!
//! Captures the live Windows DNS state — per-interface DNS server
//! addresses plus NRPT (Name Resolution Policy Table) rules — and
//! evaluates it against the reviewed RustyNet contract:
//!
//! * every network interface is configured with either an empty DNS
//!   server list or with loopback servers only (`127.0.0.0/8` for IPv4,
//!   `::1` for IPv6) — anything else is a fail-closed bypass route;
//! * at least one NRPT rule covers the root namespace (`.`) and points
//!   exclusively at loopback resolvers, so unqualified lookups also
//!   stay on the daemon-managed resolver;
//! * every captured NRPT rule's name-server set is a subset of
//!   loopback addresses; a single non-loopback NRPT entry would let a
//!   crafted name leak past the daemon.
//!
//! The pure `evaluate_windows_dns_failclosed_snapshot` aggregator
//! returns every drift reason in one pass; the `cfg(windows)`
//! collector queries the Windows DnsClient cmdlets via a static
//! PowerShell invocation (no runtime-data interpolation crosses the
//! shell boundary — the script body is a hardcoded constant) and
//! parses the typed JSON output. Off-Windows hosts return a clear
//! blocker error so the verifier still fails closed without
//! pretending to validate.
//!
//! The daemon-side `windows-dns-failclosed-check` subcommand and the
//! orchestrator stage `validate_windows_dns_failclosed` consume the
//! same report types so a Windows guest can be checked from the lab
//! orchestrator over the existing argv-only PowerShell-encoded SSH
//! channel.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// IPv4 loopback prefix length used by the verifier (`127.0.0.0/8`).
/// Any IPv4 address outside this prefix is treated as a leak vector.
const IPV4_LOOPBACK_PREFIX_LEN: u8 = 8;
/// Canonical IPv4 loopback address used in test fixtures and the
/// reviewed contract documentation. Any host inside `127.0.0.0/8` is
/// accepted; this constant is the canonical value the runtime binds
/// to.
pub const REVIEWED_WINDOWS_DNS_LOOPBACK_V4: &str = "127.0.0.1";
/// Canonical IPv6 loopback address. The verifier accepts only `::1`
/// for IPv6 — there is no IPv6 loopback prefix wider than `::1/128`.
pub const REVIEWED_WINDOWS_DNS_LOOPBACK_V6: &str = "::1";
/// NRPT rule namespace that must cover unqualified / root lookups.
/// Microsoft's NRPT format uses a single `.` to represent "match the
/// root of the namespace tree"; rules that target only sub-namespaces
/// (e.g. `.mesh.local`) leave queries for any other suffix unprotected.
pub const REVIEWED_WINDOWS_NRPT_ROOT_NAMESPACE: &str = ".";

/// Address family captured for a per-interface DNS entry. Mirrors the
/// PowerShell `Get-DnsClientServerAddress` enum (2 = IPv4, 23 = IPv6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WindowsDnsAddressFamily {
    Ipv4,
    Ipv6,
}

/// One per-interface DNS entry — typically there is one per
/// `(interface, address-family)` pair on a Windows host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsInterfaceDnsEntry {
    pub interface_alias: String,
    pub interface_index: u32,
    pub address_family: WindowsDnsAddressFamily,
    pub server_addresses: Vec<String>,
}

/// One NRPT rule as returned by `Get-DnsClientNrptRule`. The rule's
/// `name` is the SCM-assigned identifier (often a GUID); `namespace`
/// holds the DNS suffixes the rule matches; `name_servers` holds the
/// resolver addresses queries are forwarded to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsNrptRule {
    pub name: String,
    pub namespace: Vec<String>,
    pub name_servers: Vec<String>,
}

/// Live snapshot of the Windows DNS state needed by the fail-closed
/// verifier. The collector populates this; the evaluator consumes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDnsFailclosedSnapshot {
    pub schema_version: u32,
    pub interfaces: Vec<WindowsInterfaceDnsEntry>,
    pub nrpt_rules: Vec<WindowsNrptRule>,
}

/// Final report shape consumed by the `windows-dns-failclosed-check`
/// subcommand and the orchestrator stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsDnsFailclosedReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: WindowsDnsFailclosedSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator. Walks the snapshot once and aggregates every
/// drift reason; never short-circuits on the first failure so the
/// orchestrator gets a complete picture in one round-trip.
pub fn evaluate_windows_dns_failclosed_snapshot(
    snapshot: &WindowsDnsFailclosedSnapshot,
) -> Result<(), Vec<String>> {
    let mut reasons: Vec<String> = Vec::new();

    if snapshot.schema_version != 1 {
        reasons.push(format!(
            "unsupported windows DNS fail-closed snapshot schema_version={}",
            snapshot.schema_version
        ));
        return Err(reasons);
    }

    for entry in &snapshot.interfaces {
        for raw_address in &entry.server_addresses {
            let trimmed = raw_address.trim();
            if trimmed.is_empty() {
                continue;
            }
            match parse_dns_address(trimmed, entry.address_family) {
                Ok(addr) if is_loopback_address(&addr) => {}
                Ok(_) => reasons.push(format!(
                    "interface {} ({:?}) has non-loopback DNS server {}; fail-closed posture forbids any off-loopback resolver on a host interface",
                    entry.interface_alias, entry.address_family, trimmed
                )),
                Err(err) => reasons.push(format!(
                    "interface {} ({:?}) has unparseable DNS server {}: {}",
                    entry.interface_alias, entry.address_family, trimmed, err
                )),
            }
        }
    }

    for rule in &snapshot.nrpt_rules {
        if rule.namespace.is_empty() {
            reasons.push(format!(
                "NRPT rule {} has an empty namespace list; rules with no namespace cannot be reasoned about",
                rule.name
            ));
        }
        for ns in &rule.namespace {
            if ns.trim().is_empty() {
                reasons.push(format!(
                    "NRPT rule {} has an empty namespace entry; reviewed RustyNet rules must declare every namespace explicitly",
                    rule.name
                ));
            }
        }
        for raw_address in &rule.name_servers {
            let trimmed = raw_address.trim();
            if trimmed.is_empty() {
                reasons.push(format!(
                    "NRPT rule {} has an empty name-server entry; the reviewed contract requires every NRPT rule to forward to a loopback resolver",
                    rule.name
                ));
                continue;
            }
            match trimmed.parse::<IpAddr>() {
                Ok(addr) if is_loopback_address(&addr) => {}
                Ok(_) => reasons.push(format!(
                    "NRPT rule {} forwards to non-loopback name server {}; queries matching this rule would bypass the daemon resolver",
                    rule.name, trimmed
                )),
                Err(err) => reasons.push(format!(
                    "NRPT rule {} has unparseable name server {}: {}",
                    rule.name, trimmed, err
                )),
            }
        }
    }

    if !nrpt_rules_cover_root_namespace(&snapshot.nrpt_rules) {
        reasons.push(format!(
            "no NRPT rule covers the {REVIEWED_WINDOWS_NRPT_ROOT_NAMESPACE} root namespace with loopback name servers; unqualified lookups would resolve via the host's default DNS path",
        ));
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

fn nrpt_rules_cover_root_namespace(rules: &[WindowsNrptRule]) -> bool {
    rules.iter().any(|rule| {
        rule.namespace
            .iter()
            .any(|ns| ns.trim() == REVIEWED_WINDOWS_NRPT_ROOT_NAMESPACE)
            && !rule.name_servers.is_empty()
            && rule.name_servers.iter().all(|server| {
                server
                    .trim()
                    .parse::<IpAddr>()
                    .ok()
                    .map(|addr| is_loopback_address(&addr))
                    .unwrap_or(false)
            })
    })
}

fn parse_dns_address(raw: &str, family: WindowsDnsAddressFamily) -> Result<IpAddr, String> {
    let addr = raw
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid IP address: {err}"))?;
    match (addr, family) {
        (IpAddr::V4(_), WindowsDnsAddressFamily::Ipv4) => Ok(addr),
        (IpAddr::V6(_), WindowsDnsAddressFamily::Ipv6) => Ok(addr),
        (IpAddr::V4(_), WindowsDnsAddressFamily::Ipv6) => {
            Err("IPv4 address listed in an IPv6 server entry".to_string())
        }
        (IpAddr::V6(_), WindowsDnsAddressFamily::Ipv4) => {
            Err("IPv6 address listed in an IPv4 server entry".to_string())
        }
    }
}

fn is_loopback_address(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.octets()[0] == 0x7f && IPV4_LOOPBACK_PREFIX_LEN == 8,
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Convenience wrapper used by the daemon subcommand: evaluate the
/// snapshot and fold the result into a `WindowsDnsFailclosedReport`.
pub fn build_windows_dns_failclosed_report(
    snapshot: WindowsDnsFailclosedSnapshot,
) -> WindowsDnsFailclosedReport {
    let drift_reasons = match evaluate_windows_dns_failclosed_snapshot(&snapshot) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    WindowsDnsFailclosedReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Live collector. On Windows hosts this shells out to a static
/// PowerShell script that queries `Get-DnsClientServerAddress` and
/// `Get-DnsClientNrptRule`, then parses the typed JSON output back
/// into the snapshot type. The script body is hardcoded and contains
/// no runtime-data interpolation, so the privileged-boundary
/// argv-only / no-shell-construction discipline still holds: the
/// only data crossing the PowerShell boundary is the daemon's own
/// constant string.
///
/// Off-Windows hosts return a blocker error so the subcommand fails
/// closed instead of fabricating a passing snapshot.
#[cfg(windows)]
pub fn collect_windows_dns_failclosed_snapshot() -> Result<WindowsDnsFailclosedSnapshot, String> {
    use std::process::Command;

    let output = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-OutputFormat",
            "Text",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            WINDOWS_DNS_FAILCLOSED_PROBE_SCRIPT,
        ])
        .output()
        .map_err(|err| format!("failed to invoke powershell.exe for DNS probe: {err}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "powershell.exe DNS probe exited with status {}: {}",
            output.status, stderr
        ));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("powershell.exe DNS probe produced non-UTF-8 output: {err}"))?;
    parse_windows_dns_probe_output(stdout.as_str())
}

#[cfg(not(windows))]
pub fn collect_windows_dns_failclosed_snapshot() -> Result<WindowsDnsFailclosedSnapshot, String> {
    Err("windows-dns-failclosed-check requires a Windows runtime host".to_string())
}

/// Static PowerShell script body invoked by the Windows collector.
#[cfg(windows)]
/// Mapping back to Rust types via `parse_windows_dns_probe_output`:
/// each interface row carries `interface_alias` / `interface_index` /
/// `address_family` ("ipv4" | "ipv6") / `server_addresses`; each NRPT
/// rule row carries `name` / `namespace` / `name_servers`. The
/// outer object is `{schema_version: 1, interfaces, nrpt_rules}`.
/// Get-DnsClientNrptRule may not be available on all SKUs; the
/// script tolerates that by falling back to an empty rule list so
/// the evaluator can still flag missing-NRPT drift instead of the
/// collector exiting non-zero.
const WINDOWS_DNS_FAILCLOSED_PROBE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$interfaces = @(Get-DnsClientServerAddress | ForEach-Object {
    $family = if ($_.AddressFamily -eq 23) { 'ipv6' } else { 'ipv4' }
    [ordered]@{
        interface_alias = [string]$_.InterfaceAlias
        interface_index = [int]$_.InterfaceIndex
        address_family = $family
        server_addresses = @(@($_.ServerAddresses) | ForEach-Object { [string]$_ })
    }
})
$rules = @()
try {
    $rules = @(Get-DnsClientNrptRule -ErrorAction Stop | ForEach-Object {
        [ordered]@{
            name = [string]$_.Name
            namespace = @(@($_.Namespace) | ForEach-Object { [string]$_ })
            name_servers = @(@($_.NameServers) | ForEach-Object { [string]$_ })
        }
    })
} catch {
    $rules = @()
}
[ordered]@{
    schema_version = 1
    interfaces = $interfaces
    nrpt_rules = $rules
} | ConvertTo-Json -Depth 6 -Compress
"#;

/// Parse the JSON envelope produced by `WINDOWS_DNS_FAILCLOSED_PROBE_SCRIPT`.
/// Public so the unit-test harness (and any future Win32-API-based
/// collector that returns the same JSON shape) can exercise it
/// directly.
pub fn parse_windows_dns_probe_output(
    stdout: &str,
) -> Result<WindowsDnsFailclosedSnapshot, String> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Err("powershell.exe DNS probe produced empty output".to_string());
    }
    serde_json::from_str::<WindowsDnsFailclosedSnapshot>(trimmed)
        .map_err(|err| format!("failed to parse DNS probe JSON: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_snapshot() -> WindowsDnsFailclosedSnapshot {
        WindowsDnsFailclosedSnapshot {
            schema_version: 1,
            interfaces: vec![
                WindowsInterfaceDnsEntry {
                    interface_alias: "Ethernet".to_string(),
                    interface_index: 12,
                    address_family: WindowsDnsAddressFamily::Ipv4,
                    server_addresses: vec!["127.0.0.1".to_string()],
                },
                WindowsInterfaceDnsEntry {
                    interface_alias: "Ethernet".to_string(),
                    interface_index: 12,
                    address_family: WindowsDnsAddressFamily::Ipv6,
                    server_addresses: vec!["::1".to_string()],
                },
                WindowsInterfaceDnsEntry {
                    interface_alias: "Loopback Pseudo-Interface 1".to_string(),
                    interface_index: 1,
                    address_family: WindowsDnsAddressFamily::Ipv4,
                    server_addresses: vec![],
                },
            ],
            nrpt_rules: vec![WindowsNrptRule {
                name: "{rustynet-root-rule}".to_string(),
                namespace: vec![".".to_string()],
                name_servers: vec!["127.0.0.1".to_string()],
            }],
        }
    }

    #[test]
    fn evaluator_accepts_reviewed_snapshot() {
        let snapshot = reviewed_snapshot();
        evaluate_windows_dns_failclosed_snapshot(&snapshot).expect("reviewed snapshot must pass");
    }

    #[test]
    fn evaluator_accepts_127_0_0_2_within_loopback_prefix() {
        // Daemon may bind to any address inside 127.0.0.0/8; the
        // verifier must not lock to a single host within the prefix.
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses = vec!["127.0.0.2".to_string()];
        snapshot.nrpt_rules[0].name_servers = vec!["127.0.0.2".to_string()];
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("any 127/8 host must be acceptable");
    }

    #[test]
    fn evaluator_accepts_empty_interface_dns() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses.clear();
        snapshot.interfaces[1].server_addresses.clear();
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("empty interface DNS lists are acceptable when an NRPT rule covers root");
    }

    #[test]
    fn evaluator_rejects_unsupported_schema_version() {
        let snapshot = WindowsDnsFailclosedSnapshot {
            schema_version: 99,
            ..reviewed_snapshot()
        };
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("unsupported schema_version must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("schema_version=99")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_rogue_dns_server_on_interface() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses = vec!["8.8.8.8".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("rogue interface DNS must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback DNS server 8.8.8.8")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_rogue_ipv6_dns_server_on_interface() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[1].server_addresses = vec!["2606:4700:4700::1111".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("rogue IPv6 interface DNS must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback DNS server 2606:4700:4700::1111")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_address_family_mismatch() {
        let mut snapshot = reviewed_snapshot();
        // IPv6 entry that lists an IPv4 server is a misconfigured
        // fail-closed setup — the parser must surface the mismatch.
        snapshot.interfaces[1].server_addresses = vec!["127.0.0.1".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("address-family mismatch must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("IPv4 address listed in an IPv6 server entry")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unparseable_dns_address() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses = vec!["not-an-ip".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("unparseable address must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("unparseable DNS server")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_root_nrpt_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules = vec![];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("missing root NRPT rule must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("root namespace")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_root_nrpt_rule_with_non_loopback_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["1.1.1.1".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("root NRPT pointing off-loopback must fail closed");
        // Two reasons surface: the per-rule address scan AND the
        // missing-root scan (because the root rule no longer
        // qualifies as covered).
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server 1.1.1.1")),
            "unexpected reasons: {reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("root namespace")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_nrpt_rule_with_empty_namespace_list() {
        let mut snapshot = reviewed_snapshot();
        // Add a second rule with empty namespace; the reviewed root
        // rule still covers `.` so the missing-root drift does NOT
        // surface — only the empty-namespace drift should.
        snapshot.nrpt_rules.push(WindowsNrptRule {
            name: "{stale-rule}".to_string(),
            namespace: vec![],
            name_servers: vec!["127.0.0.1".to_string()],
        });
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("empty-namespace rule must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("empty namespace list")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_nrpt_rule_with_empty_namespace_entry() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules.push(WindowsNrptRule {
            name: "{stale-rule}".to_string(),
            namespace: vec!["".to_string()],
            name_servers: vec!["127.0.0.1".to_string()],
        });
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("empty-namespace-entry rule must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("empty namespace entry")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_nrpt_rule_with_empty_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers.push("".to_string());
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("empty name-server entry must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("empty name-server entry")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses = vec!["8.8.8.8".to_string()];
        snapshot.nrpt_rules[0].name_servers = vec!["1.1.1.1".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("compound drift must fail closed");
        // Three drift sources: rogue interface DNS, root rule
        // pointing off-loopback, and missing-root coverage.
        assert!(
            reasons.len() >= 3,
            "expected aggregated reasons, got: {reasons:?}"
        );
    }

    #[test]
    fn build_report_passes_for_reviewed_snapshot() {
        let snapshot = reviewed_snapshot();
        let report = build_windows_dns_failclosed_report(snapshot);
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn build_report_surfaces_drift_for_rogue_interface_dns() {
        let mut snapshot = reviewed_snapshot();
        snapshot.interfaces[0].server_addresses = vec!["8.8.8.8".to_string()];
        let report = build_windows_dns_failclosed_report(snapshot);
        assert!(!report.overall_ok);
        assert!(report.drift_reasons.iter().any(|r| r.contains("8.8.8.8")));
    }

    #[test]
    fn parse_probe_output_round_trips_reviewed_payload() {
        let snapshot = reviewed_snapshot();
        let json = serde_json::to_string(&snapshot).expect("serialize");
        let parsed = parse_windows_dns_probe_output(json.as_str()).expect("parse");
        assert_eq!(parsed, snapshot);
    }

    #[test]
    fn parse_probe_output_rejects_empty_payload() {
        let err = parse_windows_dns_probe_output("   ").expect_err("empty payload must fail");
        assert!(err.contains("empty output"), "unexpected: {err}");
    }

    #[test]
    fn parse_probe_output_rejects_malformed_json() {
        let err =
            parse_windows_dns_probe_output("{not-json").expect_err("malformed payload must fail");
        assert!(err.contains("failed to parse"), "unexpected: {err}");
    }

    #[test]
    #[cfg(not(windows))]
    fn collector_blocks_off_windows() {
        let err = collect_windows_dns_failclosed_snapshot()
            .expect_err("collector must fail closed off Windows");
        assert!(
            err.contains("requires a Windows runtime host"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn report_serde_round_trips() {
        let snapshot = reviewed_snapshot();
        let report = build_windows_dns_failclosed_report(snapshot);
        let json = serde_json::to_string(&report).expect("serialize report");
        let parsed: WindowsDnsFailclosedReport = serde_json::from_str(&json).expect("parse report");
        assert_eq!(parsed, report);
    }

    // ---- W3: IPv6 NRPT coverage --------------------------------------

    /// IPv6 loopback `::1` is a valid NRPT name-server target. A
    /// Windows host whose mesh resolver listens on `::1` should be
    /// allowed to declare a root NRPT rule with `::1` only.
    #[test]
    fn evaluator_accepts_ipv6_loopback_only_root_nrpt_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["::1".to_string()];
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("IPv6 loopback ::1 must be acceptable as a root NRPT name server");
    }

    /// Long-form `0:0:0:0:0:0:0:1` is the same loopback address as
    /// `::1`. Pin acceptance so a parser refactor that narrows to the
    /// short form doesn't silently relax behavior.
    #[test]
    fn evaluator_accepts_ipv6_loopback_long_form_in_nrpt_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["0:0:0:0:0:0:0:1".to_string()];
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("long-form IPv6 loopback must be acceptable in NRPT");
    }

    /// Mixed loopback set — IPv4 + IPv6 — both qualify as loopback so
    /// a dual-stack rule must be accepted. Mirrors the dual-listener
    /// case where the daemon binds both `127.0.0.1` and `::1`.
    #[test]
    fn evaluator_accepts_dual_stack_loopback_nrpt_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["127.0.0.1".to_string(), "::1".to_string()];
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("dual-stack loopback NRPT must be acceptable");
    }

    /// IPv6 link-local `fe80::1` is NOT loopback — any NRPT rule that
    /// forwards to a link-local resolver leaks queries to whatever is
    /// listening on the link. Reject.
    #[test]
    fn evaluator_rejects_ipv6_link_local_nrpt_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["fe80::1".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("IPv6 link-local NRPT name server must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server fe80::1")),
            "rejection must name link-local entry: {reasons:?}"
        );
        // Missing-root-coverage drift must also surface because the
        // root rule is no longer covered by loopback-only servers.
        assert!(
            reasons.iter().any(|r| r.contains("root namespace")),
            "missing-root coverage must surface: {reasons:?}"
        );
    }

    /// IPv6 unspecified `::` would mean "any source" — not loopback.
    /// Reject as a non-loopback resolver address.
    #[test]
    fn evaluator_rejects_ipv6_unspecified_nrpt_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["::".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("IPv6 unspecified :: must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server ::")),
            "rejection must name unspecified entry: {reasons:?}"
        );
    }

    /// IPv6 external `2606:4700:4700::1111` (Cloudflare's quad-1
    /// equivalent) is a public resolver. Reject.
    #[test]
    fn evaluator_rejects_ipv6_external_nrpt_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["2606:4700:4700::1111".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("IPv6 external NRPT name server must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server 2606:4700:4700::1111")),
            "rejection must name external entry: {reasons:?}"
        );
    }

    /// IPv6 multicast `ff02::1` is "all-nodes" on the local link — a
    /// resolver pointed there spits queries at every neighbor. Reject.
    #[test]
    fn evaluator_rejects_ipv6_multicast_nrpt_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["ff02::1".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("IPv6 multicast NRPT name server must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server ff02::1")),
            "rejection must name multicast entry: {reasons:?}"
        );
    }

    /// IPv4-mapped IPv6 `::ffff:8.8.8.8` is the v6 representation of
    /// a v4 external resolver — must reject like the v4 form.
    #[test]
    fn evaluator_rejects_ipv4_mapped_external_nrpt_name_server() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["::ffff:8.8.8.8".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("IPv4-mapped external NRPT name server must fail closed");
        assert!(
            reasons.iter().any(|r| r.contains("non-loopback")),
            "rejection must surface IPv4-mapped external: {reasons:?}"
        );
    }

    /// Mixed loopback + external in the same NRPT rule: every entry
    /// must be loopback. A single off-loopback entry breaks the
    /// uniformity guarantee — even if the rule has a 127.0.0.1 server
    /// first, the second non-loopback entry leaks any query that
    /// Windows happens to forward to the second server.
    #[test]
    fn evaluator_rejects_mixed_loopback_plus_external_ipv6_in_nrpt_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers =
            vec!["::1".to_string(), "2606:4700:4700::1111".to_string()];
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("mixed loopback+external IPv6 NRPT must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server 2606:4700:4700::1111")),
            "rejection must name the off-loopback entry: {reasons:?}"
        );
        // Root-coverage must also fail because not all servers are
        // loopback.
        assert!(
            reasons.iter().any(|r| r.contains("root namespace")),
            "root-namespace coverage must fail when any entry is off-loopback: {reasons:?}"
        );
    }

    /// Non-root NRPT rule with IPv6 external name server: the rule's
    /// drift surfaces, AND the missing-root drift does NOT surface
    /// because the root rule is still clean.
    #[test]
    fn evaluator_rejects_secondary_ipv6_external_nrpt_rule_only_for_that_rule() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules.push(WindowsNrptRule {
            name: "{rustynet-mesh-rule}".to_string(),
            namespace: vec![".mesh.local".to_string()],
            name_servers: vec!["2606:4700:4700::1111".to_string()],
        });
        let reasons = evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect_err("secondary IPv6 external rule must fail closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("non-loopback name server 2606:4700:4700::1111")),
            "rejection must name the off-loopback entry: {reasons:?}"
        );
        // Root coverage must NOT trip because the original root rule
        // is still loopback-only.
        assert!(
            !reasons.iter().any(|r| r.contains("root namespace")),
            "root-namespace must not regress when only a secondary rule drifts: {reasons:?}"
        );
    }

    /// Root NRPT rule covers root via IPv6 loopback only — explicitly
    /// pin that the root-coverage check accepts an `::1`-only root.
    #[test]
    fn evaluator_accepts_root_covered_by_ipv6_loopback_only() {
        let mut snapshot = reviewed_snapshot();
        snapshot.nrpt_rules[0].name_servers = vec!["::1".to_string()];
        // Root-coverage helper is exercised indirectly via the public
        // evaluator: a clean evaluation proves the rule still covers
        // the `.` namespace.
        evaluate_windows_dns_failclosed_snapshot(&snapshot)
            .expect("root rule with ::1-only must qualify as covered");
    }
}
