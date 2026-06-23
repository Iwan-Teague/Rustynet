#![allow(clippy::result_large_err)]

//! Linux IPv6 tunnel-leak adversarial capture.
//!
//! Companion of the orchestrator-side `evaluate_linux_ipv6_leak_artifact`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`.
//!
//! ## The attack this proves closed
//!
//! "IPv6 leak" is a classic VPN failure mode: the IPv4 tunnel + killswitch
//! are up and look healthy, but the host still has working native IPv6 and
//! nothing on the protected path drops it — so IPv6 traffic egresses in the
//! clear, *outside* the tunnel, bypassing the killswitch and ACL entirely.
//! `SecurityMinimumBar.md` §8 requires tunnel fail-close behaviour in
//! protected-routing modes; that promise is empty if it only covers IPv4.
//!
//! ## What "fail closed for IPv6" means here
//!
//! In a protected mode the node MUST contain every outbound *global-scope*
//! IPv6 datagram by at least one of:
//!   1. disabling IPv6 entirely (`net.ipv6.conf.all.disable_ipv6 = 1`), or
//!   2. a killswitch drop rule covering the `inet`/`ip6` family on the
//!      egress path (`rustynet_g<N>` table).
//!
//! ## How the capture bites
//!
//! The capture runs a REAL outbound IPv6 probe to a global address while
//! `tcpdump` watches the egress interface with a BPF filter that already
//! excludes link-local (`fe80::/10`) and multicast (`ff00::/8`) housekeeping
//! (NDP, mDNS, RA). Any datagram captured under that filter is therefore a
//! genuine cleartext leak. The validator fails closed if:
//!   - any leaked datagram was observed, OR
//!   - the probe actually reached its target (traffic escaped), OR
//!   - neither containment control (1) nor (2) is present.
//!
//! This module emits ONE snapshot per invocation, wired through the CLI as
//! `rustynetd linux-ipv6-leak-capture`. The decision logic lives in pure
//! functions (`build_linux_ipv6_leak_snapshot`, `parse_proc_flag`,
//! `nft_ruleset_has_v6_drop`, `count_pcap_datagrams`) so it is fully
//! unit-tested without the live lab.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LINUX_IPV6_LEAK_SCHEMA_VERSION: u32 = 1;

/// Reviewed generation-1 killswitch table. The runtime rotates generation
/// suffixes (`rustynet_g<N>`), so operators can override with
/// `--killswitch-table` when the active generation differs.
pub const DEFAULT_LINUX_KILLSWITCH_TABLE: &str = "rustynet_g1";

/// A globally-routable IPv6 address used purely as a leak probe target
/// (Cloudflare public resolver). The probe asserts this is UNREACHABLE in
/// protected mode; it is never used for resolution.
pub const DEFAULT_IPV6_PROBE_TARGET: &str = "2606:4700:4700::1111";

/// Seconds the egress capture window stays open around the probe.
#[cfg(target_os = "linux")]
pub const IPV6_EGRESS_CAPTURE_SECS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxIpv6LeakSnapshot {
    pub schema_version: u32,
    pub captured_at_unix: i64,
    pub egress_iface: String,
    pub probe_target: String,
    pub killswitch_table: String,
    /// `net.ipv6.conf.all.disable_ipv6 == 1`.
    pub ipv6_disabled: bool,
    /// A killswitch drop rule covering the `inet`/`ip6` family is present.
    pub killswitch_v6_drop_present: bool,
    /// Count of outbound global-scope IPv6 datagrams observed on the egress
    /// interface during the probe window (link-local + multicast excluded by
    /// the capture filter). MUST be zero in a fail-closed posture.
    pub leaked_datagram_count: u32,
    /// Whether the outbound IPv6 probe actually reached its global target.
    /// MUST be false in a fail-closed posture (the killswitch blocked it).
    pub probe_reached_target: bool,
    /// Whether the active probe + capture actually executed (tcpdump spawned
    /// AND the ping probe ran). A vacuous run where the tooling never executed
    /// MUST NOT read as a clean fail-closed result — the validator requires
    /// this true so the active probe is load-bearing, not just the static
    /// containment posture.
    #[serde(default)]
    pub probe_attempted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxIpv6LeakOptions {
    pub egress_iface: String,
    pub probe_target: String,
    pub killswitch_table: String,
}

impl Default for LinuxIpv6LeakOptions {
    fn default() -> Self {
        Self {
            egress_iface: String::new(),
            probe_target: DEFAULT_IPV6_PROBE_TARGET.to_owned(),
            killswitch_table: DEFAULT_LINUX_KILLSWITCH_TABLE.to_owned(),
        }
    }
}

pub fn collect_linux_ipv6_leak_snapshot(options: &LinuxIpv6LeakOptions) -> LinuxIpv6LeakSnapshot {
    let now_unix = current_unix_seconds();
    let disable_stdout = capture_proc_flag("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    let nft_ruleset = capture_nft_ruleset();
    let (pcap_text, probe_reached, probe_attempted) = run_ipv6_egress_probe_with_capture(
        options.egress_iface.as_str(),
        options.probe_target.as_str(),
    );
    build_linux_ipv6_leak_snapshot(
        now_unix,
        options.egress_iface.as_str(),
        options.probe_target.as_str(),
        options.killswitch_table.as_str(),
        disable_stdout.as_str(),
        nft_ruleset.as_str(),
        pcap_text.as_str(),
        probe_reached,
        probe_attempted,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_linux_ipv6_leak_snapshot(
    captured_at_unix: i64,
    egress_iface: &str,
    probe_target: &str,
    killswitch_table: &str,
    disable_ipv6_stdout: &str,
    nft_ruleset_stdout: &str,
    pcap_text: &str,
    probe_reached_target: bool,
    probe_attempted: bool,
) -> LinuxIpv6LeakSnapshot {
    LinuxIpv6LeakSnapshot {
        schema_version: LINUX_IPV6_LEAK_SCHEMA_VERSION,
        captured_at_unix,
        egress_iface: egress_iface.to_owned(),
        probe_target: probe_target.to_owned(),
        killswitch_table: killswitch_table.to_owned(),
        ipv6_disabled: parse_proc_flag(disable_ipv6_stdout),
        killswitch_v6_drop_present: nft_ruleset_has_v6_drop(nft_ruleset_stdout, killswitch_table),
        leaked_datagram_count: count_pcap_datagrams(pcap_text),
        probe_reached_target,
        probe_attempted,
    }
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `/proc/sys` boolean flag: "1" => true, anything else => false.
fn parse_proc_flag(stdout: &str) -> bool {
    stdout.trim() == "1"
}

/// Detect a killswitch drop rule that covers the IPv6 family on the EGRESS
/// path. Two signals count:
///   1. an explicit v6-scoped drop (`meta nfproto ipv6 ... drop`, an
///      `ip6`/`inet6` saddr/daddr drop) — explicit intent, credited anywhere;
///   2. the canonical family-agnostic terminal drop (the `block drop out quick
///      all` analogue: `policy drop` / a bare `drop`) — but ONLY inside an
///      EGRESS base chain (`hook output`/`hook postrouting`/`hook forward`) of
///      the dual-stack `inet` killswitch table. A family-agnostic terminal drop
///      on an `input`/`prerouting` chain, a regular (unhooked) chain, or an
///      `ip` (IPv4-only) table does NOT contain outbound IPv6 — crediting it
///      would be a false fail-closed positive.
fn nft_ruleset_has_v6_drop(stdout: &str, killswitch_table: &str) -> bool {
    let mut in_inet_killswitch_table = false;
    // Whether the chain currently being scanned is hooked on an egress path.
    // Reset on every `table`/`chain` boundary; set by a base-chain `hook` line.
    let mut chain_is_egress = false;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("table ") {
            in_inet_killswitch_table = line.starts_with("table inet ")
                && line
                    .split_whitespace()
                    .nth(2)
                    .map(|name| name.trim_end_matches('{').trim() == killswitch_table)
                    .unwrap_or(false);
            chain_is_egress = false;
            continue;
        }
        if line.starts_with("chain ") {
            // A new chain; its hook (if any) is declared on a following line.
            chain_is_egress = false;
            continue;
        }
        // Base-chain hook declaration (may also carry `policy drop` on the
        // same line). Only output/postrouting/forward are egress-relevant.
        if line.contains("hook output")
            || line.contains("hook postrouting")
            || line.contains("hook forward")
        {
            chain_is_egress = true;
        } else if line.contains("hook input") || line.contains("hook prerouting") {
            chain_is_egress = false;
        }
        // Explicit v6-scoped drop: credited (explicit intent, usually oifname).
        if rule_is_v6_drop(line) {
            return true;
        }
        // Family-agnostic terminal drop: only on an egress base chain of the
        // inet killswitch table.
        if in_inet_killswitch_table && chain_is_egress && line_is_terminal_drop(line) {
            return true;
        }
    }
    false
}

fn rule_is_v6_drop(line: &str) -> bool {
    let has_v6_selector = line.contains("nfproto ipv6")
        || line.contains("ip6 ")
        || line.contains("ip6.")
        || line.contains("inet6")
        || line.contains("icmpv6");
    has_v6_selector
        && (line.contains(" drop") || line.ends_with("drop") || line.contains(" reject"))
}

fn line_is_terminal_drop(line: &str) -> bool {
    // A chain-level or rule-level terminal drop with no IPv4-only selector.
    // e.g. "policy drop;", "oifname \"eth0\" drop", "drop".
    if line.contains("ip saddr") || line.contains("ip daddr") || line.contains("nfproto ipv4") {
        return false;
    }
    line == "drop"
        || line.ends_with(" drop")
        || line.ends_with(" drop;")
        || line.contains("policy drop")
}

/// Count outbound datagrams in a `tcpdump -r` text dump. The capture filter
/// excludes link-local + multicast, so every non-empty, non-banner line is a
/// leaked global-scope datagram. `reading from file` banners and `packets`
/// summary lines emitted by tcpdump on stderr/stdout are ignored.
fn count_pcap_datagrams(pcap_text: &str) -> u32 {
    let mut count = 0u32;
    for raw in pcap_text.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("reading from file")
            || lower.starts_with("listening on")
            || lower.contains("packets captured")
            || lower.contains("packets received")
            || lower.contains("packets dropped")
            || lower.starts_with("tcpdump:")
        {
            continue;
        }
        count = count.saturating_add(1);
    }
    count
}

#[cfg(target_os = "linux")]
fn capture_proc_flag(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_else(|_| "0".to_owned())
}

#[cfg(not(target_os = "linux"))]
fn capture_proc_flag(_path: &str) -> String {
    "0".to_owned()
}

#[cfg(target_os = "linux")]
fn capture_nft_ruleset() -> String {
    let output = Command::new("nft").args(["list", "ruleset"]).output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => String::new(),
    }
}

#[cfg(not(target_os = "linux"))]
fn capture_nft_ruleset() -> String {
    String::new()
}

/// Run an outbound IPv6 probe to `target` while capturing the egress
/// interface. Returns `(tcpdump_text, probe_reached_target, probe_attempted)`.
/// Argv-only; no shell construction. `probe_attempted` is true only when the
/// capture tcpdump spawned AND the ping probe actually executed — so a host
/// missing the tooling (tcpdump/`ping -6` absent) reports `attempted=false`
/// and the validator fails the run as inconclusive rather than treating a
/// never-run probe as a clean fail-closed result.
#[cfg(target_os = "linux")]
fn run_ipv6_egress_probe_with_capture(egress_iface: &str, target: &str) -> (String, bool, bool) {
    use std::thread::sleep;
    use std::time::Duration;

    if egress_iface.is_empty() {
        return (String::new(), false, false);
    }
    let pcap_path =
        std::env::temp_dir().join(format!("rustynet-ipv6-leak-{}.pcap", std::process::id()));
    let pcap_str = pcap_path.to_string_lossy().into_owned();
    // BPF filter: IPv6 only, excluding link-local + multicast housekeeping.
    let filter = "ip6 and not src net fe80::/10 and not dst net fe80::/10 and not dst net ff00::/8";
    let spawn = Command::new("tcpdump")
        .args([
            "-n",
            "-i",
            egress_iface,
            "-w",
            pcap_str.as_str(),
            "-U",
            filter,
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match spawn {
        Ok(child) => child,
        Err(_) => return (String::new(), false, false),
    };
    // Let tcpdump bind to the interface before probing.
    sleep(Duration::from_millis(800));
    // Real outbound IPv6 probe. `ping -6` egresses native IPv6 if the host
    // has a global v6 route; the killswitch must drop it. `Ok(_)` means the
    // probe tooling executed (attempted), regardless of reachability.
    let ping_status = Command::new("ping")
        .args(["-6", "-c", "2", "-W", "2", target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let probe_attempted = ping_status.is_ok();
    let reached = ping_status.map(|status| status.success()).unwrap_or(false);
    sleep(Duration::from_millis(IPV6_EGRESS_CAPTURE_SECS * 1000 - 800));
    let _ = child.kill();
    let _ = child.wait();
    let pcap_text = Command::new("tcpdump")
        .args(["-n", "-r", pcap_str.as_str()])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let _ = fs::remove_file(&pcap_path);
    (pcap_text, reached, probe_attempted)
}

#[cfg(not(target_os = "linux"))]
fn run_ipv6_egress_probe_with_capture(_egress_iface: &str, _target: &str) -> (String, bool, bool) {
    (String::new(), false, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INET_KILLSWITCH_WITH_TERMINAL_DROP: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        oifname "rustynet0" accept
    }
}"#;

    const INET_KILLSWITCH_WITH_V6_DROP: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        meta nfproto ipv6 oifname "enp0s1" drop
    }
}"#;

    const IPV4_ONLY_KILLSWITCH: &str = r#"table ip rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        ip saddr 100.64.0.0/16 accept
    }
}"#;

    #[test]
    fn parse_proc_flag_only_true_for_one() {
        assert!(parse_proc_flag("1\n"));
        assert!(parse_proc_flag("1"));
        assert!(!parse_proc_flag("0\n"));
        assert!(!parse_proc_flag(""));
        assert!(!parse_proc_flag("garbage"));
    }

    #[test]
    fn nft_ruleset_inet_terminal_drop_counts_as_v6_containment() {
        assert!(nft_ruleset_has_v6_drop(
            INET_KILLSWITCH_WITH_TERMINAL_DROP,
            "rustynet_g1"
        ));
    }

    #[test]
    fn nft_ruleset_explicit_v6_drop_counts() {
        assert!(nft_ruleset_has_v6_drop(
            INET_KILLSWITCH_WITH_V6_DROP,
            "rustynet_g1"
        ));
    }

    const INET_KILLSWITCH_INPUT_ONLY_DROP: &str = r#"table inet rustynet_g1 {
    chain inbound {
        type filter hook input priority 0; policy drop;
    }
}"#;

    #[test]
    fn nft_ruleset_terminal_drop_on_input_chain_is_not_egress_containment() {
        // A family-agnostic terminal drop on an INPUT base chain does not
        // contain OUTBOUND IPv6 — crediting it would be a false fail-closed
        // positive while v6 leaks freely on egress.
        assert!(!nft_ruleset_has_v6_drop(
            INET_KILLSWITCH_INPUT_ONLY_DROP,
            "rustynet_g1"
        ));
    }

    #[test]
    fn nft_ruleset_ipv4_only_table_is_not_v6_containment() {
        // The IPv4-only `table ip` killswitch is the exact bug: it looks like
        // a killswitch but does nothing for IPv6.
        assert!(!nft_ruleset_has_v6_drop(
            IPV4_ONLY_KILLSWITCH,
            "rustynet_g1"
        ));
    }

    #[test]
    fn nft_ruleset_empty_is_not_v6_containment() {
        assert!(!nft_ruleset_has_v6_drop("", "rustynet_g1"));
        assert!(!nft_ruleset_has_v6_drop("# comment\n", "rustynet_g1"));
    }

    #[test]
    fn nft_ruleset_inet_terminal_drop_only_for_matching_table_name() {
        // A terminal drop in some *other* inet table must not be credited to
        // our killswitch table name.
        let other = INET_KILLSWITCH_WITH_TERMINAL_DROP.replace("rustynet_g1", "someone_else");
        assert!(!nft_ruleset_has_v6_drop(other.as_str(), "rustynet_g1"));
    }

    #[test]
    fn count_pcap_datagrams_ignores_banners_and_summaries() {
        let dump = "reading from file /tmp/x.pcap, link-type EN10MB (Ethernet)\n\
3 packets captured\n";
        assert_eq!(count_pcap_datagrams(dump), 0);
        assert_eq!(count_pcap_datagrams(""), 0);
    }

    #[test]
    fn count_pcap_datagrams_counts_leaked_lines() {
        let dump = "reading from file /tmp/x.pcap, link-type EN10MB (Ethernet)\n\
12:00:00.000001 IP6 2001:db8::1 > 2606:4700:4700::1111: ICMP6, echo request\n\
12:00:00.000002 IP6 2001:db8::1 > 2606:4700:4700::1111: ICMP6, echo request\n";
        assert_eq!(count_pcap_datagrams(dump), 2);
    }

    #[test]
    fn build_snapshot_clean_failclosed_posture() {
        let snap = build_linux_ipv6_leak_snapshot(
            1_780_000_000,
            "enp0s1",
            DEFAULT_IPV6_PROBE_TARGET,
            "rustynet_g1",
            "1\n",
            INET_KILLSWITCH_WITH_TERMINAL_DROP,
            "reading from file /tmp/x.pcap\n0 packets captured\n",
            false,
            true,
        );
        assert_eq!(snap.schema_version, 1);
        assert_eq!(snap.egress_iface, "enp0s1");
        assert!(snap.ipv6_disabled);
        assert!(snap.killswitch_v6_drop_present);
        assert_eq!(snap.leaked_datagram_count, 0);
        assert!(!snap.probe_reached_target);
        assert!(snap.probe_attempted);
    }

    #[test]
    fn build_snapshot_leak_posture_records_leak() {
        let snap = build_linux_ipv6_leak_snapshot(
            1_780_000_100,
            "enp0s1",
            DEFAULT_IPV6_PROBE_TARGET,
            "rustynet_g1",
            "0\n",
            IPV4_ONLY_KILLSWITCH,
            "12:00:00 IP6 2001:db8::1 > 2606:4700:4700::1111: ICMP6, echo request\n",
            true,
            true,
        );
        assert!(!snap.ipv6_disabled);
        assert!(!snap.killswitch_v6_drop_present);
        assert_eq!(snap.leaked_datagram_count, 1);
        assert!(snap.probe_reached_target);
        assert!(snap.probe_attempted);
    }

    #[test]
    fn default_options_use_reviewed_defaults() {
        let opts = LinuxIpv6LeakOptions::default();
        assert_eq!(opts.killswitch_table, DEFAULT_LINUX_KILLSWITCH_TABLE);
        assert_eq!(opts.probe_target, DEFAULT_IPV6_PROBE_TARGET);
        assert_eq!(opts.egress_iface, "");
    }
}
