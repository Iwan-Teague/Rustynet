#![allow(clippy::result_large_err)]

//! macOS IPv6 tunnel-leak adversarial capture (pf parity of
//! [`crate::linux_ipv6_leak`]).
//!
//! Companion of the orchestrator-side `evaluate_macos_ipv6_leak_artifact`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd macos-ipv6-leak-capture`.
//!
//! ## The attack
//!
//! The classic VPN "IPv6 leak": the IPv4 tunnel + killswitch are healthy but
//! native IPv6 still egresses in the clear, bypassing the tunnel and ACL
//! (`SecurityMinimumBar.md` §8). On macOS the killswitch is a pf anchor whose
//! terminal rule is `block drop out quick all` — family-agnostic, so it covers
//! IPv6 — or, for blind-exit, an explicit `block drop out quick inet6 all`.
//! An **`inet`-only** block (`block drop out quick inet ...`) does NOT contain
//! IPv6 and is exactly the bug this stage catches.
//!
//! ## How the capture bites
//!
//! In a protected mode it runs a REAL outbound IPv6 probe to a global address
//! while `tcpdump` watches the physical egress interface with a filter that
//! excludes link-local (`fe80::/10`) + multicast (`ff00::/8`), and records the
//! pf containment posture. The validator fails closed if any datagram leaked,
//! the probe reached its target, or no v6 containment rule is present.
//!
//! Decision logic is in pure functions (`build_macos_ipv6_leak_snapshot`,
//! `pf_rules_have_v6_block`, `count_pcap_datagrams`) so it is fully unit-tested
//! without the live lab.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const MACOS_IPV6_LEAK_SCHEMA_VERSION: u32 = 1;

/// Default reviewed macOS killswitch pf anchor. blind-exit uses
/// `com.rustynet/blind_exit`; operators override with `--pf-anchor`.
pub const DEFAULT_MACOS_KILLSWITCH_ANCHOR: &str = "com.apple/rustynet_g1";

/// A globally-routable IPv6 probe target (Cloudflare). Asserted UNREACHABLE in
/// protected mode; never used for resolution.
pub const DEFAULT_IPV6_PROBE_TARGET: &str = "2606:4700:4700::1111";

#[cfg(target_os = "macos")]
pub const IPV6_EGRESS_CAPTURE_SECS: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosIpv6LeakSnapshot {
    pub schema_version: u32,
    pub captured_at_unix: i64,
    pub egress_iface: String,
    pub probe_target: String,
    pub pf_anchor: String,
    /// A pf `block drop` rule that covers IPv6 (family-agnostic `all` or an
    /// explicit `inet6` drop) is present in the killswitch anchor.
    pub killswitch_v6_block_present: bool,
    /// Outbound global-scope IPv6 datagrams observed on the egress interface
    /// during the probe window (link-local + multicast excluded). MUST be 0.
    pub leaked_datagram_count: u32,
    /// Whether the outbound IPv6 probe reached its global target. MUST be false.
    pub probe_reached_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosIpv6LeakOptions {
    pub egress_iface: String,
    pub probe_target: String,
    pub pf_anchor: String,
}

impl Default for MacosIpv6LeakOptions {
    fn default() -> Self {
        Self {
            egress_iface: String::new(),
            probe_target: DEFAULT_IPV6_PROBE_TARGET.to_owned(),
            pf_anchor: DEFAULT_MACOS_KILLSWITCH_ANCHOR.to_owned(),
        }
    }
}

pub fn collect_macos_ipv6_leak_snapshot(options: &MacosIpv6LeakOptions) -> MacosIpv6LeakSnapshot {
    let now_unix = current_unix_seconds();
    let pf_rules = capture_pf_anchor_rules(options.pf_anchor.as_str());
    let (pcap_text, probe_reached) = run_ipv6_egress_probe_with_capture(
        options.egress_iface.as_str(),
        options.probe_target.as_str(),
    );
    build_macos_ipv6_leak_snapshot(
        now_unix,
        options.egress_iface.as_str(),
        options.probe_target.as_str(),
        options.pf_anchor.as_str(),
        pf_rules.as_str(),
        pcap_text.as_str(),
        probe_reached,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_macos_ipv6_leak_snapshot(
    captured_at_unix: i64,
    egress_iface: &str,
    probe_target: &str,
    pf_anchor: &str,
    pf_rules_stdout: &str,
    pcap_text: &str,
    probe_reached_target: bool,
) -> MacosIpv6LeakSnapshot {
    MacosIpv6LeakSnapshot {
        schema_version: MACOS_IPV6_LEAK_SCHEMA_VERSION,
        captured_at_unix,
        egress_iface: egress_iface.to_owned(),
        probe_target: probe_target.to_owned(),
        pf_anchor: pf_anchor.to_owned(),
        killswitch_v6_block_present: pf_rules_have_v6_block(pf_rules_stdout),
        leaked_datagram_count: count_pcap_datagrams(pcap_text),
        probe_reached_target,
    }
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// True iff the pf ruleset contains a `block drop` rule that covers IPv6: a
/// family-agnostic `block drop ... all` (pf `all` spans inet+inet6) or an
/// explicit `block drop ... inet6 ...`. An `inet`-only block is NOT v6
/// containment — that is the leak bug.
fn pf_rules_have_v6_block(stdout: &str) -> bool {
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !line.starts_with("block") || !line.contains("drop") {
            continue;
        }
        if line.contains(" inet6") {
            return true;
        }
        // Family-agnostic terminal drop (no inet/inet6 qualifier) covers v6.
        if !line.contains(" inet ") && !line.ends_with(" inet") && line.contains(" all") {
            return true;
        }
    }
    false
}

/// Count outbound datagrams in a `tcpdump -r` text dump (banners/summaries
/// ignored). The capture filter excludes link-local + multicast, so any line
/// is a leaked global-scope datagram.
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

#[cfg(target_os = "macos")]
fn capture_pf_anchor_rules(anchor: &str) -> String {
    let output = Command::new("/sbin/pfctl")
        .args(["-a", anchor, "-s", "rules"])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => String::new(),
    }
}

#[cfg(not(target_os = "macos"))]
fn capture_pf_anchor_rules(_anchor: &str) -> String {
    String::new()
}

#[cfg(target_os = "macos")]
fn run_ipv6_egress_probe_with_capture(egress_iface: &str, target: &str) -> (String, bool) {
    use std::thread::sleep;
    use std::time::Duration;

    if egress_iface.is_empty() {
        return (String::new(), false);
    }
    let pcap_path = std::env::temp_dir().join(format!(
        "rustynet-macos-ipv6-leak-{}.pcap",
        std::process::id()
    ));
    let pcap_str = pcap_path.to_string_lossy().into_owned();
    let filter = "ip6 and not src net fe80::/10 and not dst net fe80::/10 and not dst net ff00::/8";
    let spawn = Command::new("/usr/sbin/tcpdump")
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
        Err(_) => return (String::new(), false),
    };
    sleep(Duration::from_millis(800));
    let reached = Command::new("/sbin/ping6")
        .args(["-c", "2", "-W", "2", target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    sleep(Duration::from_millis(IPV6_EGRESS_CAPTURE_SECS * 1000 - 800));
    let _ = child.kill();
    let _ = child.wait();
    let pcap_text = Command::new("/usr/sbin/tcpdump")
        .args(["-n", "-r", pcap_str.as_str()])
        .output()
        .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
        .unwrap_or_default();
    let _ = std::fs::remove_file(&pcap_path);
    (pcap_text, reached)
}

#[cfg(not(target_os = "macos"))]
fn run_ipv6_egress_probe_with_capture(_egress_iface: &str, _target: &str) -> (String, bool) {
    (String::new(), false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PF_TERMINAL_BLOCK_ALL: &str = r#"scrub-anchor "com.apple/*" all fragment reassemble
pass out quick on rustynet0 inet6 all flags S/SA keep state
block drop out quick all"#;

    const PF_EXPLICIT_INET6_BLOCK: &str = r#"pass out quick on rustynet0 all keep state
block drop out quick inet6 all
block drop out quick inet proto udp from any to any port = 53"#;

    const PF_INET_ONLY_BLOCK: &str = r#"pass out quick on rustynet0 all keep state
block drop out quick inet from any to any
block drop out quick inet proto udp from any to any port = 53"#;

    #[test]
    fn pf_terminal_block_all_counts_as_v6_containment() {
        assert!(pf_rules_have_v6_block(PF_TERMINAL_BLOCK_ALL));
    }

    #[test]
    fn pf_explicit_inet6_block_counts() {
        assert!(pf_rules_have_v6_block(PF_EXPLICIT_INET6_BLOCK));
    }

    #[test]
    fn pf_inet_only_block_is_not_v6_containment() {
        // The IPv4-only pf block is the exact leak bug: looks like a
        // killswitch, does nothing for IPv6.
        assert!(!pf_rules_have_v6_block(PF_INET_ONLY_BLOCK));
    }

    #[test]
    fn pf_empty_is_not_v6_containment() {
        assert!(!pf_rules_have_v6_block(""));
        assert!(!pf_rules_have_v6_block(
            "# comment\npass out quick on rustynet0 all\n"
        ));
    }

    #[test]
    fn count_pcap_datagrams_ignores_banners() {
        assert_eq!(
            count_pcap_datagrams("reading from file /tmp/x.pcap\n0 packets captured\n"),
            0
        );
    }

    #[test]
    fn count_pcap_datagrams_counts_leaks() {
        assert_eq!(
            count_pcap_datagrams(
                "12:00:00 IP6 2001:db8::1 > 2606:4700:4700::1111: ICMP6, echo request\n"
            ),
            1
        );
    }

    #[test]
    fn build_snapshot_clean_failclosed_posture() {
        let snap = build_macos_ipv6_leak_snapshot(
            1_780_000_000,
            "en0",
            DEFAULT_IPV6_PROBE_TARGET,
            DEFAULT_MACOS_KILLSWITCH_ANCHOR,
            PF_TERMINAL_BLOCK_ALL,
            "0 packets captured\n",
            false,
        );
        assert!(snap.killswitch_v6_block_present);
        assert_eq!(snap.leaked_datagram_count, 0);
        assert!(!snap.probe_reached_target);
    }

    #[test]
    fn build_snapshot_leak_posture() {
        let snap = build_macos_ipv6_leak_snapshot(
            1_780_000_100,
            "en0",
            DEFAULT_IPV6_PROBE_TARGET,
            DEFAULT_MACOS_KILLSWITCH_ANCHOR,
            PF_INET_ONLY_BLOCK,
            "12:00:00 IP6 2001:db8::1 > 2606:4700:4700::1111: ICMP6, echo request\n",
            true,
        );
        assert!(!snap.killswitch_v6_block_present);
        assert_eq!(snap.leaked_datagram_count, 1);
        assert!(snap.probe_reached_target);
    }

    #[test]
    fn default_options_use_reviewed_defaults() {
        let opts = MacosIpv6LeakOptions::default();
        assert_eq!(opts.pf_anchor, DEFAULT_MACOS_KILLSWITCH_ANCHOR);
        assert_eq!(opts.probe_target, DEFAULT_IPV6_PROBE_TARGET);
        assert_eq!(opts.egress_iface, "");
    }
}
