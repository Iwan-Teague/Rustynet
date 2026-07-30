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

use crate::killswitch_precedence::{
    ContainedInterfaces, RuleDisposition, nft_chain_rules_in_evaluation_order,
    terminator_is_reachable,
};
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

/// Detect whether the killswitch actually CONTAINS outbound global-scope IPv6.
///
/// Two signals can establish containment, and both are now subject to
/// precedence:
///   1. an explicit v6-scoped drop (`meta nfproto ipv6 ... drop`, an
///      `ip6`/`inet6` saddr/daddr drop);
///   2. the canonical family-agnostic terminal drop (the `block drop out quick
///      all` analogue: `policy drop` / a bare `drop`).
///
/// BOTH require the same scope, and this is the load-bearing part: the rule must
/// sit in an EGRESS base chain (`hook output`/`hook postrouting`/`hook forward`)
/// of the dual-stack `inet` killswitch table. A drop of either kind on an
/// `input`/`prerouting` chain, in a regular (unhooked) chain, in a foreign
/// table, or in an `ip` (IPv4-only) table does NOT contain outbound IPv6 —
/// crediting it would be a false fail-closed positive.
///
/// An earlier revision credited kind 1 in ANY chain, calling it "explicit
/// intent". Intent is not containment: an unhooked chain is never evaluated
/// unless jumped to, and a foreign table is not this daemon's to rely on, so
/// its verdict can change without any rustynet state changing.
///
/// # Presence is not containment (IPV-03)
///
/// This function used to return `true` the moment it saw such a drop, without
/// looking at the rules above it. nftables is first-match-wins inside a chain
/// and `policy drop` is the chain *default* — applied only after every rule
/// fails to match — so any `accept` in the chain is evaluated FIRST and the
/// policy never fires for traffic that accept matches. Fed the ruleset produced
/// by an IPv4-only killswitch with a broad v6 accept, the old scan reported
/// `killswitch_v6_drop_present=true` and the verifier passed while global IPv6
/// egressed freely.
///
/// Each candidate chain is therefore walked in evaluation order via
/// [`crate::killswitch_precedence`], and the drop is credited only if it is
/// actually REACHABLE for global-scope outbound IPv6.
///
/// # Why the result is a union across chains
///
/// A packet traverses EVERY base chain registered at a hook, and a `drop`
/// anywhere is immediate and terminal for the whole evaluation, while an
/// `accept` ends only the chain that issued it. So one chain accepting does not
/// undo another chain's drop: containment holds if ANY egress chain drops the
/// traffic. Requiring every chain to drop would fail closed on correct
/// multi-chain rulesets, so the per-chain verdicts are OR-ed.
fn nft_ruleset_has_v6_drop(stdout: &str, killswitch_table: &str) -> bool {
    let contained = ContainedInterfaces::default();
    nft_egress_chain_bodies(stdout, killswitch_table)
        .into_iter()
        .any(|(body, in_killswitch_table)| {
            let rules = nft_chain_rules_in_evaluation_order(&body);
            terminator_is_reachable(&rules, |rule| {
                classify_v6_egress_rule(rule, in_killswitch_table, &contained)
            })
            .is_ok()
        })
}

/// Split an `nft list ruleset` dump into candidate egress chain bodies.
///
/// Returns one entry per chain that could contain outbound IPv6: the chain body
/// text, plus whether that chain sits in the dual-stack `inet` killswitch table
/// (which is what licenses crediting a family-agnostic terminal drop). Chains
/// hooked on `input`/`prerouting` are excluded — they cannot contain egress.
/// Unhooked regular chains are retained because an explicit v6 drop in one is
/// still explicit intent, but they are not flagged as killswitch-table egress.
fn nft_egress_chain_bodies(stdout: &str, killswitch_table: &str) -> Vec<(String, bool)> {
    let mut chains = Vec::new();
    let mut in_inet_killswitch_table = false;
    let mut current: Option<(String, bool, bool)> = None;

    // Finish the chain under construction, keeping it unless it is hooked on an
    // ingress path.
    fn flush(current: Option<(String, bool, bool)>, chains: &mut Vec<(String, bool)>) {
        if let Some((body, in_table, is_ingress)) = current
            && !is_ingress
        {
            chains.push((body, in_table));
        }
    }

    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("table ") {
            flush(current.take(), &mut chains);
            in_inet_killswitch_table = line.starts_with("table inet ")
                && line
                    .split_whitespace()
                    .nth(2)
                    .map(|name| name.trim_end_matches('{').trim() == killswitch_table)
                    .unwrap_or(false);
            continue;
        }
        if line.starts_with("chain ") {
            flush(current.take(), &mut chains);
            // `in_table` starts false and is raised only when the chain
            // DECLARES an egress hook below. Seeding it from the table alone
            // flagged unhooked regular chains as killswitch-table egress,
            // contradicting this function's own contract and crediting a
            // family-agnostic drop in a chain the kernel never traverses.
            current = Some((String::new(), false, false));
            continue;
        }
        if line == "}" {
            flush(current.take(), &mut chains);
            continue;
        }
        if let Some((body, in_table, is_ingress)) = current.as_mut() {
            // A base chain declares its hook; only output/postrouting/forward
            // are egress-relevant.
            if line.contains("hook input") || line.contains("hook prerouting") {
                *is_ingress = true;
            } else if line.contains("hook output")
                || line.contains("hook postrouting")
                || line.contains("hook forward")
            {
                // Egress base chain: now, and only now, does membership of the
                // dual-stack killswitch table license crediting a
                // family-agnostic terminal drop.
                *in_table = in_inet_killswitch_table;
            }
            body.push_str(line);
            body.push('\n');
        }
    }
    flush(current.take(), &mut chains);
    chains
}

/// Reduce one nft rule to its effect on global-scope OUTBOUND IPv6.
///
/// Fail-closed: anything not positively recognised as unable-to-match or
/// tunnel-scoped is [`RuleDisposition::Escapes`], so an unfamiliar rule
/// withholds containment rather than being skipped over.
fn classify_v6_egress_rule(
    rule: &str,
    in_killswitch_table: bool,
    contained: &ContainedInterfaces,
) -> RuleDisposition {
    // Terminators: BOTH kinds require the chain to be an egress base chain of
    // the dual-stack killswitch table. An explicit v6 drop used to be credited
    // unconditionally on the reasoning that it is "explicit intent" — but
    // containment is about EFFECT, not intent, and a rule the kernel never
    // evaluates has no effect. That crediting survived the first half of this
    // fix and was found by adversarially reviewing it: an explicit
    // `meta nfproto ipv6 drop` in an unhooked chain, or in a table this daemon
    // does not manage, still certified containment.
    //
    // Note a non-credited drop does not become an escape: `drop` is absent from
    // `rule_has_permissive_verdict`, so it falls through to `Irrelevant` — it
    // cannot contain, and it cannot leak either.
    if in_killswitch_table && (rule_is_v6_drop(rule) || line_is_terminal_drop(rule)) {
        return RuleDisposition::Terminator;
    }
    // An IPv4-only selector cannot match IPv6 at all, whatever it permits.
    if rule_is_ipv4_only(rule) {
        return RuleDisposition::Irrelevant;
    }
    // A rule scoped to link-local or multicast v6 cannot carry global-scope
    // traffic off the host; the leak probe targets a global address.
    if rule_is_non_global_v6_scope(rule) {
        return RuleDisposition::Irrelevant;
    }
    // No verdict at all (`counter`, a bare `comment`): the packet falls
    // through to the next rule, so this one cannot escape.
    if !rule_has_permissive_verdict(rule) && !rule.contains("jump") && !rule.contains("goto") {
        return RuleDisposition::Irrelevant;
    }
    // `return` in a base chain ends the chain and applies its policy, so it
    // cannot escape a `policy drop`.
    if rule_verdict_is_return(rule) {
        return RuleDisposition::Irrelevant;
    }
    // A permissive verdict scoped to the tunnel (or loopback) is how encrypted
    // traffic legitimately leaves; that is containment, not a leak.
    if let Some(interface) = ContainedInterfaces::nft_rule_output_interface(rule)
        && contained.contains(interface)
    {
        return RuleDisposition::Contained;
    }
    // Everything else — a broad accept, an accept on a physical interface, a
    // jump to a chain whose contents are not visible here — defeats the drop.
    RuleDisposition::Escapes
}

/// Whether the rule carries a selector that can only ever match IPv4.
fn rule_is_ipv4_only(rule: &str) -> bool {
    rule.contains("nfproto ipv4")
        || rule.contains("ip saddr")
        || rule.contains("ip daddr")
        || rule.contains("ip protocol")
        || rule.contains("ip version 4")
}

/// Whether the rule is scoped to v6 addresses that cannot leave the link.
fn rule_is_non_global_v6_scope(rule: &str) -> bool {
    rule.contains("fe80::/10") || rule.contains("ff00::/8") || rule.contains("::1/128")
}

/// Whether the rule reaches a verdict that lets the packet proceed.
fn rule_has_permissive_verdict(rule: &str) -> bool {
    ["accept", "return", "queue", "dup", "fwd"]
        .iter()
        .any(|verdict| {
            rule == *verdict
                || rule.ends_with(&format!(" {verdict}"))
                || rule.ends_with(&format!(" {verdict};"))
                || rule.contains(&format!(" {verdict} "))
        })
}

fn rule_verdict_is_return(rule: &str) -> bool {
    rule == "return" || rule.ends_with(" return") || rule.ends_with(" return;")
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

    // Carries the `hook output` declaration the REAL killswitch chain has
    // (`phase10.rs` renders `type filter hook output priority 0; policy drop;`).
    // Without it this fixture modelled an unhooked chain — a shape production
    // never emits — and the test below asserted that shape credits containment,
    // which is what pinned the explicit-v6 crediting defect as correct.
    const INET_KILLSWITCH_WITH_V6_DROP: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
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

    /// REGRESSION PIN (introduced by f2e084d9, fixed here).
    ///
    /// f2e084d9 replaced a POSITIVE egress-hook test (`chain_is_egress`, set
    /// only by `hook output|postrouting|forward`) with a NEGATIVE one (retain
    /// unless `hook input|prerouting`). An unhooked regular chain satisfies the
    /// negative test, so it survived — and `in_table` was seeded from table
    /// membership alone, so a family-agnostic terminal drop inside it was
    /// credited as IPv6 egress containment.
    ///
    /// The kernel never evaluates a regular chain unless something jumps to it,
    /// so that credits containment from a chain that may never run — the same
    /// verifier-certifies-a-leak direction f2e084d9 was written to close.
    /// Confirmed by executing the pre-commit file: this input returned `false`
    /// before f2e084d9 and `true` after.
    ///
    /// The function's own doc comments said so all along (":229" — unhooked
    /// chains "are not flagged as killswitch-table egress"); only the code
    /// disagreed.
    #[test]
    fn unhooked_chain_family_agnostic_drop_is_not_egress_containment() {
        const UNHOOKED: &str = r#"table inet rustynet_g1 {
	chain helper {
		drop
	}
}"#;
        assert!(
            !nft_ruleset_has_v6_drop(UNHOOKED, "rustynet_g1"),
            "a terminal drop in an UNHOOKED chain must not be credited as egress containment"
        );

        // The same drop in a chain that DOES declare an egress hook is still
        // credited — this half is the false-fail guard. Without it the fix
        // could be "tightened" into refusing every real killswitch.
        const HOOKED: &str = r#"table inet rustynet_g1 {
	chain killswitch {
		type filter hook output priority 0; policy drop;
		drop
	}
}"#;
        assert!(
            nft_ruleset_has_v6_drop(HOOKED, "rustynet_g1"),
            "an egress-hooked chain in the killswitch table must still be credited"
        );

        // The EXPLICIT-v6 half of the same two escapes. The first half of this
        // fix gated only the family-agnostic terminator, so swapping the bare
        // `drop` here for an explicit v6 drop made the defect green again.
        const UNHOOKED_EXPLICIT_V6: &str = r#"table inet rustynet_g1 {
	chain helper {
		meta nfproto ipv6 drop
	}
}"#;
        assert!(
            !nft_ruleset_has_v6_drop(UNHOOKED_EXPLICIT_V6, "rustynet_g1"),
            "an explicit v6 drop in an UNHOOKED chain must not be credited — \
             intent is not containment when the kernel never evaluates the rule"
        );

        // A foreign table's egress chain really would drop the traffic, but it
        // is not this daemon's rule: the verdict could flip with no rustynet
        // state change, so it cannot evidence the rustynet killswitch.
        const FOREIGN_TABLE_EXPLICIT_V6: &str = r#"table inet someone_else {
	chain out {
		type filter hook output priority 0; policy accept;
		meta nfproto ipv6 drop
	}
}"#;
        assert!(
            !nft_ruleset_has_v6_drop(FOREIGN_TABLE_EXPLICIT_V6, "rustynet_g1"),
            "an explicit v6 drop in a FOREIGN table must not be credited"
        );
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

    /// IPV-03, the defect itself: a broad `accept` above the terminator.
    ///
    /// `policy drop` is the chain DEFAULT -- it fires only after every rule
    /// fails to match -- so this accept is evaluated first and global IPv6
    /// egresses freely. The old presence-only scan saw `policy drop`, returned
    /// true, and the whole verifier reported
    /// `killswitch_v6_drop_present=true, leaked=0, PASS`. Each of these
    /// rulesets must now be reported as NOT contained.
    #[test]
    fn nft_ruleset_accept_above_the_policy_drop_is_not_containment() {
        const BROAD_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        accept
    }
}"#;
        const PHYSICAL_IFACE_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        oifname "enp0s1" accept
    }
}"#;
        const EXPLICIT_V6_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        meta nfproto ipv6 accept
    }
}"#;
        const CT_STATE_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        ct state established,related accept
    }
}"#;
        // A jump whose target chain is not visible here could accept anything;
        // fail closed rather than assume the target drops.
        const JUMP_TO_UNSEEN_CHAIN: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        jump operator_overrides
    }
}"#;
        // The accept precedes an EXPLICIT v6 drop rather than a policy default.
        const ACCEPT_ABOVE_EXPLICIT_V6_DROP: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0;
        oifname "enp0s1" accept
        meta nfproto ipv6 drop
    }
}"#;

        for (label, ruleset) in [
            ("a bare accept", BROAD_ACCEPT),
            (
                "an accept on the physical egress interface",
                PHYSICAL_IFACE_ACCEPT,
            ),
            ("an explicit IPv6 accept", EXPLICIT_V6_ACCEPT),
            ("a conntrack-state accept", CT_STATE_ACCEPT),
            ("a jump to a chain not in the dump", JUMP_TO_UNSEEN_CHAIN),
            (
                "an accept above an explicit v6 drop",
                ACCEPT_ABOVE_EXPLICIT_V6_DROP,
            ),
        ] {
            assert!(
                !nft_ruleset_has_v6_drop(ruleset, "rustynet_g1"),
                "{label} precedes the terminator, so IPv6 is NOT contained"
            );
        }
    }

    /// The other direction, which matters just as much: a precedence check that
    /// fails closed on correct rulesets would be reverted within a week. None
    /// of these may be reported as a leak.
    #[test]
    fn nft_ruleset_precedence_check_does_not_false_fail_real_rulesets() {
        // The canonical shape: tunnel egress accepted, everything else dropped.
        const TUNNEL_PLUS_LOOPBACK: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        oifname "lo" accept
        oifname "rustynet0" accept
    }
}"#;
        // An IPv4-only accept cannot match IPv6, so it cannot leak it.
        const IPV4_ONLY_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        ip daddr 192.168.64.0/24 tcp dport 22 accept
    }
}"#;
        // Counters and comments reach no verdict; the packet falls through.
        const COUNTER_ONLY: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        counter packets 0 bytes 0
    }
}"#;
        // Link-local and multicast v6 never leave the link.
        const LINK_LOCAL_ACCEPT: &str = r#"table inet rustynet_g1 {
    chain killswitch {
        type filter hook output priority 0; policy drop;
        ip6 daddr fe80::/10 accept
        ip6 daddr ff00::/8 accept
    }
}"#;
        // The traversal-endpoint allows are narrow but not tunnel-scoped, so
        // they DO escape -- asserted in the negative test above via
        // ct/jump shapes. Here: a second chain drops what the first accepts.
        // A packet traverses every base chain at a hook and any drop is
        // terminal, so this ruleset genuinely contains IPv6.
        const SECOND_CHAIN_DROPS: &str = r#"table inet rustynet_g1 {
    chain permissive {
        type filter hook output priority 0;
        accept
    }
    chain killswitch {
        type filter hook output priority 10; policy drop;
        oifname "rustynet0" accept
    }
}"#;

        for (label, ruleset) in [
            ("tunnel plus loopback accepts", TUNNEL_PLUS_LOOPBACK),
            ("an IPv4-only accept", IPV4_ONLY_ACCEPT),
            ("a counter-only rule", COUNTER_ONLY),
            ("link-local and multicast accepts", LINK_LOCAL_ACCEPT),
            ("a sibling chain that drops", SECOND_CHAIN_DROPS),
        ] {
            assert!(
                nft_ruleset_has_v6_drop(ruleset, "rustynet_g1"),
                "{label} must still be credited as containment"
            );
        }
    }

    /// The fixture that pinned the blind spot deserves an explicit note, since
    /// its expected value did NOT change and that looks like an oversight.
    ///
    /// `INET_KILLSWITCH_WITH_TERMINAL_DROP` carries `oifname "rustynet0" accept`
    /// above its `policy drop`, which the review flagged as an accept-above-drop
    /// asserting `true`. The assertion is nonetheless correct: that accept is
    /// scoped to the TUNNEL, so traffic it matches leaves encrypted rather than
    /// leaking. What was wrong was the reasoning, not the expectation -- the old
    /// code would have returned `true` for a physical-interface accept too, and
    /// that case is now covered above.
    #[test]
    fn tunnel_scoped_accept_fixture_is_credited_for_the_right_reason() {
        assert!(nft_ruleset_has_v6_drop(
            INET_KILLSWITCH_WITH_TERMINAL_DROP,
            "rustynet_g1"
        ));
        // Same ruleset, tunnel swapped for the physical NIC: must now fail.
        let leaky = INET_KILLSWITCH_WITH_TERMINAL_DROP.replace("rustynet0", "enp0s1");
        assert!(
            !nft_ruleset_has_v6_drop(&leaky, "rustynet_g1"),
            "the fixture passes because of the tunnel scope, not because a drop is present"
        );
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
