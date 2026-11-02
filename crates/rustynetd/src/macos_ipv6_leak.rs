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
    /// Whether the active probe + capture actually executed (tcpdump spawned
    /// AND ping6 ran). A never-run probe MUST NOT read as a clean fail-closed
    /// result; the validator requires this true so the active probe is
    /// load-bearing alongside the static pf-containment posture.
    #[serde(default)]
    pub probe_attempted: bool,
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
    let (pcap_text, probe_reached, probe_attempted) = run_ipv6_egress_probe_with_capture(
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
        probe_attempted,
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
    probe_attempted: bool,
) -> MacosIpv6LeakSnapshot {
    MacosIpv6LeakSnapshot {
        schema_version: MACOS_IPV6_LEAK_SCHEMA_VERSION,
        captured_at_unix,
        egress_iface: egress_iface.to_owned(),
        probe_target: probe_target.to_owned(),
        pf_anchor: pf_anchor.to_owned(),
        killswitch_v6_block_present: pf_rules_have_v6_block(pf_rules_stdout, egress_iface),
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

/// How one parsed pf rule line relates to an outbound IPv6 packet leaving the
/// physical egress interface (IPV-13).
struct PfRuleView {
    is_pass: bool,
    is_block_drop: bool,
    quick: bool,
    /// False for an `in`-only rule: it can never see an outbound packet.
    can_match_outbound: bool,
    /// False for an `inet`-only rule: it can never see an IPv6 packet.
    can_match_v6: bool,
    /// The rule may match a packet leaving `egress_iface` (unscoped, or the
    /// interface list names it, or a `!iface` negation that excludes others).
    covers_egress_iface: bool,
    /// Matches every outbound IPv6 packet on the interfaces it covers: no
    /// proto, port, address, user, route-to or similar narrowing. Only such a
    /// rule is containment (its interface scope is judged by
    /// `covers_egress_iface`).
    matches_all_v6: bool,
}

fn parse_pf_rule(line: &str, egress_iface: &str) -> Option<PfRuleView> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let first = *tokens.first()?;
    let is_pass = first == "pass";
    let is_block = first == "block";
    if !is_pass && !is_block {
        return None;
    }
    let has = |word: &str| tokens.contains(&word);
    let mut iface_names: Vec<String> = Vec::new();
    // Tokens that belong to an `on <iface>` clause, so the "matches every
    // packet" scan below does not mistake the interface list for a qualifier.
    let mut in_on_clause = vec![false; tokens.len()];
    let mut on_seen = false;
    let mut negated = false;
    // `on` with no interface name, or a trailing bare `!`: not a rule we can
    // reason about, so it can never count as containment.
    let mut on_malformed = false;
    let mut idx = 0;
    while let Some(token) = tokens.get(idx) {
        let on_index = idx;
        idx += 1;
        if *token != "on" {
            continue;
        }
        on_seen = true;
        if let Some(mark) = in_on_clause.get_mut(on_index) {
            *mark = true;
        }
        // `on en0`, `on !en0`, `on ! en0`, `on { en0 rustynet0 }`,
        // `on {en0,rustynet0}`, `on { ! en0 }`
        let list = tokens.get(idx).is_some_and(|t| t.starts_with('{'));
        // A bare `!` (pfctl's spaced spelling) negates the NEXT name.
        let mut pending_negate = false;
        let names_before = iface_names.len();
        while let Some(raw) = tokens.get(idx) {
            if let Some(mark) = in_on_clause.get_mut(idx) {
                *mark = true;
            }
            idx += 1;
            for piece in raw.split(['{', '}', ',']) {
                if piece.is_empty() {
                    continue;
                }
                if piece == "!" {
                    negated = true;
                    pending_negate = true;
                    continue;
                }
                if piece.starts_with('!') {
                    negated = true;
                }
                pending_negate = false;
                iface_names.push(piece.trim_start_matches('!').to_owned());
            }
            if pending_negate {
                // The name is the next token, whatever it looks like.
                continue;
            }
            if !list || raw.ends_with('}') {
                break;
            }
        }
        if pending_negate || iface_names.len() == names_before {
            on_malformed = true;
        }
    }
    let names_egress = iface_names.iter().any(|name| name == egress_iface);
    let covers_egress_iface = !on_seen || (names_egress != negated);
    // Allow-list for "matches every packet on the interfaces it is scoped to":
    // any token outside it (proto, port, from <addr>, to <addr>, user, flags,
    // route-to, tagged, an unknown keyword, ...) means the rule is narrower
    // than a blanket drop. Harmless trailers are accepted only in their exact
    // form: `label "<text>"` (a counter tag) and `<no|keep|modulate|synproxy>
    // state` (pf state handling, irrelevant to a drop).
    let mut universal = !on_malformed;
    let mut position = 0;
    while let Some(token) = tokens.get(position) {
        let here = position;
        position += 1;
        if in_on_clause.get(here).copied().unwrap_or(false) {
            continue;
        }
        match *token {
            "block" | "drop" | "out" | "quick" | "all" | "inet6" | "log" | "(all)" | "any" => {}
            "from" | "to" => {
                // Only `from any` / `to any` is a no-op narrowing.
                if tokens.get(position) != Some(&"any") {
                    universal = false;
                }
            }
            "label" => {
                // Consume the quoted string (it may contain spaces).
                let Some(first) = tokens.get(position) else {
                    universal = false;
                    continue;
                };
                if !first.starts_with('"') {
                    universal = false;
                    continue;
                }
                let mut closed = first.len() > 1 && first.ends_with('"');
                position += 1;
                while !closed {
                    let Some(next) = tokens.get(position) else {
                        universal = false;
                        break;
                    };
                    position += 1;
                    closed = next.ends_with('"');
                }
            }
            "no" | "keep" | "modulate" | "synproxy" => {
                if tokens.get(position) == Some(&"state") {
                    position += 1;
                } else {
                    universal = false;
                }
            }
            _ => universal = false,
        }
    }
    Some(PfRuleView {
        is_pass,
        is_block_drop: is_block && has("drop"),
        quick: has("quick"),
        can_match_outbound: !has("in"),
        can_match_v6: !has("inet"),
        covers_egress_iface,
        matches_all_v6: universal,
    })
}

/// True iff, by pf's own first-match / last-match evaluation, an outbound IPv6
/// packet leaving `egress_iface` is DROPPED by this ruleset (IPV-13).
///
/// A blanket `block drop` counts only when it is outbound (not `in`-only),
/// unqualified by proto/port/address, and either unscoped or scoped to an
/// interface set that covers `egress_iface` (`on en0`, `on !rustynet0`; a block
/// on another interface, or a negation that excludes `egress_iface`, does not
/// count), and only
/// when no `pass` rule that can match that packet gets the final word: a
/// `quick` pass ahead of the block ends evaluation as a pass, and a non-quick
/// pass after the block overrides it (last match wins). Passes that cannot see
/// the packet (`in`-only, `inet`-only, or scoped to another interface such as
/// the tunnel or `lo0`) are ignored. An `inet`-only block is NOT v6
/// containment: that is the leak bug. Anchor references are not expanded; the
/// caller must feed the anchor's own rules.
fn pf_rules_have_v6_block(stdout: &str, egress_iface: &str) -> bool {
    let mut verdict_is_block = false;
    for raw in stdout.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rule) = parse_pf_rule(line, egress_iface) else {
            continue;
        };
        if !rule.can_match_outbound || !rule.can_match_v6 {
            continue;
        }
        if rule.is_pass && rule.covers_egress_iface {
            // Conservative: even a partial pass (a port, a destination) lets
            // some IPv6 egress through, so it decides the verdict.
            verdict_is_block = false;
            if rule.quick {
                return false;
            }
        } else if rule.is_block_drop && rule.matches_all_v6 && rule.covers_egress_iface {
            verdict_is_block = true;
            if rule.quick {
                return true;
            }
        }
    }
    verdict_is_block
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
fn run_ipv6_egress_probe_with_capture(egress_iface: &str, target: &str) -> (String, bool, bool) {
    use std::thread::sleep;
    use std::time::Duration;

    if egress_iface.is_empty() {
        return (String::new(), false, false);
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
        Err(_) => return (String::new(), false, false),
    };
    sleep(Duration::from_millis(800));
    let ping_status = Command::new("/sbin/ping6")
        .args(["-c", "2", "-W", "2", target])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    let probe_attempted = ping_status.is_ok();
    let reached = ping_status.map(|status| status.success()).unwrap_or(false);
    sleep(Duration::from_millis(IPV6_EGRESS_CAPTURE_SECS * 1000 - 800));
    // IPV-05 (mirrors linux_ipv6_leak): a capture that never ran must not read
    // as "zero leaked packets".
    let exited_early = !matches!(child.try_wait(), Ok(None));
    let _ = child.kill();
    let _ = child.wait();
    let pcap_present = pcap_path.exists();
    let read_back = Command::new("/usr/sbin/tcpdump")
        .args(["-n", "-r", pcap_str.as_str()])
        .output()
        .ok()
        .map(|out| {
            (
                out.status.success(),
                String::from_utf8_lossy(&out.stdout).into_owned(),
            )
        });
    let _ = std::fs::remove_file(&pcap_path);
    match crate::linux_ipv6_leak::trusted_capture_text(exited_early, pcap_present, read_back) {
        Some(pcap_text) => (pcap_text, reached, probe_attempted),
        // `attempted = false` makes the validator fail the run as inconclusive.
        None => (String::new(), reached, false),
    }
}

#[cfg(not(target_os = "macos"))]
fn run_ipv6_egress_probe_with_capture(_egress_iface: &str, _target: &str) -> (String, bool, bool) {
    (String::new(), false, false)
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
        assert!(pf_rules_have_v6_block(PF_TERMINAL_BLOCK_ALL, "en0"));
    }

    #[test]
    fn pf_explicit_inet6_block_counts() {
        assert!(pf_rules_have_v6_block(PF_EXPLICIT_INET6_BLOCK, "en0"));
    }

    #[test]
    fn pf_inet_only_block_is_not_v6_containment() {
        // The IPv4-only pf block is the exact leak bug: looks like a
        // killswitch, does nothing for IPv6.
        assert!(!pf_rules_have_v6_block(PF_INET_ONLY_BLOCK, "en0"));
    }

    #[test]
    fn pf_empty_is_not_v6_containment() {
        assert!(!pf_rules_have_v6_block("", "en0"));
        assert!(!pf_rules_have_v6_block(
            "# comment\npass out quick on rustynet0 all\n",
            "en0"
        ));
    }

    // IPV-13: `pf_rules_have_v6_block` used to accept any line holding `block`,
    // `drop` and ` all`, regardless of direction, interface scope, proto/port
    // narrowing, or a pass rule that wins first. Each case below was a false
    // "containment present". Mutation caught: reverting to the substring match
    // turns every `!pf_rules_have_v6_block` assertion here red.
    fn contained(rules: &str) -> bool {
        pf_rules_have_v6_block(rules, "en0")
    }

    #[test]
    fn inbound_only_block_is_not_outbound_v6_containment() {
        assert!(!contained("block drop in quick all"));
        assert!(!contained("block drop in quick inet6 all"));
    }

    #[test]
    fn block_scoped_to_another_interface_is_not_containment() {
        assert!(!contained("block drop out quick on utun9 all"));
        assert!(!contained("block drop out quick on lo0 inet6 all"));
        assert!(!contained(
            "block drop out quick on { utun9 lo0 } inet6 all"
        ));
        // Negation that EXCLUDES the egress interface does not cover it.
        assert!(!contained("block drop out quick on !en0 inet6 all"));
        assert!(!contained("block drop out quick on ! en0 inet6 all"));
        // Malformed `on` clauses never count.
        assert!(!contained("block drop out quick on inet6 all"));
        assert!(!contained("block drop out quick inet6 all on !"));
    }

    #[test]
    fn block_scoped_to_the_egress_interface_is_containment() {
        assert!(contained("block drop out quick on en0 inet6 all"));
        assert!(contained("block drop out quick on en0 all"));
        assert!(contained("block drop out on en0 inet6 from any to any"));
        assert!(contained("block drop out quick on { en0 en1 } inet6 all"));
        // Negation that does cover the egress interface.
        assert!(contained("block drop out quick on !rustynet0 inet6 all"));
        assert!(contained("block drop out quick on ! rustynet0 inet6 all"));
        // The egress-scoped block is still subject to pass shadowing.
        assert!(!contained(
            "pass out quick on en0 inet6 all\nblock drop out quick on en0 inet6 all"
        ));
        // ...and to qualifiers.
        assert!(!contained(
            "block drop out quick on en0 inet6 proto tcp all"
        ));
        assert!(!contained("block drop in quick on en0 inet6 all"));
    }

    #[test]
    fn spaced_and_unspaced_negation_parse_the_same() {
        // `pass out quick on !en0` / `on ! en0` do NOT cover en0, so they do
        // not shadow the block; `!rustynet0` / `! rustynet0` DO cover it.
        for spelling in ["!en0", "! en0"] {
            let rules = format!("pass out quick on {spelling} inet6 all\nblock drop out quick all");
            assert!(contained(&rules), "{rules}");
        }
        for spelling in ["!rustynet0", "! rustynet0", "{ ! rustynet0 }"] {
            let rules = format!("pass out quick on {spelling} inet6 all\nblock drop out quick all");
            assert!(!contained(&rules), "{rules}");
        }
    }

    #[test]
    fn harmless_block_trailers_are_accepted_only_in_exact_form() {
        assert!(contained("block drop out quick all label \"rn-v6\""));
        assert!(contained(
            "block drop out quick inet6 all label \"rn v6 block\" no state"
        ));
        assert!(contained("block drop out quick all keep state"));
        assert!(contained(
            "block drop out quick on en0 inet6 all label \"x\""
        ));
        // Unrecognised qualifiers keep the block from counting.
        assert!(!contained("block drop out quick all tagged FOO"));
        assert!(!contained("block drop out quick all user root"));
        assert!(!contained("block drop out quick all received-on en0"));
        assert!(!contained("block drop out quick all flags S/SA"));
        assert!(!contained("block drop out quick all route-to en1"));
        // A dangling or unterminated label / state keyword is not a no-op.
        assert!(!contained("block drop out quick all label"));
        assert!(!contained("block drop out quick all label rn-v6"));
        assert!(!contained("block drop out quick all label \"unterminated"));
        assert!(!contained("block drop out quick all no"));
        assert!(!contained("block drop out quick all keep"));
    }

    #[test]
    fn narrowed_block_is_not_containment() {
        assert!(!contained(
            "block drop out quick inet6 proto tcp from any to any port = 25"
        ));
        assert!(!contained(
            "block drop out quick inet6 from any to 2001:db8::/32"
        ));
        assert!(!contained(
            "block drop out quick inet6 from fd00::/8 to any"
        ));
        assert!(!contained("block drop out quick proto udp all"));
    }

    #[test]
    fn blanket_block_forms_are_containment() {
        assert!(contained("block drop out quick all"));
        assert!(contained("block drop out all"));
        assert!(contained("block drop out quick inet6 all"));
        assert!(contained("block drop out quick inet6 from any to any"));
        assert!(contained("block drop quick all"));
        assert!(contained("block drop out log quick all"));
    }

    #[test]
    fn quick_pass_ahead_of_the_block_shadows_it() {
        assert!(!contained("pass out quick all\nblock drop out quick all"));
        assert!(!contained(
            "pass out quick on en0 inet6 all\nblock drop out quick all"
        ));
        // Even a partial pass on the egress interface lets some IPv6 out first.
        assert!(!contained(
            "pass out quick on en0 inet6 proto udp to any port 53\nblock drop out quick all"
        ));
        assert!(!contained(
            "pass out quick on { en0 en1 } inet6 all\nblock drop out quick all"
        ));
        assert!(!contained(
            "pass out quick on !rustynet0 inet6 all\nblock drop out quick all"
        ));
    }

    #[test]
    fn non_quick_pass_after_the_block_overrides_it() {
        assert!(!contained("block drop out all\npass out on en0 inet6 all"));
        assert!(!contained("block drop out all\npass out all"));
    }

    #[test]
    fn passes_that_cannot_see_the_packet_do_not_shadow_the_block() {
        // Tunnel and loopback passes, IPv4-only egress passes, and inbound
        // passes are what the reviewed anchors really contain.
        let rules = "pass out quick on rustynet0 inet6 all flags S/SA keep state\n\
                     pass quick on lo0 all\n\
                     pass out quick on en0 inet proto udp to any port 51820 keep state\n\
                     pass in quick on en0 inet6 all keep state\n\
                     pass out quick on !en0 inet6 all keep state\n\
                     block drop out quick all";
        assert!(contained(rules));
    }

    #[test]
    fn reviewed_blind_exit_and_exit_anchors_as_pfctl_renders_them_still_contain() {
        // The pfctl-rendered shapes the reviewed blind_exit evaluator tests
        // feed back in (macos_blind_exit.rs): they must keep reading as v6
        // containment under the stricter evaluation.
        let blind_exit_dns = "set block-policy drop\n\
            pass out quick on rustynet0 inet all flags S/SA keep state\n\
            pass out quick on rustynet0 inet6 all flags S/SA keep state\n\
            pass in quick on rustynet0 inet from 100.64.0.0/10 to any flags S/SA keep state\n\
            pass out quick on en0 inet from 100.64.0.0/10 to any flags S/SA keep state\n\
            pass out quick on rustynet0 inet proto udp from any to any port = 53 keep state\n\
            block drop out quick inet proto udp from any to any port = 53 label \"rustynet-dns-block-lan-udp\"\n\
            block drop out quick all\n";
        assert!(contained(blind_exit_dns));
        let blind_exit_v6_blocked = "pass out quick on rustynet0 inet all keep state\n\
            block drop out quick inet6 all\n\
            block drop out quick all\n";
        assert!(contained(blind_exit_v6_blocked));
    }

    #[test]
    fn partial_block_does_not_end_up_as_containment_through_a_later_pass_gap() {
        // A universal block exists but a narrower quick block cannot stand in
        // for it, and a universal block followed by nothing is containment.
        assert!(!contained("block drop out quick inet6 proto tcp all"));
        assert!(contained(
            "block drop out quick inet6 proto tcp all\nblock drop out quick all"
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
            true,
        );
        assert!(snap.killswitch_v6_block_present);
        assert_eq!(snap.leaked_datagram_count, 0);
        assert!(!snap.probe_reached_target);
        assert!(snap.probe_attempted);
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
            true,
        );
        assert!(!snap.killswitch_v6_block_present);
        assert_eq!(snap.leaked_datagram_count, 1);
        assert!(snap.probe_reached_target);
        assert!(snap.probe_attempted);
    }

    #[test]
    fn default_options_use_reviewed_defaults() {
        let opts = MacosIpv6LeakOptions::default();
        assert_eq!(opts.pf_anchor, DEFAULT_MACOS_KILLSWITCH_ANCHOR);
        assert_eq!(opts.probe_target, DEFAULT_IPV6_PROBE_TARGET);
        assert_eq!(opts.egress_iface, "");
    }
}
