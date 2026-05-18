#![allow(clippy::result_large_err)]

//! L8 — Linux boot-time killswitch verifier.
//!
//! At boot the daemon programs an `inet` family table holding the
//! `killswitch` and `forward` chains via `phase10::LiveSystem`. The
//! L8 audit shape is: between cold-boot and the first daemon start,
//! and again across any unit restart, there is a window where the
//! killswitch table is absent and the host can leak traffic to the
//! underlay. The mitigation tracked by this slice is a dedicated
//! verifier the systemd unit can invoke as `ExecStartPre` (and that
//! a future boot-time service can invoke before `network-online.target`)
//! to refuse to bring the WireGuard interface up unless the
//! killswitch is already in place.
//!
//! This module owns the pure evaluator + the typed report shape. The
//! collector parses `nft list ruleset` output and the
//! `/sys/class/net/<iface>` directory presence; both surfaces are
//! deterministic on Linux and trivially mockable in tests.
//!
//! Wired through the CLI as `rustynetd linux-killswitch-boot-check`.
//! Off-Linux the collector emits a clear blocker; the check is only
//! meaningful on a Linux runtime host.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Reviewed Linux killswitch table name. Pinned to the same value the
/// Phase 10 programming uses so the verifier reads the right table.
pub const REVIEWED_KILLSWITCH_TABLE: &str = "rustynet";

/// Reviewed Linux killswitch family (nftables `inet` family covers
/// both IPv4 and IPv6 in one programmed chain set).
pub const REVIEWED_KILLSWITCH_FAMILY: &str = "inet";

/// Required chains inside the reviewed killswitch table. A missing
/// chain is a hard fail-closed reason.
pub const REVIEWED_REQUIRED_CHAINS: &[&str] = &["killswitch", "forward"];

/// Required rule shapes inside the `killswitch` chain. Each shape is
/// the substring fragment the live ruleset must contain on a single
/// line; the verifier does a substring match, not a full nftables
/// parse, so the matcher is robust against cosmetic whitespace
/// drift.
pub const REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS: &[&str] = &[
    // Allow loopback so the daemon's local IPC and resolver still
    // work even when the killswitch is otherwise closed.
    "oifname \"lo\" accept",
    // Established/related must always pass — without it, return
    // traffic for handshakes is dropped and the killswitch becomes
    // a black hole even for legitimate traffic.
    "ct state established,related accept",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKillswitchBootSnapshot {
    /// Absolute path of the nft ruleset capture used. Mostly for
    /// forensic forwarding into the report; the evaluator does not
    /// branch on the path.
    pub ruleset_source: String,
    /// True iff the verifier was able to actually inspect host state
    /// (Linux runtime host, nft binary present, `/sys/class/net`
    /// readable). False off-Linux or when the inspection couldn't
    /// run. The evaluator surfaces a clear blocker when this is
    /// false so the off-platform case doesn't claim overall_ok.
    #[serde(default = "default_host_observable_true")]
    pub host_observable: bool,
    /// True iff the reviewed family + table pair appears in the
    /// captured ruleset.
    pub table_present: bool,
    /// Chains the verifier found inside the reviewed table, in source
    /// order. Empty when `table_present` is false.
    pub chains_present: Vec<String>,
    /// Substring rule fragments the verifier found inside the
    /// `killswitch` chain. Empty when the chain is missing.
    pub killswitch_rule_fragments_present: Vec<String>,
    /// True iff the daemon's tunnel interface (e.g. `rustynet0`) is
    /// currently visible under `/sys/class/net/<iface>`. The L8
    /// invariant fails closed if the interface is up but the
    /// killswitch table is absent — that is the leak window.
    pub tunnel_interface_present: bool,
    /// The reviewed interface name the snapshot was captured against,
    /// passed through to the report for forensic context.
    pub tunnel_interface_name: String,
}

/// Default value for the host_observable field on old JSON that
/// predates the field — assume true so existing snapshots keep their
/// previous meaning. The off-Linux collector explicitly sets false.
fn default_host_observable_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKillswitchBootReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub snapshot: LinuxKillswitchBootSnapshot,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator. Walks the snapshot and aggregates every drift
/// reason in a single pass. Returns `Vec` (not `Result`) so the
/// caller decides how to handle the aggregate.
pub fn evaluate_linux_killswitch_boot_snapshot(
    snapshot: &LinuxKillswitchBootSnapshot,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();

    if !snapshot.host_observable {
        reasons.push(format!(
            "host state could not be observed via {}: \
             linux-killswitch-boot-check requires a Linux runtime host with \
             `nft` available and `/sys/class/net` readable",
            snapshot.ruleset_source
        ));
        return reasons;
    }

    // The boot-time invariant: if the tunnel interface is up, the
    // killswitch table MUST be in place. The reverse case (table
    // present, interface absent) is fine — that's the cold-boot
    // pre-up window the gate is designed to allow.
    if snapshot.tunnel_interface_present && !snapshot.table_present {
        let iface = &snapshot.tunnel_interface_name;
        reasons.push(format!(
            "tunnel interface {iface} is present in /sys/class/net but reviewed killswitch \
             table {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE} is missing — host \
             has a live tunnel without a programmed killswitch, traffic can leak to the \
             underlay"
        ));
    }

    if !snapshot.table_present {
        // No further per-chain checks are meaningful; the leak-window
        // reason above already captured the failing case.
        return reasons;
    }

    for required in REVIEWED_REQUIRED_CHAINS {
        if !snapshot.chains_present.iter().any(|c| c == required) {
            reasons.push(format!(
                "reviewed chain `{required}` missing from \
                 {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE}"
            ));
        }
    }

    if snapshot.chains_present.iter().any(|c| c == "killswitch") {
        for required in REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS {
            if !snapshot
                .killswitch_rule_fragments_present
                .iter()
                .any(|f| f == required)
            {
                reasons.push(format!(
                    "reviewed killswitch rule fragment {required:?} missing from \
                     {REVIEWED_KILLSWITCH_FAMILY}/{REVIEWED_KILLSWITCH_TABLE} killswitch chain"
                ));
            }
        }
    }

    reasons
}

pub fn build_linux_killswitch_boot_report(
    snapshot: LinuxKillswitchBootSnapshot,
) -> LinuxKillswitchBootReport {
    let drift_reasons = evaluate_linux_killswitch_boot_snapshot(&snapshot);
    let overall_ok = drift_reasons.is_empty();
    LinuxKillswitchBootReport {
        schema_version: 1,
        overall_ok,
        snapshot,
        drift_reasons,
    }
}

/// Parse `nft list ruleset` text and extract the chains found under
/// the reviewed `inet rustynet` table. Returns the table-present
/// flag, the chain names in source order, and any matched rule
/// fragments from the `killswitch` chain. Exposed (crate-visible) so
/// tests can pin the parser without shelling out to `nft`.
#[allow(dead_code)]
pub(crate) fn parse_nft_ruleset_for_killswitch(body: &str) -> (bool, Vec<String>, Vec<String>) {
    let table_header = format!("table {REVIEWED_KILLSWITCH_FAMILY} {REVIEWED_KILLSWITCH_TABLE} {{");
    let mut in_table = false;
    let mut in_killswitch_chain = false;
    let mut brace_depth: i32 = 0;
    let mut chains: Vec<String> = Vec::new();
    let mut matched_fragments: Vec<String> = Vec::new();
    let mut table_present = false;

    for raw_line in body.lines() {
        let line = raw_line.trim_end();
        let trimmed = line.trim_start();
        // Find the reviewed table header.
        if !in_table {
            if trimmed.starts_with(&table_header) {
                in_table = true;
                table_present = true;
                brace_depth = 1;
            }
            continue;
        }
        // Track brace depth so we know when we leave the table.
        for ch in trimmed.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth -= 1,
                _ => {}
            }
        }
        // Look for `chain <name> {` declarations at depth 2 (one
        // inside the table, one inside the chain itself).
        if let Some(rest) = trimmed.strip_prefix("chain ") {
            // Extract the chain name (token up to space or `{`).
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .collect();
            if !name.is_empty() && !chains.contains(&name) {
                chains.push(name.clone());
            }
            in_killswitch_chain = name == "killswitch";
            continue;
        }
        // Inside the killswitch chain, look for any reviewed fragment.
        if in_killswitch_chain {
            for frag in REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS {
                if line.contains(frag) && !matched_fragments.iter().any(|m| m == frag) {
                    matched_fragments.push((*frag).to_string());
                }
            }
        }
        // When we exit the table block, stop scanning.
        if brace_depth <= 0 {
            break;
        }
    }
    (table_present, chains, matched_fragments)
}

/// Cross-platform collector. On Linux runs `nft list ruleset` via
/// argv-exec (no shell), reads `/sys/class/net/<iface>`, and builds
/// the snapshot. Off-Linux every observable field is reported as
/// "could not observe; requires a Linux runtime host" via a
/// `table_present=false` + matching drift reason in the evaluator.
///
/// `iface_name` is the WireGuard tunnel interface the daemon will
/// bring up. If unknown to the caller, pass the reviewed default.
pub fn collect_linux_killswitch_boot_report(iface_name: &str) -> LinuxKillswitchBootReport {
    collect_linux_killswitch_boot_report_inner(iface_name)
}

#[cfg(target_os = "linux")]
fn collect_linux_killswitch_boot_report_inner(iface_name: &str) -> LinuxKillswitchBootReport {
    let tunnel_path = PathBuf::from(format!("/sys/class/net/{iface_name}"));
    let tunnel_interface_present = tunnel_path.exists();

    let ruleset_source = "nft list ruleset".to_string();
    let output = std::process::Command::new("nft")
        .arg("list")
        .arg("ruleset")
        .output();
    let body: String = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).to_string(),
        _ => String::new(),
    };

    let (table_present, chains_present, killswitch_rule_fragments_present) =
        parse_nft_ruleset_for_killswitch(body.as_str());

    let snapshot = LinuxKillswitchBootSnapshot {
        ruleset_source,
        host_observable: true,
        table_present,
        chains_present,
        killswitch_rule_fragments_present,
        tunnel_interface_present,
        tunnel_interface_name: iface_name.to_string(),
    };
    build_linux_killswitch_boot_report(snapshot)
}

#[cfg(not(target_os = "linux"))]
fn collect_linux_killswitch_boot_report_inner(iface_name: &str) -> LinuxKillswitchBootReport {
    // Off-Linux: surface a clear blocker; the check is only
    // meaningful on a Linux runtime host. The evaluator sees
    // `host_observable=false` and emits the unobservable-host drift
    // reason — overall_ok stays false without us having to claim
    // anything about the killswitch state itself.
    let snapshot = LinuxKillswitchBootSnapshot {
        ruleset_source: "off-Linux host: nft not invoked".to_string(),
        host_observable: false,
        table_present: false,
        chains_present: Vec::new(),
        killswitch_rule_fragments_present: Vec::new(),
        tunnel_interface_present: false,
        tunnel_interface_name: iface_name.to_string(),
    };
    build_linux_killswitch_boot_report(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_snapshot() -> LinuxKillswitchBootSnapshot {
        LinuxKillswitchBootSnapshot {
            ruleset_source: "test fixture".to_string(),
            host_observable: true,
            table_present: true,
            chains_present: vec!["killswitch".to_string(), "forward".to_string()],
            killswitch_rule_fragments_present: REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_string(),
        }
    }

    // ---- evaluator coverage -----------------------------------------------

    #[test]
    fn evaluator_rejects_unobservable_host() {
        let mut snap = ok_snapshot();
        snap.host_observable = false;
        snap.ruleset_source = "off-Linux host: nft not invoked".to_string();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("host state could not be observed")),
            "unobservable-host reason must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_clean_snapshot() {
        let reasons = evaluate_linux_killswitch_boot_snapshot(&ok_snapshot());
        assert!(reasons.is_empty(), "clean snapshot must pass: {reasons:?}");
    }

    #[test]
    fn evaluator_accepts_pre_boot_window_with_no_interface_and_no_table() {
        // Cold boot: iface not up yet, killswitch not programmed yet.
        // This is the legitimate window the gate must allow.
        let mut snap = ok_snapshot();
        snap.tunnel_interface_present = false;
        snap.table_present = false;
        snap.chains_present.clear();
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons.is_empty(),
            "cold-boot pre-up window must pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_interface_up_but_killswitch_table_missing() {
        // The L8 leak shape: tunnel is up but the killswitch table is
        // gone. Could happen mid-restart if the daemon flushed the
        // table before shutdown and crashed before re-programming.
        let mut snap = ok_snapshot();
        snap.table_present = false;
        snap.chains_present.clear();
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("tunnel interface rustynet0 is present")
                    && r.contains("killswitch table")
                    && r.contains("missing")),
            "leak-window must be named: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_killswitch_chain() {
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["forward".to_string()];
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("reviewed chain `killswitch` missing")),
            "missing killswitch chain must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_forward_chain() {
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["killswitch".to_string()];
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("reviewed chain `forward` missing")),
            "missing forward chain must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_loopback_accept_rule_fragment() {
        let mut snap = ok_snapshot();
        snap.killswitch_rule_fragments_present
            .retain(|f| !f.contains("oifname \"lo\""));
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("oifname \\\"lo\\\" accept") && r.contains("missing")),
            "missing loopback fragment must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_missing_established_related_fragment() {
        let mut snap = ok_snapshot();
        snap.killswitch_rule_fragments_present
            .retain(|f| !f.contains("established,related"));
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("ct state established,related") && r.contains("missing")),
            "missing est/rel fragment must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_does_not_check_rule_fragments_when_killswitch_chain_missing() {
        // If the killswitch chain isn't there, reporting "rule
        // fragments missing" would be noise — the chain-missing
        // reason already covers it.
        let mut snap = ok_snapshot();
        snap.chains_present = vec!["forward".to_string()];
        snap.killswitch_rule_fragments_present.clear();
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        // Exactly one drift reason: the chain-missing one. No noisy
        // per-fragment messages.
        let chain_missing = reasons
            .iter()
            .filter(|r| r.contains("reviewed chain `killswitch` missing"))
            .count();
        let fragment_missing = reasons
            .iter()
            .filter(|r| r.contains("rule fragment"))
            .count();
        assert_eq!(chain_missing, 1, "chain-missing must surface once");
        assert_eq!(
            fragment_missing, 0,
            "fragment-missing must stay quiet when chain absent: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_all_drift_reasons_in_one_pass() {
        // Construct the worst-case shape: table present but BOTH
        // chains missing, AND interface up but table missing flag NOT
        // set (because table_present=true means no leak-window
        // message). The evaluator must surface both chain-missing
        // reasons.
        let snap = LinuxKillswitchBootSnapshot {
            ruleset_source: "agg test".to_string(),
            host_observable: true,
            table_present: true,
            chains_present: Vec::new(),
            killswitch_rule_fragments_present: Vec::new(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_string(),
        };
        let reasons = evaluate_linux_killswitch_boot_snapshot(&snap);
        let chain_count = reasons
            .iter()
            .filter(|r| r.contains("reviewed chain"))
            .count();
        assert_eq!(
            chain_count, 2,
            "both required chains must surface: {reasons:?}"
        );
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_snapshot() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxKillswitchBootReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = build_linux_killswitch_boot_report(ok_snapshot());
        assert_eq!(
            report.schema_version, 1,
            "schema_version bump must be deliberate"
        );
    }

    // ---- nft ruleset parser coverage --------------------------------------

    #[test]
    fn parser_finds_table_and_both_chains_in_clean_ruleset() {
        let body = r#"
table inet rustynet {
        chain killswitch {
                type filter hook output priority 0; policy drop;
                oifname "lo" accept
                ct state established,related accept
                oifname "rustynet0" accept
        }
        chain forward {
                type filter hook forward priority 0; policy drop;
                ct state established,related accept
                iifname "rustynet0" oifname "eth0" accept
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present, "table must be detected");
        assert!(
            chains.iter().any(|c| c == "killswitch"),
            "killswitch chain must be detected: {chains:?}"
        );
        assert!(
            chains.iter().any(|c| c == "forward"),
            "forward chain must be detected: {chains:?}"
        );
        assert!(
            frags.iter().any(|f| f.contains("oifname \"lo\"")),
            "loopback fragment must match: {frags:?}"
        );
        assert!(
            frags
                .iter()
                .any(|f| f.contains("ct state established,related accept")),
            "est/rel fragment must match: {frags:?}"
        );
    }

    #[test]
    fn parser_returns_table_absent_when_no_rustynet_table_present() {
        let body = r#"
table inet filter {
        chain input {
                type filter hook input priority 0; policy accept;
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(!present);
        assert!(chains.is_empty());
        assert!(frags.is_empty());
    }

    #[test]
    fn parser_does_not_pick_up_fragments_from_unrelated_chains() {
        // The `forward` chain also has "ct state established,related
        // accept" but the parser must only count fragments inside
        // the killswitch chain. Confirm cross-chain isolation.
        let body = r#"
table inet rustynet {
        chain killswitch {
                type filter hook output priority 0; policy drop;
        }
        chain forward {
                ct state established,related accept
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present);
        assert!(chains.iter().any(|c| c == "killswitch"));
        // Neither reviewed fragment was inside the killswitch chain,
        // so frags must stay empty even though `forward` has one.
        assert!(
            frags.is_empty(),
            "forward-chain fragments must not leak into killswitch frag list: {frags:?}"
        );
    }

    #[test]
    fn parser_handles_multiple_unrelated_tables_before_rustynet() {
        let body = r#"
table inet filter { chain input {} }
table ip nat { chain postrouting {} }
table inet rustynet {
        chain killswitch {
                oifname "lo" accept
                ct state established,related accept
        }
        chain forward {}
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(present);
        assert_eq!(chains.len(), 2);
        assert_eq!(frags.len(), 2);
    }

    #[test]
    fn parser_returns_absent_on_empty_input() {
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch("");
        assert!(!present);
        assert!(chains.is_empty());
        assert!(frags.is_empty());
    }

    #[test]
    fn reviewed_required_chains_pinned_at_two() {
        // Snapshot: the reviewed required-chain list must stay at
        // exactly ["killswitch", "forward"]. Silent extension or
        // removal must trip a named test.
        assert_eq!(REVIEWED_REQUIRED_CHAINS, &["killswitch", "forward"]);
    }

    #[test]
    fn reviewed_required_fragments_pinned_at_two() {
        assert_eq!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.len(), 2);
        assert!(REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS.contains(&"oifname \"lo\" accept"));
        assert!(
            REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS
                .contains(&"ct state established,related accept")
        );
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collector_off_linux_marks_table_absent_with_clear_blocker() {
        let report = collect_linux_killswitch_boot_report("rustynet0");
        assert!(!report.snapshot.table_present);
        assert!(!report.snapshot.tunnel_interface_present);
        assert!(report.snapshot.ruleset_source.contains("off-Linux"));
        // overall_ok must be false because the reviewed chains are
        // missing even though no leak-window reason fires.
        assert!(!report.overall_ok);
    }
}
