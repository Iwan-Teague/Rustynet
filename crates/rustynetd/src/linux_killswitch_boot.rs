#![allow(clippy::result_large_err)]

//! L8 — Linux boot-time killswitch verifier **and pre-protective installer**.
//!
//! ## Verifier (original L8 shape)
//!
//! At boot the daemon programs an `inet` family table holding the
//! `killswitch` and `forward` chains via `phase10::LiveSystem`. The
//! L8 audit shape is: between cold-boot and the first daemon start,
//! and again across any unit restart, there is a window where the
//! killswitch table is absent and the host can leak traffic to the
//! underlay. The mitigation tracked by this slice is a dedicated
//! verifier the systemd unit can invoke as `ExecStartPre` (and that
//! a future boot-time service can invoke before `network-online.target`)
//! to refuse to bring the `WireGuard` interface up unless the
//! killswitch is already in place.
//!
//! ## Boot-time pre-protective installer
//!
//! When `--install-boot-killswitch` is passed to the CLI, the module
//! also installs a minimal `inet rustynet_boot` table **before** the
//! daemon starts.  This table survives daemon teardown because
//! `disconnect-cleanup` only removes the daemon's generation-rotated
//! `rustynet_g<N>` tables; `rustynet_boot` is left intact until the
//! next ExecStartPre reinstalls it (idempotent) or a manual `nft delete
//! table inet rustynet_boot` removes it.
//!
//! The purpose is to provide an SSH recovery path when the daemon fails
//! to start or is in fail-closed mode.  If `RUSTYNET_FAIL_CLOSED_SSH_ALLOW`
//! is true in the service environment, the boot table includes per-CIDR
//! TCP-port-22 accept rules so an operator can always reach the node via
//! SSH even after the daemon's killswitch is cleaned up.
//!
//! ### Interaction with the daemon's killswitch
//!
//! The boot table (`rustynet_boot`) and the daemon's table (`rustynet_g<N>`)
//! both hook into `output` at priority 0.  In nftables, an `accept` verdict
//! in one base chain does **not** terminate traversal of other base chains at
//! the same hook — a `policy drop` in the daemon's chain still drops the
//! packet.  The boot table's SSH accept rules therefore only take effect when
//! the daemon's table has been removed (after `disconnect-cleanup` or graceful
//! shutdown).  While the daemon is actively running in fail-closed mode with
//! `RUSTYNET_FAIL_CLOSED_SSH_ALLOW=false`, SSH remains blocked; to unblock
//! SSH during the daemon's lifetime set `RUSTYNET_FAIL_CLOSED_SSH_ALLOW=true`
//! in `/etc/default/rustynetd`.
//!
//! This module owns the pure evaluator + typed report shape + boot installer.
//! The collector parses `nft list ruleset` output and the
//! `/sys/class/net/<iface>` directory presence; both surfaces are
//! deterministic on Linux and trivially mockable in tests.
//!
//! Wired through the CLI as `rustynetd linux-killswitch-boot-check`.
//! Off-Linux the collector emits a clear blocker; the check is only
//! meaningful on a Linux runtime host.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Reviewed Linux killswitch table name. The runtime programs the
/// killswitch under a generation-rotated form `inet rustynet_g<N>`
/// (see `phase10::LiveSystem::firewall_table_name`) so it can swap
/// between generations atomically without opening a leak window. The
/// verifier accepts that rotated form as well as the canonical bare
/// `inet rustynet` — see `line_is_reviewed_table_header` for the
/// matcher. This constant remains the canonical name reported in
/// drift messages so operators see a stable identifier regardless of
/// which generation slot is currently live.
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

/// nftables table name for the boot-time pre-protective killswitch
/// installed by `linux-killswitch-boot-check --install-boot-killswitch`.
/// Distinct from the daemon's generation-rotated tables (`rustynet_g<N>`)
/// so it survives `disconnect-cleanup` and can coexist without confusing
/// the L8 verifier.
pub const BOOT_KILLSWITCH_TABLE: &str = "rustynet_boot";

/// A validated SSH management CIDR used when building boot-time
/// killswitch SSH-allow rules.  Owns the IP family string ("ip" for
/// IPv4, "ip6" for IPv6) and the CIDR string in `addr/prefix` form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSshCidr {
    /// nftables address-family selector for this CIDR ("ip" or "ip6").
    pub family: &'static str,
    /// CIDR in `<addr>/<prefix>` form, e.g. "192.168.1.0/24".
    pub cidr: String,
}

impl BootSshCidr {
    /// Parse and validate a CIDR string.  Returns an error if the
    /// address or prefix are syntactically invalid.
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if s.is_empty() {
            return Err("empty CIDR string".to_owned());
        }
        let (ip_str, prefix_str) = s
            .split_once('/')
            .ok_or_else(|| format!("CIDR missing '/': {s}"))?;
        let ip: std::net::IpAddr = ip_str
            .parse()
            .map_err(|e| format!("invalid IP address in CIDR {s}: {e}"))?;
        let prefix: u8 = prefix_str
            .parse()
            .map_err(|e| format!("invalid prefix length in CIDR {s}: {e}"))?;
        let family: &'static str = match ip {
            std::net::IpAddr::V4(_) => {
                if prefix > 32 {
                    return Err(format!("IPv4 prefix length > 32 in CIDR {s}"));
                }
                "ip"
            }
            std::net::IpAddr::V6(_) => {
                if prefix > 128 {
                    return Err(format!("IPv6 prefix length > 128 in CIDR {s}"));
                }
                "ip6"
            }
        };
        Ok(Self {
            family,
            cidr: s.to_owned(),
        })
    }
}

/// Install a minimal pre-protective boot-time killswitch table
/// (`inet rustynet_boot`) before the daemon starts.  The table is
/// always deleted and recreated so each ExecStartPre call is
/// idempotent.
///
/// The table installs:
/// - loopback accept
/// - `ct state established,related accept` (allows SSH reply traffic
///   during normal daemon operation)
/// - outbound accept for the WireGuard interface (passthrough for
///   tunnel traffic when the daemon later brings the interface up)
/// - outbound UDP accept on `wg_listen_port` when `Some(port)` is
///   supplied — without this the daemon's traversal-probe initial
///   handshake datagrams are dropped by this boot chain even though
///   the daemon's own generation-rotated table would accept them.
///   Both chains hook `output` at priority 0 and a `policy drop`
///   verdict in this boot chain still drops the packet regardless of
///   what the daemon chain decides.
/// - TCP port 22 accept for each CIDR in `ssh_cidrs` when
///   `ssh_allow` is true
/// - implicit `policy drop` for everything else
///
/// On non-Linux hosts this is a no-op (the killswitch is Linux-only).
pub fn install_linux_boot_killswitch(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
) -> Result<(), String> {
    install_linux_boot_killswitch_inner(iface, ssh_allow, ssh_cidrs, wg_listen_port)
}

#[cfg(target_os = "linux")]
fn install_linux_boot_killswitch_inner(
    iface: &str,
    ssh_allow: bool,
    ssh_cidrs: &[BootSshCidr],
    wg_listen_port: Option<u16>,
) -> Result<(), String> {
    // Argv-only helper: no shell construction, args are separate tokens.
    fn nft(args: &[&str]) -> Result<(), String> {
        let out = std::process::Command::new("nft")
            .args(args)
            .output()
            .map_err(|e| format!("nft spawn failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "nft {} failed ({}): {}",
                args.join(" "),
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(())
    }

    // Always recreate: flush any stale boot table first (ignore if absent).
    let _ = std::process::Command::new("nft")
        .args(["delete", "table", "inet", BOOT_KILLSWITCH_TABLE])
        .output();

    nft(&["add", "table", "inet", BOOT_KILLSWITCH_TABLE])?;
    nft(&[
        "add",
        "chain",
        "inet",
        BOOT_KILLSWITCH_TABLE,
        "killswitch",
        "{",
        "type",
        "filter",
        "hook",
        "output",
        "priority",
        "0",
        ";",
        "policy",
        "drop",
        ";",
        "}",
    ])?;
    nft(&[
        "add",
        "rule",
        "inet",
        BOOT_KILLSWITCH_TABLE,
        "killswitch",
        "oifname",
        "lo",
        "accept",
    ])?;
    nft(&[
        "add",
        "rule",
        "inet",
        BOOT_KILLSWITCH_TABLE,
        "killswitch",
        "ct",
        "state",
        "established,related",
        "accept",
    ])?;
    // Allow outbound through the WireGuard interface.  The iface may not
    // exist yet at ExecStartPre time, but nftables accepts the rule and
    // will match it once the interface comes up.
    nft(&[
        "add",
        "rule",
        "inet",
        BOOT_KILLSWITCH_TABLE,
        "killswitch",
        "oifname",
        iface,
        "accept",
    ])?;
    // Allow outbound UDP to the WireGuard listen port so the daemon's
    // traversal-probe handshake datagrams can leave the host during the
    // window where this boot chain hooks `output` alongside the daemon's
    // generation-rotated chain.  Without this rule, every WG outbound
    // datagram returns EPERM regardless of the daemon's own ruleset,
    // because both chains share the `output` hook and `policy drop` in
    // either chain drops the packet.
    if let Some(port) = wg_listen_port {
        let port_str = port.to_string();
        nft(&[
            "add",
            "rule",
            "inet",
            BOOT_KILLSWITCH_TABLE,
            "killswitch",
            "udp",
            "dport",
            port_str.as_str(),
            "accept",
        ])?;
    }
    if ssh_allow {
        for cidr in ssh_cidrs {
            nft(&[
                "add",
                "rule",
                "inet",
                BOOT_KILLSWITCH_TABLE,
                "killswitch",
                cidr.family,
                "daddr",
                cidr.cidr.as_str(),
                "tcp",
                "dport",
                "22",
                "accept",
            ])?;
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn install_linux_boot_killswitch_inner(
    _iface: &str,
    _ssh_allow: bool,
    _ssh_cidrs: &[BootSshCidr],
    _wg_listen_port: Option<u16>,
) -> Result<(), String> {
    // Off-Linux: no-op. The boot-time killswitch is Linux-specific.
    Ok(())
}

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
    /// false so the off-platform case doesn't claim `overall_ok`.
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

/// Default value for the `host_observable` field on old JSON that
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

/// Returns true iff `trimmed_line` opens a nftables table block for
/// the reviewed killswitch table — either the canonical bare form
/// `table inet rustynet {` or the generation-rotated form
/// `table inet rustynet_g<N> {` (one or more ASCII digits after `_g`).
/// Anything else, including unrelated tables that happen to start
/// with `rustynet` (e.g. `rustynet_nat_g1`), is rejected.
pub(crate) fn line_is_reviewed_table_header(trimmed_line: &str) -> bool {
    let prefix = format!("table {REVIEWED_KILLSWITCH_FAMILY} {REVIEWED_KILLSWITCH_TABLE}");
    let Some(after_name) = trimmed_line.strip_prefix(prefix.as_str()) else {
        return false;
    };
    if let Some(rest) = after_name.strip_prefix("_g") {
        // Generation-rotated form: require one or more digits, then `{`.
        let digit_count = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digit_count == 0 {
            return false;
        }
        return rest[digit_count..].trim_start().starts_with('{');
    }
    // Canonical bare form: name must end here — next non-whitespace is `{`.
    let next = after_name.chars().next();
    matches!(next, Some(' ') | Some('\t') | Some('{')) && after_name.trim_start().starts_with('{')
}

/// Parse `nft list ruleset` text and extract the chains found under
/// the reviewed killswitch table (`inet rustynet` or `inet
/// rustynet_g<N>`). Returns the table-present flag, the chain names
/// in source order, and any matched rule fragments from the
/// `killswitch` chain. Exposed (crate-visible) so tests can pin the
/// parser without shelling out to `nft`.
#[allow(dead_code)]
pub(crate) fn parse_nft_ruleset_for_killswitch(body: &str) -> (bool, Vec<String>, Vec<String>) {
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
            if line_is_reviewed_table_header(trimmed) {
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
                    matched_fragments.push((*frag).to_owned());
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
/// `iface_name` is the `WireGuard` tunnel interface the daemon will
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
        ruleset_source: "off-Linux host: nft not invoked".to_owned(),
        host_observable: false,
        table_present: false,
        chains_present: Vec::new(),
        killswitch_rule_fragments_present: Vec::new(),
        tunnel_interface_present: false,
        tunnel_interface_name: iface_name.to_owned(),
    };
    build_linux_killswitch_boot_report(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_snapshot() -> LinuxKillswitchBootSnapshot {
        LinuxKillswitchBootSnapshot {
            ruleset_source: "test fixture".to_owned(),
            host_observable: true,
            table_present: true,
            chains_present: vec!["killswitch".to_owned(), "forward".to_owned()],
            killswitch_rule_fragments_present: REVIEWED_REQUIRED_KILLSWITCH_RULE_FRAGMENTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_owned(),
        }
    }

    // ---- evaluator coverage -----------------------------------------------

    #[test]
    fn evaluator_rejects_unobservable_host() {
        let mut snap = ok_snapshot();
        snap.host_observable = false;
        snap.ruleset_source = "off-Linux host: nft not invoked".to_owned();
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
        snap.chains_present = vec!["forward".to_owned()];
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
        snap.chains_present = vec!["killswitch".to_owned()];
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
        snap.chains_present = vec!["forward".to_owned()];
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
            ruleset_source: "agg test".to_owned(),
            host_observable: true,
            table_present: true,
            chains_present: Vec::new(),
            killswitch_rule_fragments_present: Vec::new(),
            tunnel_interface_present: true,
            tunnel_interface_name: "rustynet0".to_owned(),
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
    fn parser_accepts_generation_rotated_table_name() {
        // The runtime's `phase10::LiveSystem::firewall_table_name`
        // programs the killswitch under a generation-rotated form
        // (`rustynet_g<N>`) so it can swap between generations
        // atomically. The verifier must accept that rotated form;
        // otherwise every post-apply state would falsely report
        // "table missing" and any unit restart would hit the L8
        // leak-window drift gate even though the killswitch is in
        // fact programmed.
        let body = r#"
table inet rustynet_g5 {
        chain killswitch {
                type filter hook output priority 0; policy drop;
                oifname "lo" accept
                ct state established,related accept
        }
        chain forward {
                type filter hook forward priority 0; policy drop;
        }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(
            present,
            "rotated `rustynet_g<N>` table must be detected as the reviewed killswitch"
        );
        assert!(chains.iter().any(|c| c == "killswitch"));
        assert!(chains.iter().any(|c| c == "forward"));
        assert_eq!(frags.len(), 2, "both reviewed fragments must match");
    }

    #[test]
    fn parser_rejects_lookalike_table_names() {
        // Tables that share the `rustynet` prefix but are NOT the
        // reviewed killswitch (e.g. the NAT table `rustynet_nat_g1`,
        // or a typo'd `rustynetfoo`) must not be conflated.
        let body = r#"
table ip rustynet_nat_g1 {
        chain postrouting { type nat hook postrouting priority 100; }
}
table inet rustynet_nat_g1 {
        chain killswitch { oifname "lo" accept }
}
table inet rustynetfoo {
        chain killswitch { oifname "lo" accept }
}
"#;
        let (present, chains, frags) = parse_nft_ruleset_for_killswitch(body);
        assert!(
            !present,
            "lookalike tables must not be matched as the reviewed killswitch: chains={chains:?} frags={frags:?}"
        );
    }

    #[test]
    fn header_matcher_pins_exact_grammar() {
        // Canonical form.
        assert!(line_is_reviewed_table_header("table inet rustynet {"));
        // Generation-rotated forms.
        assert!(line_is_reviewed_table_header("table inet rustynet_g0 {"));
        assert!(line_is_reviewed_table_header("table inet rustynet_g7 {"));
        assert!(line_is_reviewed_table_header("table inet rustynet_g42 {"));
        // Tab between name and `{` is acceptable (nft pretty-prints
        // with spaces but custom dumps may use tabs).
        assert!(line_is_reviewed_table_header("table inet rustynet_g1\t{"));
        // Negatives: wrong family, wrong base name, missing brace,
        // missing digits, lookalike prefix.
        assert!(!line_is_reviewed_table_header("table ip rustynet {"));
        assert!(!line_is_reviewed_table_header(
            "table inet rustynet_nat_g1 {"
        ));
        assert!(!line_is_reviewed_table_header("table inet rustynetfoo {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet_g {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet_gX {"));
        assert!(!line_is_reviewed_table_header("table inet rustynet"));
        assert!(!line_is_reviewed_table_header("# table inet rustynet {"));
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

    // ---- boot killswitch constants ----------------------------------------

    #[test]
    fn boot_killswitch_table_name_pinned() {
        // The disconnect-cleanup path intentionally preserves any table
        // whose name does not match `rustynet_g*` or `rustynet_nat_g*`,
        // which keeps `rustynet_boot` alive across daemon teardown.
        // Renaming the constant would silently break that invariant.
        assert_eq!(BOOT_KILLSWITCH_TABLE, "rustynet_boot");
    }

    // ---- BootSshCidr::parse -----------------------------------------------

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv4_host() {
        let c = BootSshCidr::parse("192.168.1.5/32").unwrap();
        assert_eq!(c.family, "ip");
        assert_eq!(c.cidr, "192.168.1.5/32");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv4_subnet() {
        let c = BootSshCidr::parse("10.0.0.0/8").unwrap();
        assert_eq!(c.family, "ip");
        assert_eq!(c.cidr, "10.0.0.0/8");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv6_host() {
        let c = BootSshCidr::parse("fd00::1/128").unwrap();
        assert_eq!(c.family, "ip6");
        assert_eq!(c.cidr, "fd00::1/128");
    }

    #[test]
    fn boot_ssh_cidr_parse_valid_ipv6_subnet() {
        let c = BootSshCidr::parse("fd00::/64").unwrap();
        assert_eq!(c.family, "ip6");
        assert_eq!(c.cidr, "fd00::/64");
    }

    #[test]
    fn boot_ssh_cidr_parse_trims_whitespace() {
        let c = BootSshCidr::parse("  192.168.0.0/16  ").unwrap();
        assert_eq!(c.family, "ip");
        // The stored cidr is the trimmed input.
        assert_eq!(c.cidr, "192.168.0.0/16");
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_empty() {
        assert!(BootSshCidr::parse("").is_err());
        assert!(BootSshCidr::parse("   ").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_no_slash() {
        assert!(BootSshCidr::parse("192.168.1.1").is_err());
        assert!(BootSshCidr::parse("fd00::1").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_bad_ip() {
        assert!(BootSshCidr::parse("999.0.0.0/8").is_err());
        assert!(BootSshCidr::parse("notanip/24").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_bad_prefix_non_numeric() {
        assert!(BootSshCidr::parse("192.168.0.0/abc").is_err());
        assert!(BootSshCidr::parse("fd00::/xyz").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_ipv4_prefix_over_32() {
        assert!(BootSshCidr::parse("192.168.0.0/33").is_err());
    }

    #[test]
    fn boot_ssh_cidr_parse_rejects_ipv6_prefix_over_128() {
        assert!(BootSshCidr::parse("fd00::/129").is_err());
    }

    // ---- install_linux_boot_killswitch off-Linux no-op --------------------

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn install_boot_killswitch_off_linux_is_noop() {
        // Off-Linux: must return Ok without touching any nft state.
        let cidrs = vec![
            BootSshCidr::parse("192.168.0.0/16").unwrap(),
            BootSshCidr::parse("fd00::/64").unwrap(),
        ];
        let result = install_linux_boot_killswitch("rustynet0", true, &cidrs, Some(51820));
        assert!(
            result.is_ok(),
            "off-Linux install must be a no-op: {result:?}"
        );
    }

    #[test]
    fn boot_killswitch_source_contains_wg_listen_port_rule() {
        // Pin against the regression where the boot chain (which hooks
        // `output` priority 0 alongside the daemon's generation-rotated
        // chain) had no outbound-UDP accept for the WireGuard listen
        // port. Without that rule, every WG handshake the daemon emits
        // during the pre-`path_live_proven` window returns EPERM from
        // `sendto(2)` because this boot chain's `policy drop` still
        // applies even when the daemon's chain would have accepted.
        let source = include_str!("linux_killswitch_boot.rs");
        assert!(
            source.contains("if let Some(port) = wg_listen_port {"),
            "install_linux_boot_killswitch_inner must gate the WG-port allow rule on the \
             wg_listen_port argument so a None caller skips it cleanly"
        );
        assert!(
            source.contains("\"udp\","),
            "install_linux_boot_killswitch_inner must emit an `udp` token in the boot ruleset"
        );
        assert!(
            source.contains("\"dport\","),
            "install_linux_boot_killswitch_inner must emit a `dport` token in the boot ruleset"
        );
        assert!(
            source.contains("wg_listen_port: Option<u16>"),
            "install_linux_boot_killswitch* signatures must accept Option<u16> for the \
             WireGuard listen port so the systemd unit can forward RUSTYNET_WG_LISTEN_PORT"
        );
    }
}
