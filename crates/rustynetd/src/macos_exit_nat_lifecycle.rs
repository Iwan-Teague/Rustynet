#![allow(clippy::result_large_err)]

//! Track B Step 2 follow-up — macOS exit-mode NAT lifecycle artefact
//! producer.
//!
//! Companion of the orchestrator-side
//! `evaluate_macos_exit_nat_lifecycle_artifact` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`. The validator expects a
//! two-phase artefact: a `during_run` snapshot captured while the
//! daemon is in exit mode (pf anchor present + IPv4 forwarding
//! enabled), and an `after_stop` snapshot captured once the daemon
//! has been stopped (pf anchor removed + forwarding reverted).
//!
//! This module emits ONE single-phase snapshot per invocation; the
//! orchestrator pairs two snapshots into the merged artefact the
//! validator reads. Keeping the producer single-phase keeps the
//! daemon-side surface tiny: it just shells out to `pfctl` + `sysctl`
//! and serialises the result. No host mutation, no daemon lifecycle
//! control.
//!
//! Wired through the CLI as `rustynetd macos-exit-nat-lifecycle-snapshot`.

use serde::{Deserialize, Serialize};
// `Command` is only used by the macOS-gated capture fns below; gating the import
// avoids an unused-import warning on non-macOS builds (which would fail the
// `clippy -D warnings` gate on Linux).
#[cfg(target_os = "macos")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Schema version for both the producer snapshot and the merged
/// artefact. Bumping requires an orchestrator-side bump too.
pub const MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION: u32 = 1;

/// Default pf anchor used by `rustynetd` for exit-mode NAT rules.
/// Mirrors what the daemon installs at exit-serving activation. The
/// validator accepts any non-empty string here, but the daemon's
/// reviewed default is `com.rustynet/nat`.
pub const DEFAULT_MACOS_EXIT_PF_ANCHOR: &str = "com.rustynet/nat";

/// Single-phase NAT + forwarding snapshot. Two of these are merged
/// by the orchestrator into the validator's full artefact shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosExitNatLifecycleSnapshot {
    pub schema_version: u32,
    pub captured_at_unix: i64,
    /// Mesh CIDR the operator declared at snapshot time. Lets the
    /// orchestrator-side merge step assert
    /// `during_run.internal_prefix == mesh_cidr` without re-reading
    /// the daemon's configured prefix here.
    pub mesh_cidr: String,
    /// pf anchor name the operator declared at snapshot time
    /// (`com.rustynet/nat` by default).
    pub pf_anchor: String,
    /// Whether the named pf anchor is currently loaded in pf.
    pub pf_anchor_present: bool,
    /// Internal prefix observed in the loaded pf anchor's NAT rule.
    /// Empty when no anchor is loaded.
    pub internal_prefix: String,
    /// `sysctl net.inet.ip.forwarding` — "Enabled" if 1, "Disabled"
    /// if 0, matching the producer/evaluator field shape.
    pub tunnel_forwarding: String,
    /// Same value as `tunnel_forwarding` today — macOS uses a single
    /// `ip.forwarding` sysctl rather than the Windows pair of
    /// tunnel/egress forwarding flags. Reported separately so the
    /// merge target matches the validator's per-direction shape.
    pub egress_forwarding: String,
}

/// Options for [`collect_macos_exit_nat_lifecycle_snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosExitNatLifecycleOptions {
    pub mesh_cidr: String,
    pub pf_anchor: String,
}

impl Default for MacosExitNatLifecycleOptions {
    fn default() -> Self {
        Self {
            mesh_cidr: String::new(),
            pf_anchor: DEFAULT_MACOS_EXIT_PF_ANCHOR.to_owned(),
        }
    }
}

/// Capture the current pf anchor + sysctl forwarding state.
/// Single-phase: orchestrator runs this twice (during exit mode +
/// after daemon stop) and pairs the snapshots into the merged
/// artefact the validator reads.
///
/// Argv-only `pfctl` / `sysctl` invocations, no shell construction
/// with untrusted values — matches `AGENTS.md` privileged-boundary
/// hardening for the daemon's other macOS subcommands.
pub fn collect_macos_exit_nat_lifecycle_snapshot(
    options: &MacosExitNatLifecycleOptions,
) -> MacosExitNatLifecycleSnapshot {
    let now_unix = current_unix_seconds();
    let (pf_anchor_present, internal_prefix) =
        capture_pf_anchor_state(options.pf_anchor.as_str()).unwrap_or((false, String::new()));
    let forwarding_state =
        capture_sysctl_forwarding(forwarding_sysctl_key_for_cidr(options.mesh_cidr.as_str()));
    MacosExitNatLifecycleSnapshot {
        schema_version: MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix: now_unix,
        mesh_cidr: options.mesh_cidr.clone(),
        pf_anchor: options.pf_anchor.clone(),
        pf_anchor_present,
        internal_prefix,
        tunnel_forwarding: forwarding_state.clone(),
        egress_forwarding: forwarding_state,
    }
}

/// Pure builder for the snapshot from raw pfctl output. Used by the
/// daemon-side collector above when running on macOS, and by unit
/// tests off-macOS to pin the parser shape without shelling out.
pub fn build_macos_exit_nat_lifecycle_snapshot(
    captured_at_unix: i64,
    mesh_cidr: &str,
    pf_anchor: &str,
    pfctl_anchor_show_stdout: &str,
    sysctl_forwarding_stdout: &str,
) -> MacosExitNatLifecycleSnapshot {
    let pf_anchor_present = pfctl_anchor_present(pfctl_anchor_show_stdout);
    let internal_prefix = if pf_anchor_present {
        parse_internal_prefix(pfctl_anchor_show_stdout)
    } else {
        String::new()
    };
    let forwarding_state = parse_sysctl_forwarding(sysctl_forwarding_stdout);
    MacosExitNatLifecycleSnapshot {
        schema_version: MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix,
        mesh_cidr: mesh_cidr.to_owned(),
        pf_anchor: pf_anchor.to_owned(),
        pf_anchor_present,
        internal_prefix,
        tunnel_forwarding: forwarding_state.clone(),
        egress_forwarding: forwarding_state,
    }
}

/// Merge a `during_run` snapshot and an `after_stop` snapshot into
/// the JSON shape the orchestrator-side
/// `evaluate_macos_exit_nat_lifecycle_artifact` expects. Returns a
/// `serde_json::Value` so the orchestrator can serialise it without
/// owning the schema.
pub fn merge_macos_exit_nat_lifecycle_artifact(
    during_run: &MacosExitNatLifecycleSnapshot,
    after_stop: &MacosExitNatLifecycleSnapshot,
) -> serde_json::Value {
    let forwarding_restored = after_stop
        .tunnel_forwarding
        .eq_ignore_ascii_case("disabled")
        && after_stop
            .egress_forwarding
            .eq_ignore_ascii_case("disabled");
    serde_json::json!({
        "schema_version": MACOS_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        "mesh_cidr": during_run.mesh_cidr,
        "pf_anchor": during_run.pf_anchor,
        "during_run": {
            "pf_anchor_present": during_run.pf_anchor_present,
            "internal_prefix": during_run.internal_prefix,
            "tunnel_forwarding": during_run.tunnel_forwarding,
            "egress_forwarding": during_run.egress_forwarding,
        },
        "after_stop": {
            "pf_anchor_present": after_stop.pf_anchor_present,
            "forwarding_restored": forwarding_restored,
        },
    })
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn capture_pf_anchor_state(pf_anchor: &str) -> Result<(bool, String), ()> {
    let output = Command::new("/sbin/pfctl")
        .args(["-a", pf_anchor, "-s", "nat"])
        .output()
        .map_err(|_| ())?;
    if !output.status.success() {
        // `pfctl -s nat` on a non-loaded anchor exits with status 1
        // and writes nothing useful. Report "not present" rather than
        // a hard error so the off-state snapshot still serialises.
        return Ok((false, String::new()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let present = pfctl_anchor_present(stdout.as_str());
    let prefix = if present {
        parse_internal_prefix(stdout.as_str())
    } else {
        String::new()
    };
    Ok((present, prefix))
}

#[cfg(not(target_os = "macos"))]
fn capture_pf_anchor_state(_pf_anchor: &str) -> Result<(bool, String), ()> {
    Err(())
}

#[cfg(target_os = "macos")]
fn capture_sysctl_forwarding(forwarding_key: &str) -> String {
    let output = Command::new("/usr/sbin/sysctl")
        .args(["-n", forwarding_key])
        .output();
    match output {
        Ok(out) if out.status.success() => {
            parse_sysctl_forwarding(String::from_utf8_lossy(&out.stdout).as_ref())
        }
        _ => "Disabled".to_owned(),
    }
}

#[cfg(not(target_os = "macos"))]
fn capture_sysctl_forwarding(_forwarding_key: &str) -> String {
    "Disabled".to_owned()
}

/// The macOS forwarding sysctl that governs the mesh prefix's address family:
/// `net.inet6.ip6.forwarding` for an IPv6 CIDR, else `net.inet.ip.forwarding`.
/// Matches the daemon's exit-NAT activation (which enables the same key).
pub fn forwarding_sysctl_key_for_cidr(mesh_cidr: &str) -> &'static str {
    if mesh_cidr.contains(':') {
        "net.inet6.ip6.forwarding"
    } else {
        "net.inet.ip.forwarding"
    }
}

fn pfctl_anchor_present(stdout: &str) -> bool {
    // `pfctl -a <anchor> -s nat` prints the anchor's NAT rules. Any
    // non-comment, non-blank line counts as an active rule and
    // therefore an anchor that is loaded with content. An empty
    // (loaded but ruleless) anchor still counts as "not present" for
    // the lifecycle contract — exit-mode should always install at
    // least one NAT rule.
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|line| line.starts_with("nat") || line.contains(" nat "))
}

fn parse_internal_prefix(stdout: &str) -> String {
    // pfctl emits NAT rules like:
    //   nat on en0 inet from 100.64.0.0/16 to any -> (en0) round-robin
    // Extract the `from <cidr>` token. If absent, return empty so the
    // validator surfaces the drift cleanly.
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("nat") && !trimmed.contains(" nat ") {
            continue;
        }
        let mut tokens = trimmed.split_whitespace();
        while let Some(tok) = tokens.next() {
            if tok == "from"
                && let Some(prefix) = tokens.next()
                && looks_like_cidr(prefix)
            {
                return prefix.to_owned();
            }
        }
    }
    String::new()
}

fn parse_sysctl_forwarding(stdout: &str) -> String {
    let trimmed = stdout.trim();
    match trimmed {
        "1" => "Enabled".to_owned(),
        "0" | "" => "Disabled".to_owned(),
        _ => "Disabled".to_owned(),
    }
}

fn looks_like_cidr(token: &str) -> bool {
    if let Some((host, prefix)) = token.split_once('/') {
        !host.is_empty()
            && !prefix.is_empty()
            && prefix.chars().all(|c| c.is_ascii_digit())
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':')
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pfctl_anchor_present_detects_active_nat_rule() {
        let stdout = "nat on en0 inet from 100.64.0.0/16 to any -> (en0) round-robin\n";
        assert!(pfctl_anchor_present(stdout));
    }

    #[test]
    fn pfctl_anchor_present_treats_empty_output_as_absent() {
        assert!(!pfctl_anchor_present(""));
        assert!(!pfctl_anchor_present("# comment only\n"));
    }

    #[test]
    fn parse_internal_prefix_extracts_cidr_from_nat_rule() {
        let stdout = "nat on en0 inet from 100.64.0.0/16 to any -> (en0) round-robin\n";
        assert_eq!(parse_internal_prefix(stdout), "100.64.0.0/16");
    }

    #[test]
    fn parse_internal_prefix_returns_empty_when_anchor_has_no_nat_rule() {
        assert_eq!(parse_internal_prefix(""), "");
        assert_eq!(parse_internal_prefix("# header only\n"), "");
    }

    #[test]
    fn parse_sysctl_forwarding_canonicalises_enabled() {
        assert_eq!(parse_sysctl_forwarding("1\n"), "Enabled");
        assert_eq!(parse_sysctl_forwarding("0\n"), "Disabled");
        assert_eq!(parse_sysctl_forwarding(""), "Disabled");
        assert_eq!(parse_sysctl_forwarding("garbage"), "Disabled");
    }

    #[test]
    fn forwarding_sysctl_key_matches_mesh_family() {
        assert_eq!(
            forwarding_sysctl_key_for_cidr("100.64.0.0/10"),
            "net.inet.ip.forwarding"
        );
        assert_eq!(
            forwarding_sysctl_key_for_cidr("fd7a::/48"),
            "net.inet6.ip6.forwarding"
        );
    }

    #[test]
    fn build_snapshot_matches_during_run_shape() {
        let pfctl = "nat on en0 inet from 100.64.0.0/16 to any -> (en0)\n";
        let sysctl = "1\n";
        let snap = build_macos_exit_nat_lifecycle_snapshot(
            1_780_000_000,
            "100.64.0.0/16",
            "com.rustynet/nat",
            pfctl,
            sysctl,
        );
        assert_eq!(snap.schema_version, 1);
        assert_eq!(snap.mesh_cidr, "100.64.0.0/16");
        assert_eq!(snap.pf_anchor, "com.rustynet/nat");
        assert!(snap.pf_anchor_present);
        assert_eq!(snap.internal_prefix, "100.64.0.0/16");
        assert_eq!(snap.tunnel_forwarding, "Enabled");
        assert_eq!(snap.egress_forwarding, "Enabled");
    }

    #[test]
    fn build_snapshot_after_stop_shape_has_no_anchor_and_disabled_forwarding() {
        let snap = build_macos_exit_nat_lifecycle_snapshot(
            1_780_000_100,
            "100.64.0.0/16",
            "com.rustynet/nat",
            "",
            "0\n",
        );
        assert!(!snap.pf_anchor_present);
        assert_eq!(snap.internal_prefix, "");
        assert_eq!(snap.tunnel_forwarding, "Disabled");
        assert_eq!(snap.egress_forwarding, "Disabled");
    }

    #[test]
    fn merge_artifact_matches_validator_contract() {
        let during = build_macos_exit_nat_lifecycle_snapshot(
            1,
            "100.64.0.0/16",
            "com.rustynet/nat",
            "nat on en0 inet from 100.64.0.0/16 to any -> (en0)\n",
            "1",
        );
        let after = build_macos_exit_nat_lifecycle_snapshot(
            2,
            "100.64.0.0/16",
            "com.rustynet/nat",
            "",
            "0",
        );
        let merged = merge_macos_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["schema_version"], 1);
        assert_eq!(merged["mesh_cidr"], "100.64.0.0/16");
        assert_eq!(merged["pf_anchor"], "com.rustynet/nat");
        assert_eq!(merged["during_run"]["pf_anchor_present"], true);
        assert_eq!(merged["during_run"]["internal_prefix"], "100.64.0.0/16");
        assert_eq!(merged["during_run"]["tunnel_forwarding"], "Enabled");
        assert_eq!(merged["during_run"]["egress_forwarding"], "Enabled");
        assert_eq!(merged["after_stop"]["pf_anchor_present"], false);
        assert_eq!(merged["after_stop"]["forwarding_restored"], true);
    }

    #[test]
    fn merge_artifact_after_stop_forwarding_not_restored_when_either_remains_enabled() {
        let during = build_macos_exit_nat_lifecycle_snapshot(
            1,
            "100.64.0.0/16",
            "com.rustynet/nat",
            "nat on en0 inet from 100.64.0.0/16 to any -> (en0)\n",
            "1",
        );
        // After-stop snapshot where the operator forgot to revert
        // ip.forwarding — validator should see forwarding_restored=false.
        let after = build_macos_exit_nat_lifecycle_snapshot(
            2,
            "100.64.0.0/16",
            "com.rustynet/nat",
            "",
            "1",
        );
        let merged = merge_macos_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["after_stop"]["forwarding_restored"], false);
    }

    #[test]
    fn looks_like_cidr_accepts_ipv4_and_rejects_garbage() {
        assert!(looks_like_cidr("100.64.0.0/16"));
        assert!(looks_like_cidr("2001:db8::/64"));
        assert!(!looks_like_cidr("not a cidr"));
        assert!(!looks_like_cidr("100.64.0.0"));
        assert!(!looks_like_cidr("/16"));
    }

    /// Default-options regression: the producer's default options
    /// fill in the reviewed pf anchor and leave mesh_cidr blank for
    /// the operator to set. Pinning the defaults keeps the validator
    /// + producer contract stable.
    #[test]
    fn default_options_use_reviewed_pf_anchor() {
        let opts = MacosExitNatLifecycleOptions::default();
        assert_eq!(opts.pf_anchor, DEFAULT_MACOS_EXIT_PF_ANCHOR);
        assert_eq!(opts.mesh_cidr, "");
    }
}
