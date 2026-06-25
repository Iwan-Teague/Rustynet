#![allow(clippy::result_large_err)]

//! Linux exit-mode NAT lifecycle artefact producer.
//!
//! Companion of the orchestrator-side
//! `evaluate_linux_exit_nat_lifecycle_artifact` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`. The validator expects a
//! two-phase artefact: a `during_run` snapshot captured while the
//! daemon is in exit mode (nftables NAT table present + IPv4
//! forwarding enabled), and an `after_stop` snapshot captured once
//! the daemon has been stopped (NAT table removed + forwarding
//! reverted).
//!
//! This module emits ONE single-phase snapshot per invocation; the
//! shell wrapper pairs two snapshots into the merged artefact the
//! validator reads. Keeping the producer single-phase keeps the
//! daemon-side surface read-only: it shells out to `nft` and reads
//! `/proc/sys` forwarding flags. No host mutation, no daemon
//! lifecycle control.
//!
//! Wired through the CLI as
//! `rustynetd linux-exit-nat-lifecycle-snapshot`.

use serde::{Deserialize, Serialize};
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub const LINUX_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION: u32 = 1;

/// Reviewed generation-1 NAT table. The runtime rotates generation
/// suffixes (`rustynet_nat_g<N>`), so operators can override this
/// with `--nat-table` when the active generation differs.
pub const DEFAULT_LINUX_EXIT_NAT_TABLE: &str = "rustynet_nat_g1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxExitNatLifecycleSnapshot {
    pub schema_version: u32,
    pub captured_at_unix: i64,
    pub mesh_cidr: String,
    pub nat_table: String,
    pub nat_table_present: bool,
    /// The runtime's Linux NAT rule is egress-interface scoped rather
    /// than source-CIDR scoped. When the NAT table contains a reviewed
    /// masquerade rule this field records the operator-declared mesh
    /// CIDR so the merged artefact can still pin the run to the
    /// intended mesh prefix.
    pub internal_prefix: String,
    pub tunnel_forwarding: String,
    pub egress_forwarding: String,
    #[serde(default)]
    pub ipv6_tunnel_forwarding: String,
    #[serde(default)]
    pub ipv6_egress_forwarding: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxExitNatLifecycleOptions {
    pub mesh_cidr: String,
    pub nat_table: String,
}

impl Default for LinuxExitNatLifecycleOptions {
    fn default() -> Self {
        Self {
            mesh_cidr: String::new(),
            nat_table: DEFAULT_LINUX_EXIT_NAT_TABLE.to_owned(),
        }
    }
}

pub fn collect_linux_exit_nat_lifecycle_snapshot(
    options: &LinuxExitNatLifecycleOptions,
) -> LinuxExitNatLifecycleSnapshot {
    let now_unix = current_unix_seconds();
    // Thread the capture RESULT through (not `unwrap_or_default`) so an `nft`
    // spawn/exec failure fails closed (RSA-0031 / F0.1) — see
    // `interpret_nft_nat_capture`. A capture we could not perform must read as
    // "still present", never as "torn down".
    let nat_table_present =
        interpret_nft_nat_capture(capture_nft_nat_table(options.nat_table.as_str()));
    let internal_prefix = if nat_table_present {
        options.mesh_cidr.clone()
    } else {
        String::new()
    };
    // A failed `/proc/sys` read canonicalises to "Unknown" (non-Disabled), so a
    // capture we could not perform never reads as "restored" (RSA-0031 / F0.2).
    let ipv4_forwarding =
        interpret_forwarding_capture(capture_proc_forwarding("/proc/sys/net/ipv4/ip_forward"));
    let ipv6_forwarding = interpret_forwarding_capture(capture_proc_forwarding(
        "/proc/sys/net/ipv6/conf/all/forwarding",
    ));
    LinuxExitNatLifecycleSnapshot {
        schema_version: LINUX_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix: now_unix,
        mesh_cidr: options.mesh_cidr.clone(),
        nat_table: options.nat_table.clone(),
        nat_table_present,
        internal_prefix,
        tunnel_forwarding: ipv4_forwarding.clone(),
        egress_forwarding: ipv4_forwarding,
        ipv6_tunnel_forwarding: ipv6_forwarding.clone(),
        ipv6_egress_forwarding: ipv6_forwarding,
    }
}

pub fn build_linux_exit_nat_lifecycle_snapshot(
    captured_at_unix: i64,
    mesh_cidr: &str,
    nat_table: &str,
    nft_nat_table_stdout: &str,
    ipv4_forwarding_stdout: &str,
    ipv6_forwarding_stdout: &str,
) -> LinuxExitNatLifecycleSnapshot {
    let nat_table_present = nft_nat_table_present(nft_nat_table_stdout);
    let internal_prefix = if nat_table_present {
        mesh_cidr.to_owned()
    } else {
        String::new()
    };
    let ipv4_forwarding = parse_proc_forwarding(ipv4_forwarding_stdout);
    let ipv6_forwarding = parse_proc_forwarding(ipv6_forwarding_stdout);
    LinuxExitNatLifecycleSnapshot {
        schema_version: LINUX_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        captured_at_unix,
        mesh_cidr: mesh_cidr.to_owned(),
        nat_table: nat_table.to_owned(),
        nat_table_present,
        internal_prefix,
        tunnel_forwarding: ipv4_forwarding.clone(),
        egress_forwarding: ipv4_forwarding,
        ipv6_tunnel_forwarding: ipv6_forwarding.clone(),
        ipv6_egress_forwarding: ipv6_forwarding,
    }
}

pub fn merge_linux_exit_nat_lifecycle_artifact(
    during_run: &LinuxExitNatLifecycleSnapshot,
    after_stop: &LinuxExitNatLifecycleSnapshot,
) -> serde_json::Value {
    let forwarding_restored = after_stop
        .tunnel_forwarding
        .eq_ignore_ascii_case("disabled")
        && after_stop
            .egress_forwarding
            .eq_ignore_ascii_case("disabled");
    let ipv6_forwarding_restored = after_stop
        .ipv6_tunnel_forwarding
        .eq_ignore_ascii_case("disabled")
        && after_stop
            .ipv6_egress_forwarding
            .eq_ignore_ascii_case("disabled");
    serde_json::json!({
        "schema_version": LINUX_EXIT_NAT_LIFECYCLE_SCHEMA_VERSION,
        "mesh_cidr": during_run.mesh_cidr,
        "nat_table": during_run.nat_table,
        "during_run": {
            "nat_table_present": during_run.nat_table_present,
            "internal_prefix": during_run.internal_prefix,
            "tunnel_forwarding": during_run.tunnel_forwarding,
            "egress_forwarding": during_run.egress_forwarding,
            "ipv6_tunnel_forwarding": during_run.ipv6_tunnel_forwarding,
            "ipv6_egress_forwarding": during_run.ipv6_egress_forwarding,
        },
        "after_stop": {
            "nat_table_present": after_stop.nat_table_present,
            "forwarding_restored": forwarding_restored,
            "ipv6_forwarding_restored": ipv6_forwarding_restored,
        },
    })
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Interpret an `nft list table` capture result FAIL-CLOSED (RSA-0031 / F0.1).
/// An `nft` spawn/exec *failure* (`Err`) means the daemon cannot confirm whether
/// the exit-NAT table was torn down, so it must report the table as still
/// present — never absent — so the teardown-verification validator does not pass
/// an unverifiable capture. Residual exit NAT after stop/demotion is a
/// release-blocking open relay, so "cannot confirm" must read as "present".
/// Only a *successful* `nft list table` that genuinely shows no table yields
/// `present=false`.
fn interpret_nft_nat_capture(result: Result<String, ()>) -> bool {
    match result {
        Ok(stdout) => nft_nat_table_present(stdout.as_str()),
        // Capture failed: cannot confirm absence ⇒ fail closed as present.
        Err(()) => true,
    }
}

/// Interpret a `/proc/sys` forwarding read FAIL-CLOSED (RSA-0031 / F0.2). A read
/// failure (`None`) is reported as `"Unknown"` rather than `"Disabled"`, so the
/// merge step does not conclude forwarding was restored on a capture it could
/// not perform. A successful read is canonicalised via `parse_proc_forwarding`.
fn interpret_forwarding_capture(captured: Option<String>) -> String {
    match captured {
        Some(stdout) => parse_proc_forwarding(stdout.as_str()),
        None => "Unknown".to_owned(),
    }
}

#[cfg(target_os = "linux")]
fn capture_nft_nat_table(nat_table: &str) -> Result<String, ()> {
    let output = Command::new("nft")
        .args(["list", "table", "ip", nat_table])
        .output()
        .map_err(|_| ())?;
    if !output.status.success() {
        // `nft list table` on a non-existent table exits non-zero. That is the
        // legitimate "table is genuinely absent" case (the daemon ran nft and
        // it confirmed no table), so report empty stdout ⇒ not present — NOT a
        // capture error.
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(not(target_os = "linux"))]
fn capture_nft_nat_table(_nat_table: &str) -> Result<String, ()> {
    Err(())
}

#[cfg(target_os = "linux")]
fn capture_proc_forwarding(path: &str) -> Option<String> {
    // Only a successful read yields a state; a read error returns `None` so the
    // caller fails closed (RSA-0031) rather than defaulting to "0"/"Disabled"
    // (which would falsely read as restored).
    fs::read_to_string(path).ok()
}

#[cfg(not(target_os = "linux"))]
fn capture_proc_forwarding(_path: &str) -> Option<String> {
    None
}

fn nft_nat_table_present(stdout: &str) -> bool {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .any(|line| {
            line.starts_with("table ip ")
                || line.starts_with("chain postrouting")
                || line.contains(" masquerade")
                || line.ends_with(" masquerade")
        })
}

fn parse_proc_forwarding(stdout: &str) -> String {
    match stdout.trim() {
        "1" => "Enabled".to_owned(),
        "0" => "Disabled".to_owned(),
        // Anything else — empty or malformed — is ambiguous and must NOT read as
        // "Disabled" (RSA-0031 / F0.2 fail-closed): a teardown is only confirmed
        // restored on an explicit "0".
        _ => "Unknown".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_NFT: &str = r#"table ip rustynet_nat_g1 {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "enp0s1" masquerade
    }
}"#;

    #[test]
    fn nft_nat_table_present_detects_masquerade_table() {
        assert!(nft_nat_table_present(SAMPLE_NFT));
    }

    #[test]
    fn nft_nat_table_present_treats_empty_output_as_absent() {
        assert!(!nft_nat_table_present(""));
        assert!(!nft_nat_table_present("# comment\n"));
    }

    #[test]
    fn parse_proc_forwarding_canonicalises_enabled() {
        assert_eq!(parse_proc_forwarding("1\n"), "Enabled");
        assert_eq!(parse_proc_forwarding("0\n"), "Disabled");
        // RSA-0031 / F0.2 fail-closed: empty/garbage output is ambiguous and must
        // NOT canonicalise to "Disabled" (which would falsely read as restored).
        assert_eq!(parse_proc_forwarding(""), "Unknown");
        assert_eq!(parse_proc_forwarding("garbage"), "Unknown");
    }

    #[test]
    fn nft_nat_capture_failure_fails_closed_as_present() {
        // RSA-0031 / F0.1: an `nft` spawn/exec FAILURE (capture Err) must report
        // the NAT table as still present (cannot confirm teardown), never absent.
        assert!(interpret_nft_nat_capture(Err(())));
        // A successful capture that genuinely shows no table stays absent.
        assert!(!interpret_nft_nat_capture(Ok(String::new())));
        assert!(!interpret_nft_nat_capture(Ok("# comment\n".to_owned())));
        // A successful capture that shows a masquerade table is present.
        assert!(interpret_nft_nat_capture(Ok(SAMPLE_NFT.to_owned())));
    }

    #[test]
    fn forwarding_capture_failure_fails_closed_as_unknown() {
        // RSA-0031 / F0.2: a failed `/proc/sys` read must NOT read as "Disabled".
        assert_eq!(interpret_forwarding_capture(None), "Unknown");
        // A successful read is canonicalised through `parse_proc_forwarding`.
        assert_eq!(
            interpret_forwarding_capture(Some("0\n".to_owned())),
            "Disabled"
        );
        assert_eq!(
            interpret_forwarding_capture(Some("1\n".to_owned())),
            "Enabled"
        );
        // A successful-but-unparseable read stays "Unknown" (not "Disabled").
        assert_eq!(
            interpret_forwarding_capture(Some("garbage".to_owned())),
            "Unknown"
        );
    }

    #[test]
    fn merge_artifact_does_not_report_teardown_when_forwarding_unverifiable() {
        // RSA-0031 / F0.2 regression: an after-stop snapshot whose forwarding
        // could not be confirmed disabled ("Unknown") must NOT report
        // forwarding_restored.
        let during = build_linux_exit_nat_lifecycle_snapshot(
            1,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            SAMPLE_NFT,
            "1",
            "0",
        );
        let after = build_linux_exit_nat_lifecycle_snapshot(
            2,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            "",
            // A failed/garbage forwarding read canonicalises to "Unknown".
            "garbage",
            "garbage",
        );
        let merged = merge_linux_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["after_stop"]["forwarding_restored"], false);
        assert_eq!(merged["after_stop"]["ipv6_forwarding_restored"], false);
    }

    #[test]
    fn build_snapshot_matches_during_run_shape() {
        let snap = build_linux_exit_nat_lifecycle_snapshot(
            1_780_000_000,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            SAMPLE_NFT,
            "1\n",
            "0\n",
        );
        assert_eq!(snap.schema_version, 1);
        assert_eq!(snap.mesh_cidr, "100.64.0.0/16");
        assert_eq!(snap.nat_table, "rustynet_nat_g1");
        assert!(snap.nat_table_present);
        assert_eq!(snap.internal_prefix, "100.64.0.0/16");
        assert_eq!(snap.tunnel_forwarding, "Enabled");
        assert_eq!(snap.egress_forwarding, "Enabled");
        assert_eq!(snap.ipv6_tunnel_forwarding, "Disabled");
        assert_eq!(snap.ipv6_egress_forwarding, "Disabled");
    }

    #[test]
    fn build_snapshot_after_stop_shape_has_no_nat_and_disabled_forwarding() {
        let snap = build_linux_exit_nat_lifecycle_snapshot(
            1_780_000_100,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            "",
            "0\n",
            "0\n",
        );
        assert!(!snap.nat_table_present);
        assert_eq!(snap.internal_prefix, "");
        assert_eq!(snap.tunnel_forwarding, "Disabled");
        assert_eq!(snap.egress_forwarding, "Disabled");
    }

    #[test]
    fn merge_artifact_matches_validator_contract() {
        let during = build_linux_exit_nat_lifecycle_snapshot(
            1,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            SAMPLE_NFT,
            "1",
            "0",
        );
        let after = build_linux_exit_nat_lifecycle_snapshot(
            2,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            "",
            "0",
            "0",
        );
        let merged = merge_linux_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["schema_version"], 1);
        assert_eq!(merged["mesh_cidr"], "100.64.0.0/16");
        assert_eq!(merged["nat_table"], "rustynet_nat_g1");
        assert_eq!(merged["during_run"]["nat_table_present"], true);
        assert_eq!(merged["during_run"]["internal_prefix"], "100.64.0.0/16");
        assert_eq!(merged["during_run"]["tunnel_forwarding"], "Enabled");
        assert_eq!(merged["during_run"]["egress_forwarding"], "Enabled");
        assert_eq!(merged["after_stop"]["nat_table_present"], false);
        assert_eq!(merged["after_stop"]["forwarding_restored"], true);
    }

    #[test]
    fn merge_artifact_after_stop_forwarding_not_restored_when_enabled() {
        let during = build_linux_exit_nat_lifecycle_snapshot(
            1,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            SAMPLE_NFT,
            "1",
            "0",
        );
        let after = build_linux_exit_nat_lifecycle_snapshot(
            2,
            "100.64.0.0/16",
            "rustynet_nat_g1",
            "",
            "1",
            "0",
        );
        let merged = merge_linux_exit_nat_lifecycle_artifact(&during, &after);
        assert_eq!(merged["after_stop"]["forwarding_restored"], false);
    }

    #[test]
    fn default_options_use_reviewed_nat_table() {
        let opts = LinuxExitNatLifecycleOptions::default();
        assert_eq!(opts.nat_table, DEFAULT_LINUX_EXIT_NAT_TABLE);
        assert_eq!(opts.mesh_cidr, "");
    }
}
