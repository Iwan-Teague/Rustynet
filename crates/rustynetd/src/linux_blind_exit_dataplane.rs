#![allow(clippy::result_large_err)]

//! Live Linux `blind_exit` dataplane verifier.
//!
//! This check is intentionally narrower than a packet-path lab: it captures the
//! guest's live `nft list ruleset` via argv-only execution, then runs the same
//! hardened evaluator used by the daemon's Linux blind-exit dataplane module.
//! It must not pass from generated plans or dry-run text.

use crate::linux_blind_exit::{LinuxBlindExitConfig, evaluate_linux_blind_exit_ruleset};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::process::Command;

pub const DEFAULT_BLIND_EXIT_TUNNEL_IFACE: &str = "rustynet0";
pub const DEFAULT_BLIND_EXIT_MESH_CIDR: &str = "100.64.0.0/10";
pub const DEFAULT_NFT_PATH: &str = "nft";
const DEFAULT_IP_PATH: &str = "ip";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxBlindExitDataplaneOptions {
    pub tunnel_iface: String,
    pub egress_iface: Option<String>,
    pub mesh_cidr: String,
    pub nft_path: String,
}

impl Default for LinuxBlindExitDataplaneOptions {
    fn default() -> Self {
        Self {
            tunnel_iface: DEFAULT_BLIND_EXIT_TUNNEL_IFACE.to_owned(),
            egress_iface: None,
            mesh_cidr: DEFAULT_BLIND_EXIT_MESH_CIDR.to_owned(),
            nft_path: DEFAULT_NFT_PATH.to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxBlindExitDataplaneSubcheck {
    pub name: String,
    pub status: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxBlindExitDataplaneSnapshot {
    pub ruleset_source: String,
    pub host_observable: bool,
    pub tunnel_iface: String,
    pub egress_iface: String,
    pub mesh_cidr: String,
    pub ruleset_byte_len: usize,
    pub ruleset_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxBlindExitDataplaneReport {
    pub schema_version: u32,
    pub stage: String,
    pub overall_ok: bool,
    pub snapshot: LinuxBlindExitDataplaneSnapshot,
    pub subchecks: Vec<LinuxBlindExitDataplaneSubcheck>,
    pub drift_reasons: Vec<String>,
}

pub fn collect_linux_blind_exit_dataplane_report(
    options: LinuxBlindExitDataplaneOptions,
) -> LinuxBlindExitDataplaneReport {
    if std::env::consts::OS != "linux" {
        return build_unobservable_report(
            options,
            "",
            "linux-blind-exit-dataplane-check requires a Linux host",
        );
    }

    let egress_iface = match options.egress_iface.clone() {
        Some(iface) => iface,
        None => match detect_default_egress_iface() {
            Ok(iface) => iface,
            Err(err) => return build_unobservable_report(options, "", err.as_str()),
        },
    };
    let config = match LinuxBlindExitConfig::new(
        options.tunnel_iface.as_str(),
        egress_iface.as_str(),
        options.mesh_cidr.as_str(),
    ) {
        Ok(config) => config,
        Err(err) => {
            let snapshot = LinuxBlindExitDataplaneSnapshot {
                ruleset_source: "config validation".to_owned(),
                host_observable: false,
                tunnel_iface: options.tunnel_iface,
                egress_iface,
                mesh_cidr: options.mesh_cidr,
                ruleset_byte_len: 0,
                ruleset_sha256: String::new(),
            };
            return build_report(snapshot, vec![err]);
        }
    };

    let ruleset = match capture_nft_ruleset(options.nft_path.as_str()) {
        Ok(ruleset) => ruleset,
        Err(err) => {
            return build_unobservable_report(
                LinuxBlindExitDataplaneOptions {
                    tunnel_iface: config.tunnel_interface.clone(),
                    egress_iface: Some(config.egress_interface.clone()),
                    mesh_cidr: config.mesh_cidr.clone(),
                    nft_path: options.nft_path,
                },
                "",
                err.as_str(),
            );
        }
    };
    build_linux_blind_exit_dataplane_report_from_ruleset("nft list ruleset", &ruleset, &config)
}

pub fn build_linux_blind_exit_dataplane_report_from_ruleset(
    ruleset_source: &str,
    ruleset: &str,
    config: &LinuxBlindExitConfig,
) -> LinuxBlindExitDataplaneReport {
    let mut reasons = Vec::new();
    if ruleset.trim().is_empty() {
        reasons.push("live nft ruleset capture was empty".to_owned());
    }
    reasons.extend(evaluate_linux_blind_exit_ruleset(ruleset, config));
    let snapshot = LinuxBlindExitDataplaneSnapshot {
        ruleset_source: ruleset_source.to_owned(),
        host_observable: true,
        tunnel_iface: config.tunnel_interface.clone(),
        egress_iface: config.egress_interface.clone(),
        mesh_cidr: config.mesh_cidr.clone(),
        ruleset_byte_len: ruleset.len(),
        ruleset_sha256: sha256_hex(ruleset.as_bytes()),
    };
    build_report(snapshot, reasons)
}

fn build_unobservable_report(
    options: LinuxBlindExitDataplaneOptions,
    egress_iface: &str,
    reason: &str,
) -> LinuxBlindExitDataplaneReport {
    let snapshot = LinuxBlindExitDataplaneSnapshot {
        ruleset_source: "nft list ruleset".to_owned(),
        host_observable: false,
        tunnel_iface: options.tunnel_iface,
        egress_iface: options
            .egress_iface
            .unwrap_or_else(|| egress_iface.to_owned()),
        mesh_cidr: options.mesh_cidr,
        ruleset_byte_len: 0,
        ruleset_sha256: String::new(),
    };
    build_report(snapshot, vec![reason.to_owned()])
}

fn build_report(
    snapshot: LinuxBlindExitDataplaneSnapshot,
    drift_reasons: Vec<String>,
) -> LinuxBlindExitDataplaneReport {
    let subchecks = build_subchecks(&snapshot, &drift_reasons);
    LinuxBlindExitDataplaneReport {
        schema_version: 1,
        stage: "linux_blind_exit_dataplane".to_owned(),
        overall_ok: snapshot.host_observable && drift_reasons.is_empty(),
        snapshot,
        subchecks,
        drift_reasons,
    }
}

fn build_subchecks(
    snapshot: &LinuxBlindExitDataplaneSnapshot,
    drift_reasons: &[String],
) -> Vec<LinuxBlindExitDataplaneSubcheck> {
    let captured = snapshot.host_observable && snapshot.ruleset_byte_len > 0;
    let no_reason_contains = |needle: &str| {
        !drift_reasons
            .iter()
            .any(|reason| reason.to_ascii_lowercase().contains(needle))
    };
    vec![
        subcheck(
            "live_nft_ruleset_captured",
            captured,
            format!(
                "source={} bytes={} sha256={}",
                snapshot.ruleset_source, snapshot.ruleset_byte_len, snapshot.ruleset_sha256
            ),
        ),
        subcheck(
            "mesh_scoped_forward_allow",
            captured && no_reason_contains("missing mesh-scoped"),
            format!(
                "iifname={} oifname={} saddr={}",
                snapshot.tunnel_iface, snapshot.egress_iface, snapshot.mesh_cidr
            ),
        ),
        subcheck(
            "no_nat_translation",
            captured && no_reason_contains("must not contain nat"),
            "masquerade/snat/dnat absent from evaluated ruleset".to_owned(),
        ),
        subcheck(
            "no_unrestricted_forward",
            captured && no_reason_contains("unrestricted"),
            "regular-exit tunnel-to-egress allow absent".to_owned(),
        ),
        subcheck(
            "no_own_egress_allow",
            captured && no_reason_contains("own-egress"),
            "regular-exit local-origin egress allow absent".to_owned(),
        ),
    ]
}

fn subcheck(name: &str, passed: bool, detail: String) -> LinuxBlindExitDataplaneSubcheck {
    LinuxBlindExitDataplaneSubcheck {
        name: name.to_owned(),
        status: if passed { "pass" } else { "fail" }.to_owned(),
        detail,
    }
}

fn capture_nft_ruleset(nft_path: &str) -> Result<String, String> {
    ensure_argv_token("nft path", nft_path)?;
    let output = Command::new(nft_path)
        .args(["list", "ruleset"])
        .output()
        .map_err(|err| format!("execute `{nft_path} list ruleset` failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let detail = if stderr.is_empty() {
            format!("status {}", output.status)
        } else {
            stderr
        };
        return Err(format!("`{nft_path} list ruleset` failed: {detail}"));
    }
    String::from_utf8(output.stdout)
        .map_err(|err| format!("`{nft_path} list ruleset` returned non-UTF-8 output: {err}"))
}

fn detect_default_egress_iface() -> Result<String, String> {
    let output = Command::new(DEFAULT_IP_PATH)
        .args(["-o", "-4", "route", "show", "default"])
        .output()
        .map_err(|err| format!("detect default egress interface failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{DEFAULT_IP_PATH} -o -4 route show default` failed with status {}",
            output.status
        ));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|err| format!("default-route output was non-UTF-8: {err}"))?;
    parse_default_route_iface(stdout.as_str())
}

fn parse_default_route_iface(output: &str) -> Result<String, String> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        while let Some(part) = parts.next() {
            if part == "dev" {
                let iface = parts
                    .next()
                    .ok_or_else(|| "default route contains `dev` without interface".to_owned())?;
                ensure_argv_token("default egress interface", iface)?;
                return Ok(iface.to_owned());
            }
        }
    }
    Err("default egress interface not found in `ip route show default` output".to_owned())
}

fn ensure_argv_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    if value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!("{label} contains a control character"));
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> LinuxBlindExitConfig {
        LinuxBlindExitConfig::new("rustynet0", "enp0s1", "100.64.0.0/10").unwrap()
    }

    #[test]
    fn report_accepts_live_hardened_ruleset_shape() {
        let ruleset = r#"
table inet rustynet_g1 {
 chain forward {
  ct state established,related accept
  iifname "rustynet0" oifname "enp0s1" ip saddr 100.64.0.0/10 accept
 }
}
"#;
        let report =
            build_linux_blind_exit_dataplane_report_from_ruleset("test ruleset", ruleset, &cfg());
        assert!(report.overall_ok, "{report:?}");
        assert!(report.drift_reasons.is_empty());
        assert!(
            report
                .subchecks
                .iter()
                .all(|subcheck| subcheck.status == "pass")
        );
    }

    #[test]
    fn report_rejects_regular_exit_nat_and_unrestricted_forward() {
        let ruleset = r#"
table inet rustynet_g1 {
 chain forward {
  iifname "rustynet0" oifname "enp0s1" accept
  oifname "enp0s1" accept
 }
}
table ip rustynet_nat_g1 {
 chain postrouting {
  oifname "enp0s1" masquerade
 }
}
"#;
        let report =
            build_linux_blind_exit_dataplane_report_from_ruleset("test ruleset", ruleset, &cfg());
        assert!(!report.overall_ok);
        assert!(report.drift_reasons.iter().any(|r| r.contains("NAT")));
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("unrestricted"))
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("own-egress"))
        );
    }

    #[test]
    fn parse_default_route_iface_extracts_dev_value() {
        let iface = parse_default_route_iface("default via 192.168.64.1 dev enp0s1 proto dhcp\n")
            .expect("iface");
        assert_eq!(iface, "enp0s1");
    }
}
