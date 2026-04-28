#![allow(clippy::result_large_err)]

//! Linux service-hardening verifier.
//!
//! Linux parity for `windows_service_hardening`. Confirms the live
//! systemd unit registration for `rustynetd.service` matches the
//! reviewed hardening directives baked into
//! `scripts/systemd/rustynetd.service`. Drift here means an operator
//! (or distro packaging step) has weakened the unit relative to the
//! reviewed posture.
//!
//! The collector dispatches `systemctl show rustynetd.service` and
//! parses the `key=value` output. The pure evaluator takes a parsed
//! property map and walks the reviewed-property table, returning
//! every drift reason in a single pass.
//!
//! Wired through the CLI as `rustynetd linux-service-hardening-check`.
//! The orchestrator's `LinuxDaemonProbe` adapter dispatches the
//! `ServiceHardening` op to this subcommand.
//!
//! Off-Linux the collector emits an unprobed report with an explicit
//! "requires a Linux runtime host" reason.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxServiceHardeningReport {
    pub schema_version: u32,
    pub service_name: String,
    pub overall_ok: bool,
    /// True when the verifier ran a `systemctl show` probe; false when
    /// running off-Linux or `systemctl` is unavailable.
    pub probed: bool,
    pub probe_reason: Option<String>,
    pub drift_reasons: Vec<String>,
    /// The full parsed property map (sorted) so an operator can
    /// see exactly what `systemctl show` reported. Useful for
    /// post-mortem when drift_reasons is non-empty.
    pub observed: BTreeMap<String, String>,
}

/// Reviewed systemd-unit hardening directives. Each entry pins one
/// `key` and the expected `value`. Pulled from the reviewed
/// `scripts/systemd/rustynetd.service` unit file (Phase E hardening).
const REVIEWED_HARDENING_DIRECTIVES: &[(&str, &str)] = &[
    ("User", "rustynetd"),
    ("Group", "rustynetd"),
    ("NoNewPrivileges", "yes"),
    ("PrivateTmp", "yes"),
    ("PrivateDevices", "yes"),
    ("ProtectSystem", "strict"),
    ("ProtectHome", "yes"),
    ("ProtectControlGroups", "yes"),
    ("ProtectKernelTunables", "yes"),
    ("ProtectKernelModules", "yes"),
    ("ProtectKernelLogs", "yes"),
    ("MemoryDenyWriteExecute", "yes"),
    ("LockPersonality", "yes"),
    ("RestrictSUIDSGID", "yes"),
    ("RestrictRealtime", "yes"),
    ("SystemCallArchitectures", "native"),
    // Empty CapabilityBoundingSet means "no caps inherited"; systemctl
    // reports this as the empty string.
    ("CapabilityBoundingSet", ""),
    ("AmbientCapabilities", ""),
    ("UMask", "0077"),
];

pub const REVIEWED_SERVICE_NAME: &str = "rustynetd.service";

/// Pure evaluator: walks the reviewed-property table against a
/// parsed property map. Returns every drift reason in one pass.
pub fn evaluate_linux_service_hardening(observed: &BTreeMap<String, String>) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    if observed.is_empty() {
        reasons
            .push("systemctl show output contained no parseable key=value properties".to_string());
        return reasons;
    }
    for (key, expected) in REVIEWED_HARDENING_DIRECTIVES {
        match observed.get(*key) {
            Some(actual) if actual == expected => {}
            Some(actual) => {
                reasons.push(format!(
                    "{key} drifted: expected {expected:?}, observed {actual:?}"
                ));
            }
            None => {
                reasons.push(format!(
                    "{key} missing from systemctl show output (expected {expected:?})"
                ));
            }
        }
    }
    reasons
}

/// Parse `systemctl show`'s `key=value` line-oriented output into a
/// property map. systemd emits one property per line; multiline
/// values are escaped with `\n`/`\\`. The reviewed directives we care
/// about are scalar so naive split-on-`=` works; the parser returns
/// the empty value for lines like `Foo=` (which `CapabilityBoundingSet`
/// emits in the reviewed posture).
pub fn parse_systemctl_show_output(body: &str) -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for line in body.lines() {
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    map
}

pub fn build_linux_service_hardening_report(
    probed: bool,
    probe_reason: Option<String>,
    observed: BTreeMap<String, String>,
) -> LinuxServiceHardeningReport {
    let drift_reasons = if probed {
        evaluate_linux_service_hardening(&observed)
    } else {
        vec![probe_reason.clone().unwrap_or_else(|| {
            "systemctl show was not run; service hardening posture unknown".to_string()
        })]
    };
    let overall_ok = probed && drift_reasons.is_empty();
    LinuxServiceHardeningReport {
        schema_version: 1,
        service_name: REVIEWED_SERVICE_NAME.to_string(),
        overall_ok,
        probed,
        probe_reason,
        drift_reasons,
        observed,
    }
}

/// Collector: on Linux runs `systemctl show <service>` and parses the
/// output. Off-Linux emits an unprobed report with the off-platform
/// blocker reason.
pub fn collect_linux_service_hardening_report() -> LinuxServiceHardeningReport {
    run_systemctl_show_probe()
}

#[cfg(target_os = "linux")]
fn run_systemctl_show_probe() -> LinuxServiceHardeningReport {
    use std::process::Command;
    let output = match Command::new("systemctl")
        .arg("show")
        .arg(REVIEWED_SERVICE_NAME)
        .output()
    {
        Ok(o) => o,
        Err(err) => {
            return build_linux_service_hardening_report(
                false,
                Some(format!(
                    "systemctl show {REVIEWED_SERVICE_NAME} failed to spawn: {err}"
                )),
                BTreeMap::new(),
            );
        }
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        return build_linux_service_hardening_report(
            false,
            Some(format!(
                "systemctl show {REVIEWED_SERVICE_NAME} exited non-zero: {} (stderr: {})",
                output
                    .status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".to_string()),
                stderr.trim()
            )),
            BTreeMap::new(),
        );
    }
    let body = String::from_utf8_lossy(&output.stdout).into_owned();
    let observed = parse_systemctl_show_output(body.as_str());
    build_linux_service_hardening_report(true, None, observed)
}

#[cfg(not(target_os = "linux"))]
fn run_systemctl_show_probe() -> LinuxServiceHardeningReport {
    build_linux_service_hardening_report(
        false,
        Some(
            "linux-service-hardening-check requires a Linux runtime host with systemctl"
                .to_string(),
        ),
        BTreeMap::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reviewed_property_map() -> BTreeMap<String, String> {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in REVIEWED_HARDENING_DIRECTIVES {
            map.insert((*k).to_string(), (*v).to_string());
        }
        map
    }

    #[test]
    fn parser_handles_empty_value_lines() {
        let body = "User=rustynetd\nCapabilityBoundingSet=\nGroup=rustynetd";
        let map = parse_systemctl_show_output(body);
        assert_eq!(map.get("User").unwrap(), "rustynetd");
        assert_eq!(map.get("Group").unwrap(), "rustynetd");
        assert_eq!(map.get("CapabilityBoundingSet").unwrap(), "");
    }

    #[test]
    fn parser_handles_values_containing_equals() {
        // systemd Environment= lines look like `Environment=FOO=bar BAZ=qux`.
        // Our parser uses `split_once('=')` so the value half retains the
        // equals signs. Pin it.
        let body = "Environment=RUSTYNET_NODE_ID=daemon RUSTYNET_NODE_ROLE=client";
        let map = parse_systemctl_show_output(body);
        assert_eq!(
            map.get("Environment").unwrap(),
            "RUSTYNET_NODE_ID=daemon RUSTYNET_NODE_ROLE=client"
        );
    }

    #[test]
    fn evaluator_accepts_reviewed_property_map() {
        let reasons = evaluate_linux_service_hardening(&reviewed_property_map());
        assert!(
            reasons.is_empty(),
            "reviewed posture must pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_empty_property_map() {
        let reasons = evaluate_linux_service_hardening(&BTreeMap::new());
        assert!(
            reasons.iter().any(|r| r.contains("no parseable")),
            "empty map must surface no-output: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_protect_system_drift() {
        let mut map = reviewed_property_map();
        map.insert("ProtectSystem".to_string(), "false".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("ProtectSystem drifted")),
            "ProtectSystem drift must surface: {reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("\"strict\"")),
            "drift must cite expected value: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_missing_directive() {
        let mut map = reviewed_property_map();
        map.remove("NoNewPrivileges");
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("NoNewPrivileges missing")),
            "missing directive must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_capability_bounding_set_drift_when_caps_added() {
        let mut map = reviewed_property_map();
        map.insert(
            "CapabilityBoundingSet".to_string(),
            "CAP_NET_ADMIN".to_string(),
        );
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("CapabilityBoundingSet drifted")),
            "non-empty caps must surface as drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drifts_in_one_pass() {
        let mut map = reviewed_property_map();
        map.insert("ProtectSystem".to_string(), "false".to_string());
        map.insert("LockPersonality".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("ProtectSystem"))
                && reasons.iter().any(|r| r.contains("LockPersonality")),
            "both drifts must surface: {reasons:?}"
        );
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_observed_map() {
        let report = build_linux_service_hardening_report(true, None, reviewed_property_map());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert!(report.probed);
    }

    #[test]
    fn build_report_unprobed_marks_overall_fail() {
        let report = build_linux_service_hardening_report(
            false,
            Some("systemctl unavailable".to_string()),
            BTreeMap::new(),
        );
        assert!(!report.overall_ok);
        assert!(!report.probed);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("systemctl unavailable")),
            "unprobed must surface probe reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn report_serde_round_trips() {
        let report = build_linux_service_hardening_report(true, None, reviewed_property_map());
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxServiceHardeningReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collector_off_linux_marks_unprobed_with_runtime_host_reason() {
        let report = collect_linux_service_hardening_report();
        assert!(!report.probed);
        assert!(!report.overall_ok);
        assert!(
            report
                .probe_reason
                .as_deref()
                .unwrap_or("")
                .contains("requires a Linux runtime host"),
            "off-Linux must cite runtime-host blocker: {:?}",
            report.probe_reason
        );
    }
}
