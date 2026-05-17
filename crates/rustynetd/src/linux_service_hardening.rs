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

    // ----- L3: per-directive drift coverage -----
    //
    // The evaluator walks REVIEWED_HARDENING_DIRECTIVES and surfaces a
    // drift reason for any directive that's missing or doesn't match
    // the expected value. Tests below pin each security-critical
    // directive individually so a future refactor that accidentally
    // drops a directive from the table cannot silently relax the
    // hardening contract.

    #[test]
    fn evaluator_rejects_memory_deny_write_execute_drift_to_no() {
        // W^X bypass: a process that can mprotect a region to RWX can
        // load attacker-controlled code. The reviewed posture requires
        // MemoryDenyWriteExecute=yes so the kernel blocks the
        // PROT_WRITE|PROT_EXEC combination.
        let mut map = reviewed_property_map();
        map.insert("MemoryDenyWriteExecute".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("MemoryDenyWriteExecute drifted")),
            "MemoryDenyWriteExecute=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_ambient_capabilities_drift_to_non_empty() {
        // Cap-inheritance attack: AmbientCapabilities= bypasses
        // CapabilityBoundingSet= for child processes. The reviewed
        // posture requires AmbientCapabilities= empty.
        let mut map = reviewed_property_map();
        map.insert(
            "AmbientCapabilities".to_string(),
            "CAP_NET_ADMIN CAP_NET_BIND_SERVICE".to_string(),
        );
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("AmbientCapabilities drifted")),
            "non-empty AmbientCapabilities must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_umask_drift_to_looser_value() {
        // UMask=0022 makes new files world-readable by default — a
        // posture regression if the daemon ever writes secrets through
        // a path that doesn't pin its own mode.
        let mut map = reviewed_property_map();
        map.insert("UMask".to_string(), "0022".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("UMask drifted")),
            "UMask=0022 must surface drift when 0077 is reviewed: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_user_drift_to_root() {
        // The daemon must NOT run as root. The reviewed User=rustynetd.
        let mut map = reviewed_property_map();
        map.insert("User".to_string(), "root".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("User drifted")),
            "User=root must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_group_drift_to_root() {
        let mut map = reviewed_property_map();
        map.insert("Group".to_string(), "root".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("Group drifted")),
            "Group=root must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_protect_home_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("ProtectHome".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("ProtectHome drifted")),
            "ProtectHome=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_protect_kernel_tunables_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("ProtectKernelTunables".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("ProtectKernelTunables drifted")),
            "ProtectKernelTunables=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_protect_kernel_modules_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("ProtectKernelModules".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("ProtectKernelModules drifted")),
            "ProtectKernelModules=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_private_tmp_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("PrivateTmp".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("PrivateTmp drifted")),
            "PrivateTmp=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_private_devices_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("PrivateDevices".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("PrivateDevices drifted")),
            "PrivateDevices=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_lock_personality_drift_to_no() {
        // LockPersonality=no allows changes to the personality(2)
        // syscall, which can be used to emulate old kernel quirks
        // (READ_IMPLIES_EXEC etc.) and bypass mitigations.
        let mut map = reviewed_property_map();
        map.insert("LockPersonality".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("LockPersonality drifted")),
            "LockPersonality=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_restrict_suidsgid_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("RestrictSUIDSGID".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("RestrictSUIDSGID drifted")),
            "RestrictSUIDSGID=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_restrict_realtime_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("RestrictRealtime".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("RestrictRealtime drifted")),
            "RestrictRealtime=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_syscall_architectures_drift_to_compat() {
        // SystemCallArchitectures=native blocks 32-bit syscalls on
        // a 64-bit kernel, closing a class of mitigation-bypass paths.
        let mut map = reviewed_property_map();
        map.insert(
            "SystemCallArchitectures".to_string(),
            "native x86".to_string(),
        );
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("SystemCallArchitectures drifted")),
            "SystemCallArchitectures with compat arch must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_protect_system_drift_to_full() {
        // ProtectSystem=strict (the reviewed value) is stricter than
        // =full. Drift to =full means /etc/ becomes writable inside
        // the service's mount namespace, which the reviewed posture
        // explicitly forbids.
        let mut map = reviewed_property_map();
        map.insert("ProtectSystem".to_string(), "full".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons.iter().any(|r| r.contains("ProtectSystem drifted")),
            "ProtectSystem=full must surface drift when =strict is reviewed: {reasons:?}"
        );
        assert!(
            reasons.iter().any(|r| r.contains("\"strict\"")),
            "drift must cite expected value 'strict': {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_protect_control_groups_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("ProtectControlGroups".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("ProtectControlGroups drifted")),
            "ProtectControlGroups=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_no_new_privileges_drift_to_no() {
        let mut map = reviewed_property_map();
        map.insert("NoNewPrivileges".to_string(), "no".to_string());
        let reasons = evaluate_linux_service_hardening(&map);
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("NoNewPrivileges drifted")),
            "NoNewPrivileges=no must surface drift: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_reviewed_directives_cover_complete_hardening_envelope() {
        // Snapshot test: pins exactly which keys the reviewed
        // hardening table currently inspects, so a future commit that
        // drops a directive forces a corresponding test update.
        let keys: Vec<&str> = REVIEWED_HARDENING_DIRECTIVES
            .iter()
            .map(|(k, _)| *k)
            .collect();
        let expected = [
            "User",
            "Group",
            "NoNewPrivileges",
            "PrivateTmp",
            "PrivateDevices",
            "ProtectSystem",
            "ProtectHome",
            "ProtectControlGroups",
            "ProtectKernelTunables",
            "ProtectKernelModules",
            "ProtectKernelLogs",
            "MemoryDenyWriteExecute",
            "LockPersonality",
            "RestrictSUIDSGID",
            "RestrictRealtime",
            "SystemCallArchitectures",
            "CapabilityBoundingSet",
            "AmbientCapabilities",
            "UMask",
        ];
        assert_eq!(
            keys, expected,
            "REVIEWED_HARDENING_DIRECTIVES changed shape; update this snapshot test in the same commit"
        );
    }

    // ---- L8: reviewed systemd unit content pins ------------------------

    /// Find the reviewed unit file at workspace-relative
    /// `scripts/systemd/rustynetd.service`. Returns the file contents
    /// so individual pins can assert on substring shapes.
    fn read_reviewed_unit_file_body() -> String {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR must be set under cargo test");
        let path = std::path::PathBuf::from(manifest_dir)
            .parent()
            .and_then(|p| p.parent())
            .map(|p| p.join("scripts/systemd/rustynetd.service"))
            .expect("workspace root must resolve");
        std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "failed to read reviewed unit file at {}: {err}",
                path.display()
            )
        })
    }

    #[test]
    fn reviewed_unit_file_includes_killswitch_boot_check_exec_start_pre() {
        // L8: the reviewed unit must invoke
        // `linux-killswitch-boot-check` as an ExecStartPre so the
        // daemon refuses to start when the WireGuard interface is
        // already up but the killswitch table is missing.
        let body = read_reviewed_unit_file_body();
        assert!(
            body.contains("ExecStartPre=/usr/local/bin/rustynetd linux-killswitch-boot-check"),
            "reviewed unit must include the L8 killswitch-boot-check ExecStartPre line; \
             see scripts/systemd/rustynetd.service"
        );
        // The check must NOT use --no-fail-on-drift in the
        // ExecStartPre; that would defeat the fail-closed posture.
        for line in body.lines() {
            if line.trim_start().starts_with("ExecStartPre=")
                && line.contains("linux-killswitch-boot-check")
            {
                assert!(
                    !line.contains("--no-fail-on-drift"),
                    "killswitch-boot-check ExecStartPre must NOT pass --no-fail-on-drift: {line}"
                );
                assert!(
                    line.contains("--iface"),
                    "killswitch-boot-check ExecStartPre must pass --iface for the canonical WG iface: {line}"
                );
            }
        }
    }

    #[test]
    fn reviewed_unit_file_pins_credential_load_lines() {
        // Pin the two encrypted-credential paths so a refactor that
        // accidentally renames `LoadCredentialEncrypted=` lines (or
        // drops them) trips a named failure.
        let body = read_reviewed_unit_file_body();
        assert!(
            body.contains(
                "LoadCredentialEncrypted=wg_key_passphrase:/etc/rustynet/credentials/wg_key_passphrase.cred"
            ),
            "wg_key_passphrase LoadCredentialEncrypted line drifted"
        );
        assert!(
            body.contains(
                "ExecStartPre=/usr/bin/test -f /etc/rustynet/credentials/wg_key_passphrase.cred"
            ),
            "wg_key_passphrase.cred ExecStartPre presence-check drifted"
        );
    }

    #[test]
    fn reviewed_unit_file_pins_memory_deny_write_execute() {
        // Earlier audit work noted the unit DID set
        // `MemoryDenyWriteExecute=true`; this pin keeps it honest
        // against a future refactor that might silently drop it.
        let body = read_reviewed_unit_file_body();
        assert!(
            body.lines()
                .any(|l| l.trim() == "MemoryDenyWriteExecute=true"),
            "MemoryDenyWriteExecute=true must remain in the reviewed unit"
        );
    }
}
