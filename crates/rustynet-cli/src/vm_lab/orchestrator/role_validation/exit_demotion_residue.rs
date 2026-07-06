#![allow(dead_code)]
//! Cross-OS exit-demotion-residue validation for the standard orchestrator.
//!
//! Runs the two-phase exit→client demotion capture on a Linux exit node:
//! snapshot the NAT table before demotion (anti-vacuous "was serving exit"
//! guard), demote through the public CLI surface, then snapshot again
//! post-demotion to prove the NAT table is gone AND forwarding is restored
//! with the daemon still running.
//!
//! The merged artifact is evaluated by
//! `evaluate_linux_exit_demotion_residue_artifact` — the SAME evaluator
//! the bash live-suite applies — which fails closed on residual NAT,
//! forwarding-leak, vacuous before-state, or a stopped daemon.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// Exit-demotion-residue validation runs live on Linux today.
/// macOS / Windows nodes are reported-skipped — named on disk, never a
/// silent pass — until their per-OS exit-demotion probes are proven
/// through the Rust engine.
pub fn exit_demotion_residue_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Default mesh CIDR used when dispatching
/// `linux-exit-nat-lifecycle-snapshot`. Mirrors the bash capture script's
/// default and the WireGuard address-space convention (100.64.0.0/10,
/// RFC 6598 CGNAT prefix).
const DEFAULT_MESH_CIDR: &str = "100.64.0.0/10";

const DEFAULT_NAT_TABLE: &str = "rustynet_nat_g1";

const RUSTYNET_CLI_PATH: &str = "/usr/local/bin/rustynet";

const SETTLE_SECS: &str = "4";

/// Run the full two-phase exit→client demotion capture on a Linux exit
/// node: snapshot→demote→check-daemon→settle→snapshot→merge→evaluate.
///
/// Side-effect: demotes the node from exit to client through the
/// public CLI surface (`rustynet role set client`). This is intentional
/// and mirrors the bash capture script — the stage must run while the
/// node is actively serving exit traffic.
pub fn validate_linux_exit_demotion_residue(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    let during_snapshot = capture_nat_lifecycle_snapshot(shell, daemon_path)?;
    let demotion_exit_code = demote_to_client(shell)?;
    let daemon_still_running = check_daemon_running(shell);
    let _ = shell.run_argv(&["sleep", SETTLE_SECS], &[], &[]);
    let after_snapshot = capture_nat_lifecycle_snapshot(shell, daemon_path)?;

    let merged = merge_demotion_residue_artifact(
        &during_snapshot,
        &after_snapshot,
        demotion_exit_code,
        daemon_still_running,
    );
    let merged_str = serde_json::to_string(&merged)
        .map_err(|err| format!("serialize merged demotion residue artifact: {err}"))?;

    crate::vm_lab::evaluate_linux_exit_demotion_residue_artifact(alias, &merged_str)?;
    Ok(())
}

fn capture_nat_lifecycle_snapshot(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
) -> Result<serde_json::Value, String> {
    let out = shell
        .run_argv(
            &[
                daemon_path,
                "linux-exit-nat-lifecycle-snapshot",
                "--mesh-cidr",
                DEFAULT_MESH_CIDR,
                "--nat-table",
                DEFAULT_NAT_TABLE,
            ],
            &[],
            &[],
        )
        .map_err(|err| format!("dispatch of linux-exit-nat-lifecycle-snapshot failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .map_err(|err| format!("parse linux-exit-nat-lifecycle-snapshot JSON: {err}"))
}

fn demote_to_client(shell: &dyn RemoteShellHost) -> Result<i32, String> {
    let out = shell
        .run_argv(&[RUSTYNET_CLI_PATH, "role", "set", "client"], &[], &[])
        .map_err(|err| format!("demotion (role set client) failed: {err}"))?;
    Ok(out.code)
}

fn check_daemon_running(shell: &dyn RemoteShellHost) -> bool {
    shell
        .run_argv(
            &["systemctl", "is-active", "--quiet", "rustynetd.service"],
            &[],
            &[],
        )
        .is_ok()
}

/// Merge two `LinuxExitNatLifecycleSnapshot` payloads into the artifact
/// format consumed by `evaluate_linux_exit_demotion_residue_artifact`.
/// Fail-closed defaults match the bash capture script:
/// - `during_run.nat_table_present` → `false` (anti-vacuous)  
/// - `after_demote.nat_table_present` → `true` (still-present)  
/// - Missing forwarding fields → `"Unknown"` (never `"Disabled"`)
fn merge_demotion_residue_artifact(
    during: &serde_json::Value,
    after: &serde_json::Value,
    demotion_exit_code: i32,
    daemon_still_running: bool,
) -> serde_json::Value {
    let after_tunnel = after_val_str(after, "tunnel_forwarding", "Unknown").to_lowercase();
    let after_egress = after_val_str(after, "egress_forwarding", "Unknown").to_lowercase();
    let forwarding_restored = after_tunnel == "disabled" && after_egress == "disabled";

    let after_v6_t = after_val_str(after, "ipv6_tunnel_forwarding", "Unknown").to_lowercase();
    let after_v6_e = after_val_str(after, "ipv6_egress_forwarding", "Unknown").to_lowercase();
    let ipv6_forwarding_restored = after_v6_t == "disabled" && after_v6_e == "disabled";

    serde_json::json!({
        "schema_version": 1,
        "mesh_cidr": after_val_str(during, "mesh_cidr", ""),
        "nat_table": after_val_str(during, "nat_table", ""),
        "demotion_exit_code": demotion_exit_code,
        "daemon_still_running": daemon_still_running,
        "during_run": {
            "nat_table_present": after_val_bool(during, "nat_table_present", false),
            "internal_prefix": after_val_str(during, "internal_prefix", ""),
            "tunnel_forwarding": after_val_str(during, "tunnel_forwarding", "Unknown"),
            "egress_forwarding": after_val_str(during, "egress_forwarding", "Unknown"),
        },
        "after_demote": {
            "nat_table_present": after_val_bool(after, "nat_table_present", true),
            "forwarding_restored": forwarding_restored,
            "ipv6_forwarding_restored": ipv6_forwarding_restored,
        },
    })
}

fn after_val_str(val: &serde_json::Value, key: &str, default: &str) -> String {
    val.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn after_val_bool(val: &serde_json::Value, key: &str, default: bool) -> bool {
    val.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn exit_code(code: i32) -> RemoteExitStatus {
        RemoteExitStatus {
            code,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn demo_snapshot(nat_present: bool, tunnel_fwd: &str, egress_fwd: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "captured_at_unix": 1700000000_u64,
            "mesh_cidr": "100.64.0.0/10",
            "nat_table": "rustynet_nat_g1",
            "nat_table_present": nat_present,
            "internal_prefix": if nat_present { "100.64.0.0/10" } else { "" },
            "tunnel_forwarding": tunnel_fwd,
            "egress_forwarding": egress_fwd,
            "ipv6_tunnel_forwarding": "Disabled",
            "ipv6_egress_forwarding": "Disabled",
        })
    }

    fn setup_clean_demotion_workflow(
        mock: &MockShellHost,
    ) -> ([&'static str; 6], [&'static str; 4], [&'static str; 4]) {
        let snapshot_argv: [&'static str; 6] = [
            TEST_DAEMON,
            "linux-exit-nat-lifecycle-snapshot",
            "--mesh-cidr",
            "100.64.0.0/10",
            "--nat-table",
            "rustynet_nat_g1",
        ];
        let demote_argv: [&'static str; 4] = ["/usr/local/bin/rustynet", "role", "set", "client"];
        let daemon_argv: [&'static str; 4] =
            ["systemctl", "is-active", "--quiet", "rustynetd.service"];

        let during = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&snapshot_argv, exit_ok(&during.to_string()));

        mock.program_run_response(&demote_argv, exit_code(0));

        mock.program_run_response(&daemon_argv, exit_ok("active"));

        mock.program_run_response(&["sleep", "4"], exit_ok(""));

        let after = demo_snapshot(false, "Disabled", "Disabled");
        mock.program_run_response(&snapshot_argv, exit_ok(&after.to_string()));

        (snapshot_argv, demote_argv, daemon_argv)
    }

    #[test]
    fn validate_accepts_clean_teardown() {
        let mock = MockShellHost::new();
        setup_clean_demotion_workflow(&mock);
        validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect("clean demotion teardown must validate");
    }
    #[test]
    fn validate_fails_closed_on_residual_nat() {
        let during = demo_snapshot(true, "Enabled", "Enabled");
        let after = demo_snapshot(true, "Enabled", "Enabled");
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        let err = crate::vm_lab::evaluate_linux_exit_demotion_residue_artifact(
            "deb-1",
            &merged.to_string(),
        )
        .expect_err("residual NAT after demotion must fail closed");
        assert!(
            err.contains("residual open relay") || err.contains("NAT table present after"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of linux-exit-nat-lifecycle-snapshot failed")
                || err.contains("unsupported argv"),
            "unexpected error: {err}"
        );
    }

    /// Returns the argv slices as owned values so the caller can modify
    /// individual responses without repeating the constant definitions.
    fn setup_clean_demotion_workflow_items(
        mock: &MockShellHost,
    ) -> ([&'static str; 6], [&'static str; 4], [&'static str; 4]) {
        setup_clean_demotion_workflow(mock)
    }

    #[test]
    fn merge_forwarding_restored_requires_both_disabled() {
        let during = demo_snapshot(true, "Enabled", "Enabled");
        let after = demo_snapshot(false, "Disabled", "Enabled");
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        assert!(
            !merged["after_demote"]["forwarding_restored"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn merge_defaults_missing_fields_fail_closed() {
        let during = serde_json::json!({"schema_version": 1});
        let after = serde_json::json!({"schema_version": 1});
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        assert!(!merged["during_run"]["nat_table_present"].as_bool().unwrap());
        assert!(
            merged["after_demote"]["nat_table_present"]
                .as_bool()
                .unwrap()
        );
    }
}
