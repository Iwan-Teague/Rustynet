#![allow(dead_code)]
//! Cross-OS exit NAT lifecycle validation for the standard orchestrator.
//!
//! Runs `rustynetd linux-exit-nat-lifecycle-snapshot` twice — once during
//! active exit service (captures NAT table + forwarding state), then again
//! after daemon stop — merges the two-phase artifact with the official
//! [`merge_linux_exit_nat_lifecycle_artifact`] merger, and evaluates it
//! with the same typed evaluator the bash live-suite applies
//! (`evaluate_linux_exit_nat_lifecycle_artifact`).

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role_validation::discover_single_generated_nft_table;

pub fn exit_nat_lifecycle_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

const DEFAULT_MESH_CIDR: &str = "100.64.0.0/10";

/// Run the full two-phase exit NAT lifecycle validation: snapshot during
/// active exit → stop daemon → snapshot after stop → merge → evaluate.
/// Fail-closed on dispatch, parse, merge, or evaluation failure.
pub fn validate_linux_exit_nat_lifecycle(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    let nat_table =
        discover_single_generated_nft_table(shell, "ip", "rustynet_nat_g", "active exit NAT")?;
    let during = capture_nat_lifecycle_snapshot(shell, daemon_path, "during-run", &nat_table)?;
    stop_daemon(shell)?;
    let after = capture_nat_lifecycle_snapshot(shell, daemon_path, "after-stop", &nat_table)?;

    let merged = rustynetd::linux_exit_nat_lifecycle::merge_linux_exit_nat_lifecycle_artifact(
        &during, &after,
    );
    let merged_str = serde_json::to_string(&merged)
        .map_err(|err| format!("serialize merged exit NAT lifecycle artifact: {err}"))?;

    crate::vm_lab::evaluate_linux_exit_nat_lifecycle_artifact(alias, &merged_str)?;
    Ok(())
}

fn capture_nat_lifecycle_snapshot(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    phase: &str,
    nat_table: &str,
) -> Result<rustynetd::linux_exit_nat_lifecycle::LinuxExitNatLifecycleSnapshot, String> {
    let out = shell
        .run_argv(
            &[
                daemon_path,
                "linux-exit-nat-lifecycle-snapshot",
                "--mesh-cidr",
                DEFAULT_MESH_CIDR,
                "--nat-table",
                nat_table,
            ],
            &[],
            &[],
        )
        .map_err(|err| format!("dispatch of {phase} exit NAT lifecycle snapshot failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .map_err(|err| format!("parse {phase} exit NAT lifecycle snapshot failed: {err}"))
}

fn stop_daemon(shell: &dyn RemoteShellHost) -> Result<(), String> {
    let out = shell
        .run_argv(
            &["sudo", "-n", "systemctl", "stop", "rustynetd.service"],
            &[],
            &[],
        )
        .map_err(|err| format!("stop rustynetd for after-stop snapshot failed: {err}"))?;
    if out.code != 0 {
        return Err(format!(
            "stop rustynetd for after-stop snapshot exited {}: {}",
            out.code,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_nat_lifecycle_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_nat_lifecycle_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_nat_lifecycle_runtime_implemented(
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

    fn snapshot_argv() -> [&'static str; 6] {
        [
            TEST_DAEMON,
            "linux-exit-nat-lifecycle-snapshot",
            "--mesh-cidr",
            "100.64.0.0/10",
            "--nat-table",
            "rustynet_nat_g7",
        ]
    }

    fn stop_argv() -> [&'static str; 5] {
        ["sudo", "-n", "systemctl", "stop", "rustynetd.service"]
    }

    fn program_nat_discovery(mock: &MockShellHost) {
        mock.program_run_response(
            &["sudo", "-n", "nft", "list", "tables"],
            exit_ok("table inet rustynet_g7\ntable ip rustynet_nat_g7\n"),
        );
    }

    fn during_snapshot() -> serde_json::Value {
        serde_json::to_value(
            rustynetd::linux_exit_nat_lifecycle::build_linux_exit_nat_lifecycle_snapshot(
                1700000000,
                "100.64.0.0/10",
                "rustynet_nat_g7",
                "table ip rustynet_nat_g7 {\n chain postrouting {\n  oifname \"enp0s1\" masquerade\n }\n}\n",
                "1\n",
                "0\n",
            ),
        )
        .unwrap()
    }

    fn after_snapshot() -> serde_json::Value {
        serde_json::to_value(
            rustynetd::linux_exit_nat_lifecycle::build_linux_exit_nat_lifecycle_snapshot(
                1700000001,
                "100.64.0.0/10",
                "rustynet_nat_g7",
                "",
                "0\n",
                "0\n",
            ),
        )
        .unwrap()
    }

    fn setup_clean_lifecycle_workflow(mock: &MockShellHost) {
        program_nat_discovery(mock);
        let during = during_snapshot();
        mock.program_run_response(&snapshot_argv(), exit_ok(&during.to_string()));

        mock.program_run_response(&stop_argv(), exit_ok(""));

        let after = after_snapshot();
        mock.program_run_response(&snapshot_argv(), exit_ok(&after.to_string()));
    }

    #[test]
    fn validate_accepts_clean_teardown() {
        let mock = MockShellHost::new();
        setup_clean_lifecycle_workflow(&mock);
        validate_linux_exit_nat_lifecycle(&mock, TEST_DAEMON, "deb-1")
            .expect("clean exit NAT lifecycle teardown must validate");
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_exit_nat_lifecycle(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("discover active exit NAT failed")
                || err.contains("during-run exit NAT lifecycle snapshot failed")
                || err.contains("unsupported argv"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_stop_error() {
        let mock = MockShellHost::new();
        program_nat_discovery(&mock);
        let during = during_snapshot();
        mock.program_run_response(&snapshot_argv(), exit_ok(&during.to_string()));
        let err = validate_linux_exit_nat_lifecycle(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a stop-daemon failure must fail the stage");
        assert!(
            err.contains("stop rustynetd") || err.contains("unsupported argv"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_after_stop_snapshot_error() {
        let mock = MockShellHost::new();
        program_nat_discovery(&mock);
        let during = during_snapshot();
        mock.program_run_response(&snapshot_argv(), exit_ok(&during.to_string()));
        mock.program_run_response(&stop_argv(), exit_ok(""));
        let err = validate_linux_exit_nat_lifecycle(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a second-snapshot failure must fail the stage");
        assert!(
            err.contains("after-stop exit NAT lifecycle snapshot failed")
                || err.contains("unsupported argv"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_nat_leftover_after_stop() {
        let during = during_snapshot();
        let after = serde_json::to_value(
            rustynetd::linux_exit_nat_lifecycle::build_linux_exit_nat_lifecycle_snapshot(
                1700000001,
                "100.64.0.0/10",
                "rustynet_nat_g7",
                "table ip rustynet_nat_g7 {\n chain postrouting {\n  oifname \"enp0s1\" masquerade\n }\n}\n",
                "0\n",
                "0\n",
            ),
        )
        .unwrap();
        let merged = rustynetd::linux_exit_nat_lifecycle::merge_linux_exit_nat_lifecycle_artifact(
            &serde_json::from_value(during).unwrap(),
            &serde_json::from_value(after).unwrap(),
        );
        let err =
            crate::vm_lab::evaluate_linux_exit_nat_lifecycle_artifact("deb-1", &merged.to_string())
                .expect_err("leftover NAT after stop must fail closed");
        assert!(
            err.contains("left nftables NAT table present after daemon stop"),
            "unexpected error: {err}"
        );
    }
}
