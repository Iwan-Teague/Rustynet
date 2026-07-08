#![allow(dead_code)]
//! Cross-OS service-hardening validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-service-hardening-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_service_hardening_report` in
//! `vm_lab`), which fails closed on schema mismatch, missing probe,
//! `overall_ok=false`, or inconsistent drift reasons — so a broken or
//! vacuous check fails the stage rather than silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True where service-hardening validation runs live (Linux, macOS, Windows).
pub fn service_hardening_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// Run the Linux service-hardening daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, probed, overall_ok, consistent drift reasons), not merely
/// the daemon's exit code.
pub fn validate_linux_service_hardening(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-service-hardening-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_service_hardening_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_macos_service_hardening(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-service-hardening-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_macos_service_hardening_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_windows_service_hardening(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "windows-service-hardening-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_windows_service_hardening_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_all_desktop() {
        assert!(service_hardening_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(service_hardening_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(service_hardening_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn probe_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-service-hardening-check"]
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    #[test]
    fn validate_fails_closed_when_report_is_invalid() {
        let mock = MockShellHost::new();
        let argv = probe_argv();
        let bad_report = serde_json::json!({
            "schema_version": 999,
            "service_name": "rustynetd.service",
            "overall_ok": true,
            "probed": true,
            "probe_reason": null,
            "drift_reasons": [],
            "observed": {}
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_service_hardening(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "should reject unsupported schema version, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_unprobed_report() {
        let mock = MockShellHost::new();
        let argv = probe_argv();
        let unprobed = serde_json::json!({
            "schema_version": 1,
            "service_name": "rustynetd.service",
            "overall_ok": false,
            "probed": false,
            "probe_reason": "systemctl not available",
            "drift_reasons": [],
            "observed": {}
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&unprobed));
        let err = validate_linux_service_hardening(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an unprobed report must fail the stage");
        assert!(
            err.contains("could not run"),
            "should reject unprobed report, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_service_hardening(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a mock that hasn't been configured for this command must fail");
        assert!(
            err.contains("dispatch") && err.contains("failed"),
            "should report dispatch failure, got: {err}"
        );
    }
}
