#![allow(dead_code)]
//! Cross-OS authenticode validation for the standard orchestrator.
//!
//! Authenticode is a Windows-specific runtime binary-signature mechanism
//! (`WinVerifyTrust`). Linux does not enforce binary signatures at runtime —
//! package verification happens at install time. The `linux-authenticode-check`
//! daemon subcommand emits an honest `applicable: false, overall_ok: true`
//! report; the evaluator passes it through with a clear not-applicable summary.
//! For now only Linux is live; macOS / Windows are reported-skipped until their
//! per-OS authenticode probes are proven through the Rust engine.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True where authenticode validation runs live (Linux, macOS, Windows).
pub fn authenticode_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// Run the Linux authenticode daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, overall_ok in every branch), not merely the daemon's exit
/// code. On Linux this passes only when the daemon emits an honest
/// `applicable: false, overall_ok: true` report; the evaluator records the
/// not-applicable verdict and rejects a producer that reports failure.
pub fn validate_linux_authenticode(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    validate_linux_authenticode_report(shell, daemon_path, alias).map(|_| ())
}

/// Run the Linux authenticode check and return the daemon's RAW report JSON on
/// success, so the orchestrator stage can write it as evidence. The Linux
/// producer is a known NON-ATTESTING stub (`applicable: false, overall_ok:
/// true`, zero I/O): the raw report is captured verbatim and the stage must
/// treat a Linux "pass" as a reported skip, never a Passed outcome.
/// Fail-closed on dispatch errors, non-zero exits, and evaluator rejections.
pub fn validate_linux_authenticode_report(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<String, String> {
    const SUBCOMMAND: &str = "linux-authenticode-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.is_success() {
        // Fail-closed on the exit status: if the stdout still carries a
        // failing report, surface the evaluator's drift reasons; a
        // non-zero exit with a PASSING report is unproducible by the real
        // producer, so it must fail too rather than be forgiven.
        return match crate::vm_lab::evaluate_linux_authenticode_report(alias, &stdout) {
            Err(eval_err) => Err(eval_err),
            Ok(_) => Err(format!(
                "`{SUBCOMMAND}` on {alias} exited non-zero (code {}) while emitting a passing \
                 report; failing closed",
                out.code
            )),
        };
    }
    crate::vm_lab::evaluate_linux_authenticode_report(alias, &stdout)?;
    Ok(stdout)
}

/// Run the macOS authenticode check through the shell seam, failing closed on
/// a non-zero daemon exit before the evaluator runs (a non-zero exit with a
/// passing report is unproducible by the real producer).
pub fn validate_macos_authenticode(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-authenticode-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.is_success() {
        return match crate::vm_lab::evaluate_macos_authenticode_report(alias, &stdout) {
            Err(eval_err) => Err(eval_err),
            Ok(_) => Err(format!(
                "`{SUBCOMMAND}` on {alias} exited non-zero (code {}) while emitting a passing \
                 report; failing closed",
                out.code
            )),
        };
    }
    crate::vm_lab::evaluate_macos_authenticode_report(alias, &stdout)?;
    Ok(())
}

/// Run the Windows authenticode check through the shell seam, failing closed
/// on a non-zero daemon exit before the evaluator runs (a non-zero exit with a
/// passing report is unproducible by the real producer).
pub fn validate_windows_authenticode(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "windows-authenticode-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    if !out.is_success() {
        return match crate::vm_lab::evaluate_windows_authenticode_report(alias, &stdout) {
            Err(eval_err) => Err(eval_err),
            Ok(_) => Err(format!(
                "`{SUBCOMMAND}` on {alias} exited non-zero (code {}) while emitting a passing \
                 report; failing closed",
                out.code
            )),
        };
    }
    crate::vm_lab::evaluate_windows_authenticode_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_all_desktop() {
        assert!(authenticode_runtime_implemented(VmGuestPlatform::Linux));
        assert!(authenticode_runtime_implemented(VmGuestPlatform::Macos));
        assert!(authenticode_runtime_implemented(VmGuestPlatform::Windows));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn probe_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-authenticode-check"]
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
            "overall_ok": true,
            "applicable": false,
            "reason": "test"
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_authenticode(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "should reject unsupported schema version, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_authenticode(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a mock that hasn't been configured for this command must fail");
        assert!(
            err.contains("dispatch") && err.contains("failed"),
            "should report dispatch failure, got: {err}"
        );
    }

    // Mutation coverage for the `is_success` gate: removing the non-zero-exit
    // check in `validate_linux_authenticode_report` turns this test red,
    // because a clean report on a non-zero exit would then parse as a pass.
    #[test]
    fn validate_linux_fails_closed_on_non_zero_exit_with_clean_report() {
        let mock = MockShellHost::new();
        let argv = probe_argv();
        let clean_report = serde_json::json!({
            "schema_version": 1,
            "overall_ok": true,
            "applicable": false,
            "reason": "Linux does not enforce binary signatures at runtime"
        })
        .to_string();
        mock.program_run_response(
            &argv,
            RemoteExitStatus {
                code: 1,
                stdout: clean_report.into_bytes(),
                stderr: b"boom".to_vec(),
            },
        );
        let err = validate_linux_authenticode(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a non-zero exit must fail even with a clean report");
        assert!(
            err.contains("exited non-zero"),
            "should report the non-zero exit, got: {err}"
        );
    }

    #[test]
    fn validate_linux_report_returns_raw_stdout_on_pass() {
        let mock = MockShellHost::new();
        let argv = probe_argv();
        let clean_report = serde_json::json!({
            "schema_version": 1,
            "overall_ok": true,
            "applicable": false,
            "reason": "not applicable"
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&clean_report));
        let raw = validate_linux_authenticode_report(&mock, TEST_DAEMON, "deb-1")
            .expect("a clean not-applicable report must pass and be captured");
        assert_eq!(raw, clean_report);
    }
}
