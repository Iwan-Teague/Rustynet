#![allow(dead_code)]
//! Cross-OS key-custody validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-key-custody-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_key_custody_report` in
//! `vm_lab`), which fails closed on schema mismatch, empty entries,
//! `overall_ok=false`, or inconsistent per-entry status — so a broken or
//! vacuous check fails the stage rather than silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True only where key-custody validation runs live today (Linux).
/// macOS / Windows nodes are reported-skipped — named on disk, never a silent
/// pass — until their per-OS key-custody probes are proven through the
/// Rust engine.
pub fn key_custody_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Run the Linux key-custody daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, non-empty entries, overall_ok, consistent per-entry
/// status), not merely the daemon's exit code.
pub fn validate_linux_key_custody(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-key-custody-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_key_custody_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(key_custody_runtime_implemented(VmGuestPlatform::Linux));
        assert!(!key_custody_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!key_custody_runtime_implemented(VmGuestPlatform::Windows));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn probe_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-key-custody-check"]
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
            "entries": [
                {
                    "label": "keys directory",
                    "path": "/var/lib/rustynet/keys",
                    "requirement": "present",
                    "status": "ok",
                    "mode": 33152,
                    "uid": 998,
                    "gid": 998
                }
            ],
            "drift_reasons": []
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_key_custody(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "should reject unsupported schema version, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_empty_entries_report() {
        let mock = MockShellHost::new();
        let argv = probe_argv();
        let empty = serde_json::json!({
            "schema_version": 1,
            "overall_ok": false,
            "entries": [],
            "drift_reasons": ["no entries"]
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&empty));
        let err = validate_linux_key_custody(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an empty-entries report must fail the stage");
        assert!(
            err.contains("empty entries list"),
            "should reject empty entries, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_key_custody(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a mock that hasn't been configured for this command must fail");
        assert!(
            err.contains("dispatch") && err.contains("failed"),
            "should report dispatch failure, got: {err}"
        );
    }
}
