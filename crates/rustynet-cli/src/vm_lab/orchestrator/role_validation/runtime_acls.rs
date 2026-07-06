#![allow(dead_code)]
//! Cross-OS runtime-ACLs validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-runtime-acls-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_runtime_acls_report` in `vm_lab`),
//! which fails closed on schema mismatch, empty roots, `overall_ok=false`,
//! or inconsistent per-root status — so a broken or vacuous check fails the
//! stage rather than silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True only where runtime-ACLs validation runs live today (Linux). macOS /
/// Windows nodes are reported-skipped — named on disk, never a silent pass —
/// until their per-OS runtime-ACLs probes are proven through the Rust engine.
pub fn runtime_acls_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Run the Linux runtime-ACLs daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, non-empty roots, overall_ok, consistent per-root status),
/// not merely the daemon's exit code.
pub fn validate_linux_runtime_acls(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-runtime-acls-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_runtime_acls_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(runtime_acls_runtime_implemented(VmGuestPlatform::Linux));
        assert!(!runtime_acls_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!runtime_acls_runtime_implemented(VmGuestPlatform::Windows));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn audit_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-runtime-acls-check"]
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
        let argv = audit_argv();
        let bad_report = serde_json::json!({
            "schema_version": 999,
            "overall_ok": true,
            "roots": [
                {"label": "home", "path": "/home", "status": "ok"}
            ]
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_runtime_acls(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "error must name schema mismatch: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_runtime_acls(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of `linux-runtime-acls-check` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }
}
