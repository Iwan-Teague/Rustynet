#![allow(dead_code)]
//! Cross-OS DNS-failclosed validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-dns-failclosed-check --no-fail-on-drift` over the
//! hardened [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_dns_failclosed_report` in `vm_lab`),
//! which fails closed on schema mismatch, `overall_ok=false`, or inconsistent
//! drift output — so a broken or vacuous DNS-failclosed check fails the stage
//! rather than silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True where DNS-failclosed validation runs live (Linux, macOS, Windows).
pub fn dns_failclosed_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// Run the Linux DNS-failclosed daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, overall_ok, consistency), not merely the daemon's exit code.
pub fn validate_linux_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-dns-failclosed-check";
    let argv = [daemon_path, SUBCOMMAND, "--no-fail-on-drift"];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_dns_failclosed_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_macos_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-dns-failclosed-check";
    let argv = [daemon_path, SUBCOMMAND, "--no-fail-on-drift"];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_macos_dns_failclosed_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_windows_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "windows-dns-failclosed-check";
    let argv = [daemon_path, SUBCOMMAND, "--no-fail-on-drift"];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_windows_dns_failclosed_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_all_desktop() {
        assert!(dns_failclosed_runtime_implemented(VmGuestPlatform::Linux));
        assert!(dns_failclosed_runtime_implemented(VmGuestPlatform::Macos));
        assert!(dns_failclosed_runtime_implemented(VmGuestPlatform::Windows));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn audit_argv() -> [&'static str; 3] {
        [
            TEST_DAEMON,
            "linux-dns-failclosed-check",
            "--no-fail-on-drift",
        ]
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
            "overall_ok": false,
            "drift_reasons": [],
            "snapshot": {
                "resolv_conf_path": "/etc/resolv.conf",
                "resolv_conf_present": true,
                "nameservers": ["127.0.0.53"],
                "search_domains": [],
                "loopback_resolver_advertised": true
            }
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "error must name schema mismatch: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of `linux-dns-failclosed-check` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }
}
