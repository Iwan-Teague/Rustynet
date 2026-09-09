#![allow(dead_code)]
//! Cross-OS DNS-failclosed validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-dns-failclosed-check --no-fail-on-drift` over the
//! hardened [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_dns_failclosed_report` in `vm_lab`),
//! which fails closed on schema mismatch, `overall_ok=false`, or inconsistent
//! drift output — so a broken or vacuous DNS-failclosed check fails the stage
//! rather than silently passing.

use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::VmGuestPlatform;

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
    super::require_daemon_success(out.code, SUBCOMMAND, alias, &stdout, |report| {
        crate::vm_lab::evaluate_linux_dns_failclosed_report(alias, report)
    })?;
    Ok(())
}

pub fn validate_macos_dns_failclosed(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
    expected_dns_posture: Option<&str>,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-dns-failclosed-check";
    // Fail closed: the orchestrator must thread the node's expected posture
    // (decided from its planned role). Without it the check could verify the
    // wrong contract and still pass.
    let Some(expected_dns_posture) = expected_dns_posture else {
        return Err(
            "macos-dns-failclosed-check requires an expected DNS posture threaded from the node's planned role"
                .to_owned(),
        );
    };
    let argv = [
        daemon_path,
        SUBCOMMAND,
        "--no-fail-on-drift",
        "--posture",
        expected_dns_posture,
    ];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    super::require_daemon_success(out.code, SUBCOMMAND, alias, &stdout, |report| {
        crate::vm_lab::evaluate_macos_dns_failclosed_report(alias, report, expected_dns_posture)
    })?;
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
    super::require_daemon_success(out.code, SUBCOMMAND, alias, &stdout, |report| {
        crate::vm_lab::evaluate_windows_dns_failclosed_report(alias, report)
            .map(|_| "windows-dns-failclosed-check verified".to_owned())
    })?;
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
    fn validate_linux_fails_closed_when_daemon_exits_non_zero_despite_passing_report() {
        // Mutation: removing the exit-code gate in `require_daemon_success`
        // (or reverting this wrapper to trust the evaluator alone) turns this
        // test green only by accepting a non-zero daemon exit as a pass.
        let mock = MockShellHost::new();
        let argv = audit_argv();
        let clean_report = serde_json::json!({
            "schema_version": 1,
            "overall_ok": true,
            "snapshot": {
                "resolv_conf_path": "/etc/resolv.conf",
                "resolv_conf_present": true,
                "nameservers": ["127.0.0.53"],
                "search_domains": [],
                "loopback_resolver_advertised": true
            },
            "drift_reasons": []
        })
        .to_string();
        mock.program_run_response(
            &argv,
            RemoteExitStatus {
                code: 1,
                stdout: clean_report.into_bytes(),
                stderr: Vec::new(),
            },
        );
        let err = validate_linux_dns_failclosed(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a non-zero daemon exit must fail the stage even with a passing report");
        assert!(
            err.contains("exited non-zero"),
            "error must name the non-zero exit: {err}"
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
