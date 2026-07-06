#![allow(dead_code)]
//! Cross-OS IPv6 leak validation for the standard orchestrator.
//!
//! Detects the node's default egress interface, dispatches
//! `rustynetd linux-ipv6-leak-capture` over the hardened
//! [`RemoteShellHost`] seam, and evaluates the captured snapshot with
//! the same logic the bash live-suite uses — `evaluate_linux_ipv6_leak_artifact`
//! in `vm_lab` — which fails closed on schema mismatch, unset/bad probe target,
//! un-attempted probe, leaked datagrams, or absent IPv6 containment.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True only where IPv6-leak validation runs live today (Linux). macOS /
/// Windows nodes are reported-skipped — named on disk, never a silent pass —
/// until their per-OS IPv6 leak probes are proven through the Rust engine.
pub fn ipv6_leak_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Detect the default egress interface on a Linux node by parsing
/// `ip route show default`. Returns the interface name, or an error
/// if detection fails (fail-closed: no interface means cannot verify).
fn detect_linux_egress_interface(shell: &dyn RemoteShellHost) -> Result<String, String> {
    let out = shell
        .run_argv(&["ip", "route", "show", "default"], &[], &[])
        .map_err(|err| format!("failed to query default route for egress interface: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let Some(dev_pos) = parts.iter().position(|&w| w == "dev")
            && let Some(iface) = parts.get(dev_pos + 1)
        {
            return Ok(iface.to_string());
        }
    }
    Err(format!(
        "could not determine egress interface from `ip route show default` output: {stdout}"
    ))
}

/// Run the Linux IPv6-leak capture through the shell seam, applying the
/// typed evaluator. Returns `Err` with detail on failure (fail-closed) or
/// `Ok(())` on pass — where "pass" means the evaluator's full contract
/// (schema, probe attempted, zero leaked datagrams, probe did not reach
/// target, containment control present).
pub fn validate_linux_ipv6_leak(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    let egress_iface = detect_linux_egress_interface(shell)?;
    const SUBCOMMAND: &str = "linux-ipv6-leak-capture";
    let argv = [
        daemon_path,
        SUBCOMMAND,
        "--egress-iface",
        egress_iface.as_str(),
    ];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_ipv6_leak_artifact(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(ipv6_leak_runtime_implemented(VmGuestPlatform::Linux));
        assert!(!ipv6_leak_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!ipv6_leak_runtime_implemented(VmGuestPlatform::Windows));
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

    fn reviewed_ipv6_leak_artifact() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "egress_iface": "enp0s1",
            "probe_target": "2606:4700:4700::1111",
            "killswitch_table": "rustynet_g1",
            "ipv6_disabled": true,
            "killswitch_v6_drop_present": false,
            "leaked_datagram_count": 0,
            "probe_reached_target": false,
            "probe_attempted": true
        })
    }

    #[test]
    fn validate_fails_closed_when_report_is_invalid() {
        let mock = MockShellHost::new();
        let default_route_argv = ["ip", "route", "show", "default"];
        mock.program_run_response(
            &default_route_argv,
            exit_ok("default via 10.0.2.2 dev enp0s1"),
        );
        let bad_report = serde_json::json!({
            "schema_version": 999,
            "egress_iface": "enp0s1",
            "probe_target": "2606:4700:4700::1111",
            "killswitch_table": "rustynet_g1",
            "ipv6_disabled": true,
            "killswitch_v6_drop_present": false,
            "leaked_datagram_count": 0,
            "probe_reached_target": false,
            "probe_attempted": true
        })
        .to_string();
        let capture_argv = [
            TEST_DAEMON,
            "linux-ipv6-leak-capture",
            "--egress-iface",
            "enp0s1",
        ];
        mock.program_run_response(&capture_argv, exit_ok(&bad_report));
        let err = validate_linux_ipv6_leak(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "error must name schema mismatch: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let default_route_argv = ["ip", "route", "show", "default"];
        mock.program_run_response(
            &default_route_argv,
            exit_ok("default via 10.0.2.2 dev enp0s1"),
        );
        let err = validate_linux_ipv6_leak(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("dispatch of `linux-ipv6-leak-capture` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_unattempted_probe() {
        let mock = MockShellHost::new();
        let default_route_argv = ["ip", "route", "show", "default"];
        mock.program_run_response(
            &default_route_argv,
            exit_ok("default via 10.0.2.2 dev enp0s1"),
        );
        let mut payload = reviewed_ipv6_leak_artifact();
        payload["probe_attempted"] = serde_json::Value::Bool(false);
        let capture_argv = [
            TEST_DAEMON,
            "linux-ipv6-leak-capture",
            "--egress-iface",
            "enp0s1",
        ];
        mock.program_run_response(&capture_argv, exit_ok(&payload.to_string()));
        let err = validate_linux_ipv6_leak(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an unattempted probe must fail the stage");
        assert!(
            err.contains("never executed") && err.contains("inconclusive"),
            "error must mention unattempted probe: {err}"
        );
    }
}
