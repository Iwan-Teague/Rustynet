#![allow(dead_code)]
//! Cross-OS blind-exit dataplane validation for the standard orchestrator.
//!
//! Runs `rustynetd linux-blind-exit-dataplane-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_blind_exit_dataplane_report`
//! in `vm_lab`), which fails closed on schema mismatch, wrong stage tag,
//! non-live ruleset source, empty ruleset, missing/erroneous subchecks,
//! or drift reasons present despite overall_ok=true.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

pub fn blind_exit_dataplane_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

pub fn validate_linux_blind_exit_dataplane(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-blind-exit-dataplane-check";
    let argv = [daemon_path, SUBCOMMAND];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_blind_exit_dataplane_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(blind_exit_dataplane_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!blind_exit_dataplane_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!blind_exit_dataplane_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn audit_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-blind-exit-dataplane-check"]
    }

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn reviewed_pass_report() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "stage": "linux_blind_exit_dataplane",
            "overall_ok": true,
            "snapshot": {
                "ruleset_source": "nft list ruleset",
                "host_observable": true,
                "tunnel_iface": "rustynet0",
                "egress_iface": "enp0s1",
                "mesh_cidr": "100.64.0.0/10",
                "ruleset_byte_len": 128,
                "ruleset_sha256": "abc123"
            },
            "subchecks": [
                { "name": "live_nft_ruleset_captured", "status": "pass", "detail": "source=nft list ruleset bytes=128" },
                { "name": "mesh_scoped_forward_allow", "status": "pass", "detail": "iifname=rustynet0 oifname=enp0s1" },
                { "name": "no_nat_translation", "status": "pass", "detail": "no NAT rules" },
                { "name": "no_unrestricted_forward", "status": "pass", "detail": "no unrestricted forward" },
                { "name": "no_own_egress_allow", "status": "pass", "detail": "no own-egress" }
            ],
            "drift_reasons": []
        })
    }

    #[test]
    fn validate_accepts_reviewed_pass_report() {
        let mock = MockShellHost::new();
        let argv = audit_argv();
        mock.program_run_response(&argv, exit_ok(&reviewed_pass_report().to_string()));
        validate_linux_blind_exit_dataplane(&mock, TEST_DAEMON, "deb-1")
            .expect("reviewed pass report must validate");
    }

    #[test]
    fn validate_fails_closed_when_report_has_wrong_schema_version() {
        let mock = MockShellHost::new();
        let argv = audit_argv();
        let mut report = reviewed_pass_report();
        report["schema_version"] = serde_json::json!(999);
        mock.program_run_response(&argv, exit_ok(&report.to_string()));
        let err = validate_linux_blind_exit_dataplane(&mock, TEST_DAEMON, "deb-1")
            .expect_err("wrong schema_version must fail closed");
        assert!(err.contains("unsupported schema_version"));
    }

    #[test]
    fn validate_fails_closed_when_subcheck_is_skipped() {
        let mock = MockShellHost::new();
        let argv = audit_argv();
        let mut report = reviewed_pass_report();
        report["subchecks"] = serde_json::json!([
            { "name": "live_nft_ruleset_captured", "status": "pass", "detail": "ok" },
            { "name": "mesh_scoped_forward_allow", "status": "pass", "detail": "ok" },
            { "name": "no_nat_translation", "status": "skipped", "detail": "not checked" },
            { "name": "no_unrestricted_forward", "status": "pass", "detail": "ok" },
            { "name": "no_own_egress_allow", "status": "pass", "detail": "ok" }
        ]);
        mock.program_run_response(&argv, exit_ok(&report.to_string()));
        let err = validate_linux_blind_exit_dataplane(&mock, TEST_DAEMON, "deb-1")
            .expect_err("skipped NAT subcheck must fail closed");
        assert!(err.contains("no_nat_translation"));
    }

    #[test]
    fn validate_fails_closed_when_host_not_observable() {
        let mock = MockShellHost::new();
        let argv = audit_argv();
        let mut report = reviewed_pass_report();
        let snap = &mut report["snapshot"];
        snap["host_observable"] = serde_json::json!(false);
        snap["ruleset_byte_len"] = serde_json::json!(0);
        snap["ruleset_sha256"] = serde_json::json!("");
        report["subchecks"] = serde_json::json!([]);
        report["overall_ok"] = serde_json::json!(false);
        report["drift_reasons"] = serde_json::json!(["nft unavailable"]);
        mock.program_run_response(&argv, exit_ok(&report.to_string()));
        let err = validate_linux_blind_exit_dataplane(&mock, TEST_DAEMON, "deb-1")
            .expect_err("unobservable ruleset must fail closed");
        assert!(err.contains("not observed live"));
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_blind_exit_dataplane(&mock, TEST_DAEMON, "deb-1")
            .expect_err("dispatch failure must fail closed");
        assert!(
            err.contains("dispatch of `linux-blind-exit-dataplane-check` failed"),
            "error must attribute the dispatch failure: {err}"
        );
    }
}
