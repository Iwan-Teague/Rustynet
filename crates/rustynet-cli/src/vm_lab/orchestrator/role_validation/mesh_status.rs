#![allow(dead_code)]
//! Cross-OS mesh-status validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-mesh-status-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_mesh_status_report` in
//! `vm_lab`), which fails closed on schema mismatch or `overall_ok=false`
//! — so a broken or vacuous check fails the stage rather than silently passing.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;

/// True where mesh-status validation runs live (Linux, macOS, Windows).
pub fn mesh_status_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
}

/// Freshness bound handed to every mesh-status check, in seconds.
///
/// WITHOUT this the check asserts NOTHING. The shared evaluator's `Ok` arm
/// (`windows_mesh_status.rs:162-186`) gates staleness behind `if let Some(max_age)`
/// and iterates `expected_peer_ids`; called with `None` and an empty slice it
/// runs zero checks, so `overall_ok: true` meant only "a state file exists and
/// parses". `macos-utm-1` recorded `MeshStatus: passed` in run
/// `percontrol-rebaseline-20260811` while reaching no peer at all (QH-39).
///
/// A freshness bound is a REAL liveness proof here, not a proxy: `persist_state`
/// (`rustynetd/src/daemon.rs:9126`) rewrites the snapshot after every successful
/// dataplane apply, and the reconcile loop runs at
/// `DEFAULT_RECONCILE_INTERVAL_MS = 1_000` (`daemon.rs:337`). A healthy node's
/// snapshot is therefore seconds old; a dead daemon's, or one whose reconcile
/// keeps failing, goes stale and now fails.
///
/// It also arms a second assertion for free: the negative-age / tampered-file
/// guard is nested INSIDE the same `if let Some(max_age)` arm, so passing no
/// bound silently disabled clock-skew detection too.
///
/// NOT `--expected-peer-id`. That flag exists end-to-end and looks like the
/// obvious fix, but the daemon's `SessionStateSnapshot.peer_ids` is populated
/// from `advertised_routes` — CIDRs, not node ids (`daemon.rs:9129`, restored
/// as routes at `:9196`) — so asserting node ids against it would fail 100% of
/// HEALTHY nodes. Verified before choosing the bound.
///
/// 120 s reuses the bound already shipped elsewhere in this repo
/// (`vm_lab/mod.rs:15736`, `:21351`) rather than inventing a new one.
pub const MESH_STATUS_MAX_AGE_SECS: &str = "120";

/// The argv every platform's mesh-status check dispatches. One builder so the
/// freshness bound cannot be present on some platforms and missing on others.
pub fn mesh_status_argv<'a>(daemon_path: &'a str, subcommand: &'a str) -> [&'a str; 4] {
    [
        daemon_path,
        subcommand,
        "--max-age-seconds",
        MESH_STATUS_MAX_AGE_SECS,
    ]
}

/// Run the Linux mesh-status daemon self-check through the shell seam,
/// applying the typed evaluator. Returns `Err` with detail on failure
/// (fail-closed) or `Ok(())` on pass — where "pass" means the evaluator's full
/// contract (schema, overall_ok), not merely the daemon's exit code.
pub fn validate_linux_mesh_status(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "linux-mesh-status-check";
    let argv = mesh_status_argv(daemon_path, SUBCOMMAND);
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_linux_mesh_status_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_macos_mesh_status(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-mesh-status-check";
    let argv = mesh_status_argv(daemon_path, SUBCOMMAND);
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_macos_mesh_status_report(alias, &stdout)?;
    Ok(())
}

pub fn validate_windows_mesh_status(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "windows-mesh-status-check";
    let argv = mesh_status_argv(daemon_path, SUBCOMMAND);
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_windows_mesh_join_report(alias, &stdout)?;
    Ok(())
}

#[cfg(test)]
mod qh39_tests {
    use super::*;

    const SUBCOMMANDS: [&str; 3] = [
        "linux-mesh-status-check",
        "macos-mesh-status-check",
        "windows-mesh-status-check",
    ];

    #[test]
    fn every_platform_check_carries_the_freshness_bound() {
        // QH-39: with no bound the shared evaluator asserts NOTHING -- its
        // staleness check sits behind `if let Some(max_age)` and its peer loop
        // over an empty slice does nothing -- so `overall_ok: true` meant only
        // "a state file exists and parses". macos-utm-1 recorded MeshStatus
        // passed while reaching no peer at all.
        for subcommand in SUBCOMMANDS {
            let argv = mesh_status_argv("/usr/local/bin/rustynetd", subcommand);
            assert_eq!(argv[1], subcommand);
            assert_eq!(
                argv[2], "--max-age-seconds",
                "{subcommand} must pass a freshness bound"
            );
            assert_eq!(argv[3], MESH_STATUS_MAX_AGE_SECS);
        }
    }

    #[test]
    fn the_bound_is_a_positive_whole_number_of_seconds() {
        // Zero or negative would make every snapshot stale -- a vacuous PASS
        // turned into a vacuous FAIL, which is the same defect inverted.
        let secs: i64 = MESH_STATUS_MAX_AGE_SECS
            .parse()
            .expect("bound must parse as seconds");
        assert!(secs > 0, "bound must be positive, got {secs}");
    }

    #[test]
    fn the_check_never_asserts_node_ids_against_the_snapshot() {
        // The trap this fix avoided. `--expected-peer-id` exists end-to-end and
        // looks like the obvious fix, but SessionStateSnapshot.peer_ids is
        // populated from advertised_routes -- CIDRs, not node ids
        // (rustynetd/src/daemon.rs:9129, restored as routes at :9196) -- so
        // asserting node ids against it would fail 100% of HEALTHY nodes.
        for subcommand in SUBCOMMANDS {
            let argv = mesh_status_argv("/usr/local/bin/rustynetd", subcommand);
            assert!(
                !argv.contains(&"--expected-peer-id"),
                "peer_ids holds CIDRs, not node ids"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_all_desktop() {
        assert!(mesh_status_runtime_implemented(VmGuestPlatform::Linux));
        assert!(mesh_status_runtime_implemented(VmGuestPlatform::Macos));
        assert!(mesh_status_runtime_implemented(VmGuestPlatform::Windows));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn probe_argv() -> [&'static str; 2] {
        [TEST_DAEMON, "linux-mesh-status-check"]
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
            "state_path": "/var/lib/rustynet/mesh.snapshot",
            "overall_ok": true,
            "snapshot": {"load_status": "missing", "reason": "not yet loaded"},
            "expected_peer_ids": [],
            "max_age_seconds": null,
            "drift_reasons": []
        })
        .to_string();
        mock.program_run_response(&argv, exit_ok(&bad_report));
        let err = validate_linux_mesh_status(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an invalid report must fail the stage");
        assert!(
            err.contains("unsupported schema_version"),
            "should reject unsupported schema version, got: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_mesh_status(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a mock that hasn't been configured for this command must fail");
        assert!(
            err.contains("dispatch") && err.contains("failed"),
            "should report dispatch failure, got: {err}"
        );
    }
}
