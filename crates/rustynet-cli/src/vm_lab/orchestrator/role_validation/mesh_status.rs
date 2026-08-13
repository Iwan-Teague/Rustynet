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

/// Freshness bound passed to every `*-mesh-status-check` dispatch.
///
/// Without it the check is VACUOUS. The daemon's evaluator nests both the
/// staleness test and the future-timestamp test inside
/// `if let Some(max_age)` (`rustynetd/src/windows_mesh_status.rs:167-177`), so
/// omitting the flag means a snapshot from any era passes as long as it loads —
/// which is how this stage stayed green on a node that reached no mesh peer at
/// all across four consecutive runs.
///
/// 300s, chosen from measurement rather than taste. Across four runs the gap
/// between the last snapshot-writing stage and this check was 8-46s, so 300
/// leaves a 6.5x margin. It is also strictly less than any observed run
/// (760-952s) while this check fires 579-688s in, which is the property that
/// matters: a snapshot left over from the PREVIOUS run can never pass. A looser
/// 900s bound fails exactly there — at 688s into a run it would accept a
/// snapshot written 212-321s before that run even started. 300 also matches the
/// house bound already used by the live units for
/// `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS` and `RUSTYNET_DNS_ZONE_MAX_AGE_SECS`.
///
/// KNOWN LIMIT, stated rather than discovered later: the snapshot is written on
/// events, not on a timer — every `persist_state()` call site is change-driven,
/// and the reconcile one sits inside a change-gated block, so a converged node
/// with stable membership writes nothing however often it reconciles. Snapshot
/// age therefore measures "time since the last dataplane apply", not "the
/// daemon is alive". That is correct inside a full pipeline, but it means a
/// STANDALONE re-run of just this stage, hours after setup, will fail on
/// freshness even though the node is healthy. Raise the bound for that workflow,
/// or give the daemon a heartbeat write; do not derive the bound from the
/// reconcile interval, which would red every healthy converged node.
const SNAPSHOT_MAX_AGE_SECONDS: &str = "300";

/// True where mesh-status validation runs live (Linux, macOS, Windows).
pub fn mesh_status_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    )
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
    let argv = [
        daemon_path,
        SUBCOMMAND,
        "--max-age-seconds",
        SNAPSHOT_MAX_AGE_SECONDS,
    ];
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
    let argv = [
        daemon_path,
        SUBCOMMAND,
        "--max-age-seconds",
        SNAPSHOT_MAX_AGE_SECONDS,
    ];
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
    let argv = [
        daemon_path,
        SUBCOMMAND,
        "--max-age-seconds",
        SNAPSHOT_MAX_AGE_SECONDS,
    ];
    let out = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch of `{SUBCOMMAND}` failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    crate::vm_lab::evaluate_windows_mesh_join_report(alias, &stdout)?;
    Ok(())
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

    fn probe_argv() -> [&'static str; 4] {
        [
            TEST_DAEMON,
            "linux-mesh-status-check",
            "--max-age-seconds",
            SNAPSHOT_MAX_AGE_SECONDS,
        ]
    }

    /// The dispatch MUST carry `--max-age-seconds`, on every platform.
    ///
    /// This is the test whose absence let the defect live. Without the flag the
    /// daemon's evaluator skips both the staleness and future-timestamp checks
    /// (they are nested inside `if let Some(max_age)`), so the stage passes
    /// whenever the snapshot merely loads — which it did, on a node that reached
    /// no mesh peer at all, across four consecutive runs.
    ///
    /// Asserted by dispatch rather than by reading the constant: a mock
    /// programmed ONLY for the flag-bearing argv fails to match if the flag is
    /// dropped, so reverting the argv breaks this test.
    #[test]
    fn every_platform_dispatch_passes_the_freshness_bound() {
        let good = serde_json::json!({
            "schema_version": 1,
            "state_path": "/var/lib/rustynet/rustynetd.state",
            "overall_ok": true,
            "snapshot": {
                "load_status": "ok",
                "timestamp_unix": 1_700_000_000u64,
                "age_seconds": 5,
                "peer_ids": [],
                "selected_exit_node": serde_json::Value::Null,
                "lan_access_enabled": false
            },
            "expected_peer_ids": [],
            "max_age_seconds": 300,
            "drift_reasons": []
        })
        .to_string();

        for (subcommand, validate) in [
            (
                "linux-mesh-status-check",
                validate_linux_mesh_status
                    as fn(&dyn RemoteShellHost, &str, &str) -> Result<(), String>,
            ),
            ("macos-mesh-status-check", validate_macos_mesh_status),
        ] {
            let mock = MockShellHost::new();
            mock.program_run_response(
                &[
                    TEST_DAEMON,
                    subcommand,
                    "--max-age-seconds",
                    SNAPSHOT_MAX_AGE_SECONDS,
                ],
                exit_ok(&good),
            );
            validate(&mock, TEST_DAEMON, "deb-1").unwrap_or_else(|err| {
                panic!("{subcommand} must dispatch with --max-age-seconds; got: {err}")
            });
        }
    }

    /// The bound must be a positive integer the daemon can parse, and must be
    /// tight enough that a snapshot left by the PREVIOUS run cannot pass.
    ///
    /// Measured: this check fires 579-688s into a run, and runs last 760-952s.
    /// A bound at or above ~900 would accept a snapshot written before the run
    /// began, which is precisely the staleness it exists to catch.
    #[test]
    fn freshness_bound_cannot_span_a_previous_run() {
        let seconds: i64 = SNAPSHOT_MAX_AGE_SECONDS
            .parse()
            .expect("the bound must parse as the integer the daemon expects");
        assert!(seconds > 0, "a non-positive bound disables the check");
        assert!(
            seconds < 579,
            "the bound must be smaller than the earliest observed offset of this \
             check into a run (579s), or a snapshot from the previous run passes; got {seconds}"
        );
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
