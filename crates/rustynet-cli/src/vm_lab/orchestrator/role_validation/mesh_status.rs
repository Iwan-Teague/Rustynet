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
/// 180s, chosen from measurement and corrected twice by review.
///
/// Lower bound — must not red a healthy node. Measured across 15 archived runs,
/// the gap between the last snapshot-writing stage (`validate_baseline_runtime`,
/// downstream of the daemon restart in `enforce_baseline_runtime`) and this
/// check is 3-8s. 180 leaves a 22x margin on that. A review reported a worst
/// observed snapshot age of 38s over a wider archive; that figure could NOT be
/// reproduced from the artifacts retained here (only two standalone
/// windows-exit-evidence reports carry `age_seconds`, both ~315000s), so it is
/// recorded as unverified and treated conservatively — 180 still clears it 4.7x.
///
/// Upper bound — belt-and-braces, not load-bearing. Measured earliest offset of
/// this check into a run is 232s, so a bound at or above that could accept a
/// snapshot predating the run. It cannot in practice: `cleanup_hosts` runs
/// `rm -rf /var/lib/rustynet` (`adapter/linux_install.rs:358`), so no snapshot
/// survives into the next run at all — verified live on a torn-down guest, which
/// reports `state snapshot missing`. The bound's real job is catching a daemon
/// that wedged MID-run and stopped persisting.
///
/// NOT the bundle bound, and the earlier claim that it matched one was inverted.
/// The lab deliberately sets `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS` and
/// `RUSTYNET_DNS_ZONE_MAX_AGE_SECS` to 86400 (`adapter/linux_install.rs:200-207`)
/// precisely because "the default 300-s window causes dns_alarm_state=error once
/// the bundle ages past 5 minutes". Those bundles are issued once and never
/// refreshed; the snapshot IS refreshed by the daemon restart every run, which is
/// why a tight bound is correct here and wrong there.
///
/// KNOWN LIMIT: the snapshot is written on events, not on a timer, so any
/// invocation that does not re-run `enforce_baseline_runtime` will see an old
/// snapshot and fail on freshness even though the node is healthy — `--run-only`,
/// `--resume-from` a later stage, and a single-stage re-run all reuse that stage
/// rather than executing it. Raise the bound for those workflows, or give the
/// daemon a heartbeat write; do not derive it from the reconcile interval, which
/// would red every healthy converged node.
pub(crate) const SNAPSHOT_MAX_AGE_SECONDS: &str = "180";

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

/// Run the macOS mesh-status daemon self-check through the shell seam,
/// applying the typed evaluator. `expected_node_id` is the node id the
/// orchestrator recorded for this slot (§4.7 identity challenge) — when
/// known it is dispatched as `--expected-node-id` so the daemon must find it
/// among the VERIFIED membership node ids: the peer-visibility assertion
/// becomes node-id-exact instead of the route-CIDR presence check alone.
/// The evaluator additionally fails closed when the report does not carry a
/// verified membership node-id list at all.
pub fn validate_macos_mesh_status(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
    expected_node_id: Option<&str>,
) -> Result<(), String> {
    const SUBCOMMAND: &str = "macos-mesh-status-check";
    let mut argv: Vec<&str> = vec![
        daemon_path,
        SUBCOMMAND,
        "--max-age-seconds",
        SNAPSHOT_MAX_AGE_SECONDS,
    ];
    if let Some(node_id) = expected_node_id {
        argv.push("--expected-node-id");
        argv.push(node_id);
    }
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

    /// Good macOS report body: membership VERIFIED so it clears the
    /// evaluator's fail-closed member_node_ids check.
    fn macos_good_report() -> String {
        serde_json::json!({
            "schema_version": 1,
            "state_path": "/usr/local/var/rustynet/rustynetd.state",
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
            "max_age_seconds": 180,
            "drift_reasons": [],
            "membership_snapshot_path": "/usr/local/var/rustynet/membership/membership.snapshot",
            "expected_node_ids": ["node-9"],
            "member_node_ids": {
                "membership_load_status": "verified",
                "node_ids": ["node-9"]
            }
        })
        .to_string()
    }

    fn macos_argv(extra: &[&'static str]) -> Vec<&'static str> {
        let mut argv: Vec<&'static str> = vec![
            TEST_DAEMON,
            "macos-mesh-status-check",
            "--max-age-seconds",
            SNAPSHOT_MAX_AGE_SECONDS,
        ];
        argv.extend_from_slice(extra);
        argv
    }

    /// The dispatch MUST carry `--expected-node-id` when the orchestrator
    /// knows the slot's node id: the peer-visibility assertion is
    /// node-id-exact, not just the route-CIDR presence check.
    #[test]
    fn macos_dispatch_carries_expected_node_id_when_known() {
        let mock = MockShellHost::new();
        let argv = macos_argv(&["--expected-node-id", "node-9"]);
        mock.program_run_response(&argv, exit_ok(&macos_good_report()));
        validate_macos_mesh_status(&mock, TEST_DAEMON, "mac-1", Some("node-9"))
            .unwrap_or_else(|err| panic!("expected node id must be dispatched; got: {err}"));
    }

    /// With no recorded node id the dispatch stays bare (no vacuous flag
    /// value), and the report must still carry VERIFIED membership node ids
    /// to pass the evaluator.
    #[test]
    fn macos_dispatch_bare_when_node_id_unknown_but_requires_verified_roster() {
        let mock = MockShellHost::new();
        let argv = macos_argv(&[]);
        mock.program_run_response(&argv, exit_ok(&macos_good_report()));
        validate_macos_mesh_status(&mock, TEST_DAEMON, "mac-1", None)
            .expect("a verified report must pass with no expected node id");
    }

    /// FAIL-CLOSED: a report whose member_node_ids is Missing (membership
    /// snapshot unavailable on the node) must fail the stage, not read as
    /// "no peers".
    #[test]
    fn macos_dispatch_fails_closed_when_membership_unavailable() {
        let missing_roster = serde_json::json!({
            "schema_version": 1,
            "state_path": "/usr/local/var/rustynet/rustynetd.state",
            "overall_ok": false,
            "snapshot": {
                "load_status": "ok",
                "timestamp_unix": 1_700_000_000u64,
                "age_seconds": 5,
                "peer_ids": [],
                "selected_exit_node": serde_json::Value::Null,
                "lan_access_enabled": false
            },
            "expected_peer_ids": [],
            "max_age_seconds": 180,
            "drift_reasons": [
                "membership node ids unavailable (fail-closed): membership snapshot \
                 unreadable at /usr/local/var/rustynet/membership/membership.snapshot"
            ],
            "membership_snapshot_path": "/usr/local/var/rustynet/membership/membership.snapshot",
            "expected_node_ids": [],
            "member_node_ids": {
                "membership_load_status": "missing",
                "reason": "membership snapshot unreadable"
            }
        })
        .to_string();
        let mock = MockShellHost::new();
        let argv = macos_argv(&[]);
        mock.program_run_response(&argv, exit_ok(&missing_roster));
        let err = validate_macos_mesh_status(&mock, TEST_DAEMON, "mac-1", None)
            .expect_err("an unverified membership roster must fail the stage");
        // The evaluator may reject via the overall_ok=false drift path or the
        // explicit member_node_ids gate — both are fail-closed.
        assert!(
            err.contains("membership node ids unavailable (fail-closed)")
                || err.contains("does not carry verified membership node ids"),
            "should reject a missing membership read, got: {err}"
        );
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
            ("windows-mesh-status-check", validate_windows_mesh_status),
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
        // macOS is asserted with its node-id-aware contract by
        // macos_dispatch_carries_expected_node_id_when_known /
        // macos_dispatch_bare_when_node_id_unknown_but_requires_verified_roster,
        // which program the same --max-age-seconds-bearing argv.
    }

    /// The bound must be a positive integer the daemon can parse, and must sit
    /// between two measured limits — too low reds a healthy node, too high stops
    /// discriminating.
    ///
    /// Both numbers are measured, and an earlier version of this test had the
    /// upper one badly wrong (579, from four runs) which would have admitted a
    /// bound of 500. Recomputed across 15 archived runs, the earliest offset of
    /// this check into a run is 232s.
    #[test]
    fn freshness_bound_cannot_span_a_previous_run() {
        let seconds: i64 = SNAPSHOT_MAX_AGE_SECONDS
            .parse()
            .expect("the bound must parse as the integer the daemon expects");
        assert!(seconds > 0, "a non-positive bound disables the check");
        assert!(
            seconds > 38,
            "the bound must clear the worst plausible in-pipeline snapshot age, so a healthy \
             node never reds; measured gap here is 3-8s and a wider archive reported 38s; got {seconds}"
        );
        assert!(
            seconds < 232,
            "the bound must stay under the earliest measured offset of this check into a run \
             (232s across 15 archived runs), so it cannot silently accept a snapshot predating \
             the run; got {seconds}"
        );
    }
}
