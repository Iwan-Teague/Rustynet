#![allow(dead_code)]
//! Cross-OS mesh-status validation for the standard orchestrator.
//!
//! Runs `rustynetd <platform>-mesh-status-check` over the hardened
//! [`RemoteShellHost`] seam and accepts ONLY by the SAME typed evaluator
//! the bash live-suite applies (`evaluate_linux_mesh_status_report` in
//! `vm_lab`), which fails closed on schema mismatch or `overall_ok=false`
//! — so a broken or vacuous check fails the stage rather than silently passing.
//!
//! A snapshot pass alone is NOT sufficient (QH-70): the module also evaluates
//! LIVE dataplane evidence from the daemon's IPC `status` line via
//! [`evaluate_live_handshake_status`] — every expected peer live (the full
//! `assignments.len()-1` mesh), non-zero programmed peers, and a fresh
//! latest-handshake whenever the run topology expects peers. The
//! stage's "pass" therefore means snapshot-valid AND live-handshake-proven;
//! historical run-matrix rows that passed on the snapshot alone are not
//! comparable (forward-only boundary, as plan §3 records).

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

/// Live-handshake evidence window (QH-70). Same 180s basis as
/// [`SNAPSHOT_MAX_AGE_SECONDS`]: a WireGuard handshake rekeys at most ~every
/// 120-180s under traffic, so if the daemon keeps no live peer whose latest
/// handshake falls inside this window the dataplane is idle-dead — exactly the
/// false-green this check exists to catch. A future-dated
/// `path_latest_live_handshake_unix` fails with no slack.
pub(crate) const MAX_HANDSHAKE_AGE_SECONDS: u64 = 180;

/// Split a `key=value` status line into pairs (copied from
/// `gossip_convergence.rs` — see the implementation log for why copy, not
/// hoist).
///
/// `splitn(2, '=')` is load-bearing: a value may itself contain `=`, so a
/// naive `split('=')` would silently truncate it.
fn status_tokens(line: &str) -> Vec<(&str, &str)> {
    line.split_whitespace()
        .filter_map(|token| {
            let mut parts = token.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => Some((key, value)),
                _ => None,
            }
        })
        .collect()
}

fn field<'a>(tokens: &[(&'a str, &'a str)], key: &str) -> Result<&'a str, String> {
    tokens
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("status output has no `{key}` field"))
}

fn count_field(tokens: &[(&str, &str)], key: &str) -> Result<u64, String> {
    let raw = field(tokens, key)?;
    raw.parse::<u64>()
        .map_err(|err| format!("`{key}` is not a count: {raw:?} ({err})"))
}

/// Parse the guest-clock emission appended to every platform's daemon-status
/// query (review F2, 2026-09-07): each status command now also prints
/// `now_unix=<unix seconds>` from the NODE's own clock, so handshake
/// freshness is judged on the same clock that wrote
/// `path_latest_live_handshake_unix` — not the orchestrator host clock,
/// whose skew (VM pause/resume, NTP drift) would flake a healthy node as
/// "future-dated" or "idle-dead". Missing or unparseable is an error (fail
/// closed), the same contract as the required `path_*` fields.
pub fn parse_guest_now_unix(stdout: &str) -> Result<u64, String> {
    count_field(&status_tokens(stdout), "now_unix")
}

/// Evaluate the LIVE dataplane half of a `rustynet status` line (QH-70).
/// Pure, so the contract is testable without a node.
///
/// A snapshot pass proves membership convergence, not reachability — a node
/// whose mesh-status report loads AND is fresh can still have reached no peer
/// at all, which is how `mesh_status_validation` stayed green across runs
/// whose `traffic_test_matrix` was red. This evaluator closes that gap: it
/// demands the daemon's own IPC status line carries live evidence —
/// `path_live_peer_count`, `path_programmed_peer_count` and
/// `path_latest_live_handshake_unix` — and that the evidence says the
/// dataplane is actually carrying peers.
///
/// Fail-closed, every criterion here because its absence would admit a
/// specific false green:
///
/// * any required field missing/unparseable → error (never "no peers
///   observed, so pass");
/// * `expected_live_peers > 0` and `path_live_peer_count == 0` → the node
///   reached no peer (the QH-70 defect itself);
/// * `expected_live_peers > 0` and `path_live_peer_count < expected` →
///   partial mesh: some tunnel pairs carry live handshakes while at least
///   one is dead (review F1, 2026-09-07 — the zero-only gate admitted a
///   single dead pair on any ≥3-node run);
/// * `expected_live_peers > 0` and `path_programmed_peer_count == 0` → the
///   dataplane was never applied;
/// * `path_latest_live_handshake_unix` future-dated (`> now_unix`, no slack)
///   or older than [`MAX_HANDSHAKE_AGE_SECONDS`] → handshake never proven or
///   idle-dead. Age uses `saturating_sub` plus an explicit future check, never
///   `abs()`.
///
/// `relay_session_state` / `relay_session_established_peers` are parsed and
/// echoed into the failure/evidence detail but NEVER gate: this stage runs
/// before `DeployRelayService`/`RelayValidation`, so relay sessions may
/// legitimately be absent here.
///
/// `expected_live_peers == 0` (single-node run) skips the peer/handshake
/// clauses; the required fields must still parse.
///
/// On success the accepted observation is returned (QH-70 follow-up): the
/// stage records it as evidence so a reader can confirm from the artifact
/// alone that the check ran with a non-zero expectation, rather than
/// trusting the bare pass.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LiveHandshakeObservation {
    pub alias: String,
    pub path_live_peer_count: u64,
    pub expected_live_peers: u32,
    pub path_latest_live_handshake_unix: u64,
    pub guest_now_unix: u64,
    pub handshake_age_seconds: u64,
}

pub fn evaluate_live_handshake_status(
    alias: &str,
    stdout: &str,
    expected_live_peers: u32,
    now_unix: u64,
) -> Result<LiveHandshakeObservation, String> {
    let tokens = status_tokens(stdout);
    if tokens.is_empty() {
        return Err(format!("{alias}: live handshake: empty status output"));
    }
    let fail = |detail: String| Err(format!("{alias}: live handshake: {detail}"));

    let live = match count_field(&tokens, "path_live_peer_count") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    let programmed = match count_field(&tokens, "path_programmed_peer_count") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };
    let handshake = match count_field(&tokens, "path_latest_live_handshake_unix") {
        Ok(value) => value,
        Err(err) => return fail(err),
    };

    // Echo-only evidence: relay deploy is a later stage, so a missing relay
    // session here is expected, not a failure.
    let relay_evidence = format!(
        "relay_session_state={} relay_session_established_peers={}",
        field(&tokens, "relay_session_state").unwrap_or("absent"),
        field(&tokens, "relay_session_established_peers").unwrap_or("absent"),
    );

    // Built before the expectation gates so every acceptance path (including
    // the single-node early return) carries the observation for the stage to
    // record as evidence.
    let observation = LiveHandshakeObservation {
        alias: alias.to_owned(),
        path_live_peer_count: live,
        expected_live_peers,
        path_latest_live_handshake_unix: handshake,
        guest_now_unix: now_unix,
        handshake_age_seconds: now_unix.saturating_sub(handshake),
    };

    if expected_live_peers == 0 {
        return Ok(observation);
    }
    if live == 0 {
        return fail(format!(
            "path_live_peer_count=0 but {expected_live_peers} live peer(s) expected — \
             no live dataplane evidence ({relay_evidence})"
        ));
    }
    if live < u64::from(expected_live_peers) {
        return fail(format!(
            "path_live_peer_count={live} but {expected_live_peers} live peer(s) expected — \
             partial mesh: at least one tunnel pair is dead ({relay_evidence})"
        ));
    }
    if programmed == 0 {
        return fail(format!(
            "path_programmed_peer_count=0 but {expected_live_peers} peer(s) expected — \
             dataplane never applied ({relay_evidence})"
        ));
    }
    if handshake > now_unix {
        return fail(format!(
            "path_latest_live_handshake_unix={handshake} is future-dated (now={now_unix}) \
             ({relay_evidence})"
        ));
    }
    let age = now_unix.saturating_sub(handshake);
    if age > MAX_HANDSHAKE_AGE_SECONDS {
        return fail(format!(
            "latest live handshake is {age}s old (bound {MAX_HANDSHAKE_AGE_SECONDS}s) — \
             dataplane idle-dead ({relay_evidence})"
        ));
    }
    Ok(observation)
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

    // ── QH-70 live-handshake evaluator ───────────────────────────────────────

    const NOW: u64 = 1_700_000_100;

    /// Shape per `rustynetd/src/daemon.rs` IPC `status` line (QH-70 addendum).
    const LIVE_STATUS: &str = "node_id=client-1 path_mode=direct \
         path_live_peer_count=1 path_programmed_peer_count=1 \
         path_latest_live_handshake_unix=1700000080 \
         relay_session_state=none relay_session_established_peers=0 \
         gossip_peers_registered=1 gossip_identity_mismatch=false";

    fn status_line_with(base: &str, field_name: &str, value: &str) -> String {
        base.split_whitespace()
            .map(|token| {
                if token.starts_with(&format!("{field_name}=")) {
                    format!("{field_name}={value}")
                } else {
                    token.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn status_with(field_name: &str, value: &str) -> String {
        status_line_with(LIVE_STATUS, field_name, value)
    }

    fn status_without(field_name: &str) -> String {
        LIVE_STATUS
            .split_whitespace()
            .filter(|t| !t.starts_with(&format!("{field_name}=")))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// Test 1: zero live peers with one expected is the QH-70 defect itself.
    #[test]
    fn zero_live_peers_with_one_expected_fails() {
        let err =
            evaluate_live_handshake_status("n1", &status_with("path_live_peer_count", "0"), 1, NOW)
                .expect_err("a node with no live peer must fail when a peer is expected");
        assert!(err.contains("no live dataplane evidence"), "got: {err}");
    }

    /// Test 1 (positive half): a live, fresh peer passes.
    #[test]
    fn one_live_peer_with_fresh_handshake_passes() {
        evaluate_live_handshake_status("n1", LIVE_STATUS, 1, NOW)
            .unwrap_or_else(|err| panic!("live fresh peer must pass; got: {err}"));
    }

    /// QH-70 follow-up: an acceptance must CARRY the observation the stage
    /// records as evidence — parsed counts, the guest clock it was judged on,
    /// and the computed handshake age.
    #[test]
    fn pass_returns_observation_with_parsed_fields() {
        let obs = evaluate_live_handshake_status("n1", LIVE_STATUS, 1, NOW)
            .unwrap_or_else(|err| panic!("live fresh peer must pass; got: {err}"));
        assert_eq!(obs.alias, "n1");
        assert_eq!(obs.path_live_peer_count, 1);
        assert_eq!(obs.expected_live_peers, 1);
        assert_eq!(obs.path_latest_live_handshake_unix, 1_700_000_080);
        assert_eq!(obs.guest_now_unix, NOW);
        assert_eq!(obs.handshake_age_seconds, 20);
    }

    /// The single-node early return also carries its observation (with the
    /// zero expectation visible), so a single-node run is still evidenced.
    #[test]
    fn single_node_pass_returns_zero_expectation_observation() {
        let obs =
            evaluate_live_handshake_status("n1", &status_with("path_live_peer_count", "0"), 0, NOW)
                .unwrap_or_else(|err| panic!("single-node run must pass; got: {err}"));
        assert_eq!(obs.expected_live_peers, 0);
        assert_eq!(obs.path_live_peer_count, 0);
        assert_eq!(obs.guest_now_unix, NOW);
    }

    /// Test 2: the handshake boundary discriminates at MAX_HANDSHAKE_AGE_SECONDS.
    #[test]
    fn handshake_age_boundary_discriminates() {
        evaluate_live_handshake_status(
            "n1",
            &status_with("path_latest_live_handshake_unix", &format!("{}", NOW - 180)),
            1,
            NOW,
        )
        .unwrap_or_else(|err| panic!("exactly-180s handshake must pass; got: {err}"));
        let err = evaluate_live_handshake_status(
            "n1",
            &status_with("path_latest_live_handshake_unix", &format!("{}", NOW - 181)),
            1,
            NOW,
        )
        .expect_err("181s-old handshake must fail");
        assert!(err.contains("old (bound"), "got: {err}");
    }

    /// Test 3: a future-dated handshake fails with no slack (saturating_sub +
    /// explicit `>` comparison, never `abs()`).
    #[test]
    fn future_dated_handshake_fails() {
        let err = evaluate_live_handshake_status(
            "n1",
            &status_with("path_latest_live_handshake_unix", &format!("{}", NOW + 5)),
            1,
            NOW,
        )
        .expect_err("a future-dated handshake is corrupt evidence");
        assert!(err.contains("future-dated"), "got: {err}");
    }

    /// Test 4: a missing/unparseable required field fails closed, never reads
    /// as "no peers, so pass". Mutation: delete a field → this test fails.
    #[test]
    fn missing_or_garbage_fields_fail_closed() {
        for stripped in [
            "path_live_peer_count",
            "path_programmed_peer_count",
            "path_latest_live_handshake_unix",
        ] {
            let err = evaluate_live_handshake_status("n1", &status_without(stripped), 1, NOW)
                .expect_err("a missing required field must fail closed");
            assert!(
                err.contains(&format!("no `{stripped}` field")),
                "missing {stripped} must be named, got: {err}"
            );
        }
        for garbage in [
            "",
            "garbage",
            "path_live_peer_count=notanumber path_programmed_peer_count=1 path_latest_live_handshake_unix=1",
        ] {
            assert!(
                evaluate_live_handshake_status("n1", garbage, 1, NOW).is_err(),
                "empty/unparseable status output must fail, got {garbage:?}"
            );
        }
    }

    /// Test 5: a single-node run (no peers expected) passes with zero live
    /// peers — but only because the expectation is carried. Mutation: pass an
    /// expectation > 0 (test 1) and it fails.
    #[test]
    fn single_node_run_with_no_peers_passes() {
        evaluate_live_handshake_status("n1", &status_with("path_live_peer_count", "0"), 0, NOW)
            .unwrap_or_else(|err| panic!("a single-node run must pass; got: {err}"));
    }

    /// Test 5 (mutation half): drop the expectation (i.e. expect peers on a
    /// zero-live node) and the same status line fails.
    #[test]
    fn single_node_status_fails_once_peers_are_expected() {
        assert!(
            evaluate_live_handshake_status("n1", &status_with("path_live_peer_count", "0"), 1, NOW)
                .is_err(),
            "the same zero-live line must fail once a peer is expected"
        );
    }

    /// Programmed-but-not-live fails: the dataplane was applied but no
    /// handshake was ever proven.
    #[test]
    fn programmed_but_never_live_fails() {
        let err =
            evaluate_live_handshake_status("n1", &status_with("path_live_peer_count", "0"), 1, NOW)
                .expect_err("live=0 must fail regardless of programmed");
        assert!(err.contains("no live dataplane evidence"), "got: {err}");
    }

    /// Review F2: the guest-clock emission parses; missing or unparseable
    /// fails closed (the same contract as the required `path_*` fields).
    #[test]
    fn guest_now_unix_parses_and_fails_closed() {
        assert_eq!(
            parse_guest_now_unix(LIVE_STATUS),
            Err("status output has no `now_unix` field".to_owned()),
            "a status line without the guest-clock emission must fail closed"
        );
        let with_now = format!("{LIVE_STATUS} now_unix={NOW}");
        assert_eq!(parse_guest_now_unix(&with_now), Ok(NOW));
        assert!(
            parse_guest_now_unix("now_unix=notanumber").is_err(),
            "a non-numeric guest clock must fail closed"
        );
    }

    /// Review F1 (blocker): on a 3-node run (expected 2) a single dead tunnel
    /// pair — `live=1`, others alive — must fail. The former zero-only gate
    /// admitted exactly this shape on any ≥3-node run.
    #[test]
    fn partial_live_mesh_fails_when_below_expected() {
        let err = evaluate_live_handshake_status("n1", LIVE_STATUS, 2, NOW)
            .expect_err("live < expected must fail on a multi-node run");
        assert!(
            err.contains("partial mesh"),
            "the partial-mesh condition must be named, got: {err}"
        );
    }

    /// Review F1 positive half: the same 3-node topology with every pair
    /// alive passes (live == expected).
    #[test]
    fn full_live_mesh_passes_when_live_matches_expected() {
        let full = status_line_with(
            &status_with("path_programmed_peer_count", "2"),
            "path_live_peer_count",
            "2",
        );
        evaluate_live_handshake_status("n1", &full, 2, NOW)
            .unwrap_or_else(|err| panic!("a full live mesh must pass; got: {err}"));
    }

    /// Review F3 (nit): `relay_session_state` / `relay_session_established_peers`
    /// are ECHO-ONLY. A status line carrying neither relay field must still
    /// pass (this stage runs before relay deploy), and a failure on such a
    /// line must echo `relay_session_state=absent` as evidence — a regression
    /// that starts gating on either field breaks this test.
    #[test]
    fn relay_fields_are_echo_only_and_optional() {
        let stripped: String = LIVE_STATUS
            .split_whitespace()
            .filter(|t| {
                !t.starts_with("relay_session_state=")
                    && !t.starts_with("relay_session_established_peers=")
            })
            .collect::<Vec<_>>()
            .join(" ");
        evaluate_live_handshake_status("n1", &stripped, 1, NOW)
            .unwrap_or_else(|err| panic!("missing relay fields must stay a pass; got: {err}"));
        let err = evaluate_live_handshake_status(
            "n1",
            &status_line_with(&stripped, "path_live_peer_count", "0"),
            1,
            NOW,
        )
        .expect_err("the failure must still be raised");
        assert!(
            err.contains("relay_session_state=absent")
                && err.contains("relay_session_established_peers=absent"),
            "absent relay fields must be echoed as evidence, got: {err}"
        );
    }
}
