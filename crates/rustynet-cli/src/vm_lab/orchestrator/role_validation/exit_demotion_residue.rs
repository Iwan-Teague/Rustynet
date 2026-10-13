#![allow(dead_code)]
//! Cross-OS exit-demotion-residue validation for the standard orchestrator.
//!
//! Runs the two-phase exit→client demotion capture on a Linux exit node:
//! snapshot the NAT table before demotion (anti-vacuous "was serving exit"
//! guard), demote through the public CLI surface, then snapshot again
//! post-demotion to prove the NAT table is gone AND forwarding is restored
//! with the daemon still running.
//!
//! The merged artifact is evaluated by
//! `evaluate_linux_exit_demotion_residue_artifact` — the SAME evaluator
//! the bash live-suite applies — which fails closed on residual NAT,
//! forwarding-leak, vacuous before-state, or a stopped daemon.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellHost};
use crate::vm_lab::orchestrator::role_validation::blind_exit::{
    parse_header_node_role, poll_daemon_node_role,
};
use crate::vm_lab::orchestrator::role_validation::discover_single_generated_nft_table;

/// Exit-demotion-residue validation runs live on Linux today.
/// macOS / Windows nodes are reported-skipped — named on disk, never a
/// silent pass — until their per-OS exit-demotion probes are proven
/// through the Rust engine.
pub fn exit_demotion_residue_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux)
}

/// Default mesh CIDR used when dispatching
/// `linux-exit-nat-lifecycle-snapshot`. Mirrors the bash capture script's
/// default and the WireGuard address-space convention (100.64.0.0/10,
/// RFC 6598 CGNAT prefix).
const DEFAULT_MESH_CIDR: &str = "100.64.0.0/10";

const RUSTYNET_CLI_PATH: &str = "/usr/local/bin/rustynet";
const LINUX_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

const SETTLE_SECS: &str = "4";

/// Run the full two-phase exit→client demotion capture on a Linux exit
/// node: snapshot→demote→check-daemon→settle→snapshot→merge→evaluate→restore.
///
/// Side-effect: demotes the node from exit to client through the
/// public CLI surface (`rustynet role set client`). This is intentional
/// and mirrors the bash capture script — the stage must run while the
/// node is actively serving exit traffic. The demotion is persisted
/// (`/etc/default/rustynetd` rewrite + service restart), so the node's
/// pre-demotion PRIMARY role is recorded BEFORE demoting and restored
/// through the same public CLI on EVERY path after the demotion succeeds —
/// clean residue, residue failure, dispatch failure, or evaluation panic.
/// A restore failure fails the stage even when the residue evaluation
/// passed: an exit left demoted poisons every later admin-only stage on
/// this node (katana-xnet-113 `live_enrollment_restart_validation` root
/// cause).
///
/// Scope (D5): the restore re-establishes the daemon PRIMARY role only
/// (`node_role=`) — NOT the exit-serving posture (the 0.0.0.0/0 advertise
/// and NAT are deliberately not re-run, since this stage's own residue
/// check requires the NAT gone, and later exit stages re-assert serving).
pub fn validate_linux_exit_demotion_residue(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    alias: &str,
) -> Result<(), String> {
    let nat_table =
        discover_single_generated_nft_table(shell, "ip", "rustynet_nat_g", "active exit NAT")?;
    let during_snapshot = capture_nat_lifecycle_snapshot(shell, daemon_path, &nat_table)?;

    // Record the pre-demotion PRIMARY role BEFORE demoting: the persisted
    // demotion outlives this stage, and the recorded role — not a
    // hard-coded admin — is what the node must be restored to.
    let recorded_role = capture_daemon_node_role(shell)
        .map_err(|err| format!("{alias}: capture pre-demotion node role failed: {err}"))?;

    let demotion_exit_code = match demote_to_client(shell) {
        Ok(code) => code,
        Err(err) => {
            // The demotion may have partially applied (admin done, client
            // not): restore best-effort, then surface the demotion error.
            // If even the best-effort restore fails, the node may be left
            // mid-transition — name that and carry the restore error text
            // instead of discarding it (D4).
            if let Err(restore_err) = restore_pre_demotion_role(shell, &recorded_role) {
                return Err(format!(
                    "{err}; the best-effort restore to pre-demotion primary role \
                     {recorded_role:?} also failed, so the node may be left \
                     mid-transition: {restore_err}"
                ));
            }
            return Err(err);
        }
    };

    // Everything below runs while the node is demoted. The restore runs on
    // EVERY path after the demotion and its failure overrides a passing
    // residue evaluation (fail closed). The evaluation closure is wrapped
    // in catch_unwind so a panic still reaches the restore instead of
    // leaving the node demoted (D6); the panic itself becomes a named
    // stage error.
    let evaluation =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
            #[cfg(test)]
            if INJECT_EVALUATION_PANIC.with(std::cell::Cell::get) {
                panic!("injected residue-evaluation panic");
            }
            let daemon_still_running = check_daemon_running(shell);
            let _ = shell.run_argv(&["sleep", SETTLE_SECS], &[], &[]);
            let after_snapshot = capture_nat_lifecycle_snapshot(shell, daemon_path, &nat_table)?;

            let merged = merge_demotion_residue_artifact(
                &during_snapshot,
                &after_snapshot,
                demotion_exit_code,
                daemon_still_running,
            );
            let merged_str = serde_json::to_string(&merged)
                .map_err(|err| format!("serialize merged demotion residue artifact: {err}"))?;

            crate::vm_lab::evaluate_linux_exit_demotion_residue_artifact(alias, &merged_str)
                .map(|_report| ())
        }))
        .unwrap_or_else(|payload| Err(panic_error_text(payload)));

    // Fail-closed merge (D3): when BOTH the residue evaluation and the
    // restore fail, the returned error carries BOTH texts — the restore
    // posture first (it decides the stage's fail-closed verdict) and the
    // residue evidence appended, never dropped.
    let restore_result = restore_pre_demotion_role(shell, &recorded_role);
    match (evaluation, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(eval_err), Ok(())) => Err(eval_err),
        (evaluation, Err(restore_err)) => {
            let mut message = format!(
                "{alias}: post-validation restore to pre-demotion primary role \
                 {recorded_role:?} failed; the node is left demoted and later \
                 admin-only stages would be poisoned: {restore_err}"
            );
            if let Err(eval_err) = evaluation {
                message.push_str(&format!(
                    "; the residue evaluation had also failed: {eval_err}"
                ));
            }
            Err(message)
        }
    }
}

/// Render a caught panic payload as the stage error text (D6): the panic
/// must be named, not swallowed, and must never skip the restore.
fn panic_error_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(msg) = payload.downcast_ref::<&'static str>() {
        format!("residue evaluation panicked: {msg}")
    } else if let Some(msg) = payload.downcast_ref::<String>() {
        format!("residue evaluation panicked: {msg}")
    } else {
        "residue evaluation panicked (non-string payload)".to_owned()
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only panic injection for the catch_unwind witness (D6): when
    /// set, the evaluation closure panics so the test can prove the restore
    /// still runs and the panic becomes a named stage error.
    static INJECT_EVALUATION_PANIC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

/// The `sudo -n env RUSTYNET_DAEMON_SOCKET=… rustynet …` seam every CLI IPC
/// in this validator uses: role rewrites need root (env-file + service
/// restart) and the socket is pinned explicitly instead of relying on the
/// default path resolution.
fn run_daemon_cli(shell: &dyn RemoteShellHost, args: &[&str]) -> Result<RemoteExitStatus, String> {
    let socket_env = format!("RUSTYNET_DAEMON_SOCKET={LINUX_DAEMON_SOCKET}");
    let mut argv: Vec<&str> = vec!["sudo", "-n", "env", &socket_env, RUSTYNET_CLI_PATH];
    argv.extend_from_slice(args);
    shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch failed: {err}"))
}

/// Query the daemon's current primary role (`node_role=`) through the same
/// public CLI seam the demotion uses.
fn capture_daemon_node_role(shell: &dyn RemoteShellHost) -> Result<String, String> {
    let out = run_daemon_cli(shell, &["status"]).map_err(|err| format!("rustynet status {err}"))?;
    let status = String::from_utf8_lossy(&out.stdout);
    if out.code != 0 {
        return Err(format!(
            "rustynet status exited {}: {}",
            out.code,
            status.trim()
        ));
    }
    parse_header_node_role(&status).ok_or_else(|| {
        format!(
            "rustynet status carried no node_role field: {}",
            status.trim()
        )
    })
}

/// Restore the node to `recorded_role` through the same public CLI seam and
/// wait, bounded, for the restarted daemon's IPC to come back reporting that
/// role. Returns Err when the restore command fails or the daemon does not
/// report the recorded role within the bounded window.
fn restore_pre_demotion_role(
    shell: &dyn RemoteShellHost,
    recorded_role: &str,
) -> Result<(), String> {
    let out = run_daemon_cli(shell, &["role", "set", recorded_role])
        .map_err(|err| format!("restore (role set {recorded_role}) {err}"))?;
    if out.code != 0 {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "restore (role set {recorded_role}) exited {}: {}{}",
            out.code,
            stdout.trim(),
            stderr.trim()
        ));
    }
    // Shared bounded readiness poll (blind_exit): role set restarts the
    // daemon, so the IPC needs a bounded poll before the role is asserted.
    poll_daemon_node_role(
        shell,
        VmGuestPlatform::Linux,
        recorded_role,
        "post-restore readiness poll",
    )
}

fn capture_nat_lifecycle_snapshot(
    shell: &dyn RemoteShellHost,
    daemon_path: &str,
    nat_table: &str,
) -> Result<serde_json::Value, String> {
    let out = shell
        .run_argv(
            &[
                daemon_path,
                "linux-exit-nat-lifecycle-snapshot",
                "--mesh-cidr",
                DEFAULT_MESH_CIDR,
                "--nat-table",
                nat_table,
            ],
            &[],
            &[],
        )
        .map_err(|err| format!("dispatch of linux-exit-nat-lifecycle-snapshot failed: {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(&stdout)
        .map_err(|err| format!("parse linux-exit-nat-lifecycle-snapshot JSON: {err}"))
}

fn demote_to_client(shell: &dyn RemoteShellHost) -> Result<i32, String> {
    // Hardened role planner intentionally blocks direct exit→client. Exit NAT
    // must be retracted by exit→admin before least-privilege admin→client.
    // Drive both transitions through the public CLI with the explicit daemon
    // socket and sudo, matching the reviewed Linux operator path.
    for target in ["admin", "client"] {
        let out = run_daemon_cli(shell, &["role", "set", target])
            .map_err(|err| format!("demotion (role set {target}) {err}"))?;
        if out.code != 0 {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "demotion (role set {target}) exited {}: {}{}",
                out.code,
                stdout.trim(),
                stderr.trim()
            ));
        }
    }
    Ok(0)
}

fn check_daemon_running(shell: &dyn RemoteShellHost) -> bool {
    shell
        .run_argv(
            &["systemctl", "is-active", "--quiet", "rustynetd.service"],
            &[],
            &[],
        )
        .is_ok()
}

/// Merge two `LinuxExitNatLifecycleSnapshot` payloads into the artifact
/// format consumed by `evaluate_linux_exit_demotion_residue_artifact`.
/// Fail-closed defaults match the bash capture script:
/// - `during_run.nat_table_present` → `false` (anti-vacuous)  
/// - `after_demote.nat_table_present` → `true` (still-present)  
/// - Missing forwarding fields → `"Unknown"` (never `"Disabled"`)
fn merge_demotion_residue_artifact(
    during: &serde_json::Value,
    after: &serde_json::Value,
    demotion_exit_code: i32,
    daemon_still_running: bool,
) -> serde_json::Value {
    let after_tunnel = after_val_str(after, "tunnel_forwarding", "Unknown").to_lowercase();
    let after_egress = after_val_str(after, "egress_forwarding", "Unknown").to_lowercase();
    let forwarding_restored = after_tunnel == "disabled" && after_egress == "disabled";

    let after_v6_t = after_val_str(after, "ipv6_tunnel_forwarding", "Unknown").to_lowercase();
    let after_v6_e = after_val_str(after, "ipv6_egress_forwarding", "Unknown").to_lowercase();
    let ipv6_forwarding_restored = after_v6_t == "disabled" && after_v6_e == "disabled";

    serde_json::json!({
        "schema_version": 1,
        "mesh_cidr": after_val_str(during, "mesh_cidr", ""),
        "nat_table": after_val_str(during, "nat_table", ""),
        "demotion_exit_code": demotion_exit_code,
        "daemon_still_running": daemon_still_running,
        "during_run": {
            "nat_table_present": after_val_bool(during, "nat_table_present", false),
            "internal_prefix": after_val_str(during, "internal_prefix", ""),
            "tunnel_forwarding": after_val_str(during, "tunnel_forwarding", "Unknown"),
            "egress_forwarding": after_val_str(during, "egress_forwarding", "Unknown"),
        },
        "after_demote": {
            "nat_table_present": after_val_bool(after, "nat_table_present", true),
            "forwarding_restored": forwarding_restored,
            "ipv6_forwarding_restored": ipv6_forwarding_restored,
        },
    })
}

fn after_val_str(val: &serde_json::Value, key: &str, default: &str) -> String {
    val.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or(default)
        .to_string()
}

fn after_val_bool(val: &serde_json::Value, key: &str, default: bool) -> bool {
    val.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_implemented_linux_only() {
        assert!(exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Linux
        ));
        assert!(!exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Macos
        ));
        assert!(!exit_demotion_residue_runtime_implemented(
            VmGuestPlatform::Windows
        ));
    }

    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};
    use crate::vm_lab::orchestrator::role_validation::blind_exit::DAEMON_ROLE_POLL_MAX_ATTEMPTS;

    const TEST_DAEMON: &str = "/usr/local/bin/rustynetd";

    fn exit_ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    fn exit_code(code: i32) -> RemoteExitStatus {
        RemoteExitStatus {
            code,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    fn demo_snapshot(nat_present: bool, tunnel_fwd: &str, egress_fwd: &str) -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "captured_at_unix": 1700000000_u64,
            "mesh_cidr": "100.64.0.0/10",
            "nat_table": "rustynet_nat_g1",
            "nat_table_present": nat_present,
            "internal_prefix": if nat_present { "100.64.0.0/10" } else { "" },
            "tunnel_forwarding": tunnel_fwd,
            "egress_forwarding": egress_fwd,
            "ipv6_tunnel_forwarding": "Disabled",
            "ipv6_egress_forwarding": "Disabled",
        })
    }

    fn discover_argv() -> [&'static str; 5] {
        ["sudo", "-n", "nft", "list", "tables"]
    }

    fn generation_snapshot_argv() -> [&'static str; 6] {
        [
            TEST_DAEMON,
            "linux-exit-nat-lifecycle-snapshot",
            "--mesh-cidr",
            "100.64.0.0/10",
            "--nat-table",
            "rustynet_nat_g7",
        ]
    }

    fn status_argv() -> [&'static str; 6] {
        [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "status",
        ]
    }

    fn role_set_argv(target: &'static str) -> [&'static str; 8] {
        [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "role",
            "set",
            target,
        ]
    }

    /// Programs everything up to and including the demotion pair: discover,
    /// during-snapshot, pre-demotion role capture, `role set admin` +
    /// `role set client`, daemon check, settle sleep. The after-snapshot, the
    /// restore and its readiness poll are left for each test to script so the
    /// restore outcome (ok / failing exit / never-ready poll) is per-test.
    fn setup_demotion_prefix(mock: &MockShellHost, pre_role: &'static str) {
        mock.program_run_response(
            &discover_argv(),
            exit_ok("table inet rustynet_g7\ntable ip rustynet_nat_g7\n"),
        );
        let during = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&during.to_string()));

        mock.program_run_response(
            &status_argv(),
            exit_ok(&format!("node_id=deb-1 node_role={pre_role} state=Ready\n")),
        );

        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        mock.program_run_response(&role_set_argv("client"), exit_code(0));

        mock.program_run_response(
            &["systemctl", "is-active", "--quiet", "rustynetd.service"],
            exit_ok("active"),
        );
        mock.program_run_response(&["sleep", "4"], exit_ok(""));
    }

    fn program_clean_after_snapshot(mock: &MockShellHost) {
        let after = demo_snapshot(false, "Disabled", "Disabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&after.to_string()));
    }

    /// The restore success path: `role set <recorded_role>` exits 0, then the
    /// readiness poll reads back the recorded role.
    fn program_restore_ok(mock: &MockShellHost, recorded_role: &'static str) {
        mock.program_run_response(&role_set_argv(recorded_role), exit_code(0));
        mock.program_run_response(
            &status_argv(),
            exit_ok(&format!(
                "node_id=deb-1 node_role={recorded_role} state=Ready\n"
            )),
        );
    }

    fn setup_clean_demotion_workflow(mock: &MockShellHost) {
        setup_demotion_prefix(mock, "admin");
        program_clean_after_snapshot(mock);
        program_restore_ok(mock, "admin");
    }

    /// The `role set <target>` invocations in dispatch order.
    fn recorded_role_sets(mock: &MockShellHost) -> Vec<String> {
        mock.run_log()
            .iter()
            .filter(|call| call.argv.len() == 8 && call.argv[5] == "role" && call.argv[6] == "set")
            .filter_map(|call| call.argv.last().cloned())
            .collect()
    }

    #[test]
    fn validate_accepts_clean_teardown() {
        let mock = MockShellHost::new();
        setup_clean_demotion_workflow(&mock);
        validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect("clean demotion teardown must validate");
    }

    #[test]
    fn clean_workflow_restores_recorded_role_in_order() {
        let mock = MockShellHost::new();
        setup_clean_demotion_workflow(&mock);
        validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect("clean demotion teardown must validate");
        // demote admin → demote client → restore recorded admin, in order.
        assert_eq!(
            recorded_role_sets(&mock),
            vec!["admin".to_owned(), "client".to_owned(), "admin".to_owned()],
            "the restore must be the final role set and target the recorded role"
        );
        // The restore runs only AFTER the post-demotion snapshot: the demoted
        // interval must be fully captured before the role is reverted.
        let log = mock.run_log();
        let snapshot_positions: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(_, call)| {
                call.argv
                    .contains(&"linux-exit-nat-lifecycle-snapshot".to_owned())
            })
            .map(|(idx, _)| idx)
            .collect();
        let role_set_positions: Vec<usize> = log
            .iter()
            .enumerate()
            .filter(|(_, call)| {
                call.argv.len() == 8 && call.argv[5] == "role" && call.argv[6] == "set"
            })
            .map(|(idx, _)| idx)
            .collect();
        assert_eq!(snapshot_positions.len(), 2, "{log:?}");
        assert_eq!(role_set_positions.len(), 3, "{log:?}");
        assert!(
            role_set_positions[1] < snapshot_positions[1],
            "the demotion pair must complete before the after-snapshot"
        );
        assert!(
            role_set_positions[2] > snapshot_positions[1],
            "the restore must follow the after-snapshot, not preempt it"
        );
    }

    #[test]
    fn restore_targets_recorded_role_even_when_start_role_is_not_admin() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "client");
        program_clean_after_snapshot(&mock);
        program_restore_ok(&mock, "client");
        validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect("clean workflow with a non-admin start role must validate");
        assert_eq!(
            recorded_role_sets(&mock),
            vec!["admin".to_owned(), "client".to_owned(), "client".to_owned()],
            "restore must re-issue the RECORDED role, never a hard-coded admin"
        );
    }

    #[test]
    fn restore_failure_fails_stage_even_when_artifact_is_clean() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        program_clean_after_snapshot(&mock);
        // FIFO: first `role set admin` = the demotion, second = the restore.
        mock.program_run_response(&role_set_argv("admin"), exit_code(7));
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a failed restore must fail the stage even with a clean artifact");
        assert!(
            err.contains("post-validation restore") && err.contains("left demoted"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("exited 7"),
            "the restore failure must name its cause: {err}"
        );
    }

    #[test]
    fn restore_is_attempted_even_when_residue_evaluation_fails() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        // After-snapshot carrying residual NAT: the residue evaluator fails.
        let residual = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&residual.to_string()));
        program_restore_ok(&mock, "admin");
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("residual NAT after demotion must fail the stage");
        assert!(
            err.contains("residual open relay") || err.contains("NAT table present after"),
            "the residue failure must surface: {err}"
        );
        assert_eq!(
            recorded_role_sets(&mock).len(),
            3,
            "the restore must still be attempted when the artifact evaluation fails"
        );
    }

    #[test]
    fn restore_wait_timeout_fails_stage() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        program_clean_after_snapshot(&mock);
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        // The readiness poll never sees the restored role within the bounded
        // window: every attempt reports the demoted role.
        for _ in 0..DAEMON_ROLE_POLL_MAX_ATTEMPTS {
            mock.program_run_response(
                &status_argv(),
                exit_ok("node_id=deb-1 node_role=client state=Ready\n"),
            );
        }
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a daemon that never reports the restored role must fail the stage");
        assert!(
            err.contains("post-validation restore")
                && err.contains("does not report node_role=admin"),
            "unexpected error: {err}"
        );
    }

    /// D3: when BOTH the residue evaluation and the restore fail, the stage
    /// error must carry BOTH texts — the restore posture AND the residue
    /// evidence. Mutation witness: dropping the residue append (restore
    /// error only) fails this test.
    #[test]
    fn both_residue_and_restore_failure_names_both_errors() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        // Residue failure: the after-snapshot still carries the NAT table.
        let residual = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&residual.to_string()));
        // Restore failure too: the restore `role set admin` exits 7.
        mock.program_run_response(&role_set_argv("admin"), exit_code(7));
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("both failures together must fail the stage");
        assert!(
            err.contains("post-validation restore") && err.contains("exited 7"),
            "the restore failure must be named: {err}"
        );
        assert!(
            err.contains("residual open relay") || err.contains("NAT table present after"),
            "the residue evidence text must not be dropped when the restore also failed: {err}"
        );
    }

    /// D4: on the demotion-failure path, a failing best-effort restore must
    /// surface the mid-transition risk and the restore error text. Mutation
    /// witness: the old `let _ = restore...` (outcome discarded) fails the
    /// mid-transition assertion.
    #[test]
    fn failed_demotion_with_failed_restore_names_mid_transition() {
        let mock = MockShellHost::new();
        mock.program_run_response(
            &discover_argv(),
            exit_ok("table inet rustynet_g7\ntable ip rustynet_nat_g7\n"),
        );
        let during = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&during.to_string()));
        mock.program_run_response(
            &status_argv(),
            exit_ok("node_id=deb-1 node_role=admin state=Ready\n"),
        );
        // Demotion: admin ok, client fails.
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        mock.program_run_response(&role_set_argv("client"), exit_code(1));
        // The best-effort restore's own `role set admin` also fails.
        mock.program_run_response(&role_set_argv("admin"), exit_code(7));
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a failed demotion must fail the stage");
        assert!(
            err.contains("demotion (role set client) exited 1"),
            "the demotion error must surface: {err}"
        );
        assert!(
            err.contains("mid-transition"),
            "a failed best-effort restore must name the mid-transition risk: {err}"
        );
        assert!(
            err.contains("restore (role set admin) exited 7"),
            "the restore error text must be carried: {err}"
        );
    }

    /// D6: a panic inside the evaluation closure must not skip the restore —
    /// the node is still restored, and the panic becomes a named stage
    /// error. Mutation witness: removing catch_unwind lets the panic unwind
    /// past the restore, failing this test.
    #[test]
    fn evaluation_panic_still_restores_and_fails_named() {
        let mock = MockShellHost::new();
        setup_clean_demotion_workflow(&mock);
        INJECT_EVALUATION_PANIC.with(|flag| flag.set(true));
        let result = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1");
        INJECT_EVALUATION_PANIC.with(|flag| flag.set(false));
        let err = result.expect_err("an evaluation panic must become a named stage error");
        assert!(
            err.contains("residue evaluation panicked")
                && err.contains("injected residue-evaluation panic"),
            "unexpected error: {err}"
        );
        assert_eq!(
            recorded_role_sets(&mock),
            vec!["admin".to_owned(), "client".to_owned(), "admin".to_owned()],
            "the restore must still run after a panic in the evaluation closure"
        );
    }

    /// Mutation witness (review M8): a restore poll whose attempts exit
    /// non-zero is retried within the bounded window and then fails with the
    /// non-zero-naming error — it must not be silently treated as a
    /// successful query.
    #[test]
    fn restore_poll_retries_non_zero_status_then_fails_named() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        program_clean_after_snapshot(&mock);
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        // Every readiness-poll attempt exits non-zero (IPC not up).
        for _ in 0..DAEMON_ROLE_POLL_MAX_ATTEMPTS {
            mock.program_run_response(&status_argv(), exit_code(1));
        }
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a poll that never sees exit 0 must fail the stage");
        assert!(
            err.contains(&format!(
                "rustynet status exited non-zero after {DAEMON_ROLE_POLL_MAX_ATTEMPTS} attempts"
            )),
            "unexpected error: {err}"
        );
    }

    /// The retry half of M8: a SINGLE transient non-zero poll attempt is
    /// retried, and a later attempt reporting the restored role succeeds.
    #[test]
    fn restore_poll_recovers_after_transient_non_zero_status() {
        let mock = MockShellHost::new();
        setup_demotion_prefix(&mock, "admin");
        program_clean_after_snapshot(&mock);
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        // First poll attempt exits non-zero (daemon mid-restart), the
        // second reports the restored role.
        mock.program_run_response(&status_argv(), exit_code(1));
        mock.program_run_response(
            &status_argv(),
            exit_ok("node_id=deb-1 node_role=admin state=Ready\n"),
        );
        validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect("a transient non-zero poll must be retried, not fatal");
    }

    #[test]
    fn failed_demotion_still_attempts_restore_of_recorded_role() {
        let mock = MockShellHost::new();
        // Demotion fails part-way (admin ok, client exits 1): the restore to
        // the recorded role must still be attempted, best-effort.
        mock.program_run_response(
            &discover_argv(),
            exit_ok("table inet rustynet_g7\ntable ip rustynet_nat_g7\n"),
        );
        let during = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&during.to_string()));
        mock.program_run_response(
            &status_argv(),
            exit_ok("node_id=deb-1 node_role=admin state=Ready\n"),
        );
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        mock.program_run_response(&role_set_argv("client"), exit_code(1));
        program_restore_ok(&mock, "admin");
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a failed demotion must fail the stage");
        assert!(
            err.contains("demotion (role set client) exited 1"),
            "the demotion error must surface: {err}"
        );
        assert_eq!(
            recorded_role_sets(&mock),
            vec!["admin".to_owned(), "client".to_owned(), "admin".to_owned()],
            "the restore must be attempted even on the demotion failure path"
        );
    }
    #[test]
    fn validate_fails_closed_on_residual_nat() {
        let during = demo_snapshot(true, "Enabled", "Enabled");
        let after = demo_snapshot(true, "Enabled", "Enabled");
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        let err = crate::vm_lab::evaluate_linux_exit_demotion_residue_artifact(
            "deb-1",
            &merged.to_string(),
        )
        .expect_err("residual NAT after demotion must fail closed");
        assert!(
            err.contains("residual open relay") || err.contains("NAT table present after"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_fails_closed_on_dispatch_error() {
        let mock = MockShellHost::new();
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("a dispatch error must fail the stage");
        assert!(
            err.contains("discover active exit NAT failed")
                || err.contains("dispatch of linux-exit-nat-lifecycle-snapshot failed")
                || err.contains("unsupported argv"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nat_table_discovery_accepts_one_generated_table() {
        let mock = MockShellHost::new();
        let argv = ["sudo", "-n", "nft", "list", "tables"];
        mock.program_run_response(
            &argv,
            exit_ok("table inet rustynet_g12\ntable ip rustynet_nat_g12\n"),
        );
        assert_eq!(
            discover_single_generated_nft_table(&mock, "ip", "rustynet_nat_g", "active exit NAT",)
                .unwrap(),
            "rustynet_nat_g12"
        );
    }

    #[test]
    fn nat_table_discovery_rejects_none_or_multiple() {
        let argv = ["sudo", "-n", "nft", "list", "tables"];

        let none = MockShellHost::new();
        none.program_run_response(&argv, exit_ok("table inet rustynet_g3\n"));
        assert!(
            discover_single_generated_nft_table(&none, "ip", "rustynet_nat_g", "active exit NAT",)
                .is_err()
        );

        let multiple = MockShellHost::new();
        multiple.program_run_response(
            &argv,
            exit_ok("table ip rustynet_nat_g2\ntable ip rustynet_nat_g9\n"),
        );
        let err = discover_single_generated_nft_table(
            &multiple,
            "ip",
            "rustynet_nat_g",
            "active exit NAT",
        )
        .unwrap_err();
        assert!(err.contains("multiple") && err.contains("residual state"));
    }

    #[test]
    fn demotion_uses_required_exit_admin_client_path() {
        let mock = MockShellHost::new();
        let admin = [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "role",
            "set",
            "admin",
        ];
        let client = [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "role",
            "set",
            "client",
        ];
        mock.program_run_response(&admin, exit_code(0));
        mock.program_run_response(&client, exit_code(0));
        assert_eq!(demote_to_client(&mock).unwrap(), 0);
    }

    #[test]
    fn merge_forwarding_restored_requires_both_disabled() {
        let during = demo_snapshot(true, "Enabled", "Enabled");
        let after = demo_snapshot(false, "Disabled", "Enabled");
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        assert!(
            !merged["after_demote"]["forwarding_restored"]
                .as_bool()
                .unwrap()
        );
    }

    #[test]
    fn merge_defaults_missing_fields_fail_closed() {
        let during = serde_json::json!({"schema_version": 1});
        let after = serde_json::json!({"schema_version": 1});
        let merged = merge_demotion_residue_artifact(&during, &after, 0, true);
        assert!(!merged["during_run"]["nat_table_present"].as_bool().unwrap());
        assert!(
            merged["after_demote"]["nat_table_present"]
                .as_bool()
                .unwrap()
        );
    }
}
