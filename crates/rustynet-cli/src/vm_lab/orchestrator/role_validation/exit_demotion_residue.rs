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

use crate::role_cli::DEFAULT_DAEMON_ENV_PATH;
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
/// node is actively serving exit traffic.
///
/// The demotion outlives this stage in TWO places, so BOTH are recorded
/// BEFORE any demotion command and BOTH are restored on EVERY path after the
/// demotion — clean residue, residue failure, dispatch failure, or
/// evaluation panic:
///
/// * the daemon's LIVE primary role (`node_role=` from `rustynet status`);
/// * the PERSISTED role line in the daemon env file
///   (`RUSTYNET_NODE_ROLE=` / `NODE_ROLE=` in `/etc/default/rustynetd`),
///   which is what the NEXT daemon start reads.
///
/// Why the persisted line needs its own restore (katana-xnet-146 root
/// cause): `rustynet role set` plans from the LIVE preset the daemon reports
/// (`role_cli::plan_concrete_actions`). exit→admin only retracts the exit
/// (no env write); admin→client rewrites the env file but does NOT restart
/// the daemon, so the live preset stays `admin` while the file says
/// `client`. A restore `role set admin` therefore plans identity/no-op (live
/// is already admin), writes nothing, and the poll of the LIVE role passes
/// while `client` stays persisted — until the next stage that restarts the
/// stack reads it back and the enrollment precondition finds a demoted
/// admin. The restore thus rewrites the recorded env line with an argv-only
/// `sudo -n sed` and VERIFIES it by reading the file again; the live role is
/// restored through the public CLI and confirmed by the bounded
/// `node_role=` poll.
///
/// A restore failure fails the stage even when the residue evaluation
/// passed: an exit left demoted poisons every later admin-only stage on
/// this node (katana-xnet-113 / katana-xnet-146
/// `live_enrollment_restart_validation` root cause). A persisted role line
/// that cannot be recorded (absent, duplicated, garbled) fails the stage
/// BEFORE the demotion, because a role that cannot be restored and verified
/// must never be demoted.
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

    // Record the pre-demotion roles BEFORE demoting: the demotion outlives
    // this stage, and the recorded roles — not a hard-coded admin — are what
    // the node must be restored to. The LIVE primary role comes from the
    // daemon; the PERSISTED role is the env-file line the next daemon start
    // reads, and an unrecordable line (absent / several / garbled) fails the
    // stage here, before any demotion command is issued.
    let recorded_live_role = capture_daemon_node_role(shell).map_err(|err| {
        format!(
            "{alias}: capture pre-demotion node role failed: {err} (nothing was demoted: \
             the live and persisted roles are untouched)"
        )
    })?;
    let recorded_persisted_role = read_persisted_node_role(shell).map_err(|err| {
        format!(
            "{alias}: capture pre-demotion persisted node role failed: {err}; refusing to \
             demote a node whose persisted role cannot be restored and verified (nothing \
             was demoted: the live and persisted roles are untouched)"
        )
    })?;
    let recorded = PreDemotionRoles {
        live: recorded_live_role,
        persisted: recorded_persisted_role,
    };

    let demotion_exit_code = match demote_to_client(shell) {
        Ok(code) => code,
        Err(err) => {
            // The demotion may have partially applied (admin done, client
            // not; or the env line rewritten before a later step failed):
            // restore best-effort, then surface the demotion error. If even
            // the best-effort restore fails, the node may be left
            // mid-transition — name that and carry the restore error text
            // instead of discarding it (D4).
            if let Err(restore_err) = restore_pre_demotion_role(shell, &recorded) {
                return Err(format!(
                    "{err}; the best-effort restore to the pre-demotion roles ({}) also \
                     failed, so the node may be left mid-transition: {restore_err}",
                    recorded.describe()
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
    let restore_result = restore_pre_demotion_role(shell, &recorded);
    match (evaluation, restore_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(eval_err), Ok(())) => Err(eval_err),
        (evaluation, Err(restore_err)) => {
            let mut message = format!(
                "{alias}: post-validation restore to the pre-demotion roles ({}) failed; \
                 the node is left demoted and later admin-only stages would be poisoned: \
                 {restore_err}",
                recorded.describe()
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
/// in this validator uses: role rewrites need root (the env-file write) and
/// the daemon socket is root-owned, and the socket is pinned explicitly
/// instead of relying on the default path resolution.
fn run_daemon_cli(shell: &dyn RemoteShellHost, args: &[&str]) -> Result<RemoteExitStatus, String> {
    let socket_env = format!("RUSTYNET_DAEMON_SOCKET={LINUX_DAEMON_SOCKET}");
    let mut argv: Vec<&str> = vec!["sudo", "-n", "env", &socket_env, RUSTYNET_CLI_PATH];
    argv.extend_from_slice(args);
    shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch failed: {err}"))
}

/// The `sudo -n <args…>` seam for the root-owned env-file reads and rewrites.
/// Argv-only: every element is a literal argument (the POSIX backend
/// single-quotes each one), so no value is ever interpreted by a shell.
fn run_sudo_argv(shell: &dyn RemoteShellHost, args: &[&str]) -> Result<RemoteExitStatus, String> {
    let mut argv: Vec<&str> = vec!["sudo", "-n"];
    argv.extend_from_slice(args);
    shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("dispatch failed: {err}"))
}

/// Grep pattern selecting the daemon env file's persisted role line. The
/// installer writes `RUSTYNET_NODE_ROLE` (the key `rustynetd.service`
/// substitutes into `--node-role`); the role CLI's env rewrite
/// (`update_node_role_env_file` in main.rs) keeps whichever of the two
/// spellings it finds, so the restore must put back exactly the line, key
/// included, that was there.
const PERSISTED_ROLE_GREP_PATTERN: &str = "^(RUSTYNET_)?NODE_ROLE=";

/// Longest persisted role value accepted. The accepted alphabet is
/// `[a-z_]` (every primary role the daemon knows: `admin`, `client`,
/// `blind_exit`, `blind_relay`), which also keeps the value free of every
/// character that is special in a sed program or a shell.
const PERSISTED_ROLE_VALUE_MAX_LEN: usize = 32;

/// The env-file key a persisted role line is written under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistedRoleKey {
    RustynetNodeRole,
    NodeRole,
}

impl PersistedRoleKey {
    const ALL: [Self; 2] = [Self::RustynetNodeRole, Self::NodeRole];

    const fn as_str(self) -> &'static str {
        match self {
            Self::RustynetNodeRole => "RUSTYNET_NODE_ROLE",
            Self::NodeRole => "NODE_ROLE",
        }
    }
}

/// The validated persisted role line: which key the installer chose and the
/// role value it holds. Only [`parse_persisted_role_record`] constructs one,
/// so the key is always one of the two closed spellings and the value always
/// matches `[a-z_]{1,32}` — the sed program built from a record can therefore
/// never carry a delimiter, an escape, a metacharacter or a newline.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PersistedRoleRecord {
    key: PersistedRoleKey,
    value: String,
}

impl PersistedRoleRecord {
    /// The exact env-file line (`KEY=value`, no newline).
    fn line(&self) -> String {
        format!("{}={}", self.key.as_str(), self.value)
    }
}

/// The node's roles as recorded BEFORE the demotion: both are restored, and
/// both are verified, after it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PreDemotionRoles {
    /// The daemon's LIVE primary role (`node_role=` from `rustynet status`).
    live: String,
    /// The PERSISTED role line the next daemon start reads.
    persisted: PersistedRoleRecord,
}

impl PreDemotionRoles {
    fn describe(&self) -> String {
        format!(
            "live primary role {:?}, persisted {:?} in {DEFAULT_DAEMON_ENV_PATH}",
            self.live,
            self.persisted.line()
        )
    }
}

/// Role values are lowercase ASCII letters and underscores, 1..=32 long.
fn is_valid_persisted_role_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= PERSISTED_ROLE_VALUE_MAX_LEN
        && value.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Judge the stdout of the persisted-role grep: EXACTLY ONE line, spelled
/// `RUSTYNET_NODE_ROLE=<role>` or `NODE_ROLE=<role>` with a `[a-z_]{1,32}`
/// role. Zero lines (absent), several lines (ambiguous: which one does the
/// next start honour?) and any other shape (garbled: quotes, whitespace,
/// carriage return, uppercase, an over-long value…) are refused, never
/// guessed at. Lines are split on `\n` only, so a stray `\r` stays in the
/// value and is refused rather than silently normalised away.
fn parse_persisted_role_record(grep_stdout: &str) -> Result<PersistedRoleRecord, String> {
    let mut lines: Vec<&str> = grep_stdout.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    match lines.as_slice() {
        [] => {
            Err("no `RUSTYNET_NODE_ROLE=` / `NODE_ROLE=` line (persisted role absent)".to_owned())
        }
        [line] => {
            let (key, value) = PersistedRoleKey::ALL
                .iter()
                .find_map(|key| {
                    line.strip_prefix(key.as_str())
                        .and_then(|rest| rest.strip_prefix('='))
                        .map(|value| (*key, value))
                })
                .ok_or_else(|| format!("unrecognised persisted role line {line:?}"))?;
            if !is_valid_persisted_role_value(value) {
                return Err(format!(
                    "persisted role line {line:?} does not carry a [a-z_]{{1,{PERSISTED_ROLE_VALUE_MAX_LEN}}} role"
                ));
            }
            Ok(PersistedRoleRecord {
                key,
                value: value.to_owned(),
            })
        }
        several => Err(format!(
            "{} role lines (persisted role ambiguous): {several:?}",
            several.len()
        )),
    }
}

/// Read the daemon env file's persisted role line through
/// `sudo -n grep -E '<pattern>' <env path>` and validate it. Fails closed on
/// every other shape: a non-zero exit, a grep that matched nothing, several
/// matches, a garbled value, a dispatch failure.
fn read_persisted_node_role(shell: &dyn RemoteShellHost) -> Result<PersistedRoleRecord, String> {
    let out = run_sudo_argv(
        shell,
        &[
            "grep",
            "-E",
            PERSISTED_ROLE_GREP_PATTERN,
            DEFAULT_DAEMON_ENV_PATH,
        ],
    )
    .map_err(|err| format!("read of {DEFAULT_DAEMON_ENV_PATH} {err}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    match out.code {
        0 => parse_persisted_role_record(&stdout)
            .map_err(|why| format!("{DEFAULT_DAEMON_ENV_PATH}: {why}")),
        // grep's "no line selected" exit; anything on stderr means it was
        // really sudo (or the file) that failed, which the arm below names.
        1 if stderr.trim().is_empty() => Err(format!(
            "{DEFAULT_DAEMON_ENV_PATH}: no `RUSTYNET_NODE_ROLE=` / `NODE_ROLE=` line \
             (persisted role absent)"
        )),
        code => Err(format!(
            "`sudo -n grep` of {DEFAULT_DAEMON_ENV_PATH} exited {code}: {}{}",
            stdout.trim(),
            stderr.trim()
        )),
    }
}

/// The sed program that puts `record` back: replace the whole line of the
/// SAME key (`^KEY=.*$`) with `KEY=value`. Built only from a validated
/// record, so it contains no delimiter, escape or metacharacter beyond the
/// fixed `^`, `.*`, `$` of the template.
fn persisted_role_sed_program(record: &PersistedRoleRecord) -> String {
    let key = record.key.as_str();
    format!("s/^{key}=.*$/{key}={}/", record.value)
}

/// Rewrite the persisted role line back to `record` with an argv-only
/// `sudo -n sed -i -E <program> <env path>`. The role CLI cannot do this
/// itself: its planner works from the LIVE preset, so `role set <role>` is a
/// no-op whenever the live daemon already reports that role.
fn rewrite_persisted_node_role(
    shell: &dyn RemoteShellHost,
    record: &PersistedRoleRecord,
) -> Result<(), String> {
    let program = persisted_role_sed_program(record);
    let out = run_sudo_argv(
        shell,
        &["sed", "-i", "-E", &program, DEFAULT_DAEMON_ENV_PATH],
    )
    .map_err(|err| format!("persisted role rewrite ({program}) {err}"))?;
    if out.code != 0 {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "persisted role rewrite (sed -i -E {program} {DEFAULT_DAEMON_ENV_PATH}) exited {}: {}{}",
            out.code,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
}

/// Best-effort LIVE restore through the public CLI seam: `role set <role>`.
/// Against a live daemon that already reports `<role>` this plans a no-op
/// (see [`validate_linux_exit_demotion_residue`]), so it is NOT what restores
/// the persisted line — but it is the right tool if the live role really
/// drifted, and a failure of it is a failure of the restore (never hidden).
fn restore_live_role_via_cli(shell: &dyn RemoteShellHost, role: &str) -> Result<(), String> {
    let out = run_daemon_cli(shell, &["role", "set", role])
        .map_err(|err| format!("restore (role set {role}) {err}"))?;
    if out.code != 0 {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "restore (role set {role}) exited {}: {}{}",
            out.code,
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(())
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

/// Restore the node to its recorded pre-demotion roles and verify BOTH:
///
/// 1. the LIVE role, best-effort through the public CLI (`role set <live>`);
/// 2. the PERSISTED role line, rewritten to the recorded line with an
///    argv-only `sudo -n sed` — the authoritative restore, because
///    `role set` plans from the live preset and writes nothing when the
///    live daemon already reports the recorded role;
/// 3. the persisted line read back through the same grep as the pre-demotion
///    record, which must yield the identical single line (done after the
///    rewrite even when the rewrite failed, so the failure can name what is
///    left behind);
/// 4. the live role through the shared bounded `node_role=` poll.
///
/// Every step runs even when an earlier one failed, and every failure is
/// reported: a restore that can only partly succeed must still say exactly
/// which part is left behind. The returned error names the left-behind
/// persisted role and the live role.
fn restore_pre_demotion_role(
    shell: &dyn RemoteShellHost,
    recorded: &PreDemotionRoles,
) -> Result<(), String> {
    let mut failures: Vec<String> = Vec::new();

    if let Err(err) = restore_live_role_via_cli(shell, &recorded.live) {
        failures.push(err);
    }

    let rewrite = rewrite_persisted_node_role(shell, &recorded.persisted);
    let rewrite_failed = rewrite.is_err();
    if let Err(err) = rewrite {
        failures.push(err);
    }

    let observed_persisted = read_persisted_node_role(shell);
    match &observed_persisted {
        Ok(found) if *found == recorded.persisted => {}
        // The rewrite failure above already names the cause; the
        // left-behind summary below names what the file holds.
        Ok(_) if rewrite_failed => {}
        Ok(found) => failures.push(format!(
            "persisted role verify mismatch: expected {:?} but {DEFAULT_DAEMON_ENV_PATH} holds {:?}",
            recorded.persisted.line(),
            found.line()
        )),
        Err(err) => failures.push(format!("persisted role verify read failed: {err}")),
    }

    // Shared bounded readiness poll (blind_exit): the daemon IPC may need a
    // bounded wait before its role can be asserted.
    let live_poll = poll_daemon_node_role(
        shell,
        VmGuestPlatform::Linux,
        &recorded.live,
        "post-restore readiness poll",
    );
    if let Err(err) = &live_poll {
        failures.push(err.clone());
    }

    if failures.is_empty() {
        return Ok(());
    }
    let persisted_left_behind = match &observed_persisted {
        Ok(found) => format!(
            "persisted role {} ({:?} in {DEFAULT_DAEMON_ENV_PATH})",
            found.value,
            found.line()
        ),
        Err(_) => "persisted role unreadable".to_owned(),
    };
    // A confirmed poll names the recorded role; an unconfirmed one reads the
    // live role once more so the message names what the daemon reports NOW.
    let live_left_behind = match &live_poll {
        Ok(()) => format!("live role {}", recorded.live),
        Err(_) => match capture_daemon_node_role(shell) {
            Ok(role) => format!("live role {role} (recorded {})", recorded.live),
            Err(err) => format!("live role unreadable ({err}; recorded {})", recorded.live),
        },
    };
    Err(format!(
        "{}; left behind: {persisted_left_behind}, {live_left_behind}",
        failures.join("; ")
    ))
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
    //
    // Side effects that outlive this call (katana-xnet-146): exit→admin only
    // retracts the exit (no env write); admin→client rewrites the persisted
    // role line to `client` WITHOUT restarting the daemon, so the live role
    // stays `admin` while the next daemon start would read `client`. The
    // caller records and restores BOTH (see `restore_pre_demotion_role`).
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

    fn grep_persisted_argv() -> [&'static str; 6] {
        [
            "sudo",
            "-n",
            "grep",
            "-E",
            "^(RUSTYNET_)?NODE_ROLE=",
            "/etc/default/rustynetd",
        ]
    }

    /// Program one persisted-role grep reply (FIFO: the first is the
    /// pre-demotion record, the second the post-restore verification).
    fn program_persisted_grep(mock: &MockShellHost, line: &str) {
        mock.program_run_response(&grep_persisted_argv(), exit_ok(&format!("{line}\n")));
    }

    /// The persisted-role restore succeeding: the argv-only `sed` rewrite
    /// exits 0 and the verification grep reads back the recorded line.
    fn program_persisted_restore_ok(mock: &MockShellHost, key: &str, role: &str) {
        let program = format!("s/^{key}=.*$/{key}={role}/");
        mock.program_run_response(
            &[
                "sudo",
                "-n",
                "sed",
                "-i",
                "-E",
                &program,
                "/etc/default/rustynetd",
            ],
            exit_code(0),
        );
        program_persisted_grep(mock, &format!("{key}={role}"));
    }

    /// One live-role poll attempt reporting `role`.
    fn program_live_poll_ok(mock: &MockShellHost, role: &str) {
        mock.program_run_response(
            &status_argv(),
            exit_ok(&format!("node_id=deb-1 node_role={role} state=Ready\n")),
        );
    }

    /// Programs everything up to and including the demotion pair: discover,
    /// during-snapshot, pre-demotion live role + persisted role capture,
    /// `role set admin` + `role set client`, daemon check, settle sleep. The
    /// after-snapshot, the restore and its readiness poll are left for each
    /// test to script so the restore outcome (ok / failing exit / never-ready
    /// poll) is per-test.
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
        program_persisted_grep(mock, &format!("RUSTYNET_NODE_ROLE={pre_role}"));

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

    /// The restore success path: `role set <recorded_role>` exits 0, the
    /// persisted line is rewritten and verified, then the readiness poll
    /// reads back the recorded role.
    fn program_restore_ok(mock: &MockShellHost, recorded_role: &'static str) {
        mock.program_run_response(&role_set_argv(recorded_role), exit_code(0));
        program_persisted_restore_ok(mock, "RUSTYNET_NODE_ROLE", recorded_role);
        program_live_poll_ok(mock, recorded_role);
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
        // Everything else in the restore works: only the live `role set` fails.
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
        program_live_poll_ok(&mock, "admin");
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
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
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
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
        program_live_poll_ok(&mock, "admin");
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
        program_persisted_grep(&mock, "RUSTYNET_NODE_ROLE=admin");
        // Demotion: admin ok, client fails.
        mock.program_run_response(&role_set_argv("admin"), exit_code(0));
        mock.program_run_response(&role_set_argv("client"), exit_code(1));
        // The best-effort restore's own `role set admin` also fails.
        mock.program_run_response(&role_set_argv("admin"), exit_code(7));
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
        program_live_poll_ok(&mock, "admin");
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
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
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
        program_persisted_restore_ok(&mock, "RUSTYNET_NODE_ROLE", "admin");
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
        program_persisted_grep(&mock, "RUSTYNET_NODE_ROLE=admin");
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

    // ── Persisted role record: parser, argv pins, sed program ───────────────

    fn record(key: PersistedRoleKey, value: &str) -> PersistedRoleRecord {
        PersistedRoleRecord {
            key,
            value: value.to_owned(),
        }
    }

    #[test]
    fn persisted_role_parser_accepts_exactly_one_well_formed_line() {
        let longest = "a".repeat(PERSISTED_ROLE_VALUE_MAX_LEN);
        let longest_line = format!("RUSTYNET_NODE_ROLE={longest}\n");
        let cases: Vec<(&str, PersistedRoleKey, &str)> = vec![
            (
                "RUSTYNET_NODE_ROLE=admin\n",
                PersistedRoleKey::RustynetNodeRole,
                "admin",
            ),
            (
                "RUSTYNET_NODE_ROLE=admin",
                PersistedRoleKey::RustynetNodeRole,
                "admin",
            ),
            ("NODE_ROLE=client\n", PersistedRoleKey::NodeRole, "client"),
            (
                "RUSTYNET_NODE_ROLE=blind_exit\n",
                PersistedRoleKey::RustynetNodeRole,
                "blind_exit",
            ),
            (
                "RUSTYNET_NODE_ROLE=a\n",
                PersistedRoleKey::RustynetNodeRole,
                "a",
            ),
            (
                longest_line.as_str(),
                PersistedRoleKey::RustynetNodeRole,
                longest.as_str(),
            ),
        ];
        for (stdout, key, value) in cases {
            assert_eq!(
                parse_persisted_role_record(stdout),
                Ok(record(key, value)),
                "{stdout:?}"
            );
        }
    }

    #[test]
    fn persisted_role_parser_refuses_absent_several_and_garbled() {
        let too_long = format!("RUSTYNET_NODE_ROLE={}\n", "a".repeat(33));
        let refused: Vec<&str> = vec![
            "",
            "\n",
            "RUSTYNET_NODE_ROLE=admin\nRUSTYNET_NODE_ROLE=admin\n",
            "RUSTYNET_NODE_ROLE=admin\nNODE_ROLE=admin\n",
            "\nRUSTYNET_NODE_ROLE=admin\n",
            "RUSTYNET_NODE_ROLE=\n",
            "RUSTYNET_NODE_ROLE=\"admin\"\n",
            "RUSTYNET_NODE_ROLE=Admin\n",
            "RUSTYNET_NODE_ROLE=admin \n",
            "RUSTYNET_NODE_ROLE=admin\r\n",
            "RUSTYNET_NODE_ROLE=admin;reboot\n",
            "RUSTYNET_NODE_ROLE=ad/min\n",
            "RUSTYNET_NODE_ROLE=ad&min\n",
            "RUSTYNET_NODE_ROLE=admin2\n",
            "RUSTYNET_NODE_ROLE=blind-exit\n",
            "RUSTYNET_NODE_ROLE=\u{e9}\n",
            " RUSTYNET_NODE_ROLE=admin\n",
            "NODE_ROLE_X=admin\n",
            "XRUSTYNET_NODE_ROLE=admin\n",
            "RUSTYNET_NODE_ROLE\n",
            "FOO=admin\n",
            too_long.as_str(),
        ];
        for stdout in refused {
            assert!(
                parse_persisted_role_record(stdout).is_err(),
                "{stdout:?} must be refused"
            );
        }
        assert!(
            parse_persisted_role_record("")
                .expect_err("absent")
                .contains("absent")
        );
        assert!(
            parse_persisted_role_record("NODE_ROLE=a\nNODE_ROLE=b\n")
                .expect_err("several")
                .contains("ambiguous")
        );
    }

    #[test]
    fn persisted_role_sed_program_is_the_closed_template() {
        assert_eq!(
            persisted_role_sed_program(&record(PersistedRoleKey::RustynetNodeRole, "admin")),
            "s/^RUSTYNET_NODE_ROLE=.*$/RUSTYNET_NODE_ROLE=admin/"
        );
        assert_eq!(
            persisted_role_sed_program(&record(PersistedRoleKey::NodeRole, "client")),
            "s/^NODE_ROLE=.*$/NODE_ROLE=client/"
        );
    }

    /// REAL-TOOL witness, no shim in the loop: the production sed program and
    /// grep pattern, executed by this machine's actual `sed -E` and `grep -E`
    /// on a realistic env file full of look-alike lines. (Without `-i`: BSD and
    /// GNU sed disagree about what follows `-i`, and the in-place flag changes
    /// where the result goes, not what the program does.) The guest-model tests
    /// prove the stage drives these tools correctly; this proves the tools do
    /// what the stage assumes of them.
    #[test]
    fn real_sed_and_grep_apply_the_production_program_and_pattern() {
        use std::process::Command;

        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .subsec_nanos();
        let dir =
            std::env::temp_dir().join(format!("exdemo_realtool_{}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let env_file = dir.join("rustynetd");
        let env_path = env_file.to_str().expect("utf-8 temp path").to_owned();

        // None of these may be selected by the grep or touched by the rewrite.
        let decoys = [
            "RUSTYNET_NODE_ID=katana-exit-1",
            "RUSTYNET_NODE_ROLE_EXTRA=client",
            "XRUSTYNET_NODE_ROLE=client",
            "NODE_ROLE_NOT=me",
            "# NODE_ROLE=commented",
            " RUSTYNET_NODE_ROLE=indented",
            "RUSTYNET_BACKEND=linux-wireguard",
        ];
        for key in PersistedRoleKey::ALL {
            let demoted = record(key, "client");
            let recorded = record(key, "admin");
            let mut lines: Vec<String> = decoys.iter().map(|line| (*line).to_owned()).collect();
            lines.insert(3, demoted.line());
            std::fs::write(&env_file, format!("{}\n", lines.join("\n"))).expect("write env");

            let grep = Command::new("grep")
                .args(["-E", PERSISTED_ROLE_GREP_PATTERN, &env_path])
                .output()
                .expect("spawn grep");
            assert_eq!(grep.status.code(), Some(0), "{key:?}");
            assert_eq!(
                String::from_utf8_lossy(&grep.stdout),
                format!("{}\n", demoted.line()),
                "grep must select exactly the role line, never a look-alike ({key:?})"
            );
            assert_eq!(
                parse_persisted_role_record(&String::from_utf8_lossy(&grep.stdout)),
                Ok(demoted.clone()),
                "{key:?}"
            );

            let program = persisted_role_sed_program(&recorded);
            let sed = Command::new("sed")
                .args(["-E", &program, &env_path])
                .output()
                .expect("spawn sed");
            assert_eq!(sed.status.code(), Some(0), "{key:?}: {program}");
            let mut expected = lines.clone();
            expected[3] = recorded.line();
            assert_eq!(
                String::from_utf8_lossy(&sed.stdout),
                format!("{}\n", expected.join("\n")),
                "sed must rewrite only the role line of the recorded key ({key:?}): {program}"
            );
        }

        // No role line at all: grep selects nothing, exits 1 with an empty
        // stderr — the exact shape `read_persisted_node_role` calls "absent".
        std::fs::write(&env_file, format!("{}\n", decoys.join("\n"))).expect("write env");
        let none = Command::new("grep")
            .args(["-E", PERSISTED_ROLE_GREP_PATTERN, &env_path])
            .output()
            .expect("spawn grep");
        assert_eq!(none.status.code(), Some(1));
        assert!(none.stdout.is_empty() && none.stderr.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn persisted_role_read_issues_the_pinned_argv_and_judges_the_exit() {
        let mock = MockShellHost::new();
        program_persisted_grep(&mock, "RUSTYNET_NODE_ROLE=admin");
        assert_eq!(
            read_persisted_node_role(&mock),
            Ok(record(PersistedRoleKey::RustynetNodeRole, "admin")),
            "the exact argv `sudo -n grep -E '^(RUSTYNET_)?NODE_ROLE=' /etc/default/rustynetd`"
        );

        // grep selected nothing and sudo said nothing: the line is absent.
        let absent = MockShellHost::new();
        absent.program_run_response(&grep_persisted_argv(), exit_code(1));
        let err = read_persisted_node_role(&absent).expect_err("absent line");
        assert!(err.contains("persisted role absent"), "{err}");

        // A non-zero exit WITH stderr is a failure, not an absent line.
        let denied = MockShellHost::new();
        denied.program_run_response(
            &grep_persisted_argv(),
            RemoteExitStatus {
                code: 1,
                stdout: Vec::new(),
                stderr: b"sudo: a password is required\n".to_vec(),
            },
        );
        let err = read_persisted_node_role(&denied).expect_err("sudo denied");
        assert!(
            err.contains("exited 1") && err.contains("a password is required"),
            "{err}"
        );
        assert!(!err.contains("absent"), "{err}");

        let unreadable = MockShellHost::new();
        unreadable.program_run_response(&grep_persisted_argv(), exit_code(2));
        let err = read_persisted_node_role(&unreadable).expect_err("grep error");
        assert!(err.contains("exited 2"), "{err}");

        // Exit 0 with garbled content is still refused.
        let garbled = MockShellHost::new();
        program_persisted_grep(&garbled, "RUSTYNET_NODE_ROLE=Admin");
        assert!(read_persisted_node_role(&garbled).is_err());

        // A dispatch failure is a failure.
        let unprogrammed = MockShellHost::new();
        let err = read_persisted_node_role(&unprogrammed).expect_err("dispatch failure");
        assert!(err.contains("dispatch failed"), "{err}");
    }

    #[test]
    fn persisted_role_rewrite_issues_the_pinned_argv_and_reports_a_non_zero_exit() {
        let rec = record(PersistedRoleKey::RustynetNodeRole, "admin");
        let ok = MockShellHost::new();
        program_persisted_restore_ok(&ok, "RUSTYNET_NODE_ROLE", "admin");
        rewrite_persisted_node_role(&ok, &rec)
            .expect("the exact argv `sudo -n sed -i -E <program> /etc/default/rustynetd`");
        assert_eq!(
            ok.run_log()[0].argv,
            vec![
                "sudo",
                "-n",
                "sed",
                "-i",
                "-E",
                "s/^RUSTYNET_NODE_ROLE=.*$/RUSTYNET_NODE_ROLE=admin/",
                "/etc/default/rustynetd"
            ]
        );

        let failing = MockShellHost::new();
        failing.program_run_response(
            &[
                "sudo",
                "-n",
                "sed",
                "-i",
                "-E",
                "s/^RUSTYNET_NODE_ROLE=.*$/RUSTYNET_NODE_ROLE=admin/",
                "/etc/default/rustynetd",
            ],
            RemoteExitStatus {
                code: 4,
                stdout: Vec::new(),
                stderr: b"sed: read-only file system\n".to_vec(),
            },
        );
        let err = rewrite_persisted_node_role(&failing, &rec).expect_err("non-zero exit");
        assert!(
            err.contains("exited 4") && err.contains("read-only file system"),
            "{err}"
        );

        let unprogrammed = MockShellHost::new();
        let err = rewrite_persisted_node_role(&unprogrammed, &rec).expect_err("dispatch failure");
        assert!(err.contains("dispatch failed"), "{err}");
    }

    /// The persisted record is judged BEFORE any demotion command: a refused
    /// record leaves the mock's run log with no `role set` at all.
    #[test]
    fn refused_persisted_record_issues_no_demotion_command() {
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
        mock.program_run_response(&grep_persisted_argv(), exit_code(1));
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an absent persisted role must fail the stage");
        assert!(
            err.contains("persisted node role") && err.contains("nothing was demoted"),
            "{err}"
        );
        assert!(
            recorded_role_sets(&mock).is_empty(),
            "no demotion command may precede a refused record: {:?}",
            mock.run_log()
        );
    }

    /// The live role is recorded before any demotion too: an unreadable
    /// status fails the stage with nothing demoted.
    #[test]
    fn unreadable_live_role_issues_no_demotion_command() {
        let mock = MockShellHost::new();
        mock.program_run_response(
            &discover_argv(),
            exit_ok("table inet rustynet_g7\ntable ip rustynet_nat_g7\n"),
        );
        let during = demo_snapshot(true, "Enabled", "Enabled");
        mock.program_run_response(&generation_snapshot_argv(), exit_ok(&during.to_string()));
        mock.program_run_response(&status_argv(), exit_code(1));
        let err = validate_linux_exit_demotion_residue(&mock, TEST_DAEMON, "deb-1")
            .expect_err("an unreadable live role must fail the stage");
        assert!(
            err.contains("capture pre-demotion node role failed")
                && err.contains("nothing was demoted"),
            "{err}"
        );
        assert!(
            recorded_role_sets(&mock).is_empty(),
            "no demotion command may precede a failed record: {:?}",
            mock.run_log()
        );
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

#[cfg(test)]
#[path = "exit_demotion_residue_semantic_tests.rs"]
mod semantic_tests;
