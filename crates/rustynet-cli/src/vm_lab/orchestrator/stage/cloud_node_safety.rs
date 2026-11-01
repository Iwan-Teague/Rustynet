//! Orchestrator-side safety net for cloud nodes: nodes that declare an
//! inventory `dataplane_endpoint`, or that are managed over the tailnet
//! (ssh target / last known address in `100.64.0.0/10` or
//! `fd7a:115c:a1e0::/48`).
//!
//! Why this exists (harness-only; no product or daemon change). As soon as the
//! rustynet daemon starts on such a node, its `ExecStartPre` installs the
//! `rustynet_boot` killswitch (bootstrap's `ops install-systemd` restarts the
//! daemon, long before `enforce_baseline_runtime`), and once enforcement
//! engages the runtime table joins it. Those tables drop tailscaled's OUTER
//! transport for NEW flows (only UDP 51820, the ssh-CIDR tcp/22 and STUN
//! pinholes are allowed on output). The orchestrator can then manage the node
//! only over a tailnet path that is ALREADY established and DIRECT; a
//! DERP-only or degrading path strands the node (a reboot reinstalls the boot
//! killswitch, and the cloud provider's own control channel is dropped too).
//!
//! Guards, all keyed strictly on the cloud-node predicate so every other
//! node's behaviour is byte-identical:
//!
//! 1. PRECONDITION: the node's tailscale path to the orchestrator peer must be
//!    direct (`CurAddr` non-empty). Refuse otherwise.
//! 2. DEAD-MAN: a node-local `systemd-run` timer that runs a recovery script
//!    after [`DEADMAN_BUDGET_SECS`] even if the orchestrator dies or the
//!    management path is lost. Armed at the earliest node-touching stage
//!    (`verify_ssh_reachability`, before any daemon start) and re-armed at
//!    `enforce_baseline_runtime` (which resets the clock); disarmed at
//!    teardown (`FinalCleanupStage`, always-run) once the node is clean.
//!    Arming failure refuses the run; disarm failure is a loud warning.
//! 3. REBOOT REFUSAL: the transient timer lives in `/run` and is lost on
//!    reboot while the boot killswitch is reinstalled at boot, so a plan that
//!    reboots nodes (`live_reboot_recovery_validation`) is refused when a
//!    cloud node is selected.
//!
//! Recovery script note: `rustynet ops disconnect-cleanup` deliberately keeps
//! the `inet rustynet_boot` table (it is the ssh recovery path), but that table
//! is also what drops tailscaled's outer transport, so the dead-man also
//! disables the rustynet units and deletes every `rustynet*` nft table. It
//! mirrors the harness's own `cleanup_runtime_state` resets in
//! `adapter/linux_traffic.rs` (those constants are private to that file and
//! carry `sudo -n`; a drift test pins the shared table-name pattern).

use std::net::IpAddr;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::stage::StageId;
use crate::vm_lab::orchestrator::stage::node_diagnostics::{is_safe_component, single_host_cidrs};

/// How long the dead-man waits before force-cleaning the node. It only matters
/// if the orchestrator dies or loses the node, so it is deliberately generous
/// (4 h): a full run (soak on) takes 40-90 minutes, and a dead-man that fires
/// mid-run would silently tear down a valid run. Each (re-)arm restarts the
/// clock.
pub(crate) const DEADMAN_BUDGET_SECS: u64 = 4 * 60 * 60;
/// Transient unit name; the timer is `<name>.timer`.
pub(crate) const DEADMAN_UNIT: &str = "rn-deadman-cleanup";
const DEADMAN_TIMER_UNIT: &str = "rn-deadman-cleanup.timer";
const DEADMAN_SERVICE_UNIT: &str = "rn-deadman-cleanup.service";
/// Bound for every safety-net command on the node.
const CMD_TIMEOUT: &str = "20";
/// `systemctl stop` exit code for "unit not loaded": a transient timer only
/// vanishes by firing (or by the node rebooting, since it lives in `/run`).
const SYSTEMCTL_NOT_LOADED_RC: i32 = 5;
/// PATH the recovery script runs with (root's, including the sbin dirs `nft`
/// and `ip` live in).
const RECOVERY_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// Stages that reboot nodes; a cloud node cannot be guarded across a reboot.
const REBOOT_STAGES: &[StageId] = &[
    StageId::LiveRebootRecoveryValidation,
    StageId::MacosRebootRecoveryValidation,
];

/// Directory of per-alias run markers (report-dir relative).
fn marker_dir(report_dir: &std::path::Path) -> std::path::PathBuf {
    report_dir.join("state").join("cloud_node_safety")
}

/// Marker recording that THIS run armed a dead-man on an alias, so teardown
/// knows a disarm is owed (and an absent timer then means it FIRED or the node
/// rebooted). Written BEFORE arming so a half-successful arm is still tracked.
fn armed_marker_path(report_dir: &std::path::Path, alias: &str) -> std::path::PathBuf {
    marker_dir(report_dir).join(format!("armed.{alias}"))
}

/// Marker recording that the dead-man was found absent (fired or rebooted).
fn fired_marker_path(report_dir: &std::path::Path, alias: &str) -> std::path::PathBuf {
    marker_dir(report_dir).join(format!("fired.{alias}"))
}

/// Aliases with an armed marker in this report dir, sorted. Teardown iterates
/// these rather than reloading the inventory.
fn armed_aliases(report_dir: &std::path::Path) -> Vec<String> {
    let mut aliases: Vec<String> = std::fs::read_dir(marker_dir(report_dir))
        .map(|rd| {
            rd.filter_map(Result::ok)
                .filter_map(|e| e.file_name().to_str().map(str::to_owned))
                .filter_map(|n| n.strip_prefix("armed.").map(str::to_owned))
                .filter(|a| is_safe_component(a))
                .collect()
        })
        .unwrap_or_default();
    aliases.sort();
    aliases
}

/// Node-side recovery run by the dead-man (as root, from systemd). Constant
/// text apart from the two parameters (production passes the installed CLI
/// path and [`RECOVERY_PATH`]; tests pass stubs).
///
/// Robustness mirrors the harness's own cleanup: bounded `disconnect-cleanup`;
/// disable every `rustynet*` unit; `pkill -x` then a bounded wait for the
/// process to go (a daemon mid-shutdown re-applies `rustynet_boot`); up to 10
/// list-and-delete passes over `rustynet*` nft tables only (a
/// `rustynet-push-all` timer can re-apply the boot table between passes); and
/// a `rustynet*` link sweep. Everything tolerates failure.
///
/// Systemd-safe: systemd substitutes `${VAR}`, `$$` and `%` specifiers in
/// `ExecStart`, so the text contains none of them (a test pins this).
pub(crate) fn deadman_recovery_script_with(cli: &str, path: &str) -> String {
    format!(
        "export PATH={path}; \
         timeout 60 {cli} ops disconnect-cleanup >/dev/null 2>&1 || true; \
         for u in $(systemctl list-unit-files 2>/dev/null | awk '$1 ~ /^rustynet/ {{print $1}}'); do \
             systemctl disable --now \"$u\" >/dev/null 2>&1 || true; \
         done; \
         pkill -x rustynetd >/dev/null 2>&1 || true; \
         for n in $(seq 1 60); do \
             pgrep -x rustynetd >/dev/null 2>&1 && sleep 0.5 || break; \
         done; \
         if command -v nft >/dev/null 2>&1; then \
             for n in $(seq 1 10); do \
                 t=$(nft list tables 2>/dev/null | awk '$3 ~ /^rustynet/ {{print $2 \" \" $3}}'); \
                 [ -z \"$t\" ] && break; \
                 echo \"$t\" | while read -r fam tbl; do \
                     nft delete table \"$fam\" \"$tbl\" >/dev/null 2>&1 || true; \
                 done; \
                 sleep 0.5; \
             done; \
         fi; \
         if command -v ip >/dev/null 2>&1; then \
             for l in $(ip -o link show 2>/dev/null | awk -F': ' '{{print $2}}' | awk -F'@' '{{print $1}}' | awk '/^rustynet/ {{print}}'); do \
                 ip link delete \"$l\" >/dev/null 2>&1 || true; \
             done; \
         fi; \
         exit 0"
    )
}

/// The production recovery script.
pub(crate) fn deadman_recovery_script() -> String {
    deadman_recovery_script_with(crate::vm_lab::LINUX_RUSTYNET_CLI_PATH, RECOVERY_PATH)
}

/// argv that arms the dead-man. Run through the shell seam (`sudo -n`, every
/// element single-quoted); the budget is rendered from a `u64`.
pub(crate) fn deadman_arm_argv(budget_secs: u64) -> Vec<String> {
    vec![
        "systemd-run".to_owned(),
        format!("--on-active={budget_secs}s"),
        format!("--unit={DEADMAN_UNIT}"),
        "--description=rustynet lab dead-man cleanup (harness-armed)".to_owned(),
        "/bin/sh".to_owned(),
        "-c".to_owned(),
        deadman_recovery_script(),
    ]
}

fn first_line(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("(no output)")
        .chars()
        .take(300)
        .collect()
}

/// Run `argv` through the seam and require exit 0.
fn run_checked(shell: &dyn RemoteShellHost, argv: &[&str], what: &str) -> Result<Vec<u8>, String> {
    let status = shell
        .run_argv(argv, &[], &[])
        .map_err(|e| format!("{what}: {e}"))?;
    if !status.is_success() {
        let stderr = first_line(&status.stderr).replace(['\n', '\r'], " ");
        return Err(format!("{what}: rc={}: {stderr}", status.code));
    }
    Ok(status.stdout)
}

/// Decide from `tailscale status --json` whether the path to the orchestrator
/// peer(s) is direct. The orchestrator's peer is identified as the tailscale
/// peer owning one of the `ssh_allow_cidrs` single-host addresses; if that
/// cannot be determined the answer is a refusal (fail closed). Every matched
/// peer must be online with a non-empty `CurAddr`. Returns the number of
/// peers verified; messages carry host names only, never addresses.
pub(crate) fn check_direct_path(status_json: &str, ssh_allow_cidrs: &str) -> Result<usize, String> {
    let candidates = single_host_cidrs(ssh_allow_cidrs);
    if candidates.is_empty() {
        return Err(
            "ssh_allow_cidrs carries no single-host (/32, /128) tailnet address, so the \
             orchestrator's tailscale peer cannot be identified"
                .to_owned(),
        );
    }
    let value: serde_json::Value = serde_json::from_str(status_json)
        .map_err(|e| format!("tailscale status --json is not valid JSON: {e}"))?;
    let peers = value
        .get("Peer")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "tailscale status --json has no Peer map".to_owned())?;
    let mut verified = 0usize;
    for peer in peers.values() {
        let owns_candidate = peer
            .get("TailscaleIPs")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|ips| {
                ips.iter()
                    .filter_map(serde_json::Value::as_str)
                    .filter_map(|s| s.parse::<IpAddr>().ok())
                    .any(|ip| candidates.contains(&ip))
            });
        if !owns_candidate {
            continue;
        }
        let host = peer
            .get("HostName")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .replace(['\n', '\r'], " ");
        if peer.get("Online").and_then(serde_json::Value::as_bool) == Some(false) {
            return Err(format!("tailscale peer {host} is offline"));
        }
        let cur_addr = peer
            .get("CurAddr")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        if cur_addr.is_empty() {
            let relay = peer
                .get("Relay")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("-");
            return Err(format!(
                "tailscale path to orchestrator peer {host} is not direct (CurAddr empty, \
                 DERP relay {relay}); the killswitch would strand this node"
            ));
        }
        verified += 1;
    }
    if verified == 0 {
        return Err(
            "no tailscale peer owns an ssh_allow_cidrs single-host address, so the \
             orchestrator's tailscale peer cannot be identified"
                .to_owned(),
        );
    }
    Ok(verified)
}

/// Run the precondition over the shell seam.
pub(crate) fn require_direct_tailscale_path(
    shell: &dyn RemoteShellHost,
    ssh_allow_cidrs: &str,
) -> Result<usize, String> {
    let stdout = run_checked(
        shell,
        &["timeout", CMD_TIMEOUT, "tailscale", "status", "--json"],
        "tailscale status --json",
    )?;
    check_direct_path(&String::from_utf8_lossy(&stdout), ssh_allow_cidrs)
}

/// Arm (or re-arm) the dead-man. Clears any previous timer first, which also
/// restarts the budget clock; requires both a clean `systemd-run` and an
/// `active` timer. Returns whether the pre-clear found NO timer loaded (rc 5):
/// for a re-arm that means the previous dead-man fired or the node rebooted.
pub(crate) fn arm_deadman(shell: &dyn RemoteShellHost, budget_secs: u64) -> Result<bool, String> {
    // A stale timer/unit would make `systemd-run` refuse the reused name.
    let previous_absent = shell
        .run_argv(
            &[
                "timeout",
                CMD_TIMEOUT,
                "systemctl",
                "stop",
                DEADMAN_TIMER_UNIT,
            ],
            &[],
            &[],
        )
        .is_ok_and(|s| s.code == SYSTEMCTL_NOT_LOADED_RC);
    let _ = shell.run_argv(
        &[
            "timeout",
            CMD_TIMEOUT,
            "systemctl",
            "reset-failed",
            DEADMAN_TIMER_UNIT,
            DEADMAN_SERVICE_UNIT,
        ],
        &[],
        &[],
    );
    let mut argv_owned = vec!["timeout".to_owned(), CMD_TIMEOUT.to_owned()];
    argv_owned.extend(deadman_arm_argv(budget_secs));
    let argv: Vec<&str> = argv_owned.iter().map(String::as_str).collect();
    run_checked(shell, &argv, "arm dead-man (systemd-run)")?;
    let state = run_checked(
        shell,
        &[
            "timeout",
            CMD_TIMEOUT,
            "systemctl",
            "is-active",
            DEADMAN_TIMER_UNIT,
        ],
        "verify dead-man timer active",
    )?;
    if String::from_utf8_lossy(&state).trim() != "active" {
        return Err("dead-man timer is not active after arming".to_owned());
    }
    Ok(previous_absent)
}

/// Why a disarm did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DisarmError {
    /// The timer is not loaded: it fired, or the node rebooted (`/run` is
    /// volatile). Either way the node is no longer guarded.
    TimerAbsent(String),
    /// Any other failure (transport error, non-zero rc).
    Failed(String),
}

impl std::fmt::Display for DisarmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TimerAbsent(m) | Self::Failed(m) => f.write_str(m),
        }
    }
}

/// Disarm the dead-man. A missing timer is an ERROR here (not success): it
/// only vanishes by firing or by a reboot, and the operator must see that.
pub(crate) fn disarm_deadman(shell: &dyn RemoteShellHost) -> Result<(), DisarmError> {
    let status = shell
        .run_argv(
            &[
                "timeout",
                CMD_TIMEOUT,
                "systemctl",
                "stop",
                DEADMAN_TIMER_UNIT,
            ],
            &[],
            &[],
        )
        .map_err(|e| DisarmError::Failed(format!("disarm dead-man (systemctl stop): {e}")))?;
    if status.is_success() {
        return Ok(());
    }
    let stderr = first_line(&status.stderr).replace(['\n', '\r'], " ");
    let message = format!(
        "disarm dead-man (systemctl stop): rc={}: {stderr}",
        status.code
    );
    if status.code == SYSTEMCTL_NOT_LOADED_RC {
        Err(DisarmError::TimerAbsent(format!(
            "{message} (the timer is gone: it fired, or the node rebooted; the node was \
             force-cleaned or is no longer guarded)"
        )))
    } else {
        Err(DisarmError::Failed(message))
    }
}

/// True when `ip` is a Tailscale-managed address: `100.64.0.0/10` (CGNAT
/// range tailscale assigns) or `fd7a:115c:a1e0::/48`.
fn is_tailnet_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 100 && (o[1] & 0xc0) == 64
        }
        IpAddr::V6(v6) => v6.segments()[..3] == [0xfd7a, 0x115c, 0xa1e0],
    }
}

/// The IP literal in an ssh target (`user@host`, `host`, `host:port`,
/// `[v6]`), if it is one.
fn host_ip(target: &str) -> Option<IpAddr> {
    let host = target.rsplit_once('@').map_or(target, |(_, h)| h);
    let host = host.trim_matches(['[', ']']);
    host.parse::<IpAddr>().ok().or_else(|| {
        let (left, _port) = host.split_once(':')?;
        left.parse::<IpAddr>().ok()
    })
}

/// Aliases in the run's scope that are cloud nodes: they declare a
/// `dataplane_endpoint`, or are managed over the tailnet (their ssh target or
/// last known address is a tailnet address). A load failure is an error: not
/// knowing which nodes are cloud nodes must not silently mean "none". With no
/// inventory path (unit-test contexts) there are none.
pub(crate) fn guarded_aliases(ctx: &OrchestrationContext) -> Result<Vec<String>, String> {
    let Some(path) = ctx.inventory_path.as_deref() else {
        return Ok(Vec::new());
    };
    let entries = crate::vm_lab::load_inventory(path)
        .map_err(|e| format!("load inventory for cloud-node detection failed: {e}"))?;
    Ok(ctx
        .assignments
        .iter()
        .filter(|a| {
            entries.iter().any(|e| {
                e.alias == a.alias
                    && (e.dataplane_endpoint.is_some()
                        || host_ip(&e.ssh_target).is_some_and(|ip| is_tailnet_addr(&ip))
                        || e.last_known_ip
                            .as_deref()
                            .and_then(host_ip)
                            .is_some_and(|ip| is_tailnet_addr(&ip)))
            })
        })
        .map(|a| a.alias.clone())
        .collect())
}

fn record(ctx: &OrchestrationContext, stage: &StageId, line: &str) {
    if line.starts_with("WARNING") {
        eprintln!("{line}");
    }
    if let Err(e) = append_stage_evidence_line(&ctx.report_dir, stage.as_str(), line) {
        eprintln!("cloud_node_safety: evidence write failed ({e}): {line}");
    }
}

/// Precondition + arm for every in-scope cloud node. Called at the earliest
/// node-touching stage (before any daemon start) and again at enforce (which
/// re-arms, restarting the budget). Runs for all such nodes first so a
/// refusal leaves no node enforced. Nodes that are not cloud nodes are never
/// touched (no adapter call at all). `planned` is the run's stage plan: a plan
/// that reboots nodes is refused while a cloud node is selected. Returns the
/// armed aliases.
pub(crate) fn guard_dataplane_nodes(
    ctx: &OrchestrationContext,
    stage: &StageId,
    planned: &[StageId],
) -> Result<Vec<String>, String> {
    let aliases = guarded_aliases(ctx)?;
    if aliases.is_empty() {
        return Ok(Vec::new());
    }
    if let Some(reboot) = REBOOT_STAGES.iter().find(|id| planned.contains(id)) {
        return Err(format!(
            "plan includes {} while cloud node(s) {} are selected: the dead-man timer lives in \
             /run and is lost on reboot while the boot killswitch is reinstalled at boot, which \
             would strand the node; exclude that stage from the plan (or drop the cloud node)",
            reboot.as_str(),
            aliases.join(", ")
        ));
    }
    let mut armed = Vec::new();
    let mut errors = Vec::new();
    for alias in &aliases {
        match guard_one(ctx, alias, stage) {
            Ok(()) => armed.push(alias.clone()),
            Err(e) => errors.push(format!("{alias}: {e}")),
        }
    }
    if errors.is_empty() {
        Ok(armed)
    } else {
        Err(errors.join("; "))
    }
}

fn guard_one(ctx: &OrchestrationContext, alias: &str, stage: &StageId) -> Result<(), String> {
    if !is_safe_component(alias) {
        return Err("alias is not a safe filename component".to_owned());
    }
    let adapter = ctx
        .adapters
        .get(alias)
        .ok_or_else(|| "no adapter; cannot arm the dead-man".to_owned())?;
    if adapter.platform() != VmGuestPlatform::Linux {
        return Err(format!(
            "dead-man guard is Linux/systemd-only (platform {:?}); refusing to run with an \
             unguarded cloud node",
            adapter.platform()
        ));
    }
    let shell = adapter
        .shell_host()
        .map_err(|e| format!("remote shell unavailable: {e}"))?;
    let peers = require_direct_tailscale_path(shell.as_ref(), &ctx.ssh_allow_cidrs)?;
    // Marker FIRST: an arm that half-succeeds must still be tracked so
    // teardown owes (and attempts) the disarm.
    let marker = armed_marker_path(&ctx.report_dir, alias);
    let marker_existed = marker.exists();
    marker
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&marker, DEADMAN_UNIT))
        .map_err(|e| format!("armed-marker write failed before arming: {e}"))?;
    let previous_absent = match arm_deadman(shell.as_ref(), DEADMAN_BUDGET_SECS) {
        Ok(absent) => absent,
        Err(e) => {
            // Best-effort undo of a possibly half-armed timer; keep the marker
            // if the undo did not take so teardown retries.
            let undo = disarm_deadman(shell.as_ref());
            if undo.is_ok() && !marker_existed {
                let _ = std::fs::remove_file(&marker);
            }
            return Err(format!(
                "{e} (undo of partial arm: {})",
                undo.map_or_else(|u| u.to_string(), |()| "ok".to_owned())
            ));
        }
    };
    if marker_existed && previous_absent {
        // Armed earlier in this run but the timer is gone now: it fired, or the
        // node rebooted. The run continues (the re-arm above restored the
        // safety net) but the caveat must be loud.
        let _ = std::fs::write(fired_marker_path(&ctx.report_dir, alias), DEADMAN_UNIT);
        record(
            ctx,
            stage,
            &format!(
                "WARNING cloud_node_safety alias={alias} deadman=FIRED_OR_NODE_REBOOTED \
                 (previously armed this run but no timer was loaded; node state may have been \
                 force-cleaned; re-armed)"
            ),
        );
    }
    record(
        ctx,
        stage,
        &format!(
            "cloud_node_safety alias={alias} direct_path=verified peers={peers} \
             deadman=armed budget_secs={DEADMAN_BUDGET_SECS}"
        ),
    );
    Ok(())
}

/// What happened to a node's runtime cleanup at teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupState {
    /// Reset and asserted clean.
    Clean,
    /// Cleanup did not complete; the dead-man is deliberately left armed.
    Failed,
    /// Excluded from `--rebuild-nodes`: left enforced for reuse.
    SkippedForReuse,
}

/// Teardown: disarm the dead-man on every node this run armed (iterating the
/// armed markers, not the inventory). Ordered AFTER the node's own cleanup so
/// a failed cleanup keeps its safety net. A disarm failure never changes the
/// stage outcome but is always a loud `WARNING` line in the cleanup stage log
/// and on stderr.
pub(crate) fn disarm_dataplane_nodes_after_cleanup(
    ctx: &OrchestrationContext,
    states: &[(String, CleanupState)],
) {
    for alias in armed_aliases(&ctx.report_dir) {
        let marker = armed_marker_path(&ctx.report_dir, &alias);
        let state = states
            .iter()
            .find(|(a, _)| *a == alias)
            .map_or(CleanupState::Clean, |(_, s)| *s);
        if state == CleanupState::Failed {
            record(
                ctx,
                &StageId::Cleanup,
                &format!(
                    "WARNING cloud_node_safety alias={alias} deadman=LEFT_ARMED (cleanup did \
                     not complete; node recovery cleanup fires at budget expiry)"
                ),
            );
            continue;
        }
        let outcome = match ctx.adapters.get(alias.as_str()) {
            None => Err(DisarmError::Failed("no adapter".to_owned())),
            Some(adapter) => adapter
                .shell_host()
                .map_err(|e| DisarmError::Failed(format!("remote shell unavailable: {e}")))
                .and_then(|shell| disarm_deadman(shell.as_ref())),
        };
        match outcome {
            Ok(()) => {
                let removed = std::fs::remove_file(&marker);
                let reuse = if state == CleanupState::SkippedForReuse {
                    " node_left_enforced_for_reuse"
                } else {
                    ""
                };
                record(
                    ctx,
                    &StageId::Cleanup,
                    &format!("cloud_node_safety alias={alias} deadman=disarmed{reuse}"),
                );
                if let Err(e) = removed {
                    record(
                        ctx,
                        &StageId::Cleanup,
                        &format!(
                            "WARNING cloud_node_safety alias={alias} armed-marker removal \
                             failed: {e}"
                        ),
                    );
                }
            }
            Err(DisarmError::TimerAbsent(e)) => {
                // Nothing left to disarm, but the run-level caveat is loud.
                let _ = std::fs::write(fired_marker_path(&ctx.report_dir, &alias), DEADMAN_UNIT);
                let _ = std::fs::remove_file(&marker);
                record(
                    ctx,
                    &StageId::Cleanup,
                    &format!(
                        "WARNING cloud_node_safety alias={alias} deadman=FIRED_OR_NODE_REBOOTED: \
                         {}",
                        e.replace(['\n', '\r'], " ")
                    ),
                );
            }
            Err(DisarmError::Failed(e)) => record(
                ctx,
                &StageId::Cleanup,
                &format!(
                    "WARNING cloud_node_safety alias={alias} deadman DISARM FAILED: {} \
                     (recovery cleanup will fire at budget expiry)",
                    e.replace(['\n', '\r'], " ")
                ),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::error::StageOutcome;
    use crate::vm_lab::orchestrator::remote_shell::{RemoteExitStatus, RemoteShellError};
    use crate::vm_lab::orchestrator::stage::node_diagnostics::test_support::{
        EventLog, Responder, ScriptedShell, ShellAdapter, ctx_with_adapters, ok, rc, scratch_dir,
        transport_err,
    };
    use crate::vm_lab::orchestrator::stage::{
        OrchestrationStage, enforce_runtime, final_cleanup, verify_ssh,
    };
    use std::sync::{Arc, Mutex};

    const ORCH_CIDRS: &str = "100.64.9.9/32,192.168.50.0/24";

    fn ts_json(cur_addr: &str, online: bool) -> String {
        format!(
            r#"{{"BackendState":"Running","Peer":{{
                "nodekey:a":{{"HostName":"katana","TailscaleIPs":["100.64.9.9","fd7a::9"],
                              "Online":{online},"Relay":"fra","CurAddr":"{cur_addr}"}},
                "nodekey:b":{{"HostName":"other","TailscaleIPs":["100.64.1.1"],
                              "Online":true,"Relay":"fra","CurAddr":""}}}}}}"#
        )
    }

    // ── budget + recovery script witnesses ──────────────────────────────────

    /// Witness for the budget constant: value AND units. A run (soak on) takes
    /// 40-90 minutes, so the dead-man must be far longer than that; it only
    /// matters if the orchestrator dies. Mutation caught: reverting to a
    /// minutes-scale budget or changing the unit suffix.
    #[test]
    fn budget_is_four_hours_in_seconds_and_reaches_the_arm_argv() {
        assert_eq!(DEADMAN_BUDGET_SECS, 14_400);
        assert_eq!(DEADMAN_BUDGET_SECS, 4 * 60 * 60);
        let argv = deadman_arm_argv(DEADMAN_BUDGET_SECS);
        assert_eq!(argv[0], "systemd-run");
        assert_eq!(argv[1], "--on-active=14400s");
        assert_eq!(argv[2], "--unit=rn-deadman-cleanup");
        assert_eq!(argv[4], "/bin/sh");
        assert_eq!(argv[5], "-c");
    }

    /// systemd substitutes `${VAR}`, `$$` and `%` specifiers in ExecStart, so
    /// the recovery script must contain none of them; it must also parse.
    #[test]
    fn recovery_script_is_systemd_safe_and_syntactically_valid() {
        let script = deadman_recovery_script();
        for forbidden in ["$$", "${", "%"] {
            assert!(
                !script.contains(forbidden),
                "systemd would substitute {forbidden:?}: {script}"
            );
        }
        // Robustness features mirrored from the harness's own cleanup.
        assert!(script.contains("timeout 60 /usr/local/bin/rustynet ops disconnect-cleanup"));
        assert!(script.contains("pkill -x rustynetd"));
        assert!(script.contains("pgrep -x rustynetd"));
        assert!(script.contains("seq 1 10"));
        assert!(script.contains("ip link delete"));
        // Only rustynet* tables are ever deleted.
        assert!(script.contains("$3 ~ /^rustynet/"));
        assert!(!script.contains("flush ruleset"), "{script}");
        assert!(!script.contains("pkill -f"), "{script}");
        #[cfg(unix)]
        {
            let out = std::process::Command::new("sh")
                .args(["-n", "-c", &script])
                .output()
                .expect("run sh -n");
            assert!(
                out.status.success(),
                "sh -n rejected the script: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// Drift guard: the table-name pattern is shared with the harness's own
    /// `cleanup_runtime_state` reset (private constants in linux_traffic.rs).
    #[test]
    fn recovery_script_shares_the_harness_table_pattern() {
        let harness = include_str!("../adapter/linux_traffic.rs");
        assert!(
            harness.contains("LINUX_NFT_KILLSWITCH_RESET_COMMAND")
                && harness.contains("$3 ~ /^rustynet/"),
            "linux_traffic.rs changed its rustynet table pattern; re-sync the dead-man script"
        );
        assert!(deadman_recovery_script().contains("$3 ~ /^rustynet/"));
    }

    /// Execute the script against stub binaries: it must delete ONLY rustynet*
    /// tables (re-applied once mid-run, like a daemon mid-shutdown), disable
    /// only rustynet* units, use `pkill -x`, delete the rustynet* link, and
    /// exit 0 although the stubbed CLI / systemctl / pkill all fail.
    /// Mutations caught: `pkill -x` -> `-f`, single delete pass (loop removed),
    /// deleting non-rustynet tables, not tolerating stub failures.
    #[cfg(unix)]
    #[test]
    fn recovery_script_with_stubs_deletes_only_rustynet_tables_and_tolerates_failures() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch_dir("recovery");
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let stub = |name: &str, body: &str| {
            let p = bin.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        };
        let log = r#"echo "$0 $*" | sed "s#.*/##" >> "$STUB_DIR/calls.log""#;
        stub("timeout", "shift\nexec \"$@\"");
        stub("rustynet", &format!("{log}\nexit 1"));
        stub("pkill", &format!("{log}\nexit 1"));
        stub("pgrep", &format!("{log}\nexit 1"));
        stub(
            "systemctl",
            &format!(
                "{log}\ncase \"$1\" in\n  list-unit-files) printf 'rustynetd.service enabled enabled\\nrustynet-push-all.timer enabled enabled\\nsshd.service enabled enabled\\n' ;;\n  *) exit 1 ;;\nesac"
            ),
        );
        stub(
            "ip",
            &format!(
                "{log}\nif [ \"$1 $2 $3\" = \"-o link show\" ]; then printf '1: lo: <LOOPBACK>\\n2: rustynet0: <UP>\\n3: eth0@if9: <UP>\\n'; fi\nexit 0"
            ),
        );
        stub(
            "nft",
            &format!(
                "{log}\nT=\"$STUB_DIR/tables\"\ncase \"$1 $2\" in\n  \"list tables\") while read -r fam name; do echo \"table $fam $name\"; done < \"$T\" ;;\n  \"delete table\")\n    grep -v -x \"$3 $4\" \"$T\" > \"$T.new\"; mv \"$T.new\" \"$T\"\n    if [ \"$4\" = rustynet_boot ] && [ ! -f \"$STUB_DIR/reapplied\" ]; then touch \"$STUB_DIR/reapplied\"; echo 'inet rustynet_boot' >> \"$T\"; fi ;;\nesac"
            ),
        );
        std::fs::write(
            dir.join("tables"),
            "inet rustynet_boot\ninet filter\nip rustynet_nat_g1\ninet fw_other\n",
        )
        .unwrap();
        let cli = bin.join("rustynet");
        let path = format!("{}:/usr/bin:/bin", bin.display());
        let script = deadman_recovery_script_with(cli.to_str().unwrap(), &path);
        let out = std::process::Command::new("sh")
            .args(["-c", &script])
            .env("STUB_DIR", &dir)
            .output()
            .expect("run recovery script");
        assert!(
            out.status.success(),
            "script must tolerate stub failures: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let tables = std::fs::read_to_string(dir.join("tables")).unwrap();
        assert_eq!(
            tables, "inet filter\ninet fw_other\n",
            "every rustynet* table (incl. the re-applied boot table) must go, nothing else"
        );
        let calls = std::fs::read_to_string(dir.join("calls.log")).unwrap();
        for expected in [
            "rustynet ops disconnect-cleanup",
            "systemctl disable --now rustynetd.service",
            "systemctl disable --now rustynet-push-all.timer",
            "pkill -x rustynetd",
            "pgrep -x rustynetd",
            "nft delete table ip rustynet_nat_g1",
            "ip link delete rustynet0",
        ] {
            assert!(
                calls.contains(expected),
                "missing {expected:?} in:\n{calls}"
            );
        }
        assert_eq!(
            calls.matches("nft delete table inet rustynet_boot").count(),
            2,
            "the re-applied boot table needs a second pass:\n{calls}"
        );
        for forbidden in [
            "sshd",
            "fw_other",
            "delete table inet filter",
            "link delete eth0",
            "link delete lo",
            "pkill -f",
        ] {
            assert!(
                !calls.contains(forbidden),
                "unexpected {forbidden:?} in:\n{calls}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── precondition ────────────────────────────────────────────────────────

    /// Mutation caught: dropping the `CurAddr` emptiness check (DERP-only
    /// would pass) or matching the wrong peer.
    #[test]
    fn precondition_accepts_direct_and_refuses_derp_only() {
        assert_eq!(
            check_direct_path(&ts_json("198.51.100.9:41641", true), ORCH_CIDRS),
            Ok(1)
        );
        // The unrelated DERP-only peer must not matter; the orchestrator's does.
        let err = check_direct_path(&ts_json("", true), ORCH_CIDRS)
            .expect_err("DERP-only path must be refused");
        assert!(err.contains("not direct"), "{err}");
        assert!(err.contains("katana"), "{err}");
        // Messages never carry addresses.
        assert!(!err.contains("100.64.9.9"), "{err}");
    }

    #[test]
    fn precondition_fails_closed_when_peer_cannot_be_identified() {
        // No /32 in the allow list.
        assert!(check_direct_path(&ts_json("1.2.3.4:1", true), "192.168.50.0/24").is_err());
        assert!(check_direct_path(&ts_json("1.2.3.4:1", true), "").is_err());
        // /32 present but no peer owns it.
        assert!(check_direct_path(&ts_json("1.2.3.4:1", true), "100.64.77.7/32").is_err());
        // Offline peer.
        assert!(check_direct_path(&ts_json("1.2.3.4:1", false), ORCH_CIDRS).is_err());
        // Garbage / missing Peer map.
        assert!(check_direct_path("not json", ORCH_CIDRS).is_err());
        assert!(check_direct_path(r#"{"BackendState":"Running"}"#, ORCH_CIDRS).is_err());
    }

    // ── arm / disarm over the seam ──────────────────────────────────────────

    #[test]
    fn arm_argv_is_a_systemd_run_timer_with_the_recovery_script() {
        let argv = deadman_arm_argv(2700);
        assert_eq!(argv[0], "systemd-run");
        assert_eq!(argv[1], "--on-active=2700s");
        let script = argv.last().unwrap();
        // disconnect-cleanup keeps rustynet_boot, so the script must delete
        // every rustynet* table itself.
        assert!(script.contains("nft delete table"), "{script}");
        assert!(script.contains("disable --now"), "{script}");
        // Budget is numeric-only.
        assert!(
            argv[1]["--on-active=".len()..argv[1].len() - 1]
                .chars()
                .all(|c| c.is_ascii_digit())
        );
    }

    type ShellResult = Result<RemoteExitStatus, RemoteShellError>;

    fn responder_ok() -> impl Fn(&[String]) -> ShellResult + Send + Sync {
        |argv: &[String]| {
            if argv.iter().any(|a| a == "is-active") {
                ok("active\n")
            } else {
                ok("")
            }
        }
    }

    fn shell_for(
        responder: impl Fn(&[String]) -> ShellResult + Send + Sync + 'static,
    ) -> (ScriptedShell, EventLog) {
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        (
            ScriptedShell {
                log: Arc::clone(&log),
                responder: Arc::new(responder),
            },
            log,
        )
    }

    #[test]
    fn arm_succeeds_and_clears_a_stale_timer_first() {
        let (shell, log) = shell_for(responder_ok());
        assert_eq!(arm_deadman(&shell, 60), Ok(false));
        let events = log.lock().unwrap().clone();
        assert!(
            events[0].contains("systemctl stop rn-deadman-cleanup.timer"),
            "{events:?}"
        );
        assert!(
            events.iter().any(|e| e.contains("systemd-run")),
            "{events:?}"
        );
        assert!(events.last().unwrap().contains("is-active"), "{events:?}");
    }

    /// The pre-clear `stop` answering rc 5 (not loaded) is reported so a
    /// re-arm can detect that the previous timer is gone.
    #[test]
    fn arm_reports_when_no_previous_timer_was_loaded() {
        let (shell, _) = shell_for(|argv| {
            if argv.iter().any(|a| a == "stop") {
                rc(5, "Unit rn-deadman-cleanup.timer not loaded.")
            } else if argv.iter().any(|a| a == "is-active") {
                ok("active\n")
            } else {
                ok("")
            }
        });
        assert_eq!(arm_deadman(&shell, 60), Ok(true));
    }

    /// Mutation caught: ignoring the systemd-run result, or the activity check.
    #[test]
    fn arm_failure_modes_are_errors() {
        let (shell, _) = shell_for(|argv| {
            if argv.iter().any(|a| a == "systemd-run") {
                rc(1, "Failed to start transient timer unit")
            } else {
                ok("active\n")
            }
        });
        assert!(
            arm_deadman(&shell, 60)
                .unwrap_err()
                .contains("arm dead-man")
        );

        let (shell, _) = shell_for(|argv| {
            if argv.iter().any(|a| a == "is-active") {
                ok("inactive\n")
            } else {
                ok("")
            }
        });
        assert!(arm_deadman(&shell, 60).unwrap_err().contains("not active"));

        let (shell, _) = shell_for(|_| transport_err());
        assert!(arm_deadman(&shell, 60).is_err());
    }

    #[test]
    fn disarm_distinguishes_a_gone_timer_from_other_failures() {
        let (shell, _) = shell_for(|_| ok(""));
        assert_eq!(disarm_deadman(&shell), Ok(()));
        let (shell, _) = shell_for(|_| rc(5, "Unit rn-deadman-cleanup.timer not loaded."));
        match disarm_deadman(&shell) {
            Err(DisarmError::TimerAbsent(m)) => {
                assert!(m.contains("fired, or the node rebooted"), "{m}");
            }
            other => panic!("expected TimerAbsent, got {other:?}"),
        }
        let (shell, _) = shell_for(|_| rc(1, "Access denied"));
        assert!(matches!(
            disarm_deadman(&shell),
            Err(DisarmError::Failed(_))
        ));
        let (shell, _) = shell_for(|_| transport_err());
        assert!(matches!(
            disarm_deadman(&shell),
            Err(DisarmError::Failed(_))
        ));
    }

    // ── cloud-node predicate ────────────────────────────────────────────────

    #[test]
    fn tailnet_address_detection() {
        for yes in ["100.64.0.1", "100.127.255.254", "fd7a:115c:a1e0::5"] {
            assert!(is_tailnet_addr(&yes.parse().unwrap()), "{yes}");
        }
        for no in [
            "100.63.255.255",
            "100.128.0.1",
            "10.0.0.5",
            "192.168.1.9",
            "fd7a:115c:a1e1::5",
            "fd00::1",
        ] {
            assert!(!is_tailnet_addr(&no.parse().unwrap()), "{no}");
        }
        assert_eq!(
            host_ip("debian@100.64.15.9"),
            Some("100.64.15.9".parse().unwrap())
        );
        assert_eq!(
            host_ip("debian@100.64.15.9:22"),
            Some("100.64.15.9".parse().unwrap())
        );
        assert_eq!(
            host_ip("debian@[fd7a:115c:a1e0::5]"),
            Some("fd7a:115c:a1e0::5".parse().unwrap())
        );
        assert_eq!(host_ip("guest.lab"), None);
    }

    fn write_inventory_full(
        dir: &std::path::Path,
        cloud: &[&str],
        plain: &[&str],
        tailnet_only: &[&str],
    ) -> std::path::PathBuf {
        let mut entries = Vec::new();
        for a in cloud {
            entries.push(format!(
                r#"{{"alias":"{a}","ssh_target":"100.64.15.9","dataplane_endpoint":"203.0.113.7","platform":"linux"}}"#
            ));
        }
        for a in plain {
            entries.push(format!(
                r#"{{"alias":"{a}","ssh_target":"10.0.0.5","platform":"linux"}}"#
            ));
        }
        for a in tailnet_only {
            entries.push(format!(
                r#"{{"alias":"{a}","ssh_target":"debian@100.64.77.1","platform":"linux"}}"#
            ));
        }
        let path = dir.join("inventory.json");
        std::fs::write(
            &path,
            format!(r#"{{"version":1,"entries":[{}]}}"#, entries.join(",")),
        )
        .unwrap();
        path
    }

    fn write_inventory(
        dir: &std::path::Path,
        cloud: &[&str],
        plain: &[&str],
    ) -> std::path::PathBuf {
        write_inventory_full(dir, cloud, plain, &[])
    }

    /// Cloud = dataplane_endpoint OR tailnet-managed; RFC1918 lab guests are
    /// never cloud. Mutation caught: dropping the tailnet arm or the
    /// dataplane arm.
    #[test]
    fn guarded_aliases_cover_dataplane_and_tailnet_managed_nodes_only() {
        let dir = scratch_dir("predicate");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let r: Arc<Responder> = Arc::new(|_: &[String]| ok(""));
        let mut ctx = ctx_with_adapters(
            &dir,
            vec![
                ShellAdapter::new("cloud-1", &log, Arc::clone(&r)),
                ShellAdapter::new("plain-1", &log, Arc::clone(&r)),
                ShellAdapter::new("ts-1", &log, r),
            ],
        );
        ctx.inventory_path = Some(write_inventory_full(
            &dir,
            &["cloud-1"],
            &["plain-1"],
            &["ts-1"],
        ));
        assert_eq!(
            guarded_aliases(&ctx).unwrap(),
            vec!["cloud-1".to_owned(), "ts-1".to_owned()]
        );
        ctx.inventory_path = None;
        assert!(guarded_aliases(&ctx).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── stage-level wiring ──────────────────────────────────────────────────

    /// Responder for a healthy cloud node: direct tailscale path, arm OK.
    fn healthy_cloud_responder(cur_addr: &'static str) -> Arc<Responder> {
        Arc::new(move |argv: &[String]| {
            if argv.iter().any(|a| a == "tailscale") {
                ok(&ts_json(cur_addr, true))
            } else if argv.iter().any(|a| a == "is-active") {
                ok("active\n")
            } else {
                ok("")
            }
        })
    }

    fn position(events: &[String], needle: &str) -> usize {
        events
            .iter()
            .position(|e| e.contains(needle))
            .unwrap_or_else(|| panic!("no event containing {needle:?} in {events:?}"))
    }

    fn count(events: &[String], needle: &str) -> usize {
        events.iter().filter(|e| e.contains(needle)).count()
    }

    fn enforce_planned(ctx: &mut OrchestrationContext, planned: Vec<StageId>) -> StageOutcome {
        enforce_runtime::EnforceBaselineRuntimeStage::new(
            1,
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
        .with_planned_stage_ids(planned)
        .execute(ctx)
    }

    fn enforce(ctx: &mut OrchestrationContext) -> StageOutcome {
        enforce_planned(ctx, Vec::new())
    }

    fn verify(ctx: &mut OrchestrationContext, planned: Vec<StageId>) -> StageOutcome {
        verify_ssh::VerifySshReachabilityStage::new(planned).execute(ctx)
    }

    struct Fixture {
        dir: std::path::PathBuf,
        log: EventLog,
        ctx: OrchestrationContext,
    }

    fn fixture(tag: &str, cur_addr: &'static str) -> Fixture {
        let dir = scratch_dir(tag);
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let cloud = ShellAdapter::new("cloud-1", &log, healthy_cloud_responder(cur_addr));
        let plain = ShellAdapter::new(
            "plain-1",
            &log,
            Arc::new(|_: &[String]| ok("")) as Arc<Responder>,
        );
        let mut ctx = ctx_with_adapters(&dir, vec![cloud, plain]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &["plain-1"]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        Fixture { dir, log, ctx }
    }

    fn stage_log(dir: &std::path::Path, stage: &str) -> String {
        std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(dir, stage),
        )
        .unwrap_or_default()
    }

    /// Question 4 (reviewer): bootstrap's `ops install-systemd` restarts
    /// rustynetd, whose ExecStartPre installs `rustynet_boot`, BEFORE enforce.
    /// So the guard runs at the earliest node-touching stage
    /// (verify_ssh_reachability: precondition -> arm, no daemon work yet) and
    /// enforce re-arms (clock reset) before enforcing. Mutation caught:
    /// dropping the early guard, or arming after enforce.
    #[test]
    fn guard_runs_at_verify_ssh_before_any_daemon_start_then_rearms_before_enforce() {
        let mut f = fixture("order", "198.51.100.9:41641");
        assert_eq!(verify(&mut f.ctx, Vec::new()), StageOutcome::Passed);
        let after_verify = f.log.lock().unwrap().clone();
        assert!(
            !after_verify.iter().any(|e| e.starts_with("enforce:")),
            "{after_verify:?}"
        );
        let ts = position(&after_verify, "shell:timeout 20 tailscale status --json");
        let arm = position(&after_verify, "systemd-run");
        assert!(ts < arm, "{after_verify:?}");
        assert!(
            stage_log(&f.dir, "verify_ssh_reachability").contains("deadman=armed"),
            "{}",
            stage_log(&f.dir, "verify_ssh_reachability")
        );

        assert_eq!(enforce(&mut f.ctx), StageOutcome::Passed);
        let events = f.log.lock().unwrap().clone();
        assert_eq!(
            count(&events, "systemd-run"),
            2,
            "enforce must re-arm: {events:?}"
        );
        let second_arm = events
            .iter()
            .enumerate()
            .filter(|(_, e)| e.contains("systemd-run"))
            .nth(1)
            .unwrap()
            .0;
        let enf = position(&events, "enforce:cloud-1");
        assert!(second_arm < enf, "{events:?}");
        // The plain node never sees a safety-net command.
        assert!(
            !events
                .iter()
                .any(|e| e.contains("systemd-run") && e.contains("plain-1")),
            "{events:?}"
        );
        let log = stage_log(&f.dir, "enforce_baseline_runtime");
        assert!(
            log.contains("cloud_node_safety alias=cloud-1 direct_path=verified"),
            "{log}"
        );
        assert!(!log.contains("plain-1 direct_path"), "{log}");
        assert!(!log.contains("FIRED"), "{log}");
        // Post-enforce diagnostics: after the last enforce, for every node.
        let last_enforce = events
            .iter()
            .rposition(|e| e.starts_with("enforce:"))
            .unwrap();
        let first_diag = position(&events, "shell:timeout 10 nft list ruleset");
        assert!(last_enforce < first_diag, "{events:?}");
        for alias in ["cloud-1", "plain-1"] {
            assert!(
                f.dir
                    .join(format!("logs/diag_post-enforce_{alias}.txt"))
                    .exists(),
                "missing post-enforce diag for {alias}"
            );
        }
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// Enforce alone (plan without verify_ssh) still guards: precondition ->
    /// arm -> enforce.
    #[test]
    fn enforce_alone_runs_precondition_then_arm_then_enforce() {
        let mut f = fixture("enforce-only", "198.51.100.9:41641");
        assert_eq!(enforce(&mut f.ctx), StageOutcome::Passed);
        let events = f.log.lock().unwrap().clone();
        let ts = position(&events, "shell:timeout 20 tailscale status --json");
        let arm = position(&events, "systemd-run");
        let enf = position(&events, "enforce:cloud-1");
        assert!(ts < arm && arm < enf, "{events:?}");
        let _ = std::fs::remove_dir_all(&f.dir);
    }

    /// A DERP-only path refuses the whole stage: no arm, no enforce anywhere.
    #[test]
    fn enforce_and_verify_refuse_derp_only_cloud_node_before_any_change() {
        for early in [false, true] {
            let mut f = fixture("derp", "");
            let outcome = if early {
                verify(&mut f.ctx, Vec::new())
            } else {
                enforce(&mut f.ctx)
            };
            match outcome {
                StageOutcome::Failed(m) => {
                    assert!(m.contains("cloud-1"), "{m}");
                    assert!(m.contains("not direct"), "{m}");
                }
                other => panic!("expected refusal, got {other:?}"),
            }
            let events = f.log.lock().unwrap().clone();
            assert!(
                !events.iter().any(|e| e.contains("systemd-run")),
                "{events:?}"
            );
            assert!(
                !events.iter().any(|e| e.starts_with("enforce:")),
                "{events:?}"
            );
            assert!(!f.dir.join("state/cloud_node_safety").exists());
            let _ = std::fs::remove_dir_all(&f.dir);
        }
    }

    /// Arming failure aborts (fail closed). Mutation caught: ignoring the arm
    /// result.
    #[test]
    fn enforce_refuses_when_arming_fails() {
        let dir = scratch_dir("armfail");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(|argv: &[String]| {
            if argv.iter().any(|a| a == "tailscale") {
                ok(&ts_json("198.51.100.9:41641", true))
            } else if argv.iter().any(|a| a == "systemd-run") {
                rc(1, "Failed to start transient timer unit")
            } else {
                ok("active\n")
            }
        });
        let mut ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("cloud-1", &log, responder)]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &[]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        assert!(matches!(enforce(&mut ctx), StageOutcome::Failed(m) if m.contains("arm dead-man")));
        assert!(
            !log.lock()
                .unwrap()
                .iter()
                .any(|e| e.starts_with("enforce:"))
        );
        // The undo stop took, so no marker is left behind.
        assert!(!dir.join("state/cloud_node_safety/armed.cloud-1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An arm that half-succeeds (timer created but not active) and whose
    /// undo fails is still tracked: the marker was written BEFORE arming and
    /// stays. Mutation caught: writing the marker only after a clean arm.
    #[test]
    fn half_armed_node_stays_tracked_when_the_undo_fails() {
        let dir = scratch_dir("halfarm");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(|argv: &[String]| {
            if argv.iter().any(|a| a == "tailscale") {
                ok(&ts_json("198.51.100.9:41641", true))
            } else if argv.iter().any(|a| a == "is-active") {
                ok("inactive\n")
            } else if argv.iter().any(|a| a == "stop") {
                rc(1, "Failed to stop")
            } else {
                ok("")
            }
        });
        let mut ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("cloud-1", &log, responder)]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &[]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        match enforce(&mut ctx) {
            StageOutcome::Failed(m) => {
                assert!(m.contains("not active"), "{m}");
                assert!(m.contains("undo of partial arm"), "{m}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(dir.join("state/cloud_node_safety/armed.cloud-1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Nodes that are not cloud nodes: no safety-net command ever runs and
    /// enforce/verify proceed exactly as before (no inventory, or no
    /// override). Mutation caught: guarding every node.
    #[test]
    fn nodes_that_are_not_cloud_nodes_are_untouched() {
        for with_inventory in [false, true] {
            let dir = scratch_dir("plain");
            let log: EventLog = Arc::new(Mutex::new(Vec::new()));
            let responder: Arc<Responder> = Arc::new(|_: &[String]| ok(""));
            let mut ctx =
                ctx_with_adapters(&dir, vec![ShellAdapter::new("plain-1", &log, responder)]);
            if with_inventory {
                ctx.inventory_path = Some(write_inventory(&dir, &[], &["plain-1"]));
            }
            assert_eq!(
                verify(&mut ctx, vec![StageId::LiveRebootRecoveryValidation]),
                StageOutcome::Passed
            );
            assert_eq!(
                enforce_planned(&mut ctx, vec![StageId::LiveRebootRecoveryValidation]),
                StageOutcome::Passed
            );
            let events = log.lock().unwrap().clone();
            assert!(
                !events
                    .iter()
                    .any(|e| e.contains("systemd-run") || e.contains("rn-deadman")),
                "{events:?}"
            );
            assert!(events.iter().any(|e| e.starts_with("enforce:")));
            assert!(!dir.join("state/cloud_node_safety").exists());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    /// Tailnet-managed node without a dataplane_endpoint is guarded too.
    #[test]
    fn tailnet_managed_node_without_dataplane_endpoint_is_guarded() {
        let dir = scratch_dir("tsnode");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let mut ctx = ctx_with_adapters(
            &dir,
            vec![ShellAdapter::new(
                "ts-1",
                &log,
                healthy_cloud_responder("198.51.100.9:41641"),
            )],
        );
        ctx.inventory_path = Some(write_inventory_full(&dir, &[], &[], &["ts-1"]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        assert_eq!(enforce(&mut ctx), StageOutcome::Passed);
        assert!(
            log.lock()
                .unwrap()
                .iter()
                .any(|e| e.contains("systemd-run"))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Reboot stages are refused while a cloud node is selected (the /run timer
    /// is lost on reboot while the boot killswitch returns). Mutation caught:
    /// dropping the refusal, or refusing plain-only topologies.
    #[test]
    fn reboot_stages_are_refused_for_cloud_nodes_and_name_the_stage() {
        for reboot in [
            StageId::LiveRebootRecoveryValidation,
            StageId::MacosRebootRecoveryValidation,
        ] {
            let mut f = fixture("reboot", "198.51.100.9:41641");
            match verify(&mut f.ctx, vec![StageId::TrafficTestMatrix, reboot.clone()]) {
                StageOutcome::Failed(m) => {
                    assert!(m.contains(reboot.as_str()), "{m}");
                    assert!(m.contains("cloud-1"), "{m}");
                }
                other => panic!("expected refusal, got {other:?}"),
            }
            assert!(matches!(
                enforce_planned(&mut f.ctx, vec![reboot]),
                StageOutcome::Failed(_)
            ));
            let events = f.log.lock().unwrap().clone();
            assert!(
                !events.iter().any(|e| e.starts_with("shell:")),
                "a refusal must run no node command: {events:?}"
            );
            let _ = std::fs::remove_dir_all(&f.dir);
        }
    }

    /// A previously armed node whose timer is gone at re-arm (fired/rebooted)
    /// gets a loud caveat in the stage log and a `fired.` marker. Mutation
    /// caught: dropping the detection.
    #[test]
    fn rearm_detects_a_timer_that_fired_or_vanished() {
        let dir = scratch_dir("fired-rearm");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let stops = Arc::new(Mutex::new(0usize));
        let s2 = Arc::clone(&stops);
        let responder: Arc<Responder> = Arc::new(move |argv: &[String]| {
            if argv.iter().any(|a| a == "tailscale") {
                ok(&ts_json("198.51.100.9:41641", true))
            } else if argv.iter().any(|a| a == "is-active") {
                ok("active\n")
            } else if argv.iter().any(|a| a == "stop") {
                // First arm: nothing loaded yet is normal; the SECOND arm must
                // find the timer gone (rc 5) although it was armed before.
                let mut n = s2.lock().unwrap();
                *n += 1;
                if *n >= 2 {
                    rc(5, "Unit rn-deadman-cleanup.timer not loaded.")
                } else {
                    ok("")
                }
            } else {
                ok("")
            }
        });
        let mut ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("cloud-1", &log, responder)]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &[]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        assert_eq!(verify(&mut ctx, Vec::new()), StageOutcome::Passed);
        assert_eq!(enforce(&mut ctx), StageOutcome::Passed);
        let text = stage_log(&dir, "enforce_baseline_runtime");
        assert!(
            text.contains("WARNING cloud_node_safety alias=cloud-1 deadman=FIRED_OR_NODE_REBOOTED"),
            "{text}"
        );
        assert!(dir.join("state/cloud_node_safety/fired.cloud-1").exists());
        // The first arm never warns.
        assert!(
            !stage_log(&dir, "verify_ssh_reachability").contains("FIRED"),
            "{}",
            stage_log(&dir, "verify_ssh_reachability")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── teardown ────────────────────────────────────────────────────────────

    fn cleanup(ctx: &mut OrchestrationContext) -> StageOutcome {
        final_cleanup::FinalCleanupStage::new(None).execute(ctx)
    }

    fn cleanup_log(dir: &std::path::Path) -> String {
        stage_log(dir, "cleanup")
    }

    /// Disarm happens AFTER the node's own cleanup, on the pipeline-pass path
    /// and on the pipeline-fail path (an earlier failed stage; FinalCleanup is
    /// always-run), and iterates the armed MARKERS — it does not need the
    /// inventory. Mutation caught: skipping the disarm, disarming before
    /// cleanup, or depending on the inventory.
    #[test]
    fn teardown_disarms_after_cleanup_on_pass_and_fail_paths_without_the_inventory() {
        assert!(final_cleanup::FinalCleanupStage::new(None).always_run());
        for failed_pipeline in [false, true] {
            let mut f = fixture("disarm", "198.51.100.9:41641");
            assert_eq!(enforce(&mut f.ctx), StageOutcome::Passed);
            if failed_pipeline {
                f.ctx.stage_outcomes.insert(
                    StageId::TrafficTestMatrix,
                    StageOutcome::Failed("boom".to_owned()),
                );
            }
            // Teardown must not reload the inventory (5c).
            f.ctx.inventory_path = Some(f.dir.join("does-not-exist.json"));
            f.log.lock().unwrap().clear();
            assert_eq!(cleanup(&mut f.ctx), StageOutcome::Passed);
            let events = f.log.lock().unwrap().clone();
            let cleaned = position(&events, "cleanup:cloud-1");
            let stop = position(&events, "systemctl stop rn-deadman-cleanup.timer");
            assert!(cleaned < stop, "disarm must follow cleanup: {events:?}");
            let log = cleanup_log(&f.dir);
            assert!(
                log.contains("cloud_node_safety alias=cloud-1 deadman=disarmed"),
                "{log}"
            );
            assert!(!f.dir.join("state/cloud_node_safety/armed.cloud-1").exists());
            let _ = std::fs::remove_dir_all(&f.dir);
        }
    }

    fn armed_then_stop_behaves(
        stop_result: fn() -> ShellResult,
    ) -> (std::path::PathBuf, OrchestrationContext) {
        let dir = scratch_dir("disarmfail");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let armed = Arc::new(Mutex::new(false));
        let responder: Arc<Responder> = Arc::new(move |argv: &[String]| {
            if argv.iter().any(|a| a == "tailscale") {
                ok(&ts_json("198.51.100.9:41641", true))
            } else if argv.iter().any(|a| a == "is-active") {
                ok("active\n")
            } else if argv.iter().any(|a| a == "systemd-run") {
                *armed.lock().unwrap() = true;
                ok("")
            } else if argv.iter().any(|a| a == "stop") && *armed.lock().unwrap() {
                // Only teardown's stop (after arming) fails.
                stop_result()
            } else {
                ok("")
            }
        });
        let mut ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("cloud-1", &log, responder)]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &[]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        assert_eq!(enforce(&mut ctx), StageOutcome::Passed);
        (dir, ctx)
    }

    /// A disarm failure is loud (WARNING in the evidence) and never silent; the
    /// stage outcome is unchanged and the marker stays so a retry is possible.
    /// Mutation caught: dropping the warning.
    #[test]
    fn disarm_failure_is_recorded_loudly_without_failing_cleanup() {
        let (dir, mut ctx) = armed_then_stop_behaves(|| rc(1, "Access denied"));
        assert_eq!(cleanup(&mut ctx), StageOutcome::Passed);
        let text = cleanup_log(&dir);
        assert!(
            text.contains("WARNING cloud_node_safety alias=cloud-1 deadman DISARM FAILED"),
            "{text}"
        );
        assert!(dir.join("state/cloud_node_safety/armed.cloud-1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An absent timer at teardown is reported as fired-or-rebooted (loud),
    /// with a run-level `fired.` marker; the armed marker is cleared.
    #[test]
    fn absent_timer_at_teardown_is_a_loud_fired_or_rebooted_caveat() {
        let (dir, mut ctx) =
            armed_then_stop_behaves(|| rc(5, "Unit rn-deadman-cleanup.timer not loaded."));
        assert_eq!(cleanup(&mut ctx), StageOutcome::Passed);
        let text = cleanup_log(&dir);
        assert!(
            text.contains("WARNING cloud_node_safety alias=cloud-1 deadman=FIRED_OR_NODE_REBOOTED"),
            "{text}"
        );
        assert!(dir.join("state/cloud_node_safety/fired.cloud-1").exists());
        assert!(!dir.join("state/cloud_node_safety/armed.cloud-1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// When the node's own cleanup fails, the dead-man is deliberately left
    /// armed (and said so). Mutation caught: disarming regardless.
    #[test]
    fn failed_cleanup_leaves_the_deadman_armed_with_a_warning() {
        let dir = scratch_dir("cleanfail");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let mut adapter = ShellAdapter::new(
            "cloud-1",
            &log,
            healthy_cloud_responder("198.51.100.9:41641"),
        );
        adapter.cleanup_result = Err("node still dirty".to_owned());
        let mut ctx = ctx_with_adapters(&dir, vec![adapter]);
        ctx.inventory_path = Some(write_inventory(&dir, &["cloud-1"], &[]));
        ctx.ssh_allow_cidrs = ORCH_CIDRS.to_owned();
        assert_eq!(enforce(&mut ctx), StageOutcome::Passed);
        log.lock().unwrap().clear();
        assert!(matches!(cleanup(&mut ctx), StageOutcome::Failed(_)));
        let events = log.lock().unwrap().clone();
        assert!(
            !events
                .iter()
                .any(|e| e.contains("systemctl stop rn-deadman")),
            "{events:?}"
        );
        assert!(
            cleanup_log(&dir).contains("deadman=LEFT_ARMED"),
            "{}",
            cleanup_log(&dir)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Teardown with nothing armed this run is quiet and runs no systemctl at
    /// all (plain nodes are byte-identical).
    #[test]
    fn teardown_without_arming_touches_nothing() {
        let dir = scratch_dir("noarm");
        let log: EventLog = Arc::new(Mutex::new(Vec::new()));
        let responder: Arc<Responder> = Arc::new(|_: &[String]| ok(""));
        let mut ctx = ctx_with_adapters(&dir, vec![ShellAdapter::new("plain-1", &log, responder)]);
        ctx.inventory_path = Some(write_inventory(&dir, &[], &["plain-1"]));
        assert_eq!(cleanup(&mut ctx), StageOutcome::Passed);
        assert!(!log.lock().unwrap().iter().any(|e| e.starts_with("shell:")));
        assert_eq!(cleanup_log(&dir), "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
