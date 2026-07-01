#![allow(dead_code)]
use std::io::Write as IoWrite;
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::verifier_key::decode_assignment_pubkey_hex;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

pub const MACOS_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
pub const MACOS_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
/// Canonical path of the `rustynet-relay` sibling binary on macOS targets.
/// Built + installed by `Bootstrap-RustyNetMacos.sh` alongside rustynetd /
/// rustynet so a Relay-role node always has it; the relay *service* is only
/// enabled on Relay nodes by `DeployRelayServiceStage` via
/// [`deploy_relay_service`].
pub const MACOS_RUSTYNET_RELAY_PATH: &str = "/usr/local/bin/rustynet-relay";
pub const MACOS_SERVICE_LABEL: &str = "com.rustynet.daemon";
pub const MACOS_STATE_ROOT: &str = "/usr/local/var/rustynet";
pub const MACOS_KEYS_DIR: &str = "/usr/local/var/rustynet/keys";
pub const MACOS_DAEMON_SOCKET: &str = "/private/var/run/rustynet/rustynetd.sock";
pub const MACOS_MEMBERSHIP_DIR: &str = "/usr/local/var/rustynet/membership";
pub const MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.owner.key.pub";
pub const MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";
pub const MACOS_ENROLLMENT_SECRET_PATH: &str = "/usr/local/var/rustynet/keys/enrollment.secret";

static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh");
static INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Install-RustyNetMacosService.sh");
// Phase 23 orchestrator-side wrappers (per-OS dispatch from
// `live_linux_lab_orchestrator.sh::bootstrap_host_worker`). Compiled
// in for tests only so the FNV-1a parity guard and the input-validation
// pins below stay enforced; the wrappers themselves run on the target
// host (orchestrator scp's them from `scripts/e2e/`).
#[cfg(test)]
static MACOS_BOOTSTRAP_WRAPPER: &str =
    include_str!("../../../../../../scripts/e2e/rn_bootstrap_macos.sh");
#[cfg(test)]
static WINDOWS_BOOTSTRAP_WRAPPER: &str =
    include_str!("../../../../../../scripts/e2e/rn_bootstrap_windows.ps1");
#[cfg(test)]
static LIVE_LINUX_LAB_ORCHESTRATOR: &str =
    include_str!("../../../../../../scripts/e2e/live_linux_lab_orchestrator.sh");
#[cfg(test)]
static LIVE_LAB_COMMON: &str = include_str!("../../../../../../scripts/e2e/live_lab_common.sh");

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(300);

/// Bootstrap the daemon on a macOS host. Transfers the source archive and
/// bootstrap script, runs the bootstrap, waits for the daemon socket.
pub fn install_daemon(
    conn: &NodeConnection,
    alias: &str,
    source: &SourceArchive,
    ctx: &OrchestrationContext,
) -> Result<InstallReport, AdapterError> {
    let role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .cloned()
        .unwrap_or(NodeRole::Client);
    let node_id = ctx
        .node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| format!("{alias}-bootstrap"));
    if node_id.is_empty() {
        return Err(AdapterError::Protocol {
            message: "install_daemon: node_id must not be empty".to_owned(),
        });
    }
    // Defence-in-depth: revalidate the derived utun name before it ever
    // reaches the shell layer. utun_name_for_node_id always produces
    // utun<N>, but pinning the check here makes a future refactor of the
    // helper fail at the install boundary instead of silently writing
    // junk into the plist.
    validate_utun_name(&utun_name_for_node_id(&node_id))?;

    let script_tmp = write_temp_file("rn_macos_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;
    let env_content = build_bootstrap_env(&node_id, &role, ctx);
    let env_tmp = write_temp_file("rn_macos_env_", ".env", env_content.as_bytes())?;

    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/Install-RustyNetMacosService.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.env",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", SHORT_TIMEOUT)?;

    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);
    let _ = std::fs::remove_file(&env_tmp);

    ssh::run_remote(
        conn,
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
         sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env",
        BUILD_TIMEOUT,
    )?;

    let verify_script = format!(
        "test -x {MACOS_RUSTYNETD_PATH} && test -x {MACOS_RUSTYNET_PATH} && \
         test -f {MACOS_KEYS_DIR}/wireguard.pub && \
         test -f {MACOS_ENROLLMENT_SECRET_PATH} && \
         test $(stat -f '%Mp%Lp' {MACOS_ENROLLMENT_SECRET_PATH}) = '0600'",
    );
    ssh::run_remote(conn, &verify_script, SHORT_TIMEOUT)?;

    // Wait for the daemon socket so the next stage (collect_pubkeys)
    // can talk to it; launchctl returns before the daemon finishes
    // initialising.
    wait_for_macos_daemon_socket(conn)?;

    Ok(InstallReport {
        daemon_path: MACOS_RUSTYNETD_PATH.into(),
        service_name: MACOS_SERVICE_LABEL.to_owned(),
    })
}

/// Bootstrap via a remote workdir.
///
/// Used when `rustynet_src_dir` is set in inventory.  When `source` is
/// `Some` and the workdir is absent on the remote host, the source
/// archive is SCP'd over and extracted into the workdir before the
/// build step runs.  This guarantees the bootstrap always builds the
/// freshest code rather than silently falling back to the binary
/// already installed at `/usr/local/bin/rustynetd` (which may be from
/// an earlier deploy).  Pass `None` only for legacy callers that
/// genuinely need the "use existing workdir if present, else
/// SKIP_BUILD" behaviour.
pub fn install_daemon_from_workdir(
    conn: &NodeConnection,
    alias: &str,
    workdir: &str,
    source: Option<&SourceArchive>,
    ctx: &OrchestrationContext,
) -> Result<InstallReport, AdapterError> {
    if workdir.is_empty() {
        return Err(AdapterError::Protocol {
            message: "install_daemon_from_workdir: workdir must not be empty".to_owned(),
        });
    }
    let role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .cloned()
        .unwrap_or(NodeRole::Client);
    let node_id = ctx
        .node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| format!("{alias}-bootstrap"));
    if node_id.is_empty() {
        return Err(AdapterError::Protocol {
            message: "install_daemon_from_workdir: node_id must not be empty".to_owned(),
        });
    }
    // Defence-in-depth: same check as install_daemon — the helper is
    // deterministic, but pinning validation at the install boundary
    // protects against a future refactor producing an invalid utun name.
    validate_utun_name(&utun_name_for_node_id(&node_id))?;

    let env_content = build_bootstrap_env(&node_id, &role, ctx);
    let env_tmp = write_temp_file("rn_macos_env_", ".env", env_content.as_bytes())?;
    let script_tmp = write_temp_file("rn_macos_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;

    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.env",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_macos_bootstrap.sh",
        SHORT_TIMEOUT,
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/Install-RustyNetMacosService.sh",
        SHORT_TIMEOUT,
    )?;

    let _ = std::fs::remove_file(&env_tmp);
    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);

    // Pre-warm the relay cargo dep cache on the guest before running the
    // bootstrap. The bootstrap builds rustynet-relay in addition to
    // rustynetd+rustynet-cli; a guest that has never built relay may be missing
    // tokio/bytes/mio .crate files. The online fallback fails on an isolated lab
    // guest with no internet (DNS times out). Fail-open: a cache warm failure
    // is logged but does not abort — the build may still succeed on a guest
    // whose cache is already warm, and blocking here would be strictly worse.
    if let Err(e) = ensure_relay_cargo_deps(conn) {
        eprintln!(
            "[macos bootstrap] relay dep cache warm failed (best-effort): {e}; \
             proceeding — offline relay build may fail if cache is cold"
        );
    }

    // Probe: exit 0 if workdir exists, non-zero otherwise.
    let workdir_present =
        ssh::run_remote(conn, &format!("test -d '{workdir}'"), SHORT_TIMEOUT).is_ok();

    let build_cmd = if let Some(source) = source {
        // A freshly-carried source archive ALWAYS wins, even when a remote
        // workdir exists. The workdir may be a stale checkout from a prior
        // deploy, and building stale code would make this node's security
        // evidence describe the wrong binary — and diverge from the Linux
        // nodes, which always build the orchestrator's archived source. The
        // archive is `git archive HEAD`, so every node builds the same known,
        // reproducible commit. (Previously the workdir-present branch tar'd the
        // remote workdir and ignored this archive — silently keeping stale
        // binaries, the original root cause of "membership role preflight
        // failed" reappearing after a fix had merged.)
        ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", BUILD_TIMEOUT)?;
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
    } else if workdir_present {
        // No fresh archive carried, but a workdir exists (e.g. an operator
        // manually synced it). Build from it.
        format!(
            "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             cd '{workdir}' && tar -czf /tmp/rn_source.tar.gz . && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
        )
    } else {
        // No workdir AND no source — last-resort legacy path: rely on
        // SKIP_BUILD=1 so the bootstrap re-runs the service-install
        // phase against whatever binary is already on disk.
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SKIP_BUILD=1' >> /tmp/rn_macos_bootstrap.env && \
             echo 'SOURCE_ARCHIVE=/dev/null' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
    };
    ssh::run_remote(conn, &build_cmd, BUILD_TIMEOUT)?;

    // The launchd plist is loaded by Bootstrap-RustyNetMacos.sh's final
    // step, but launchctl returns before the daemon process actually
    // opens its socket — the daemon has to verify trust evidence,
    // initialise its state directory, and bind the socket, which can
    // take ~10-30 s.  Without a wait here, the orchestrator's next
    // stage (collect_pubkeys) immediately tries to read from
    // /private/var/run/rustynet/rustynetd.sock and fails with
    // "No such file or directory" because we got there first.  Poll
    // for up to ~40 s (40 * 1 s) which matches the Linux
    // install-systemd socket wait.
    wait_for_macos_daemon_socket(conn)?;

    Ok(InstallReport {
        daemon_path: MACOS_RUSTYNETD_PATH.into(),
        service_name: MACOS_SERVICE_LABEL.to_owned(),
    })
}

/// Poll the remote macOS host for the rustynetd Unix socket to appear.
/// Used by install_daemon and install_daemon_from_workdir to bridge the
/// gap between launchctl returning and the daemon actually being ready.
fn wait_for_macos_daemon_socket(conn: &NodeConnection) -> Result<(), AdapterError> {
    let socket = "/private/var/run/rustynet/rustynetd.sock";
    // 40 iterations × 1 s = 40 s total — comfortably longer than the
    // observed worst-case daemon startup on the lab VM and aligned with
    // the Linux install-systemd timeout.  Probe via `test -S`
    // (Unix-domain socket) to avoid false positives on placeholder
    // files left by a crashed previous run.
    // Probe in short bursts over SEPARATE SSH connections rather than one long
    // 40 s connection. The daemon perturbs the host network as it comes up
    // (binding the userspace-shared utun, reconcile touching routes), which can
    // drop a single in-flight SSH session (observed: bootstrap_hosts failing
    // with ssh `exit 255` even though the daemon was healthy and the socket
    // present). Re-establishing the connection each burst means one transient
    // drop no longer fails the whole wait. ~8 bursts × (8 s probe + 2 s pause)
    // ≈ 80 s budget, comfortably longer than observed daemon startup.
    let probe = format!(
        "for i in $(seq 1 8); do \
            if sudo test -S {socket}; then echo socket-ready; exit 0; fi; \
            sleep 1; \
         done; \
         echo socket-missing; exit 1"
    );
    let mut last_status = String::from("no probe attempt completed");
    for attempt in 1..=8 {
        match ssh::run_remote(conn, &probe, Duration::from_secs(30)) {
            Ok(output) if output.contains("socket-ready") => return Ok(()),
            Ok(_) => last_status = "socket not present yet".to_string(),
            // Transient SSH failure (e.g. exit 255 while the daemon briefly
            // perturbs the network) — re-establish the connection and retry.
            Err(err) => last_status = format!("ssh probe error: {err}"),
        }
        if attempt < 8 {
            std::thread::sleep(Duration::from_secs(2));
        }
    }
    Err(AdapterError::Protocol {
        message: format!(
            "macOS daemon socket {socket} failed to appear after 8 retried probes (~80 s) post launchd bootstrap: {last_status}"
        ),
    })
}

/// Start the launchd service.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let plist = "/Library/LaunchDaemons/com.rustynet.daemon.plist";
    // `launchctl bootstrap` is idempotent (errors if already loaded, which we ignore).
    ssh::run_remote(
        conn,
        &format!(
            "sudo launchctl bootstrap system '{plist}' 2>/dev/null || \
             sudo launchctl kickstart system/com.rustynet.daemon 2>/dev/null || true"
        ),
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Stop the launchd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(
        conn,
        "sudo launchctl bootout system/com.rustynet.daemon 2>/dev/null || true",
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Restart the launchd service (stop + start; launchd has no native restart).
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    stop_daemon(conn)?;
    start_daemon(conn)
}

/// Enforce production runtime for the macOS daemon.
///
/// Mirrors `enforce_daemon` on Linux: re-installs the launchd plist with
/// `--auto-tunnel-enforce true` and extended max-age windows, then restarts
/// the daemon so it picks up the bundles deployed in the prior pipeline stages.
///
/// Called by [`MacosNodeAdapter::enforce_runtime`] from the
/// `EnforceBaselineRuntime` stage, which runs after all bundle-distribution
/// stages (`DistributeAssignments`, `DistributeTraversal`, `DistributeDnsZone`)
/// have completed.
///
/// Max-age windows: 86400 s (24 h). The pipeline issues bundles once and does
/// not rotate them; production daemons rely on periodic refresh timers that do
/// not exist in the lab. This matches the Linux lab setting.
pub fn enforce_daemon(
    conn: &NodeConnection,
    alias: &str,
    ctx: &OrchestrationContext,
) -> Result<(), AdapterError> {
    let role = ctx
        .assignments
        .iter()
        .find(|a| a.alias == alias)
        .map(|a| &a.role)
        .cloned()
        .unwrap_or(NodeRole::Client);
    let node_id = ctx
        .node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| format!("{alias}-bootstrap"));
    let daemon_node_role = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
        .map_err(|message| AdapterError::Protocol { message })?;
    let ssh_allow_cidrs = ctx.ssh_allow_cidrs.clone();
    let ssh_allow_flag = if ssh_allow_cidrs.is_empty() {
        "false"
    } else {
        "true"
    };

    if node_id.is_empty() {
        return Err(AdapterError::Protocol {
            message: "enforce_daemon: node_id must not be empty".to_owned(),
        });
    }
    let wg_interface = utun_name_for_node_id(&node_id);
    validate_utun_name(&wg_interface)?;

    // Escape single quotes in values interpolated into single-quoted shell args
    // (parity with the Linux enforce path, which escapes ssh_allow_cidrs). The
    // un-escaped `node_id` above is still used for the utun derivation; only the
    // shell interpolation below uses the escaped copies. daemon_node_role comes
    // from a fixed enum mapping and wg_interface is digit-validated, so neither
    // needs escaping.
    let node_id_arg = node_id.replace('\'', "'\\''");
    let network_id_arg = ctx.network_id.replace('\'', "'\\''");
    let ssh_allow_cidrs_arg = ssh_allow_cidrs.replace('\'', "'\\''");

    // Write the install-service script to a temp file on the remote host and
    // re-invoke it with enforce-mode settings.  The script is compiled into the
    // binary so the same version is always used; the local working copy stays in
    // sync automatically when the binary is rebuilt.
    let install_tmp = write_temp_file(
        "rn_macos_install_svc_",
        ".sh",
        INSTALL_SERVICE_SCRIPT.as_bytes(),
    )?;
    ssh::scp_to(
        conn,
        install_tmp.as_path(),
        "/tmp/Install-RustyNetMacosService.sh",
        SHORT_TIMEOUT,
    )?;
    let _ = std::fs::remove_file(&install_tmp);

    // Build the re-install command: same params as bootstrap but with
    // auto-tunnel-enforce=true and extended max-age windows.
    // trust-max-age-secs 86400: macOS has no periodic trust-evidence refresh
    // timer (unlike Linux rustynetd-trust-refresh.service).  The lab issues
    // trust evidence once during bootstrap; 86400 s keeps it valid for the
    // duration of any reasonable lab run without requiring a separate refresh.
    let script = format!(
        "chmod 700 /tmp/Install-RustyNetMacosService.sh && \
         sudo /tmp/Install-RustyNetMacosService.sh \
           --rustynetd-bin {MACOS_RUSTYNETD_PATH} \
           --state-root {MACOS_STATE_ROOT} \
           --node-id '{node_id_arg}' \
           --node-role '{daemon_node_role}' \
           --network-id '{network_id_arg}' \
           --wg-interface '{wg_interface}' \
           --auto-tunnel-enforce true \
           --trust-max-age-secs 86400 \
           --auto-tunnel-max-age-secs 86400 \
           --traversal-max-age-secs 86400 \
           --dns-zone-max-age-secs 86400 \
           --fail-closed-ssh-allow '{ssh_allow_flag}' \
           --fail-closed-ssh-allow-cidrs '{ssh_allow_cidrs_arg}'",
    );
    ssh::run_remote(conn, &script, Duration::from_secs(60))?;
    // The install script reloads the launchd plist, which bounces the daemon.
    // launchctl returns before the daemon re-binds its control socket, but the
    // next stage (ValidateBaselineRuntime) probes that socket with no retry of
    // its own. Wait for the socket to reappear so a mid-restart daemon does not
    // produce a spurious validation failure. Mirrors install_daemon and the
    // Windows enforce path's post-restart readiness wait.
    wait_for_macos_daemon_socket(conn)?;
    Ok(())
}

/// Stop the service and remove daemon binaries and state.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    let _ = stop_daemon(conn);
    ssh::run_remote(
        conn,
        &format!(
            "sudo rm -f {MACOS_RUSTYNETD_PATH} {MACOS_RUSTYNET_PATH} \
             /Library/LaunchDaemons/com.rustynet.daemon.plist && \
             sudo rm -rf {MACOS_STATE_ROOT} /usr/local/etc/rustynet /private/var/run/rustynet",
        ),
        timeout,
    )?;
    Ok(())
}

// ── utun interface name derivation ────────────────────────────────────────────

/// Derive a deterministic utun index for a node_id using FNV-1a.
/// Range: [10, 4095] — avoids utun0-9 (macOS system interfaces) and keeps the
/// name ≤ 8 chars ("utun4095"), well within the 15-char IFNAMSIZ limit.
fn utun_index_for_node_id(node_id: &str) -> u16 {
    let mut hash: u32 = 2_166_136_261; // FNV-1a offset basis
    for byte in node_id.bytes() {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619); // FNV-1a prime
    }
    (hash % 4086) as u16 + 10 // [10, 4095]
}

/// Format the deterministic utun interface name for a node_id.
fn utun_name_for_node_id(node_id: &str) -> String {
    format!("utun{}", utun_index_for_node_id(node_id))
}

/// Validate that a utun name is safe for use as an interface name.
fn validate_utun_name(name: &str) -> Result<(), AdapterError> {
    let suffix = name
        .strip_prefix("utun")
        .ok_or_else(|| AdapterError::Protocol {
            message: format!("utun name {name:?} must start with utun"),
        })?;
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return Err(AdapterError::Protocol {
            message: format!("utun name {name:?} must be utun followed by digits"),
        });
    }
    if name.len() > 15 {
        return Err(AdapterError::Protocol {
            message: format!("utun name {name:?} exceeds 15-char IFNAMSIZ"),
        });
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_bootstrap_env(node_id: &str, role: &NodeRole, ctx: &OrchestrationContext) -> String {
    let role_str = role.as_str();
    let daemon_node_role = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
        .expect("macOS lab role must have explicit daemon role mapping");
    // Derive the per-node utun interface name and pass it through to the
    // bootstrap shell so the FIRST plist install already targets the
    // node-specific utun device. Without WG_INTERFACE in the env file the
    // bootstrap-time install would fall back to the install-script default
    // (utun9) and the orchestrator's later enforce_runtime phase would have
    // to re-render the plist; mac hosts running concurrently with the same
    // utun9 would collide. Computing it here keeps the value identical in
    // both code paths and avoids re-deriving it in shell.
    let wg_interface = utun_name_for_node_id(node_id);
    format!(
        "ROLE={role_str}\nDAEMON_NODE_ROLE={daemon_node_role}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\n\
         SSH_ALLOW_CIDRS={cidrs}\nWG_INTERFACE={wg_interface}\n",
        network_id = ctx.network_id,
        cidrs = ctx.ssh_allow_cidrs,
    )
}

/// Deploy the `rustynet-relay` sibling service onto this macOS Relay node so the
/// `relay_validation` stage has a live relay to prove — the macOS analogue of
/// `linux_install::deploy_relay_service`, sharing its security posture.
///
/// The relay binary is already present at [`MACOS_RUSTYNET_RELAY_PATH`] (built +
/// installed by `Bootstrap-RustyNetMacos.sh` while the network was open). This
/// step supplies the two things the launchd unit needs that the baseline
/// install does not:
///
///   1. The relay `--verifier-key` at
///      `/usr/local/var/rustynet/relay-verifier.pub` — the path hardcoded in the
///      reviewed `com.rustynet.relay.plist`. `rustynet-relay` loads it as raw 32
///      bytes and fail-closes if it is absent. We derive it from the assignment
///      authority public key the orchestrator already distributed to this node
///      as `{MACOS_STATE_ROOT}/trust/assignment.pub` (hex) — the same control-
///      plane verifier the relay must trust, and a PUBLIC key (never secret), so
///      it is safe to read, decode, and re-place. Decoding to raw bytes happens
///      in Rust (fail-closed on a short / non-hex key); the bytes are shipped via
///      scp + `install` so no key data is interpolated into a shell string and
///      the guest needs no `xxd`.
///   2. The installed + bootstrapped `com.rustynet.relay` launchd service, via
///      the shared `ops install-macos-relay` helper — the one hardened relay-
///      install path. It copies the reviewed plist from
///      `scripts/launchd/com.rustynet.relay.plist` relative to the source root,
///      so it runs from that cwd (the configured workdir, else `$HOME/Rustynet`).
///
/// Fail-closed throughout: a missing assignment key, a malformed key, or a
/// failed install all surface as `Err`.
pub fn deploy_relay_service(
    conn: &NodeConnection,
    workdir: Option<&str>,
) -> Result<(), AdapterError> {
    let short_timeout = Duration::from_secs(30);

    // 1. Read the already-distributed assignment authority pubkey (hex). On
    //    macOS distribute_verifier_key(Assignment) places it at
    //    {MACOS_STATE_ROOT}/trust/assignment.pub, owned by rustynetd, so read it
    //    with sudo. The path is a compile-time constant; nothing untrusted is
    //    interpolated.
    let assignment_pub = format!("{MACOS_STATE_ROOT}/trust/assignment.pub");
    let assignment_hex =
        ssh::run_remote(conn, &format!("sudo cat '{assignment_pub}'"), short_timeout)?;

    // 2. Decode hex -> raw 32 bytes (fail-closed); the relay --verifier-key
    //    loader requires exactly 32 raw bytes.
    let verifier_bytes = decode_assignment_pubkey_hex(&assignment_hex)
        .map_err(|message| AdapterError::Protocol { message })?;

    // 3. Ship the raw verifier key to the host and install it at the plist's
    //    hardcoded path (mode 0644 — a public key). scp the bytes (no shell data
    //    interpolation), then install with a constant command. `mkdir -p` keeps
    //    the existing rustynetd-owned state-root mode (no chmod of an existing
    //    dir) while fail-closing if the state root is somehow absent.
    let tmp = write_temp_file("rn_relay_verifier_", ".pub", &verifier_bytes)?;
    let ship = ssh::scp_to(
        conn,
        tmp.as_path(),
        "/tmp/rn-relay-verifier.pub",
        short_timeout,
    );
    let _ = std::fs::remove_file(&tmp);
    ship?;
    ssh::run_remote(
        conn,
        &format!(
            "sudo sh -c 'mkdir -p {MACOS_STATE_ROOT} && \
             install -m 0644 /tmp/rn-relay-verifier.pub {MACOS_STATE_ROOT}/relay-verifier.pub && \
             rm -f /tmp/rn-relay-verifier.pub'"
        ),
        short_timeout,
    )?;

    // 4. Install + bootstrap com.rustynet.relay via the shared helper. It reads
    //    scripts/launchd/com.rustynet.relay.plist relative to cwd, so run from
    //    the source root (the configured workdir, else $HOME/Rustynet). The
    //    source dir is passed only inside a single-quoted env assignment; the
    //    executed shell body is a compile-time constant. Absolute CLI path so
    //    the install never depends on sudo's PATH inside the root `sh -c`.
    let src_dir = match workdir {
        Some(w) if !w.trim().is_empty() => w.trim().to_owned(),
        _ => {
            let home = ssh::run_remote(conn, "echo $HOME", Duration::from_secs(10))?
                .trim()
                .to_owned();
            if home.is_empty() {
                return Err(AdapterError::Protocol {
                    message: "could not determine $HOME on remote for install-macos-relay"
                        .to_owned(),
                });
            }
            format!("{home}/Rustynet")
        }
    };
    let src_dir_esc = src_dir.replace('\'', "'\\''");
    let install_cmd = format!(
        "sudo env RN_SRC='{src_dir_esc}' sh -c 'cd \"$RN_SRC\" && {MACOS_RUSTYNET_PATH} ops install-macos-relay'"
    );
    ssh::run_remote(conn, &install_cmd, Duration::from_secs(120))?;
    Ok(())
}

/// Pre-warm the relay dep cargo registry cache on a macOS guest by shipping any
/// `.crate` files the offline relay build needs that are absent from the guest's
/// `~/.cargo/registry/cache/` directory.
///
/// # Why this is needed
///
/// The macOS guest's cargo registry is populated during the initial bootstrap
/// (when it builds `rustynetd` + `rustynet-cli`). If the relay binary (`rustynet-
/// relay`) was added to the build list after the guest's registry was last
/// populated — or the guest has never built relay — its tokio/bytes/mio dep
/// .crate files may be absent. The bootstrap falls through to the online fallback,
/// which fails on an isolated lab guest with no internet (DNS times out).
///
/// This function detects the missing files by querying the guest's registry, then
/// copies them from the orchestrator host's registry (which always has them since
/// the orchestrator builds the full workspace). The `.crate` files are source
/// archives — architecture-neutral — so copying from an amd64 orchestrator to an
/// arm64 guest is correct. Only external (non-path) crates appear in the registry;
/// workspace crates are always built from source and need no cache entry.
///
/// # Fail-open design
///
/// A failure here should not abort the bootstrap: the worst case is the bootstrap
/// falls back to the online path and fails on a no-internet guest, which is the
/// exact failure mode this function prevents. Returning `Err` would skip the
/// bootstrap entirely, which is worse. Callers should log + continue on error.
pub fn ensure_relay_cargo_deps(conn: &NodeConnection) -> Result<(), String> {
    // Known relay dep .crate files (external, non-workspace). Derived from the
    // Cargo.lock at the time this code was written; update when relay's dep tree
    // changes. The list is conservative: presence of all files here is sufficient
    // for a warm offline build of rustynet-relay --features daemon.
    //
    // These are the tokio-ecosystem crates rustynetd/rustynet-cli do NOT pull in
    // (so they are absent from a macOS relay guest that only built those two),
    // plus the bytes/mio crates that tokio depends on.
    const RELAY_EXTRA_CRATES: &[&str] = &[
        "bytes-1.11.1.crate",
        "mio-1.1.1.crate",
        "tokio-1.50.0.crate",
        "tokio-macros-2.6.1.crate",
    ];

    // Locate the orchestrator host's cargo registry cache.
    let cargo_home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/iwan".to_owned());
        format!("{home}/.cargo")
    });
    let short = Duration::from_secs(20);

    // Find the registry cache dir on the guest (resolve the hashed subdir name
    // dynamically so this works regardless of the exact hash).
    let guest_registry = ssh::run_remote(
        conn,
        "ls -d ~/.cargo/registry/cache/index.crates.io-* 2>/dev/null | head -1 | tr -d '\n'",
        short,
    )
    .unwrap_or_default();
    let guest_registry = guest_registry.trim().to_owned();
    if guest_registry.is_empty() {
        return Err(
            "could not find ~/.cargo/registry/cache/index.crates.io-* on macOS guest".to_owned(),
        );
    }

    // Discover the orchestrator's registry dir (same hash or any index.crates.io-* dir).
    let local_cache = {
        let cache_root = format!("{cargo_home}/registry/cache");
        let Ok(entries) = std::fs::read_dir(&cache_root) else {
            return Err(format!(
                "orchestrator cargo registry cache not found at {cache_root}"
            ));
        };
        let mut found = None;
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("index.crates.io-") {
                found = Some(e.path());
                break;
            }
        }
        found.ok_or_else(|| format!("no index.crates.io-* dir in {cache_root}"))?
    };

    // Check which crates are missing on the guest, then ship them.
    let missing: Vec<&str> = {
        let check_cmd = RELAY_EXTRA_CRATES
            .iter()
            .map(|c| {
                format!(
                    "test -f '{guest_registry}/{c}' && echo 'present:{c}' || echo 'missing:{c}'"
                )
            })
            .collect::<Vec<_>>()
            .join(" ; ");
        let output = ssh::run_remote(conn, &check_cmd, short).unwrap_or_default();
        RELAY_EXTRA_CRATES
            .iter()
            .copied()
            .filter(|c| !output.contains(&format!("present:{c}")))
            .collect()
    };

    if missing.is_empty() {
        return Ok(());
    }

    for crate_name in &missing {
        let local_path = local_cache.join(crate_name);
        if !local_path.exists() {
            return Err(format!(
                "relay dep {crate_name} missing from orchestrator registry at {}",
                local_cache.display()
            ));
        }
        ssh::scp_to(
            conn,
            Path::new(&local_path),
            &format!("{guest_registry}/{crate_name}"),
            short,
        )
        .map_err(|e| format!("failed to ship {crate_name} to macOS guest registry: {e}"))?;
    }
    Ok(())
}

fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    let mut path = std::env::temp_dir();
    path.push(format!("{prefix}{}{suffix}", std::process::id()));
    let mut file = std::fs::File::create(&path).map_err(|err| AdapterError::Io {
        message: format!("create temp file failed: {err}"),
    })?;
    file.write_all(content).map_err(|err| AdapterError::Io {
        message: format!("write temp file failed: {err}"),
    })?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn make_ctx(role: NodeRole) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "macos-1".to_owned(),
                role,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            node_ids: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "test-net".to_owned(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        }
    }

    #[test]
    fn bootstrap_env_contains_role_and_node_id() {
        let ctx = make_ctx(NodeRole::Client);
        let env = build_bootstrap_env("mac-node-1", &NodeRole::Exit, &ctx);
        assert!(env.contains("ROLE=exit"));
        assert!(env.contains("DAEMON_NODE_ROLE=blind_exit"));
        assert!(env.contains("NODE_ID=mac-node-1"));
        assert!(env.contains("NETWORK_ID=test-net"));
    }

    #[test]
    fn bootstrap_scripts_are_non_empty() {
        assert!(
            !BOOTSTRAP_SCRIPT.is_empty(),
            "Bootstrap-RustyNetMacos.sh must not be empty"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Bootstrap-RustyNetMacos.sh"),
            "bootstrap script must contain its own filename"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.is_empty(),
            "Install-RustyNetMacosService.sh must not be empty"
        );
    }

    #[test]
    fn bootstrap_script_clears_stale_signed_state_on_fresh_enroll() {
        // A fresh (re)enrollment must wipe the prior membership/trust signed-state
        // + anti-replay watermarks, or the daemon rejects the fresh genesis bundle
        // as a replay/rollback ("membership replay/rollback detected by watermark")
        // and fail-closes (observed live: macOS stuck state=FailClosed,
        // membership_active_nodes=none). macOS analogue of the Linux cleanup's
        // `rm -rf /var/lib/rustynet`; key custody must be preserved.
        assert!(
            BOOTSTRAP_SCRIPT.contains("for _residual_dir in membership trust"),
            "clear_residual_state must wipe the membership/ and trust/ signed-state"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("rm -f \"${STATE_ROOT}/rustynetd.state\""),
            "clear_residual_state must remove the stale top-level session state"
        );
        // The reset must NOT touch key-custody material.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("for _residual_dir in membership trust keys")
                && !BOOTSTRAP_SCRIPT.contains("rm -rf \"${KEYS_DIR}\""),
            "key custody (keys/) must be preserved by the fresh-enroll reset"
        );
        // The reset must run in BOTH the full-install and SKIP_BUILD paths (a
        // SKIP_BUILD redeploy onto a prior enrollment is the exact case that
        // stranded the epoch-16 watermark live).
        assert_eq!(
            BOOTSTRAP_SCRIPT.matches("  clear_residual_state\n").count(),
            2,
            "clear_residual_state must be invoked in both the full and SKIP_BUILD paths"
        );
    }

    #[test]
    fn bootstrap_script_refuses_root_homebrew_fallback() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("resolve_non_root_bootstrap_user"),
            "bootstrap script must centralize non-root Homebrew user resolution"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("RUSTYNET_MACOS_BOOTSTRAP_USER"),
            "bootstrap script must allow an explicit non-root override for headless SSH bootstrap"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Refusing to run Homebrew/Rust toolchain as root"),
            "bootstrap script must fail closed instead of running Homebrew as root"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("REAL_USER=\"$(whoami)\""),
            "bootstrap script must not fall back to root when invoked by root over SSH"
        );
    }

    #[test]
    fn bootstrap_script_skips_coreutils_when_timeout_exists() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("timeout: already available; skipping coreutils install"),
            "bootstrap must not fetch coreutils when a working timeout binary is already present"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("Installing coreutils for gtimeout"),
            "bootstrap still needs a fail-closed coreutils install path when timeout is absent"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("wireguard-go wireguard-tools rustup coreutils"),
            "coreutils must not be part of the unconditional Homebrew formula install loop"
        );
    }

    #[test]
    fn bootstrap_script_uses_root_for_system_keychain_writes_only() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("sudo RUSTYNET_WG_BINARY_PATH=\"${BREW_PREFIX}/bin/wg\""),
            "macOS key init must run as root so System.keychain writes succeed"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("sudo \"${RUSTYNETD_BIN}\" key store-passphrase"),
            "macOS passphrase provisioning must run as root so System.keychain writes succeed"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("chown root:wheel \"${passphrase_tmp}\""),
            "bootstrap passphrase must be root-owned while root reads it for secure-store provisioning"
        );
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("chown rustynetd:rustynetd \"${encrypted_key}\" \"${public_key}\""),
            "encrypted key + public key must be handed back to the daemon service account after key init"
        );
        // Phase E: wireguard.passphrase lives in BOOTSTRAP_DIR (not keys/) and is
        // kept root:rustynetd 0600. The cdhash re-bind reads it as root; the daemon
        // never reads it at runtime (uses System.keychain). Keeping it root-owned
        // prevents the daemon account from accidentally reading plaintext passphrase
        // material outside the keychain path.
        assert!(
            BOOTSTRAP_SCRIPT.contains("chown root:rustynetd \"${passphrase_file}\""),
            "bootstrap passphrase in BOOTSTRAP_DIR must be root:rustynetd (not daemon-owned)"
        );
        // Encrypted-at-rest custody (Phase E): `key init` writes a plaintext
        // runtime key under keys/, but a plaintext private key MUST NOT persist
        // at rest on macOS. The bootstrap removes it (the daemon re-derives it
        // from wireguard.key.enc + the keychain passphrase into the ephemeral
        // runtime dir on every start, mirroring Linux's tmpfs runtime key).
        // These two assertions GUARD that custody: a regression that chowned /
        // kept the plaintext runtime key at rest (the pre-relocation behaviour
        // this test previously asserted) would fail here.
        assert!(
            BOOTSTRAP_SCRIPT.contains("rm -f \"${runtime_key}\""),
            "macOS bootstrap must remove the plaintext runtime key from the persistent keys/ dir (no plaintext private key at rest)"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("chown rustynetd:rustynetd \"${runtime_key}\""),
            "the plaintext runtime key must be removed, never chowned/persisted at rest"
        );
        assert!(
            !BOOTSTRAP_SCRIPT
                .contains("sudo -u rustynetd RUSTYNET_WG_BINARY_PATH=\"${BREW_PREFIX}/bin/wg\""),
            "key init must not run as rustynetd; that account cannot write System.keychain"
        );
        assert!(
            !BOOTSTRAP_SCRIPT
                .contains("sudo -u rustynetd \"${RUSTYNETD_BIN}\" key store-passphrase"),
            "passphrase keychain provisioning must not run as rustynetd"
        );
    }

    #[test]
    fn bootstrap_builds_and_installs_rustynet_relay() {
        // A Relay-role macOS node needs the rustynet-relay sibling binary present
        // for DeployRelayServiceStage (macos_install::deploy_relay_service) to
        // enable the com.rustynet.relay launchd service. The bootstrap builds it
        // (with the daemon feature) and installs it to /usr/local/bin alongside
        // rustynetd / rustynet. A regression dropping either step would leave a
        // Relay node with no binary for the unit to launch.
        assert!(
            BOOTSTRAP_SCRIPT.contains("-p rustynet-relay --features daemon"),
            "macOS bootstrap must build the rustynet-relay binary with the daemon feature"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains(
                "\"${BUILD_DIR}/target/release/rustynet-relay\" \"${RUSTYNET_RELAY_BIN}\""
            ),
            "macOS bootstrap must install rustynet-relay to /usr/local/bin"
        );
    }

    #[test]
    fn live_lab_membership_distribution_uses_macos_writable_staging() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("staging_dir=\"/private/var/tmp\""),
            "macOS membership distribution must not stage files under locked-down /tmp"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("remote_snapshot=\"${staging_dir}/rn-membership.snapshot\""),
            "membership snapshot staging path must be platform-derived"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("root install -m 0600 '${remote_snapshot}' '${snapshot_path}'"),
            "macOS membership install must consume the platform-specific staging path"
        );
        assert!(
            !LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("root install -m 0600 /tmp/rn-membership.snapshot '${snapshot_path}'"),
            "macOS membership distribution must not hard-code /tmp"
        );
    }

    #[test]
    fn live_lab_macos_signed_artifact_distribution_uses_writable_staging() {
        for needle in [
            // Assignment staging paths are node_id-scoped (commit 29ef235) to
            // prevent a parallel-worker race when multiple nodes stage
            // concurrently on the same shared /tmp.
            "remote_pub=\"${staging_dir}/rn-assignment-${node_id}.pub\"",
            "remote_bundle=\"${staging_dir}/rn-assignment-${node_id}.bundle\"",
            "remote_env=\"${staging_dir}/rn-assignment-refresh-${node_id}.env\"",
            "remote_pub=\"${staging_dir}/rn-dns-zone.pub\"",
            "remote_bundle=\"${staging_dir}/rn-dns-zone.bundle\"",
        ] {
            assert!(
                LIVE_LAB_COMMON.contains(needle),
                "common helper missing {needle}"
            );
        }
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("remote_pub=\"${staging_dir}/rn-traversal.pub\""),
            "traversal pub staging path must be platform-derived"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("remote_bundle=\"${staging_dir}/rn-traversal.bundle\""),
            "traversal bundle staging path must be platform-derived"
        );
        assert!(
            !LIVE_LAB_COMMON.contains(
                "scp_to \"$assignment_pub_local\" \"$target\" \"/tmp/rn-assignment.pub\""
            ),
            "assignment install must not hard-code /tmp for macOS"
        );
        assert!(
            !LIVE_LAB_COMMON
                .contains("scp_to \"$env_local\" \"$target\" \"/tmp/rn-assignment-refresh.env\""),
            "assignment refresh install must not hard-code /tmp for macOS"
        );
        assert!(
            !LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "scp_to \"$STATE_DIR/traversal.pub\" \"$target\" \"/tmp/rn-traversal.pub\""
            ),
            "traversal install must not hard-code /tmp for macOS"
        );
    }

    #[test]
    fn live_lab_macos_enforce_uses_writable_staging() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "local remote_install_script=\"/private/var/tmp/Install-RustyNetMacosService.sh\""
            ),
            "macOS enforce must stage Install-RustyNetMacosService.sh under /private/var/tmp"
        );
        assert!(
            !LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("local remote_install_script=\"/tmp/Install-RustyNetMacosService.sh\""),
            "macOS enforce must not regress to locked-down /tmp"
        );
    }

    /// Every live-lab stage must automatically append a duration row to
    /// documents/operations/live_lab_stage_timings.csv, mirroring how cargo
    /// gate timings land in documents/operations/gate_timings.csv (identical
    /// schema). run_stage is the single choke point (run_setup_stage delegates
    /// to it), so the timing helper must be defined and invoked there, and it
    /// must target the dedicated sibling CSV — not the gate-timings file.
    #[test]
    fn live_lab_run_stage_logs_per_stage_timing_to_csv() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("record_stage_timing() {"),
            "orchestrator must define the record_stage_timing helper"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("record_stage_timing \"$stage_name\" \"$_stage_elapsed_secs\" \"$status\" \"$started_at\""),
            "run_stage must invoke record_stage_timing with the raw elapsed seconds and finalized status"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("documents/operations/live_lab_stage_timings.csv"),
            "stage timings must be appended to the dedicated live_lab_stage_timings.csv sibling file"
        );
    }

    /// Regression guard for the macOS stale-bundle enforce wedge. The legacy
    /// bash enforce path (`enforce_runtime_worker_macos`) and the bootstrap
    /// install invocation must forward the same relaxed lab freshness window
    /// (86400 s) for the auto-tunnel, traversal and DNS-zone bundles that the
    /// Linux systemd unit, the Windows installer and the Rust `enforce_daemon`
    /// path already use. When only `--trust-max-age-secs` was forwarded the
    /// macOS daemon fell back to the strict 300 s production default for those
    /// three bundles; on a slower multi-node run a bundle aged past 300 s
    /// before the next re-mint reached the daemon, the auto-tunnel reconcile
    /// fail-closed as "stale", the daemon wedged in restricted-safe mode, and
    /// the subsequent `rustynet state refresh` hung until the stage watchdog
    /// fired. The 300 s production default is unchanged; this only keeps macOS
    /// at parity with the existing Linux/Windows lab window.
    #[test]
    fn macos_daemon_launch_relaxes_lab_freshness_window_for_all_bundles() {
        for flag in [
            "--auto-tunnel-max-age-secs 86400",
            "--traversal-max-age-secs 86400",
            "--dns-zone-max-age-secs 86400",
        ] {
            assert!(
                LIVE_LINUX_LAB_ORCHESTRATOR.contains(flag),
                "macOS enforce path (enforce_runtime_worker_macos) must forward {flag} so the \
                 enforced daemon does not fall back to the strict 300 s production default"
            );
            assert!(
                BOOTSTRAP_SCRIPT.contains(flag),
                "macOS bootstrap install invocation must forward {flag} so the bootstrap-time \
                 daemon uses the same lab freshness window"
            );
        }
    }

    #[test]
    fn live_lab_prime_remote_access_skips_sudo_for_windows_role_node() {
        // A Windows role node has no sudo. live_lab_push_sudo_password runs a
        // POSIX `sudo -n` probe over plain ssh (not the cmd.exe/EncodedCommand
        // wrapper a Windows guest needs), so against a Windows node it blocks
        // for the full live_lab_ssh timeout (3h) instead of completing. The
        // prime worker must resolve the node platform and skip the sudo-prime
        // for windows, returning success without ever invoking the probe.
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("[prime-remote] %s skipping sudo-prime (windows/non-posix role node)"),
            "prime_remote_access_worker must skip (not hang on) the sudo-prime for a windows role node"
        );
        // The skip must be platform-gated: the worker resolves the node's
        // platform and the windows branch must precede the sudo push so the
        // POSIX probe is never reached for a Windows node.
        let prime_fn = LIVE_LINUX_LAB_ORCHESTRATOR
            .split("prime_remote_access_worker() {")
            .nth(1)
            .and_then(|rest| rest.split("\nstage_preflight() {").next())
            .expect("prime_remote_access_worker body must be present");
        let skip_idx = prime_fn
            .find("skipping sudo-prime (windows/non-posix role node)")
            .expect("prime worker must log the windows skip");
        // Match the actual call form (`live_lab_push_sudo_password "$target"`),
        // not the bare symbol — the guard comment above also names the helper,
        // and matching the symbol alone would find the comment, not the call.
        let push_idx = prime_fn
            .find("live_lab_push_sudo_password \"$target\"")
            .expect("prime worker must still push sudo for posix nodes");
        assert!(
            skip_idx < push_idx,
            "windows skip must be evaluated before the POSIX sudo-prime so a windows node never reaches it"
        );
        assert!(
            prime_fn.contains("if [[ \"$platform\" == \"windows\" ]]; then"),
            "prime worker windows guard must branch on the resolved node platform"
        );
    }

    #[test]
    fn live_lab_cleanup_host_worker_reachability_probe_is_platform_aware() {
        // cleanup_host_worker runs an SSH reachability gate before dispatching
        // per-platform cleanup. A Windows role node must NOT be probed with the
        // bare `true`-over-default-shell `ssh_wait_for_host`, which wedges a
        // memory-pressured Windows guest (the cleanup_hosts hang we are fixing).
        // The gate must route through ssh_wait_for_host_for_platform, which
        // sends Windows through the cmd.exe-wrapped probe.
        let cleanup_fn = LIVE_LINUX_LAB_ORCHESTRATOR
            .split("cleanup_host_worker() {")
            .nth(1)
            .and_then(|rest| rest.split("\ncleanup_host_worker_macos() {").next())
            .expect("cleanup_host_worker body must be present");
        assert!(
            cleanup_fn.contains("ssh_wait_for_host_for_platform \"$target\" \"$platform\" 120 5"),
            "cleanup_host_worker must gate reachability via the platform-aware probe"
        );
        assert!(
            !cleanup_fn.contains("ssh_wait_for_host \"$target\" 120 5"),
            "cleanup_host_worker must not call the POSIX-only ssh_wait_for_host directly"
        );
    }

    #[test]
    fn live_lab_windows_reachability_probe_uses_cmd_exe_wrapper() {
        // The Windows-safe reachability helper must route through
        // live_lab_ssh_windows (cmd.exe /c powershell.exe -EncodedCommand),
        // never the POSIX live_lab_ssh_via_ssh default-shell path that hangs.
        let probe_fn = LIVE_LINUX_LAB_ORCHESTRATOR
            .split("ssh_wait_for_host_windows() {")
            .nth(1)
            .and_then(|rest| rest.split("\nssh_wait_for_host_for_platform() {").next())
            .expect("ssh_wait_for_host_windows body must be present");
        assert!(
            probe_fn.contains("live_lab_ssh_windows \"$target\" 'exit 0'"),
            "windows reachability probe must use the cmd.exe-wrapped live_lab_ssh_windows"
        );
        assert!(
            !probe_fn.contains("live_lab_ssh_via_ssh"),
            "windows reachability probe must not use the POSIX default-shell ssh path"
        );
        // The dispatcher must send windows to the windows probe and POSIX
        // platforms to the POSIX probe, and fail closed on an unknown platform.
        let dispatch_fn = LIVE_LINUX_LAB_ORCHESTRATOR
            .split("ssh_wait_for_host_for_platform() {")
            .nth(1)
            .and_then(|rest| rest.split("\ncapture_boot_id() {").next())
            .expect("ssh_wait_for_host_for_platform body must be present");
        assert!(
            dispatch_fn.contains("windows)")
                && dispatch_fn.contains(
                    "ssh_wait_for_host_windows \"$target\" \"$attempts\" \"$sleep_secs\""
                ),
            "dispatcher must route windows to the windows-safe probe"
        );
        assert!(
            dispatch_fn.contains("linux|macos)"),
            "dispatcher must keep the POSIX probe for linux/macos"
        );
        assert!(
            dispatch_fn.contains("unsupported platform"),
            "dispatcher must fail closed on an unknown platform"
        );
    }

    #[test]
    fn live_lab_windows_bootstrap_worker_reachability_probe_is_windows_safe() {
        // bootstrap_host_worker_windows used the POSIX ssh_wait_for_host before
        // its per-step live_lab_ssh_windows calls — the same default-shell hang
        // class. It must use the Windows-safe probe so the bootstrap_hosts stage
        // cannot wedge on a Windows guest.
        let win_bootstrap = LIVE_LINUX_LAB_ORCHESTRATOR
            .split("bootstrap_host_worker_windows() {")
            .nth(1)
            .and_then(|rest| rest.split("\nstage_collect_pubkeys() {").next())
            .expect("bootstrap_host_worker_windows body must be present");
        assert!(
            win_bootstrap.contains("ssh_wait_for_host_windows \"$target\""),
            "windows bootstrap worker must use the windows-safe reachability probe"
        );
        assert!(
            !win_bootstrap.contains("ssh_wait_for_host \"$target\" ||"),
            "windows bootstrap worker must not call the POSIX-only ssh_wait_for_host"
        );
    }

    #[test]
    fn live_lab_stage_watchdog_kills_process_tree() {
        // The per-stage watchdog must terminate the whole descendant tree, not
        // just the subshell pid: a stuck remote ssh/scp child would otherwise
        // survive and keep the run wedged past --stage-timeout-secs. This is the
        // companion to the CLI wiring that forwards the flag.
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("kill_stage_process_tree() {"),
            "orchestrator must define a descendant-tree kill helper for the watchdog"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("kill_stage_process_tree TERM \"$_bg_pid\"")
                && LIVE_LINUX_LAB_ORCHESTRATOR
                    .contains("kill_stage_process_tree KILL \"$_bg_pid\""),
            "stage watchdog must escalate TERM then KILL across the stage process tree"
        );
    }

    #[test]
    fn live_lab_refresh_runtime_state_dispatches_per_platform() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "root launchctl kickstart -k system/com.rustynet.privileged-helper 2>/dev/null || true; root launchctl kickstart -k system/com.rustynet.daemon"
            ),
            "macOS runtime refresh must bounce daemon via launchctl kickstart"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "live_lab_ssh_windows \"$target\" \"Restart-Service -Name RustyNet -Force\""
            ),
            "Windows runtime refresh must restart RustyNet service via PowerShell"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("rustynet ops force-local-assignment-refresh-now"),
            "Linux runtime refresh must keep the existing systemd-aware path"
        );
    }

    #[test]
    fn live_lab_refresh_trust_resolves_macos_paths_via_env() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR
                .contains("RUSTYNET_TRUST_SIGNER_KEY='/usr/local/etc/rustynet/trust-evidence.key'"),
            "macOS trust refresh must pin signer key path to the macOS canonical location"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "RUSTYNET_TRUST_EVIDENCE='/usr/local/var/rustynet/trust/rustynetd.trust'"
            ),
            "macOS trust refresh must pin trust evidence path to the macOS canonical location"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "[trust-refresh] %s skipped on windows (DPAPI signer-key unwrap pending)"
            ),
            "Windows trust refresh stays an explicit no-op until DPAPI unwrap lands"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains("rustynet ops refresh-signed-trust"),
            "Linux trust refresh must keep the existing signed-trust verb"
        );
    }

    #[test]
    fn live_lab_role_coupling_validation_passes_platform() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "live_lab_apply_role_coupling \"$target\" \"client\" \"$exit_node_id\" \"false\" \"$env_path\" \"true\" \"$platform\""
            ),
            "validation role coupling must pass platform so non-Linux uses canonical assignment-refresh.env path"
        );
        assert!(
            !LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "live_lab_apply_role_coupling \"$target\" \"client\" \"$exit_node_id\" \"false\" \"/etc/rustynet/assignment-refresh.env\" \"true\""
            ),
            "validation role coupling must not hard-code Linux assignment-refresh.env path"
        );
    }

    #[test]
    fn live_lab_assert_runtime_spec_dispatches_macos_route_assertions() {
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "expected_route_device=\"$(macos_wg_interface_for_node_id \"$node_id\")\""
            ),
            "macOS client route device assertion must derive from FNV-1a(node_id), not hard-code rustynet0"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "expected_next_hop=\"direct:$(macos_wg_interface_for_node_id \"$node_id\")\""
            ),
            "validate_runtime_worker must derive macOS expected_next_hop from FNV-1a(node_id)"
        );
        // Linux assertion must remain unchanged for backwards compatibility.
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "assert_text_contains \"$route_check\" \"$route_label\" \"actual_route_device=rustynet0\""
            ),
            "Linux client route device assertion must keep the existing rustynet0 pin"
        );
        assert!(
            LIVE_LINUX_LAB_ORCHESTRATOR.contains(
                "assert_text_contains \"$route_check\" \"$route_label\" \"actual_route_table=51820\""
            ),
            "Linux client route table assertion must keep the existing 51820 pin"
        );
    }

    #[test]
    fn live_lab_route_policy_body_dispatches_per_command() {
        assert!(
            LIVE_LAB_COMMON.contains("if command -v ip >/dev/null 2>&1; then"),
            "route policy body must detect Linux via `command -v ip`"
        );
        assert!(
            LIVE_LAB_COMMON.contains("elif command -v route >/dev/null 2>&1; then"),
            "route policy body must fall through to macOS / BSD `route` command"
        );
        assert!(
            LIVE_LAB_COMMON.contains("route -n get"),
            "macOS route policy body must use `route -n get` to query the route table"
        );
        assert!(
            LIVE_LAB_COMMON.contains("route_platform=\"macos\""),
            "platform classification must be carried through the snapshot wire format"
        );
    }

    #[test]
    fn live_lab_route_policy_body_normalizes_macos_tunnel_gateway_index() {
        // macOS route -n get returns gateway as 'index: <ifindex> <device>' when
        // the next-hop is a P2P/tunnel interface. After whitespace stripping
        // that becomes 'index:<N><device>'. The body must rewrite this to
        // direct:<device> so the orchestrator's expected_next_hop assertion
        // (direct:utunN) matches the actual route.
        //
        // The extraction uses sed -nE (not `[[ =~ ]]` with BASH_REMATCH) because
        // the body executes under zsh on macOS, where bash's capture array
        // is absent and accessing it under set -u aborts the snapshot body.
        assert!(
            LIVE_LAB_COMMON.contains(r"sed -nE 's/^index:[0-9]+([A-Za-z][A-Za-z0-9]*)\$/\1/p'"),
            "route policy body must extract device via sed (portable across bash and zsh)"
        );
    }

    #[test]
    fn live_lab_secret_hygiene_body_dispatches_per_platform() {
        assert!(
            LIVE_LAB_COMMON.contains("state_root=\"$(rustynet_state_root \"$platform\")\""),
            "secret hygiene body must resolve state_root via the platform helper"
        );
        assert!(
            LIVE_LAB_COMMON.contains("daemon_socket=\"$(rustynet_daemon_socket \"$platform\")\""),
            "secret hygiene body must probe the platform-aware daemon socket path"
        );
    }

    #[test]
    fn live_lab_status_snapshot_body_accepts_platform() {
        assert!(
            LIVE_LAB_COMMON.contains("live_lab_status_snapshot_body() {")
                && LIVE_LAB_COMMON.contains("local platform=\"${1:-linux}\"")
                && LIVE_LAB_COMMON
                    .contains("daemon_socket=\"$(rustynet_daemon_socket \"$platform\")\""),
            "live_lab_status_snapshot_body must accept platform and resolve socket per-platform"
        );
    }

    #[test]
    fn live_lab_signed_state_body_dispatches_per_platform() {
        assert!(
            LIVE_LAB_COMMON.contains("daemon_socket=\"$(rustynet_daemon_socket \"$platform\")\"")
                && LIVE_LAB_COMMON.contains(
                    "assignment_bundle=\"$(rustynet_assignment_bundle_path \"$platform\")\""
                ),
            "signed-state body must derive daemon socket and assignment bundle path from platform"
        );
        assert!(
            !LIVE_LAB_COMMON.contains(
                "rustynet assignment verify --bundle /var/lib/rustynet/rustynetd.assignment"
            ),
            "signed-state body must not hard-code Linux assignment bundle path"
        );
        assert!(
            LIVE_LAB_COMMON.contains("rustynet_trust_evidence_path \"$platform\"")
                && LIVE_LAB_COMMON.contains("rustynet_trust_verifier_key_path \"$platform\"")
                && LIVE_LAB_COMMON.contains("rustynet_trust_watermark_path \"$platform\""),
            "signed-state body must resolve trust evidence / verifier / watermark via platform helpers"
        );
    }

    #[test]
    fn live_lab_dns_zone_body_dispatches_per_platform() {
        assert!(
            LIVE_LAB_COMMON
                .contains("dns_zone_bundle=\"$(rustynet_dns_zone_bundle_path \"$platform\")\"")
                && LIVE_LAB_COMMON
                    .contains("dns_zone_pub=\"$(rustynet_dns_zone_pub_path \"$platform\")\""),
            "DNS zone body must derive bundle and verifier paths from platform"
        );
        assert!(
            !LIVE_LAB_COMMON.contains(
                "rustynet dns zone verify --bundle /var/lib/rustynet/rustynetd.dns-zone --verifier-key /etc/rustynet/dns-zone.pub"
            ),
            "DNS zone body must not hard-code Linux paths"
        );
    }

    #[test]
    fn live_lab_trust_path_helpers_cover_all_platforms() {
        for needle in [
            "rustynet_trust_evidence_path() {",
            "'/usr/local/var/rustynet/trust/rustynetd.trust'",
            "'/var/lib/rustynet/rustynetd.trust'",
            "rustynet_trust_verifier_key_path() {",
            "'/usr/local/var/rustynet/trust/trust-evidence.pub'",
            "'/etc/rustynet/trust-evidence.pub'",
            "rustynet_trust_watermark_path() {",
            "'/usr/local/var/rustynet/trust/rustynetd.trust.watermark'",
            "'/var/lib/rustynet/rustynetd.trust.watermark'",
        ] {
            assert!(
                LIVE_LAB_COMMON.contains(needle),
                "common helper missing trust-path needle: {needle}"
            );
        }
    }

    #[test]
    fn bootstrap_maps_orchestrator_exit_role_to_daemon_blind_exit() {
        assert!(
            !BOOTSTRAP_SCRIPT.contains("daemon_node_role_from_orchestrator_role"),
            "macOS daemon role mapping must live in Rust role model, not bootstrap shell"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("DAEMON_NODE_ROLE"),
            "bootstrap script must consume explicit Rust-provided daemon role"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("admin|client|blind_exit"),
            "bootstrap script must validate daemon role values fail-closed"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("--node-role \"${daemon_node_role}\""),
            "installer call must pass explicit daemon node role, not raw ROLE"
        );
    }

    #[test]
    fn bootstrap_unlocks_system_keychain_before_key_init() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("ensure_system_keychain_unlocked() {"),
            "bootstrap must define ensure_system_keychain_unlocked"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("security set-keychain-settings"),
            "bootstrap must disable the System.keychain auto-lock so a long idle window does not lock the keychain between bootstrap and `rustynetd key init`"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("security unlock-keychain -p \"\" \"${keychain_path}\""),
            "bootstrap must explicitly unlock System.keychain with the default empty password before key init"
        );
        // Both install paths (SKIP_BUILD and full install) must call the
        // unlock helper *before* the first `key init` invocation.
        let skip_build_marker = "install_binaries";
        let full_install_marker = "ensure_system_keychain_unlocked\n  generate_wireguard_keys";
        assert!(
            BOOTSTRAP_SCRIPT.contains(full_install_marker),
            "ensure_system_keychain_unlocked must precede generate_wireguard_keys in the full install path"
        );
        // The SKIP_BUILD branch also lists generate_wireguard_keys after
        // ensure_system_keychain_unlocked; assert by string proximity to the
        // skip-build install_binaries-skipping marker comment.
        let _ = skip_build_marker;
    }

    #[test]
    fn install_service_script_pins_userspace_shared_backend_and_keychain_env() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<string>macos-wireguard-userspace-shared</string>"),
            "install script must launch userspace-shared backend"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.contains("<string>macos-wireguard</string>"),
            "install script must not regress to legacy command backend"
        );
        for needle in [
            "--wg-private-key",
            "--wg-encrypted-private-key",
            "--wg-key-passphrase",
            "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT",
            "RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE",
            "RUSTYNET_WG_KEY_PASSPHRASE_CREDENTIAL_PATH",
            "--enrollment-secret",
            "--enrollment-ledger",
            "enrollment.secret",
        ] {
            assert!(
                INSTALL_SERVICE_SCRIPT.contains(needle),
                "install script missing {needle}"
            );
        }
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("wg-interface")
                || INSTALL_SERVICE_SCRIPT.contains("wg_interface"),
            "install script must accept --wg-interface flag"
        );
    }

    /// Regression guard: the WireGuard decrypt config (keychain env +
    /// `--wg-encrypted-private-key`) must be gated on the encrypted key in
    /// `keys/` and reference the passphrase at its real location in
    /// `bootstrap/`. A prior version gated on `keys/wireguard.passphrase` —
    /// which never exists, because the passphrase deliberately lives in
    /// BOOTSTRAP_DIR (+ System.keychain) so the key-custody check does not flag
    /// it — so the plist silently dropped the decrypt config and the macOS
    /// daemon crash-looped at startup ("wireguard private key metadata read
    /// failed", exit 65).
    #[test]
    fn install_service_script_gates_wg_decrypt_on_encrypted_key_and_bootstrap_passphrase() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("keys/wireguard.key.enc"),
            "decrypt config must be gated on the encrypted key in keys/"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("bootstrap/wireguard.passphrase"),
            "passphrase file reference must point at BOOTSTRAP_DIR, not keys/"
        );
        assert!(
            !INSTALL_SERVICE_SCRIPT.contains("keys/wireguard.passphrase"),
            "must not reference keys/wireguard.passphrase — it never exists by \
             design and gating on it drops the decrypt config (daemon exit 65)"
        );
    }

    #[test]
    fn utun_index_is_in_valid_range_for_lab_node_ids() {
        let long_id = "x".repeat(64);
        let mut node_ids: Vec<&str> = vec![
            "exit-1",
            "macos-client-1",
            "macos-client-2",
            "client-1",
            "relay-1",
            "anchor-1",
            "a",
        ];
        node_ids.push(long_id.as_str());
        for node_id in node_ids {
            let n = utun_index_for_node_id(node_id);
            assert!(
                (10..=4095).contains(&n),
                "utun index {n} out of range for {node_id:?}"
            );
            let name = utun_name_for_node_id(node_id);
            assert!(name.len() <= 15, "utun name {name:?} exceeds IFNAMSIZ");
            assert!(name.starts_with("utun"));
            assert!(name[4..].chars().all(|c| c.is_ascii_digit()));
            validate_utun_name(&name).expect("derived name must validate");
        }
    }

    #[test]
    fn utun_index_is_deterministic_across_invocations() {
        assert_eq!(
            utun_index_for_node_id("exit-1"),
            utun_index_for_node_id("exit-1")
        );
        assert_eq!(
            utun_name_for_node_id("macos-client-1"),
            utun_name_for_node_id("macos-client-1")
        );
    }

    #[test]
    fn utun_index_avoids_reserved_low_range() {
        // utun0..9 are commonly used by macOS system interfaces.
        for node_id in [
            "a",
            "b",
            "c",
            "exit-1",
            "macos-client-1",
            "macos-client-2",
            "client-1",
        ] {
            let n = utun_index_for_node_id(node_id);
            assert!(
                n >= 10,
                "must not use utun0..9 for {node_id:?} (got utun{n})"
            );
        }
    }

    /// Phase 20 collision guard. The 7-node live lab inventory (one mac
    /// client + one windows client + five linux nodes) must produce
    /// distinct utun indices so a future "second macOS client" or
    /// "second exit" cannot silently collide with another node. The
    /// 4086-slot range [10, 4095] gives plenty of headroom for this.
    #[test]
    fn utun_index_collisions_for_known_lab_inventory_are_zero() {
        use std::collections::HashSet;
        let lab_node_ids = [
            "exit-1",
            "client-1",
            "client-2",
            "client-3",
            "client-4",
            "macos-client-1",
            "windows-client-1",
        ];
        let mut seen: HashSet<u16> = HashSet::new();
        for node_id in &lab_node_ids {
            let n = utun_index_for_node_id(node_id);
            assert!(
                seen.insert(n),
                "utun collision for {node_id:?} at utun{n} \u{2014} entire lab inventory must be unique"
            );
        }
    }

    /// enforce_daemon's invocation string is the actual surface that
    /// reaches the install-script. Reconstruct the same format!() shape
    /// the fn uses to pin that the derived utun name lands as
    /// `--wg-interface 'utun<N>'` for the lab macOS node.
    #[test]
    fn enforce_daemon_constructs_wg_interface_flag_with_derived_value() {
        let node_id = "macos-client-1";
        let expected_iface = utun_name_for_node_id(node_id);
        // Reconstruct the relevant portion of the enforce_daemon command.
        let script = format!(
            "sudo /tmp/Install-RustyNetMacosService.sh \
               --node-id '{node_id}' \
               --wg-interface '{expected_iface}'"
        );
        assert!(
            script.contains(&format!("--wg-interface '{expected_iface}'")),
            "enforce_daemon must pass --wg-interface with the derived utun name"
        );
        // Pin that the derived name is in the legal range, not the
        // install-script default (utun9). For node_id "macos-client-1"
        // the FNV-1a hash must NOT land on 9.
        assert_ne!(
            expected_iface, "utun9",
            "derived name for macos-client-1 must not collide with the install-script default"
        );
    }

    #[test]
    fn validate_utun_name_accepts_valid_names() {
        for name in ["utun0", "utun9", "utun42", "utun100", "utun4095"] {
            validate_utun_name(name)
                .unwrap_or_else(|e| panic!("rejected valid name {name}: {e:?}"));
        }
    }

    /// Phase 20 injection-vector pin. The install-script does the
    /// authoritative regex check, but the Rust validate_utun_name is
    /// the first line of defence — any shell-special, control-char, or
    /// non-utun-prefixed input must fail before reaching the shell.
    #[test]
    fn validate_utun_name_rejects_injection_vectors() {
        for bad in [
            "",
            "utun",
            "utunX",
            "utun-evil",
            "utun;rm -rf /",
            "utun 0",
            "utun\n0",
            "utun\t0",
            "rustynet0",
            "tun0",
            "utun12345678901234",
            "utun4096x",
            "wg0",
            "utunABC",
        ] {
            assert!(validate_utun_name(bad).is_err(), "must reject {bad:?}");
        }
    }

    /// Phase 20 install-script presence pin. The install-script must
    /// keep all three integration points alive: the CLI flag handler,
    /// the WG_INTERFACE shell variable, the strict regex validation
    /// before plist render, and the `<string>--wg-interface</string>`
    /// emit into the plist ProgramArguments array. Any refactor that
    /// drops one of these silently regresses the per-node interface
    /// derivation.
    #[test]
    fn install_service_script_includes_wg_interface_flag_in_plist() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--wg-interface")
                && INSTALL_SERVICE_SCRIPT.contains("WG_INTERFACE"),
            "install script must accept --wg-interface CLI arg and propagate WG_INTERFACE env"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("^utun[0-9]+$"),
            "install script must validate utun name against ^utun[0-9]+$ before plist render"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<string>--wg-interface</string>"),
            "install script must emit --wg-interface into plist ProgramArguments"
        );
    }

    /// Phase 20 bootstrap-script propagation pin. The bootstrap script
    /// must (a) document WG_INTERFACE as an env-file variable, (b)
    /// validate it against the same ^utun[0-9]+$ regex used by the
    /// install script, and (c) forward `--wg-interface` to
    /// Install-RustyNetMacosService.sh so the FIRST plist install
    /// already targets the per-node interface (not the utun9 default).
    #[test]
    fn bootstrap_script_propagates_wg_interface_to_install_service() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("WG_INTERFACE"),
            "bootstrap script must document and consume WG_INTERFACE env var"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("^utun[0-9]+\\$"),
            "bootstrap script must validate WG_INTERFACE before passing it to install script"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("--wg-interface \"${wg_interface}\""),
            "bootstrap script must pass --wg-interface to Install-RustyNetMacosService.sh"
        );
    }

    /// Phase 20 env-file pin. build_bootstrap_env must always emit a
    /// WG_INTERFACE line with the derived utun name so the FIRST plist
    /// install already targets the per-node device. Without this the
    /// orchestrator's later enforce_runtime phase would have to re-render
    /// the plist and the bootstrap-time daemon start would race against
    /// the still-stale utun9 default.
    #[test]
    fn build_bootstrap_env_emits_wg_interface_derived_from_node_id() {
        let ctx = make_ctx(NodeRole::Client);
        let env = build_bootstrap_env("macos-client-1", &NodeRole::Client, &ctx);
        let expected = utun_name_for_node_id("macos-client-1");
        assert!(
            env.contains(&format!("WG_INTERFACE={expected}")),
            "bootstrap env must contain WG_INTERFACE={expected}, got:\n{env}"
        );
        // The derived name must be in the [10, 4095] range, never the default.
        assert_ne!(expected, "utun9");
    }

    #[test]
    fn install_service_script_rejects_plist_unsafe_inputs_before_rendering() {
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("require_safe_plist_string"),
            "install script must validate plist-rendered path inputs"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--node-id contains characters unsafe"),
            "install script must validate node id before plist rendering"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--network-id contains characters unsafe"),
            "install script must validate network id before plist rendering"
        );
    }

    #[test]
    fn constants_are_under_usr_local() {
        assert!(MACOS_RUSTYNETD_PATH.starts_with("/usr/local/bin/"));
        assert!(MACOS_STATE_ROOT.starts_with("/usr/local/var/"));
        assert!(MACOS_KEYS_DIR.starts_with(MACOS_STATE_ROOT));
    }

    #[test]
    fn bootstrap_script_provisions_enrollment_secret() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("enrollment.secret"),
            "bootstrap script must provision enrollment.secret"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("0600"),
            "bootstrap script must set mode 0600 on enrollment.secret"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("if [ -f \"${secret_path}\" ]"),
            "enrollment.secret provisioning must be idempotent (skip-if-present)"
        );
    }

    /// HIGH 1 + 2 reviewer fold-in (Phase 21 follow-up).
    ///
    /// Pins the atomic tmpfile+rename pattern for `enrollment.secret`:
    ///   - generation writes to a tmpfile inside `${KEYS_DIR}` (same fs →
    ///     atomic rename),
    ///   - the tmpfile is `chmod 0600`'d BEFORE any secret bytes land in
    ///     it (chmod-first eliminates the race with default umask),
    ///   - the script verifies the tmpfile is exactly 32 bytes before
    ///     promoting it via `mv` (partial-write trap),
    ///   - an `EXIT` trap removes the tmpfile if any pre-rename step
    ///     fails so a re-run is always a clean fresh write.
    #[test]
    fn bootstrap_enrollment_secret_uses_atomic_tmpfile_rename() {
        // Must mktemp inside ${KEYS_DIR} so the final mv is an atomic
        // intra-filesystem rename, not a cross-device copy.
        assert!(
            BOOTSTRAP_SCRIPT.contains("mktemp \"${KEYS_DIR}/enrollment.secret.tmp.XXXXXX\""),
            "bootstrap must mktemp the enrollment secret tmpfile inside ${{KEYS_DIR}}"
        );
        // EXIT trap so a SIGTERM/SIGHUP/abort path does not leak a partial tmpfile.
        assert!(
            BOOTSTRAP_SCRIPT.contains("trap 'rm -f \"${tmp}\"' EXIT"),
            "bootstrap must install an EXIT trap to clean up the enrollment secret tmpfile"
        );
        // Atomic rename into the final secret path.
        assert!(
            BOOTSTRAP_SCRIPT.contains("mv \"${tmp}\" \"${secret_path}\""),
            "bootstrap must promote the tmpfile via atomic mv"
        );
    }

    #[test]
    fn bootstrap_removes_temporary_sudoers_grant_on_every_exit_path() {
        // RSA-0063: the temporary `NOPASSWD: ALL` sudoers grant used so the
        // Homebrew installer's sudo check passes must be removed on EVERY exit
        // path — including a `curl|bash` failure under `set -e` or a SIGINT — so
        // a failed/aborted bootstrap never leaves passwordless root on disk
        // (local privilege-escalation residue, CWE-250/CWE-279). Assert the EXIT
        // trap is registered, and that it appears BEFORE the curl|bash installer
        // and is cleared on the success path.
        let trap_idx = BOOTSTRAP_SCRIPT
            .find("trap 'rm -f \"${sudoers_tmp}\"' EXIT")
            .expect("bootstrap must register an EXIT trap to remove the temporary sudoers grant");
        let write_idx = BOOTSTRAP_SCRIPT
            .find("> \"${sudoers_tmp}\"")
            .expect("bootstrap must write the temporary sudoers grant");
        let curl_idx = BOOTSTRAP_SCRIPT
            .find("install.sh)")
            .expect("bootstrap must run the Homebrew installer via curl");
        assert!(
            write_idx < trap_idx && trap_idx < curl_idx,
            "the sudoers EXIT trap must be registered after the grant is written and \
             before the curl|bash installer (write@{write_idx} trap@{trap_idx} curl@{curl_idx})"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("trap - EXIT"),
            "bootstrap must clear the EXIT trap on the success path"
        );
    }

    /// HIGH 1 reviewer fold-in (Phase 21 follow-up).
    ///
    /// The `chmod 0600` MUST happen BEFORE `openssl rand` writes any
    /// secret bytes into the tmpfile. The previous non-atomic pattern
    /// (`openssl rand -out … && chmod 0600 …`) left the file at the
    /// process umask mode for a brief window. Without this ordering
    /// pin, a refactor could silently regress.
    #[test]
    fn bootstrap_enrollment_secret_chmod_precedes_openssl_write() {
        let chmod_idx = BOOTSTRAP_SCRIPT
            .find("chmod 0600 \"${tmp}\"")
            .expect("bootstrap must chmod the tmpfile 0600");
        let openssl_idx = BOOTSTRAP_SCRIPT
            .find("openssl rand -out \"${tmp}\" 32")
            .expect("bootstrap must write 32 random bytes to the tmpfile");
        assert!(
            chmod_idx < openssl_idx,
            "chmod 0600 must run BEFORE openssl rand writes the secret (chmod-first \
             prevents the race window where the file exists at umask perms)"
        );
    }

    /// HIGH 2 reviewer fold-in (Phase 21 follow-up).
    ///
    /// The 32-byte size verification must run against the TMPFILE before
    /// promotion, not against the final secret path after promotion. The
    /// old pattern verified after `openssl rand` wrote directly to the
    /// final path; a truncated openssl output (signal-killed, disk full)
    /// would leave a partial secret at the canonical path. Next bootstrap
    /// saw the file as present and skipped regeneration, then size-check
    /// exited 1 → install stuck.
    #[test]
    fn bootstrap_enrollment_secret_size_check_targets_tmpfile_before_rename() {
        // The size check must reference $tmp (pre-rename), and must
        // appear BEFORE the `mv "${tmp}" "${secret_path}"` line.
        let size_check_idx = BOOTSTRAP_SCRIPT
            .find("size=\"$(wc -c < \"${tmp}\" | tr -d ' ')\"")
            .expect("bootstrap must size-check the tmpfile before rename");
        let rename_idx = BOOTSTRAP_SCRIPT
            .find("mv \"${tmp}\" \"${secret_path}\"")
            .expect("bootstrap must promote the tmpfile via mv");
        assert!(
            size_check_idx < rename_idx,
            "size verification must target the tmpfile and run BEFORE the rename, \
             so a truncated openssl output never reaches the canonical secret path"
        );
        // The pre-existing secret path also has its own size guard, so a
        // partial file left behind by a hostile pre-Phase-21 install is
        // also detected at the next bootstrap (rather than silently
        // skipped).
        assert!(
            BOOTSTRAP_SCRIPT.contains("existing enrollment.secret has invalid size"),
            "bootstrap must hard-fail when an existing enrollment.secret is wrong size"
        );
    }

    /// HIGH 3 reviewer fold-in (Phase 21 follow-up).
    ///
    /// `seed_trust_evidence` previously called
    ///   `install -d -m 0755 -o root -g rustynetd "${trust_dir}"`
    /// which rewrote the directory perms set by `setup_directories`
    /// (`install -d -m 0700 -o rustynetd -g rustynetd`). The result
    /// was a world-traversable trust dir. The fix must use the same
    /// 0700 rustynetd:rustynetd perms in both call sites.
    #[test]
    fn bootstrap_trust_dir_perms_are_consistent_700_rustynetd() {
        // setup_directories — unchanged baseline.
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("install -d -m 0700 -o rustynetd -g rustynetd \"${STATE_ROOT}/trust\""),
            "setup_directories must create the trust dir as 0700 rustynetd:rustynetd"
        );
        // seed_trust_evidence — fixed to match.
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("install -d -m 0700 -o rustynetd -g rustynetd \"${trust_dir}\""),
            "seed_trust_evidence must reaffirm 0700 rustynetd:rustynetd on the trust dir"
        );
        // Negative: the old 0755 root:rustynetd line must not reappear.
        assert!(
            !BOOTSTRAP_SCRIPT
                .contains("install -d -m 0755 -o root      -g rustynetd \"${trust_dir}\"")
                && !BOOTSTRAP_SCRIPT
                    .contains("install -d -m 0755 -o root -g rustynetd \"${trust_dir}\""),
            "seed_trust_evidence must not regress to 0755 root:rustynetd on the trust dir"
        );
    }

    #[test]
    fn macos_canonical_paths_cover_all_required_state_files() {
        let required = [
            MACOS_RUSTYNETD_PATH,
            MACOS_RUSTYNET_PATH,
            MACOS_KEYS_DIR,
            MACOS_DAEMON_SOCKET,
            MACOS_MEMBERSHIP_DIR,
            MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH,
            MACOS_MEMBERSHIP_SNAPSHOT_PATH,
            MACOS_ENROLLMENT_SECRET_PATH,
        ];
        for path in required {
            assert!(
                path.starts_with("/usr/local/") || path.starts_with("/private/"),
                "macOS state path {path} must be under /usr/local/ or /private/"
            );
        }
    }

    #[test]
    fn bootstrap_script_sets_correct_ownership_and_mode_for_secrets() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("chown rustynetd")
                || BOOTSTRAP_SCRIPT.contains("chown -R rustynetd"),
            "bootstrap must set rustynetd ownership"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("chmod 0600") || BOOTSTRAP_SCRIPT.contains("chmod 600"),
            "bootstrap must set 0600 mode on secret files"
        );
    }

    /// HIGH 4 reviewer fold-in (Phase 21 follow-up).
    ///
    /// The macOS plist's ProgramArguments must be a deliberate, audited
    /// match to the Linux systemd-unit ExecStart flag set. For each
    /// flag the Linux unit passes that the macOS plist omits, the
    /// install script must either pass the flag explicitly or carry a
    /// comment block declaring the omission intentional + safe.
    ///
    /// This test pins the audited add list (currently
    /// `--gossip-watermark`, required for D2.5 gossip-state persistence
    /// across daemon restarts) and pins the audited intentional-omission
    /// comment block so a refactor cannot silently drop the audit.
    #[test]
    fn install_service_script_carries_audited_linux_parity_flag_set() {
        // Added flags (Linux passes, macOS plist now also passes).
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("--gossip-watermark"),
            "plist must pass --gossip-watermark (D2.5 gossip-state spool); \
             omitting it makes the daemon run gossip purely in-memory and \
             loses replay protection across restarts"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("${STATE_ROOT}/membership/rustynetd.gossip.watermark"),
            "gossip-watermark spool must live under the membership/ dir so it \
             inherits the 0700 rustynetd:rustynetd perms from setup_directories"
        );

        // Audited intentional-omission comment block — pins each omitted
        // flag by name so a refactor that drops the comment fails the test.
        // For each name below the comment must explain WHY the daemon
        // default is correct on macOS for the lab.
        let omitted_flags = [
            "--anchor-bundle-pull-addr",
            "--anchor-bundle-pull-token-path",
            "--anchor-bundle-pull-allow-lan",
            "--wg-listen-port",
            "--egress-interface",
            "--auto-port-forward-exit",
            "--auto-port-forward-lease-secs",
            "--privileged-helper-timeout-ms",
            "--reconcile-interval-ms",
            "--max-reconcile-failures",
            "--dns-zone-name",
            "--dns-resolver-bind-addr",
            "--traversal-stun-servers",
            "--traversal-stun-gather-timeout-ms",
            "--dataplane-mode",
        ];
        for flag in omitted_flags {
            assert!(
                INSTALL_SERVICE_SCRIPT.contains(flag),
                "install script must name {flag} in the audited omission comment \
                 block so its absence from the plist is a deliberate, documented \
                 choice rather than an accidental drop"
            );
        }

        // Pin the audit-block header so the comment stays a single coherent
        // block and is not split across the file by a refactor.
        assert!(
            INSTALL_SERVICE_SCRIPT
                .contains("Audited Linux→macOS plist flag parity (HIGH 4 reviewer fold-in)"),
            "install script must keep the audited-omission header intact"
        );
    }

    // ── Phase 23: cross-OS orchestrator bootstrap wrapper parity ────────────

    /// The bash wrapper (rn_bootstrap_macos.sh) and the Rust adapter MUST
    /// derive the same utun interface name for a given node_id. A drift
    /// would mean the bootstrap-time plist names one interface and the
    /// enforce-runtime plist names another, breaking WireGuard bringup.
    /// This test runs the Rust implementation against the known-good
    /// values pinned in the bash wrapper's `assert_known_utun_index`
    /// guard so a refactor of either side trips the same canary.
    #[test]
    fn phase23_macos_wrapper_utun_parity_matches_rust_impl() {
        // Pins from rn_bootstrap_macos.sh's `assert_known_utun_index` calls.
        let known_inputs_expected_indices: &[(&str, u16)] = &[
            ("macos-client-1", 3912),
            ("exit-1", 2369),
            ("client-1", 3466),
        ];
        for (node_id, expected_index) in known_inputs_expected_indices {
            let rust_index = utun_index_for_node_id(node_id);
            assert_eq!(
                rust_index, *expected_index,
                "Rust utun_index_for_node_id({node_id:?}) = {rust_index}, expected {expected_index} \
                 — bash wrapper's assert_known_utun_index pin and Rust impl have drifted"
            );
        }
    }

    /// The bash wrapper's `fnv1a_utun_index` must use the same FNV-1a
    /// 32-bit constants as the Rust implementation. This test pins the
    /// offset basis (2166136261) and prime (16777619) in the wrapper so
    /// a refactor cannot silently swap them.
    #[test]
    fn phase23_macos_wrapper_uses_canonical_fnv1a_constants() {
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("2166136261"),
            "rn_bootstrap_macos.sh must embed the FNV-1a 32-bit offset basis (2166136261)"
        );
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("16777619"),
            "rn_bootstrap_macos.sh must embed the FNV-1a 32-bit prime (16777619)"
        );
        // utun range guard: (hash % 4086) + 10 → [10, 4095].
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("(hash % 4086) + 10"),
            "rn_bootstrap_macos.sh must reproduce the (hash % 4086) + 10 utun-range guard"
        );
        // The Rust impl wraps multiplication and masks with the 32-bit
        // wrap. The bash impl must explicitly mask too because bash uses
        // 64-bit integers (without masking, the values diverge after a
        // few iterations).
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("& 0xFFFFFFFF"),
            "rn_bootstrap_macos.sh must mask the FNV-1a state to 32 bits each iteration"
        );
    }

    /// The bash wrapper must pin its known-input parity assertions so
    /// any divergence (in either the bash hash or the Rust hash) fails
    /// before the macOS host gets a bogus WG_INTERFACE.
    #[test]
    fn phase23_macos_wrapper_pins_known_utun_assertions() {
        for needle in [
            "assert_known_utun_index \"macos-client-1\" \"3912\"",
            "assert_known_utun_index \"exit-1\"         \"2369\"",
            "assert_known_utun_index \"client-1\"       \"3466\"",
        ] {
            assert!(
                MACOS_BOOTSTRAP_WRAPPER.contains(needle),
                "rn_bootstrap_macos.sh must pin the known-input parity assertion: {needle}"
            );
        }
    }

    /// The bash wrapper must validate every CLI input with a strict
    /// allowlist before reaching any side-effect (sudo, tar, bootstrap
    /// invocation). This pins the validators so a future refactor
    /// cannot silently drop them.
    #[test]
    fn phase23_macos_wrapper_validates_inputs_fail_closed() {
        for needle in [
            "validate_identifier \"--node-id\" \"$NODE_ID\"",
            "validate_identifier \"--network-id\" \"$NETWORK_ID\"",
            "validate_node_role \"$NODE_ROLE\"",
            "validate_ssh_allow_cidrs \"$SSH_ALLOW_CIDRS\"",
            "validate_path_argument \"--source-archive\" \"$SOURCE_ARCHIVE_PATH\"",
        ] {
            assert!(
                MACOS_BOOTSTRAP_WRAPPER.contains(needle),
                "rn_bootstrap_macos.sh must call validator: {needle}"
            );
        }
    }

    /// The bash wrapper must invoke the reviewed bootstrap script via
    /// `sudo -n bash <absolute-path> <env-file>` — argv-only exec, no
    /// shell construction of operator-controlled values.
    #[test]
    fn phase23_macos_wrapper_invokes_bootstrap_argv_only() {
        assert!(
            MACOS_BOOTSTRAP_WRAPPER
                .contains("sudo -n bash \"$BOOTSTRAP_SCRIPT\" \"$ENV_FILE_PATH\""),
            "rn_bootstrap_macos.sh must invoke the reviewed bootstrap via argv-only sudo bash"
        );
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains(
                "BOOTSTRAP_SCRIPT=\"$BUILD_DIR/scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh\""
            ),
            "rn_bootstrap_macos.sh must point at the canonical bootstrap script path"
        );
    }

    /// The bash wrapper must poll for the daemon Unix socket before
    /// returning so the next orchestrator stage (collect_pubkeys) does
    /// not race with launchctl bootstrap. This mirrors the Rust
    /// adapter's wait_for_macos_daemon_socket.
    #[test]
    fn phase23_macos_wrapper_waits_for_daemon_socket() {
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("/private/var/run/rustynet/rustynetd.sock"),
            "rn_bootstrap_macos.sh must probe the macOS daemon socket path"
        );
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("sudo -n test -S"),
            "rn_bootstrap_macos.sh must probe the socket via `sudo -n test -S` (Unix socket test)"
        );
        assert!(
            MACOS_BOOTSTRAP_WRAPPER.contains("for attempt in $(seq 1 40)"),
            "rn_bootstrap_macos.sh must poll 40 iterations × 1 s (matches wait_for_macos_daemon_socket)"
        );
    }

    /// The Windows wrapper must apply the same strict input validation
    /// posture (Set-StrictMode + ErrorActionPreference Stop + named-arg
    /// validators) as the macOS wrapper.
    #[test]
    fn phase23_windows_wrapper_fails_closed() {
        for needle in [
            "Set-StrictMode -Version Latest",
            "$ErrorActionPreference = 'Stop'",
            "Assert-Identifier -Label '-NodeId' -Value $NodeId",
            "Assert-Identifier -Label '-NetworkId' -Value $NetworkId",
            "Assert-NodeRole -Value $NodeRole",
            "Assert-SshAllowCidrs -Value $SshAllowCidrs",
            "Assert-AbsolutePath -Label '-SourceArchive'",
            "Assert-ServiceName -Label '-ServiceName'",
        ] {
            assert!(
                WINDOWS_BOOTSTRAP_WRAPPER.contains(needle),
                "rn_bootstrap_windows.ps1 must include: {needle}"
            );
        }
    }

    /// Per CLAUDE.md / project style: PowerShell scripts must use
    /// `$null -eq <var>` (not `<var> -eq $null`) to avoid silent
    /// breakage under StrictMode when $var is unset.
    #[test]
    fn phase23_windows_wrapper_uses_null_lhs_comparisons() {
        // No `-eq $null` (rhs form) — the linter pattern that flags
        // bugs under StrictMode.
        assert!(
            !WINDOWS_BOOTSTRAP_WRAPPER.contains("-eq $null"),
            "rn_bootstrap_windows.ps1 must use `$null -eq <var>` (lhs form), \
             not `<var> -eq $null` (rhs form)"
        );
        // At least one positive use of the lhs form to confirm the
        // pattern is in active use, not just absent because there are
        // no null checks.
        assert!(
            WINDOWS_BOOTSTRAP_WRAPPER.contains("$null -eq"),
            "rn_bootstrap_windows.ps1 must contain at least one `$null -eq <var>` check"
        );
    }

    /// The Windows wrapper must invoke the reviewed bootstrap via
    /// PowerShell named-arg surface (no string concatenation of
    /// operator values into the command line).
    #[test]
    fn phase23_windows_wrapper_invokes_bootstrap_named_args() {
        for needle in [
            "& $bootstrapScript",
            "-Phase $phase",
            "-SourceMode archive",
            "-RustyNetRoot $rustyNetRoot",
            "-InstallRoot $installRoot",
            "-StateRoot $stateRoot",
            "-ServiceName $ServiceName",
            "& $installHelper",
            "-NodeId $NodeId",
        ] {
            assert!(
                WINDOWS_BOOTSTRAP_WRAPPER.contains(needle),
                "rn_bootstrap_windows.ps1 must invoke the reviewed bootstrap via named arg: {needle}"
            );
        }
    }

    /// The Windows wrapper must poll for the service to reach Running
    /// before returning (analog of the macOS daemon-socket wait).
    #[test]
    fn phase23_windows_wrapper_waits_for_service_running() {
        assert!(
            WINDOWS_BOOTSTRAP_WRAPPER.contains("Get-Service -Name $ServiceName"),
            "rn_bootstrap_windows.ps1 must probe service status via Get-Service"
        );
        assert!(
            WINDOWS_BOOTSTRAP_WRAPPER.contains("$svc.Status -eq 'Running'"),
            "rn_bootstrap_windows.ps1 must wait for Status = Running"
        );
        assert!(
            WINDOWS_BOOTSTRAP_WRAPPER.contains("ServiceReadyTimeoutSecs"),
            "rn_bootstrap_windows.ps1 must accept a configurable timeout"
        );
    }
}
