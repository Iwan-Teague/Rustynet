#![allow(dead_code)]
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::adapter::verifier_key::decode_assignment_pubkey_hex;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;
use crate::vm_lab::orchestrator::stage::host_cross_build;

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
/// Privileged-helper launchd label (`Install-RustyNetMacosService.sh`).
pub const MACOS_PRIVILEGED_HELPER_LABEL: &str = "com.rustynet.privileged-helper";
/// Where `Install-RustyNetMacosService.sh` installs the helper plist
/// (`HELPER_PLIST_DST`): the bootstrap source for the S2b liveness restore.
pub const MACOS_PRIVILEGED_HELPER_PLIST: &str =
    "/Library/LaunchDaemons/com.rustynet.privileged-helper.plist";
/// The privileged-helper socket the daemon's shutdown rollback dials
/// (`PRIVILEGED_HELPER_SOCKET` in `Install-RustyNetMacosService.sh`).
pub const MACOS_PRIVILEGED_HELPER_SOCKET: &str =
    "/private/var/run/rustynet/rustynetd-privileged.sock";
pub const MACOS_MEMBERSHIP_DIR: &str = "/usr/local/var/rustynet/membership";
/// Owner SIGNING (private) key path on macOS. Mirrors
/// `ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH`: the macOS genesis driver
/// (`execute_ops_e2e_bootstrap_macos`, run by `ops e2e-bootstrap-host`
/// during lab bootstrap) passes this as `rustynetd membership init
/// --owner-signing-key`, and `run_membership_init` persists the encrypted
/// private key exactly here.
pub const MACOS_OWNER_SIGNING_KEY_PATH: &str = "/usr/local/etc/rustynet/membership.owner.key";
/// Owner PUBLIC key path on macOS. `rustynetd membership init` writes the
/// public key alongside the private key at `{owner_signing_key_path}.pub`,
/// so with [`MACOS_OWNER_SIGNING_KEY_PATH`] the seeded location is
/// `/usr/local/etc/rustynet/membership.owner.key.pub`. The membership
/// reader (`macos_membership::issue_membership_owner_key`) must read
/// exactly where genesis writes — a key placed anywhere else (e.g. the
/// Linux-conventional `/etc/rustynet/...`, or a STATE_ROOT guess) is a
/// hand-seeded leftover, not install provenance.
pub const MACOS_MEMBERSHIP_OWNER_PUBKEY_PATH: &str =
    "/usr/local/etc/rustynet/membership.owner.key.pub";
pub const MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";
pub const MACOS_ENROLLMENT_SECRET_PATH: &str = "/usr/local/var/rustynet/keys/enrollment.secret";

static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh");
static INSTALL_SERVICE_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/macos/Install-RustyNetMacosService.sh");
// Phase 23 orchestrator-side wrappers (per-OS dispatch from
// the retired bash orchestrator's bootstrap_host_worker). Compiled
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
static LIVE_LAB_COMMON: &str = include_str!("../../../../../../scripts/e2e/live_lab_common.sh");

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const BUILD_TIMEOUT: Duration = Duration::from_secs(1800);
const SOCKET_TIMEOUT: Duration = Duration::from_secs(300);
const SUDO_N: &str = "sudo -n";

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
    // host-cross-binary: if the orchestrator wrote a prebuilt-binary manifest for
    // this node, ship those binaries (same-triple aarch64-apple-darwin, plain
    // cargo — no zig) and tell the bootstrap to install them instead of building.
    // Absent manifest = normal build-on-guest run, unchanged.
    let prebuilt_binaries = host_cross_build::read_host_cross_binaries(&ctx.report_dir, alias)
        .map_err(|message| AdapterError::Protocol { message })?;
    let mut env_content = build_bootstrap_env(&node_id, &role, ctx)?;
    if prebuilt_binaries.is_some() {
        env_content.push_str("\nRN_PREBUILT_BINARIES=1\nRN_PREBUILT_DIR=/tmp/rn_prebuilt\n");
    }
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
    // The source archive is bulk data; SHORT_TIMEOUT (sized for tiny script
    // files) timed the equivalent Linux transfer out cross-LAN. Use the build
    // budget for the bulk copy, mirroring the second install site below.
    ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", BUILD_TIMEOUT)?;

    // host-cross: ship the host-built binaries so the bootstrap stages them into
    // the build dir and skips the guest build. Names preserved (rustynetd /
    // rustynet-cli / rustynet-relay), matching Bootstrap-RustyNetMacos.sh's
    // RN_PREBUILT_DIR staging.
    if let Some(binaries) = &prebuilt_binaries {
        let mkdir = ssh::RemoteCommand::from_args(
            "host-cross prebuilt dir",
            &[
                ValidatedArg::cli_token("mkdir")?,
                ValidatedArg::cli_token("-p")?,
                ValidatedArg::path("/tmp/rn_prebuilt")?,
            ],
        )?;
        ssh::run_remote(conn, mkdir.as_str(), SHORT_TIMEOUT)?;
        for bin in binaries {
            let name =
                bin.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| AdapterError::Protocol {
                        message: format!(
                            "host-cross: prebuilt binary path has no filename: {}",
                            bin.display()
                        ),
                    })?;
            ssh::scp_to(
                conn,
                bin.as_path(),
                &format!("/tmp/rn_prebuilt/{name}"),
                BUILD_TIMEOUT,
            )?;
        }
        eprintln!(
            "[host-cross] {alias}: shipped {} prebuilt binaries to /tmp/rn_prebuilt",
            binaries.len()
        );
    }

    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&install_tmp);
    let _ = std::fs::remove_file(&env_tmp);

    ssh::run_remote(
        conn,
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
         sudo -n bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env",
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

    // host-cross-binary: same as install_daemon — ship prebuilts + flag the
    // bootstrap to skip the build. This is the path macOS nodes with a configured
    // workdir (rustynet_src_dir) actually take.
    let prebuilt_binaries = host_cross_build::read_host_cross_binaries(&ctx.report_dir, alias)
        .map_err(|message| AdapterError::Protocol { message })?;
    let mut env_content = build_bootstrap_env(&node_id, &role, ctx)?;
    if prebuilt_binaries.is_some() {
        env_content.push_str("\nRN_PREBUILT_BINARIES=1\nRN_PREBUILT_DIR=/tmp/rn_prebuilt\n");
    }
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

    // host-cross: ship the host-built binaries so the bootstrap stages them and
    // skips the guest build (the workdir path macOS nodes take).
    if let Some(binaries) = &prebuilt_binaries {
        let mkdir = ssh::RemoteCommand::from_args(
            "host-cross prebuilt dir",
            &[
                ValidatedArg::cli_token("mkdir")?,
                ValidatedArg::cli_token("-p")?,
                ValidatedArg::path("/tmp/rn_prebuilt")?,
            ],
        )?;
        ssh::run_remote(conn, mkdir.as_str(), SHORT_TIMEOUT)?;
        for bin in binaries {
            let name =
                bin.file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| AdapterError::Protocol {
                        message: format!(
                            "host-cross: prebuilt binary path has no filename: {}",
                            bin.display()
                        ),
                    })?;
            ssh::scp_to(
                conn,
                bin.as_path(),
                &format!("/tmp/rn_prebuilt/{name}"),
                BUILD_TIMEOUT,
            )?;
        }
        eprintln!(
            "[host-cross] {alias}: shipped {} prebuilt binaries to /tmp/rn_prebuilt",
            binaries.len()
        );
    }

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
    // QH-01 Step 4c: argv-shaped probe rendered through the validated seam.
    let workdir_args = vec![
        ValidatedArg::cli_token("test")?,
        ValidatedArg::cli_token("-d")?,
        ValidatedArg::path(workdir)?,
    ];
    let workdir_script = ssh::RemoteCommand::from_args("macos workdir probe", &workdir_args)?;
    let workdir_present = ssh::run_remote(conn, workdir_script.as_str(), SHORT_TIMEOUT).is_ok();

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
             sudo -n bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
    } else if workdir_present {
        // No fresh archive carried, but a workdir exists (e.g. an operator
        // manually synced it). Build from it.
        format!(
            "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             cd '{workdir}' && tar -czf /tmp/rn_source.tar.gz . && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo -n bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
        )
    } else {
        // No workdir AND no source — last-resort legacy path: rely on
        // SKIP_BUILD=1 so the bootstrap re-runs the service-install
        // phase against whatever binary is already on disk.
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SKIP_BUILD=1' >> /tmp/rn_macos_bootstrap.env && \
             echo 'SOURCE_ARCHIVE=/dev/null' >> /tmp/rn_macos_bootstrap.env && \
             sudo -n bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
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

/// Wait until the remote macOS daemon is LIVE — i.e. it answers on its control
/// socket with its own identity — after a launchd bootstrap or plist reload.
/// Used by install_daemon, install_daemon_from_workdir and the enforce path to
/// bridge the gap between launchctl returning and the daemon actually serving.
///
/// PROVES LIVENESS, NOT EXISTENCE. This previously probed `test -S <socket>`,
/// which asks only whether the path is an `S_IFSOCK` inode. That is not a
/// readiness signal here, for a reason that makes it fail every time rather
/// than occasionally: **rustynetd does not unlink its socket on shutdown**, so
/// after any successful first start the inode survives every subsequent
/// restart-in-place. `test -S` was therefore satisfied by the DEAD
/// predecessor's socket and the wait returned immediately.
///
/// Measured on `macos-utm-1`, run `percontrol-rebaseline-20260811`: the plist
/// reload booted the daemon out at 08:01:18Z, launchd respawned it at
/// 08:01:20Z, and it bound its socket at 08:01:26Z (socket inode birth-time) —
/// but this wait had already returned, so `dns_failclosed_validation` probed at
/// 08:01:24Z and got `ECONNREFUSED`, taking nine dependent stages down with it.
/// `ECONNREFUSED` rather than `ENOENT` is itself the tell: the path existed and
/// nothing was listening.
///
/// The probe now runs the same query the §4.7 identity challenge uses
/// (`rustynet status` over the control socket, see
/// `macos_traffic::query_live_identity`) and additionally requires a parseable
/// `node_id`, so the gate proves exactly what the next stage will demand —
/// a daemon that answers and knows who it is — rather than a weaker proxy for
/// it. A socket that exists but refuses, or answers without an identity, is
/// NOT ready.
///
/// Probe in short bursts over SEPARATE SSH connections rather than one long
/// connection. The daemon perturbs the host network as it comes up (binding the
/// userspace-shared utun, reconcile touching routes), which can drop a single
/// in-flight SSH session (observed: bootstrap_hosts failing with ssh `exit 255`
/// even though the daemon was healthy). Re-establishing the connection each
/// burst means one transient drop no longer fails the whole wait. ~8 bursts ×
/// (8 s probe + 2 s pause) ≈ 80 s budget, comfortably longer than the observed
/// ~6 s bind and than the 10-30 s worst case this path was written for.
/// Marker the in-guest probe echoes once `rustynet status` has exited 0.
const DAEMON_LIVE_MARKER: &str = "daemon-live";

/// Whether a readiness-probe transcript proves the daemon is LIVE.
///
/// Two conditions, both required. The marker alone proves only that `rustynet
/// status` exited 0; the parseable `node_id` proves the daemon actually
/// reported an identity, which is precisely what the §4.7 identity challenge
/// gating every role validator will demand seconds later. Anything else — a
/// refusing socket, a daemon still initialising, or the OLD probe's
/// `socket-ready` token — is NOT ready.
fn daemon_probe_reports_live(output: &str) -> bool {
    output.contains(DAEMON_LIVE_MARKER) && ssh::parse_status_node_id(output).is_some()
}

/// The in-guest readiness probe: retry `rustynet status` against the control
/// socket, echoing [`DAEMON_LIVE_MARKER`] on the first success.
///
/// Every interpolated value is a compile-time constant — no untrusted input
/// reaches this command string.
fn macos_daemon_readiness_probe() -> String {
    format!(
        "for i in $(seq 1 8); do \
            if out=$({SUDO_N} env RUSTYNET_DAEMON_SOCKET={MACOS_DAEMON_SOCKET} \
                {MACOS_RUSTYNET_PATH} status 2>/dev/null); then \
                printf '%s\\n' \"$out\"; echo {DAEMON_LIVE_MARKER}; exit 0; \
            fi; \
            sleep 1; \
         done; \
         echo daemon-unreachable; exit 1"
    )
}

fn wait_for_macos_daemon_socket(conn: &NodeConnection) -> Result<(), AdapterError> {
    let probe = macos_daemon_readiness_probe();
    let mut last_status = String::from("no probe attempt completed");
    for attempt in 1..=8 {
        match ssh::run_remote(conn, &probe, Duration::from_secs(30)) {
            Ok(output) if daemon_probe_reports_live(&output) => return Ok(()),
            Ok(output) if output.contains(DAEMON_LIVE_MARKER) => {
                last_status =
                    "daemon answered but reported no node_id (still initialising)".to_string();
            }
            Ok(_) => last_status = "daemon not answering on its control socket yet".to_string(),
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
            "macOS daemon at {MACOS_DAEMON_SOCKET} did not become LIVE after 8 retried probes \
             (~80 s) post launchd bootstrap: {last_status}"
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
            "sudo -n launchctl bootstrap system '{plist}' 2>/dev/null || \
             sudo -n launchctl kickstart system/com.rustynet.daemon"
        ),
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Ensure passwordless sudo on this node so that daemon lifecycle commands
/// (stop/start/restart) and network-stack operations work without blocking
/// for a password prompt. Uses `sshpass` + the lab SSH password to push a
/// temporary `/etc/sudoers.d/99-rustynet-lab` grant when `sudo -n true` fails.
/// Idempotent: if the node already answers `sudo -n true`, this is a no-op.
pub fn prime_remote_access(conn: &NodeConnection) -> Result<(), AdapterError> {
    match conn.ssh_parts() {
        Some((host, port, user, identity_file, Some(password))) => {
            let user_flag = user.map(|u| format!("{u}@")).unwrap_or_default();
            let mut cmd = std::process::Command::new("sshpass");
            cmd.arg("-p")
                .arg(password)
                .arg("ssh")
                .arg("-i")
                .arg(identity_file)
                .arg("-o")
                .arg("StrictHostKeyChecking=yes")
                .arg("-o")
                .arg("ConnectTimeout=10")
                .arg("-p")
                .arg(port.to_string())
                .arg(format!("{user_flag}{host}"))
                .arg("sudo -n true 2>/dev/null && echo 'sudo-ok' || echo 'need-sudo'");
            let output = cmd.output().map_err(|e| AdapterError::Protocol {
                message: format!("sshpass prime check failed: {e}"),
            })?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.trim() == "sudo-ok" {
                return Ok(());
            }
            let mut push = std::process::Command::new("sshpass");
            push.arg("-p").arg(password)
                .arg("ssh")
                .arg("-i").arg(identity_file)
                .arg("-o").arg("StrictHostKeyChecking=yes")
                .arg("-o").arg("ConnectTimeout=10")
                .arg("-p").arg(port.to_string())
                .arg(format!("{user_flag}{host}"))
                .arg("echo 'tempo' | sudo -S bash -c 'echo \"%admin ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/99-rustynet-lab && chmod 0440 /etc/sudoers.d/99-rustynet-lab'");
            let status = push.status().map_err(|e| AdapterError::Protocol {
                message: format!("sshpass prime push failed: {e}"),
            })?;
            if !status.success() {
                return Err(AdapterError::Protocol {
                    message: "failed to push temporary sudoers grant".to_owned(),
                });
            }
            Ok(())
        }
        _ => {
            // Non-SSH or no password: assume sudo already works (Linux).
            Ok(())
        }
    }
}

/// Stop the launchd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(
        conn,
        "sudo -n launchctl bootout system/com.rustynet.daemon 2>/dev/null || true",
        Duration::from_secs(30),
    )?;
    Ok(())
}

/// Tri-state result of the S2b helper-job probe (post-merge review §1,
/// MacosHelperShutdownOrderingS2bM2Review_2026-09-02): `launchctl print` exits
/// 0 for a *loaded* job whose process has exited (KeepAlive respawn pending,
/// throttled, or crashed-with-retry), so a bare `is_ok()` conflates
/// "alive" with "present". A loaded-but-dead job's socket is gone or stale
/// (launchd removes per-job sockets at job exit), so the daemon's shutdown
/// rollback would dial a dead socket exactly as if the job were absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperJobPresence {
    /// `launchctl print system/com.rustynet.privileged-helper` failed: the
    /// job is not bootstrapped at all.
    Absent,
    /// The job is bootstrapped but reports no `pid = ` line: loaded, dead.
    PresentDead,
    /// The job is bootstrapped and reports a live `pid = ` line.
    PresentAlive,
}

/// Why the pre-restart liveness step entered the restore path (post-merge
/// review §1): rendered into the restart's log line so the run's stage log
/// distinguishes the present-but-dead demotion from a plain absent job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperRestoreReason {
    /// The launchd job was not bootstrapped at all.
    JobAbsent,
    /// The job was bootstrapped but had no live `pid = ` line, or its live
    /// pid's socket was absent: present-but-dead, restored like an absent job
    /// (after a best-effort bootout of the stale job slot).
    PresentButDead,
}

impl std::fmt::Display for HelperRestoreReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::JobAbsent => write!(f, "job absent"),
            Self::PresentButDead => write!(
                f,
                "job present but dead (no live pid or helper socket gone)"
            ),
        }
    }
}

/// What the pre-restart privileged-helper liveness step found and did
/// (S2b of MacosHelperShutdownOrderingImplementationPlan_2026-09-02). Rendered
/// into the restart's log line so the run's stage log records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HelperLivenessStep {
    /// The job is bootstrapped with a live `pid = ` line AND its socket is
    /// present: the probe-gated step is a no-op.
    HelperPresent,
    /// The helper was not live (absent, or present-but-dead per review §1);
    /// it was re-bootstrapped from its installed plist and the socket appeared
    /// after `socket_probes` poll(s) of the bounded wait.
    HelperRestored {
        socket_probes: usize,
        reason: HelperRestoreReason,
    },
}

impl std::fmt::Display for HelperLivenessStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HelperPresent => {
                write!(f, "job present (probe-gated no-op)")
            }
            Self::HelperRestored {
                socket_probes,
                reason,
            } => write!(
                f,
                "{reason}; booted out any stale job, re-bootstrapped from \
                 {MACOS_PRIVILEGED_HELPER_PLIST} and socket appeared after \
                 {socket_probes} poll(s)"
            ),
        }
    }
}

/// Order-enforcing driver behind [`restart_daemon`] (S2b, review §1): the
/// daemon stop/start steps run ONLY after the helper-liveness step succeeds —
/// a failed liveness restore propagates its error and the daemon restart
/// commands are never issued. The `HelperPresent` no-op branch requires a
/// live job AND a present socket: a job that is loaded but has no live pid
/// (`PresentDead`), or a live pid whose socket is gone, is demoted to the
/// restore path instead of sailing through (review §1's exact hole). The
/// remote effects are closures so the ordering guarantee (no daemon restart
/// past a failed helper restore) is testable without SSH.
fn drive_restart_with_helper_liveness(
    probe_helper_job: &mut dyn FnMut() -> HelperJobPresence,
    socket_present: &mut dyn FnMut() -> bool,
    restore_helper: &mut dyn FnMut() -> Result<usize, AdapterError>,
    stop_daemon: &mut dyn FnMut() -> Result<(), AdapterError>,
    start_daemon: &mut dyn FnMut() -> Result<(), AdapterError>,
) -> Result<HelperLivenessStep, AdapterError> {
    let step = match probe_helper_job() {
        HelperJobPresence::PresentAlive if socket_present() => HelperLivenessStep::HelperPresent,
        presence => {
            let reason = match presence {
                HelperJobPresence::Absent => HelperRestoreReason::JobAbsent,
                HelperJobPresence::PresentDead | HelperJobPresence::PresentAlive => {
                    HelperRestoreReason::PresentButDead
                }
            };
            let socket_probes = restore_helper()?;
            HelperLivenessStep::HelperRestored {
                socket_probes,
                reason,
            }
        }
    };
    stop_daemon()?;
    start_daemon()?;
    Ok(step)
}

/// The ONE remote-sink lowering shared by every S2b helper-liveness command:
/// each command is built through `RemoteCommand::from_args` (validated argv)
/// and then lowered through the `run_remote` sink exactly here, so the new
/// functionality contributes a single counted sink call site.
fn run_validated(
    conn: &NodeConnection,
    command: &ssh::RemoteCommand,
    timeout: Duration,
) -> Result<String, AdapterError> {
    ssh::run_remote(conn, command.as_str(), timeout)
}

/// Classify `launchctl print system/com.rustynet.privileged-helper` stdout
/// (post-merge review §1): launchd exits 0 for a *loaded* job whose process
/// has exited, and the loaded job's description carries a `pid = <n>` line
/// only while the process is alive — the same predicate
/// `macos_daemon_job_reported_exit` in `install/uninstall.rs` relies on. An
/// empty/failed print ⇒ not bootstrapped at all; a print without a live
/// `pid = ` line ⇒ present-but-dead.
fn classify_helper_job_stdout(stdout: &str) -> HelperJobPresence {
    if stdout.contains("pid = ") {
        HelperJobPresence::PresentAlive
    } else {
        HelperJobPresence::PresentDead
    }
}

/// Probe the privileged-helper launchd job through the validated seam:
/// `sudo -n launchctl print system/com.rustynet.privileged-helper`, capturing
/// stdout. The `run_remote` sink maps a non-zero remote exit to
/// `AdapterError::Command` — launchd reports no such job — so an error ⇒
/// [`HelperJobPresence::Absent`]; a successful print is classified by its
/// stdout, because exit 0 alone conflates "alive" with "loaded but dead"
/// (review §1).
fn probe_privileged_helper_job(conn: &NodeConnection) -> HelperJobPresence {
    match privileged_helper_job_probe_command()
        .and_then(|probe| run_validated(conn, &probe, SHORT_TIMEOUT))
    {
        Ok(stdout) => classify_helper_job_stdout(&stdout),
        Err(_) => HelperJobPresence::Absent,
    }
}

/// The validated-argv probe command (QH-01 seam; fixed literals only — the
/// target is derived from a const label, and the validator still gates it).
fn privileged_helper_job_probe_command() -> Result<ssh::RemoteCommand, AdapterError> {
    ssh::RemoteCommand::from_args(
        "macos privileged-helper job probe",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("launchctl")?,
            ValidatedArg::cli_token("print")?,
            ValidatedArg::cli_token(&format!("system/{MACOS_PRIVILEGED_HELPER_LABEL}"))?,
        ],
    )
}

/// The validated-argv socket probe (`sudo -n test -S <socket>`), shared by
/// the restore path's bounded wait and the pre-restart liveness check.
fn privileged_helper_socket_probe_command() -> Result<ssh::RemoteCommand, AdapterError> {
    ssh::RemoteCommand::from_args(
        "macos privileged-helper socket probe",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("test")?,
            ValidatedArg::cli_token("-S")?,
            ValidatedArg::path(MACOS_PRIVILEGED_HELPER_SOCKET)?,
        ],
    )
}

/// Is the helper socket present right now? One poll of the validated probe.
fn privileged_helper_socket_present(conn: &NodeConnection) -> bool {
    privileged_helper_socket_probe_command()
        .and_then(|probe| run_validated(conn, &probe, SHORT_TIMEOUT))
        .is_ok()
}

/// The restore path's two launchd commands, IN ORDER: the bootout of any
/// stale job slot comes FIRST (a bootstrapped job cannot be re-bootstrapped
/// in place — `launchctl bootstrap` of an already-loaded job fails, review
/// §1), the `launchctl bootstrap` from the installed plist comes SECOND.
/// Returned as an ordered pair so the ordering is pinned by test without SSH.
fn privileged_helper_restore_commands()
-> Result<(ssh::RemoteCommand, ssh::RemoteCommand), AdapterError> {
    let bootout = ssh::RemoteCommand::from_args(
        "macos privileged-helper bootout",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("launchctl")?,
            ValidatedArg::cli_token("bootout")?,
            ValidatedArg::cli_token(&format!("system/{MACOS_PRIVILEGED_HELPER_LABEL}"))?,
        ],
    )?;
    let bootstrap = ssh::RemoteCommand::from_args(
        "macos privileged-helper bootstrap",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("launchctl")?,
            ValidatedArg::cli_token("bootstrap")?,
            ValidatedArg::cli_token("system")?,
            ValidatedArg::path(MACOS_PRIVILEGED_HELPER_PLIST)?,
        ],
    )?;
    Ok((bootout, bootstrap))
}

/// Restore the helper launchd job so its socket serves the daemon's shutdown
/// rollback again: boot out any stale job slot FIRST (`launchctl bootout … ||
/// true` — a bootstrapped job cannot be re-bootstrapped in place, and the
/// bootout of an already-absent job is a benign failure), THEN `launchctl
/// bootstrap` from the installed plist, then wait, bounded (≤10 s, mirroring
/// the installer's post-bootstrap socket wait at
/// `Install-RustyNetMacosService.sh:614-625`), for the socket to appear.
/// Returns the number of socket polls consumed.
fn restore_privileged_helper(conn: &NodeConnection) -> Result<usize, AdapterError> {
    eprintln!(
        "[macos daemon restart] privileged-helper launchd job not live; \
         booting out any stale job and re-bootstrapping from \
         {MACOS_PRIVILEGED_HELPER_PLIST}"
    );
    let (bootout, bootstrap) = privileged_helper_restore_commands()?;
    // Best-effort by construction: the bootout fails harmlessly when the job
    // is not bootstrapped (the common `JobAbsent` path), so its error is
    // deliberately not propagated — the bootstrap below is the real action.
    let _ = run_validated(conn, &bootout, SHORT_TIMEOUT);
    run_validated(conn, &bootstrap, SHORT_TIMEOUT)?;
    wait_for_privileged_helper_socket(conn)
}

/// Bounded socket wait (20 × 0.5 s = 10 s): a `sudo -n test -S <socket>` probe
/// polled from the adapter, mirroring the installer's post-bootstrap wait
/// (`Install-RustyNetMacosService.sh:614-625`). Expiry is a loud refusal — the
/// daemon restart that would follow is KNOWN to lose its shutdown rollback,
/// because the rollback dials this socket.
fn wait_for_privileged_helper_socket(conn: &NodeConnection) -> Result<usize, AdapterError> {
    let probe = privileged_helper_socket_probe_command()?;
    for attempt in 1..=20 {
        if run_validated(conn, &probe, SHORT_TIMEOUT).is_ok() {
            return Ok(attempt);
        }
        if attempt < 20 {
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    Err(AdapterError::Protocol {
        message: format!(
            "privileged helper socket {MACOS_PRIVILEGED_HELPER_SOCKET} did not appear within \
             10 s of launchctl bootstrap; refusing to restart the daemon: its shutdown rollback \
             dials the helper socket, so the restart would be known to lose its rollback \
             (S2b, MacosHelperShutdownOrderingImplementationPlan_2026-09-02)"
        ),
    })
}

/// Restart the launchd service (stop + start; launchd has no native restart).
///
/// S2b (MacosHelperShutdownOrderingImplementationPlan_2026-09-02): before the
/// daemon bootout/bootstrap, probe the privileged-helper launchd job; only a
/// job that is bootstrapped with a live `pid = ` line AND a present socket
/// counts as live — a loaded-but-dead job, or a live job whose socket is
/// gone, enters the same restore path as an absent job (bootout of the stale
/// slot, re-bootstrap, bounded socket wait). The daemon's shutdown rollback
/// dials the helper socket, so restarting the daemon against a dead helper is
/// the exact completion-order defect that failed `macos-utm-1` (run
/// `livelab-1788325534-2e7bdaf7bf57`): the restart would be known to lose its
/// rollback before it is issued. If the helper cannot be restored, the restart
/// is refused loudly instead of proceeding.
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let step = drive_restart_with_helper_liveness(
        &mut || probe_privileged_helper_job(conn),
        &mut || privileged_helper_socket_present(conn),
        &mut || restore_privileged_helper(conn),
        &mut || stop_daemon(conn),
        &mut || start_daemon(conn),
    )?;
    eprintln!("[macos daemon restart] privileged helper liveness: {step}");
    Ok(())
}

/// Build the remote shell command that re-invokes the compiled macOS
/// install-service script in ENFORCE mode (QH-24): same parameters as
/// bootstrap but with `--auto-tunnel-enforce true` and extended max-age
/// windows, so the daemon applies the assignment bundles on its next start.
///
/// trust-max-age-secs 86400: macOS has no periodic trust-evidence refresh
/// timer (unlike Linux rustynetd-trust-refresh.service). The lab issues
/// trust evidence once during bootstrap; 86400 s keeps it valid for the
/// duration of any reasonable lab run without requiring a separate refresh.
/// This matches the Linux lab setting.
///
/// The STUN detection prelude (C-STUN, BashOrchestratorRetirementProgram)
/// mirrors Bootstrap-RustyNetMacos.sh: the enforce re-render would otherwise
/// silently drop the bootstrap-time --traversal-stun-servers (the same trap
/// as --wg-interface, which is threaded explicitly). Detection failure passes
/// no flag, preserving the pre-C-STUN plist.
///
/// `lab_stun_csv` (--lab-stun-servers): when `Some(csv)`, the validated
/// numeric ip:port CSV REPLACES the gateway detection — the STUN flags are set
/// to the literal override (each entry validated as a SocketAddr upstream, so
/// the interpolation carries only numeric characters, dots, colons, and
/// commas). `None` preserves the C-STUN gateway detection byte-identically.
///
/// Split out of `enforce_daemon` so the generated command is unit-testable
/// without a live `NodeConnection`. This is the fail-closed enforcement path:
/// until it runs, the daemon is in non-enforcing mode
/// (`auto_tunnel_enforce=false`), so a regression that drops the flag or a
/// max-age silently weakens the enforced posture. `node_id_arg`,
/// `network_id_arg`, and `ssh_allow_cidrs_arg` must arrive ALREADY
/// single-quote-escaped by the caller (the caller's own values are
/// interpolated into single-quoted shell args); `daemon_node_role` comes from
/// a fixed enum mapping and `wg_interface` is digit-validated upstream.
/// Pinned by `auto_tunnel_enforce_install_script_pins_enforce_posture`.
fn build_auto_tunnel_enforce_install_script(
    daemon_node_role: &str,
    node_id_arg: &str,
    network_id_arg: &str,
    wg_interface: &str,
    ssh_allow_flag: &str,
    ssh_allow_cidrs_arg: &str,
    lab_stun_csv: Option<&str>,
) -> String {
    let stun_prelude = match lab_stun_csv {
        Some(csv) => format!(
            "RN_STUN_FLAG='--traversal-stun-servers' ; RN_STUN_VAL='{csv}' ;"
        ),
        // Plain string literal, NOT a format! template: the braces are literal
        // awk / regex syntax here (a `{{` escape would ship a broken program
        // and an IPv4 guard that never matches).
        None => "RN_LAB_GW=\"$(route -n get default 2>/dev/null | awk '/gateway:/{print $2; exit}')\" ; \
                 RN_STUN_FLAG='' ; RN_STUN_VAL='' ; \
                 if echo \"$RN_LAB_GW\" | grep -Eq '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'; then \
                   RN_STUN_FLAG='--traversal-stun-servers' ; RN_STUN_VAL=\"$RN_LAB_GW:3478\" ; fi ;"
            .to_owned(),
    };
    format!(
        "chmod 700 /tmp/Install-RustyNetMacosService.sh && \
         {stun_prelude} \
         sudo -n /tmp/Install-RustyNetMacosService.sh \
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
           $RN_STUN_FLAG $RN_STUN_VAL \
           --fail-closed-ssh-allow '{ssh_allow_flag}' \
           --fail-closed-ssh-allow-cidrs '{ssh_allow_cidrs_arg}'",
    )
}

/// Budget for the post-restart `state refresh` IPC: the daemon re-applies the
/// signed dataplane generation (trust, peers, DNS posture) synchronously
/// before answering, which is bounded work on the lab guests.
const STATE_REFRESH_TIMEOUT: Duration = Duration::from_secs(60);

/// The validated-argv post-restart signed-state refresh command (Gap A,
/// `MacosEnforceRefreshParityPlan_2026-09-02` §3.1):
/// `sudo -n env RUSTYNET_DAEMON_SOCKET=<socket> /usr/local/bin/rustynet state
/// refresh` — the same command shape the C6 role-transition path
/// (`vm_lab/mod.rs`) and `macos_daemon_readiness_probe` use to reach the
/// daemon's control socket in-guest, and the same IPC the systemd
/// trust-refresh unit issues on Linux via
/// `ops state-refresh-if-socket-present`. Split out so the exact argv is
/// pinned by test without SSH (QH-01 seam: typed `ValidatedArg` tokens only —
/// no `format!`-built shell with runtime values).
fn macos_state_refresh_command() -> Result<ssh::RemoteCommand, AdapterError> {
    ssh::RemoteCommand::from_args(
        "macos daemon state refresh",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("env")?,
            ValidatedArg::cli_token(&format!("RUSTYNET_DAEMON_SOCKET={MACOS_DAEMON_SOCKET}"))?,
            ValidatedArg::path(MACOS_RUSTYNET_PATH)?,
            ValidatedArg::cli_token("state")?,
            ValidatedArg::cli_token("refresh")?,
        ],
    )
}

/// The enforce-path refresh sequencing driver (Gap A, ordering pin): the
/// post-restart signed-state refresh is issued ONLY after the daemon socket
/// wait has succeeded, and a refresh `Err` propagates as the enforce error.
/// Closure-driven so a unit test pins the order and the error propagation
/// without SSH. One attempt only — the refresh is never retried, so a
/// persistently failing daemon surfaces loudly instead of being masked by a
/// loop.
fn drive_enforce_post_restart_refresh(
    wait_socket: &mut dyn FnMut() -> Result<(), AdapterError>,
    refresh: &mut dyn FnMut() -> Result<String, AdapterError>,
) -> Result<String, AdapterError> {
    wait_socket()?;
    refresh()
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
///
/// Self-contained refresh (Gap A, `MacosEnforceRefreshParityPlan_2026-09-02`
/// §3.1): after the restart the enforce path waits for the daemon socket, then
/// issues the IPC signed-state refresh (`state refresh`) and FAILS on a
/// non-zero result — one attempt, no retry loop. A refresh error propagates as
/// the enforce error so a failing daemon surfaces loudly instead of the stage
/// passing on stale signed state.
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

    // Build the re-install command via the extracted builder (QH-24): same
    // params as bootstrap but with auto-tunnel-enforce=true and extended
    // max-age windows. --lab-stun-servers override (validated numeric CSV)
    // replaces the gateway detection when configured.
    let lab_stun_csv: Option<String> = if ctx.lab_stun_servers.is_empty() {
        None
    } else {
        Some(
            ctx.lab_stun_servers
                .iter()
                .map(std::net::SocketAddr::to_string)
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    let script = build_auto_tunnel_enforce_install_script(
        daemon_node_role,
        &node_id_arg,
        &network_id_arg,
        &wg_interface,
        ssh_allow_flag,
        &ssh_allow_cidrs_arg,
        lab_stun_csv.as_deref(),
    );
    ssh::run_remote(conn, &script, Duration::from_secs(60))?;
    // The install script reloads the launchd plist, which bounces the daemon.
    // launchctl returns before the daemon re-binds its control socket, but the
    // next stage (ValidateBaselineRuntime) probes that socket with no retry of
    // its own. Wait for the socket to reappear so a mid-restart daemon does not
    // produce a spurious validation failure. Mirrors install_daemon and the
    // Windows enforce path's post-restart readiness wait.
    //
    // Gap A (MacosEnforceRefreshParityPlan_2026-09-02 §3.1): after the socket
    // wait succeeds, issue the IPC signed-state refresh so the enforce path is
    // self-contained instead of timer-lucky (macOS installs no trust-refresh
    // timer). A non-zero refresh result FAILS the enforce — one attempt, no
    // retry loop that could mask a failing daemon. Ordering pinned by
    // `enforce_refresh_runs_only_after_socket_wait_and_propagates_refresh_error`.
    let refresh = macos_state_refresh_command()?;
    let refresh_message = drive_enforce_post_restart_refresh(
        &mut || wait_for_macos_daemon_socket(conn),
        &mut || {
            run_validated(conn, &refresh, STATE_REFRESH_TIMEOUT)
                .map(|stdout| format!("macOS daemon state refresh ok: {}", stdout.trim()))
        },
    )?;
    eprintln!("[macos daemon enforce] {refresh_message}");
    Ok(())
}

/// Stop the service and remove daemon binaries and state.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    let _ = stop_daemon(conn);
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n rm -f {MACOS_RUSTYNETD_PATH} {MACOS_RUSTYNET_PATH} \
             /Library/LaunchDaemons/com.rustynet.daemon.plist && \
             sudo -n rm -rf {MACOS_STATE_ROOT} /usr/local/etc/rustynet /private/var/run/rustynet",
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
///
/// Shared source of truth: the rule lives in the QH-01 seam module
/// (`validated_args.rs`) so every adapter validates the class identically.
pub(crate) use super::validated_args::validate_utun_name;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn build_bootstrap_env(
    node_id: &str,
    role: &NodeRole,
    ctx: &OrchestrationContext,
) -> Result<String, AdapterError> {
    let role_str = role.as_str();
    let daemon_node_role = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Macos)
        .map_err(|message| AdapterError::Protocol { message })?;
    // Derive the per-node utun interface name and pass it through to the
    // bootstrap shell so the FIRST plist install already targets the
    // node-specific utun device. Without WG_INTERFACE in the env file the
    // bootstrap-time install would fall back to the install-script default
    // (utun9) and the orchestrator's later enforce_runtime phase would have
    // to re-render the plist; mac hosts running concurrently with the same
    // utun9 would collide. Computing it here keeps the value identical in
    // both code paths and avoids re-deriving it in shell.
    let wg_interface = utun_name_for_node_id(node_id);
    // --lab-stun-servers override: Bootstrap-RustyNetMacos.sh reads
    // RUSTYNET_LAB_STUN_SERVERS and falls back to the guest's default gateway
    // on 3478 when it is unset, so the line is only emitted when the operator
    // configured servers (byte-identical env when unset).
    let lab_stun_line = if ctx.lab_stun_servers.is_empty() {
        String::new()
    } else {
        format!(
            "RUSTYNET_LAB_STUN_SERVERS={}\n",
            ctx.lab_stun_servers
                .iter()
                .map(std::net::SocketAddr::to_string)
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    Ok(format!(
        "ROLE={role_str}\nDAEMON_NODE_ROLE={daemon_node_role}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\n\
         SSH_ALLOW_CIDRS={cidrs}\nWG_INTERFACE={wg_interface}\n{lab_stun_line}",
        network_id = ctx.network_id,
        cidrs = ctx.ssh_allow_cidrs,
    ))
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
    // QH-01 Step 4c: argv-shaped read rendered through the validated seam
    // (the path is const-derived from MACOS_STATE_ROOT).
    let assignment_args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("cat")?,
        ValidatedArg::path(&assignment_pub)?,
    ];
    let assignment_script =
        ssh::RemoteCommand::from_args("macos assignment pubkey read", &assignment_args)?;
    let assignment_hex = ssh::run_remote(conn, assignment_script.as_str(), short_timeout)?;

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
            "sudo -n sh -c 'mkdir -p {MACOS_STATE_ROOT} && \
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
        "sudo -n env RN_SRC='{src_dir_esc}' sh -c 'cd \"$RN_SRC\" && {MACOS_RUSTYNET_PATH} ops install-macos-relay'"
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
    super::write_secure_temp_file(prefix, suffix, content)
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
            collected_gossip_identities: HashMap::new(),
            network_id: "test-net".to_owned(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        }
    }

    #[test]
    fn bootstrap_env_contains_role_and_node_id() {
        let ctx = make_ctx(NodeRole::Client);
        let env = build_bootstrap_env("mac-node-1", &NodeRole::Exit, &ctx).expect("env");
        assert!(env.contains("ROLE=exit"));
        assert!(env.contains("DAEMON_NODE_ROLE=blind_exit"));
        assert!(env.contains("NODE_ID=mac-node-1"));
        assert!(env.contains("NETWORK_ID=test-net"));
        assert!(
            !env.contains("RUSTYNET_LAB_STUN_SERVERS="),
            "unset --lab-stun-servers must leave the env byte-identical: {env}"
        );
    }

    #[test]
    fn bootstrap_env_threads_lab_stun_servers_when_configured() {
        let mut ctx = make_ctx(NodeRole::Client);
        ctx.lab_stun_servers = vec![
            "1.2.3.4:19302".parse().expect("socket addr"),
            "5.6.7.8:3478".parse().expect("socket addr"),
        ];
        let env = build_bootstrap_env("mac-node-1", &NodeRole::Client, &ctx).expect("env");
        assert!(
            env.contains("RUSTYNET_LAB_STUN_SERVERS=1.2.3.4:19302,5.6.7.8:3478\n"),
            "configured --lab-stun-servers must override the gateway default as a CSV line: {env}"
        );
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

    /// MAC-D2 cross-check: the adapter's owner-signing-key constant must
    /// equal the one the macOS genesis driver actually passes to
    /// `rustynetd membership init` (`ops_e2e`), so the adapter's `.pub`
    /// read path is provably the genesis write path. macOS-gated because
    /// the ops_e2e constant is.
    #[cfg(target_os = "macos")]
    #[test]
    fn owner_signing_key_path_matches_macos_genesis_driver() {
        assert_eq!(
            MACOS_OWNER_SIGNING_KEY_PATH,
            crate::ops_e2e::MACOS_OWNER_SIGNING_KEY_PATH,
            "adapter and genesis driver must agree on the macOS owner signing key path"
        );
    }

    #[test]
    fn bootstrap_script_clears_stale_signed_state_on_fresh_enroll() {
        // A fresh (re)enrollment must wipe the prior trust signed-state +
        // anti-replay watermarks, or the daemon rejects the fresh genesis
        // bundle as a replay/rollback ("membership replay/rollback detected
        // by watermark") and fail-closes (observed live: macOS stuck
        // state=FailClosed, membership_active_nodes=none). macOS analogue of
        // the Linux cleanup's `rm -rf /var/lib/rustynet`; key custody must be
        // preserved.
        assert!(
            BOOTSTRAP_SCRIPT.contains("for _residual_dir in trust"),
            "clear_residual_state must wipe the trust/ signed-state"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("rm -f \"${STATE_ROOT}/rustynetd.state\""),
            "clear_residual_state must remove the stale top-level session state"
        );
        // The reset must NOT touch key-custody material.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("for _residual_dir in membership trust")
                && !BOOTSTRAP_SCRIPT.contains("for _residual_dir in membership trust keys")
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

    /// MAC-D10: the membership/ wipe must be pinned INSIDE
    /// `seed_membership_genesis`, immediately before `membership init`
    /// re-seeds the state — never in a general cleanup pass. A cleanup that
    /// wipes membership/ without the re-genesis directly following it leaves
    /// a destructive window (observed live: genesis seeded by bootstrap,
    /// membership/ empty while the orchestrator's membership stage was
    /// mid-flight, and the stage's silent `test -s` read-back could not even
    /// name the failure).
    #[test]
    fn bootstrap_script_pins_membership_wipe_inside_genesis_seeder() {
        assert!(
            !BOOTSTRAP_SCRIPT.contains("for _residual_dir in membership"),
            "clear_residual_state must NOT wipe membership/; the wipe is pinned \
             inside seed_membership_genesis (MAC-D10)"
        );
        let wipe = BOOTSTRAP_SCRIPT
            .find("find \"${membership_dir}\" -mindepth 1 -maxdepth 1")
            .unwrap_or_else(|| {
                panic!(
                    "seed_membership_genesis must wipe the stale membership/ signed-state \
                     before re-seeding: {}",
                    BOOTSTRAP_SCRIPT.len()
                )
            });
        let membership_init = BOOTSTRAP_SCRIPT
            .find("\"${RUSTYNETD_BIN}\" membership init")
            .expect("bootstrap must seed genesis via `membership init`");
        assert!(
            wipe < membership_init,
            "the membership/ wipe must be ordered immediately before `membership init` \
             inside the same function (wipe at byte {wipe}, init at byte {membership_init})"
        );
    }

    /// MAC-D4 drift guard: the bootstrap script must seed the membership
    /// owner keypair at the canonical genesis location the adapter reads
    /// (MAC-D2). The Linux bootstrap re-seeds its owner key on every install
    /// via `e2e-bootstrap-host`'s membership-init step; the macOS bootstrap
    /// previously had no genesis step at all, so a fresh macOS deploy could
    /// never hold an owner key and the orchestrator's membership_init stage
    /// failed on every macOS exit run (MacCellsHarvest_2026-08-28 §8.3).
    #[test]
    fn bootstrap_script_seeds_membership_owner_key_at_canonical_genesis_path() {
        // Genesis must run `rustynetd membership init` against the canonical
        // owner-signing-key path (== MACOS_OWNER_SIGNING_KEY_PATH, pinned to
        // ops_e2e by owner_signing_key_path_matches_macos_genesis_driver),
        // with a passphrase file (the encrypted-at-rest envelope requires
        // one) and --force (re-genesis per bootstrap, mirroring Linux).
        assert!(
            BOOTSTRAP_SCRIPT.contains("membership init \\\n    --snapshot"),
            "bootstrap must run `rustynetd membership init` genesis (MAC-D4)"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("local owner_key=\"${CONFIG_ROOT}/membership.owner.key\"")
                && BOOTSTRAP_SCRIPT.contains("--owner-signing-key \"${owner_key}\""),
            "genesis must seed the owner signing key at the canonical \
             MACOS_OWNER_SIGNING_KEY_PATH location"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("--owner-signing-key-passphrase-file"),
            "genesis must seal the owner signing key with a passphrase (no plaintext key at rest)"
        );
        // The .pub sibling is the MAC-D2 read target: deterministic
        // ownership/mode must be pinned after genesis.
        for expected in [
            "chown root:rustynetd \"${owner_key}.pub\"",
            "chmod 0644 \"${owner_key}.pub\"",
        ] {
            assert!(
                BOOTSTRAP_SCRIPT.contains(expected),
                "genesis must pin the .pub read target ({expected})"
            );
        }
        // Genesis snapshot/log must be handed to the daemon service account
        // (same ownership restore ops_e2e applies after root-run membership
        // mutations) or the launchd daemon cannot persist membership state.
        assert!(
            BOOTSTRAP_SCRIPT.contains(
                "chown rustynetd:rustynetd \\\n    \"${membership_dir}/membership.snapshot\""
            ),
            "genesis must restore daemon-service ownership of the signed state"
        );
        // The signing-key passphrase must ALSO land in the System.keychain
        // under the canonical unwrap descriptor (service/account pair from
        // credential_unwrap::membership_signing_key_passphrase_descriptor),
        // matching execute_ops_e2e_bootstrap_macos's provisioner.
        for expected in [
            "-a membership-owner-signing-key",
            "-s signing_key_passphrase",
        ] {
            assert!(
                BOOTSTRAP_SCRIPT.contains(expected),
                "genesis must provision the keychain unwrap descriptor ({expected})"
            );
        }
        // Genesis must run in BOTH the full-install and SKIP_BUILD paths —
        // the definition plus the two call sites.
        assert!(
            BOOTSTRAP_SCRIPT.matches("seed_membership_genesis").count() >= 3,
            "seed_membership_genesis must be defined and invoked in both main paths"
        );
        // Fail-closed: the genesis function must not soften membership init
        // with an allow-failure escape hatch.
        for softened in ["membership init ||", "|| membership init"] {
            assert!(
                !BOOTSTRAP_SCRIPT.contains(softened),
                "genesis must fail the bootstrap loud, not soften with '{softened}'"
            );
        }
    }

    /// MAC-D13 parity on the ORCHESTRATOR bootstrap path: genesis must seed
    /// the encrypted assignment-signing secret at the canonical config root.
    /// MAC-D13 initially landed the seed step only inside
    /// `execute_ops_e2e_bootstrap_macos` (`ops e2e-bootstrap-host`), a driver
    /// the Rust --node orchestrator never invokes for macOS — unlike Linux,
    /// whose rn_bootstrap.sh calls e2e-bootstrap-host and therefore got the
    /// secret. The orchestrator's macOS nodes shipped without
    /// /usr/local/etc/rustynet/assignment.signing.secret and
    /// distribute_assignments kept failing closed with "assignment signing
    /// secret missing" even after a verified rebuild (observed live:
    /// livelab-1788024350, commit 022952bc7e55 — bootstrap_hosts pass, then
    /// the macOS issuer errored). Pinned here so the seed cannot regress out
    /// of the path that actually runs.
    #[test]
    fn bootstrap_script_seeds_assignment_signing_secret_at_canonical_path() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("assignment init-signing-secret"),
            "macOS genesis must seed the assignment signing secret \
             (distribute_assignments fails closed without it)"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("--output \"${CONFIG_ROOT}/assignment.signing.secret\""),
            "the secret must be seeded at the canonical macOS config root \
             (/usr/local/etc/rustynet/assignment.signing.secret)"
        );
        // Encrypted-at-rest envelope requires a passphrase file, and --force
        // keeps the secret re-seeded with each per-bootstrap re-genesis so it
        // never outlives the owner keypair it is bound to.
        assert!(
            BOOTSTRAP_SCRIPT.contains("--signing-secret-passphrase-file \"${passphrase_file}\"")
                && BOOTSTRAP_SCRIPT.contains("--force"),
            "the seed must encrypt the secret under the genesis passphrase and \
             re-seed with --force per bootstrap"
        );
        // The seed must live INSIDE seed_membership_genesis, ordered after the
        // keychain unwrap descriptor is provisioned (the issuers unwrap the
        // secret's passphrase via MacosKeychainBackend) — not in a general
        // cleanup or install phase that could run without genesis.
        let genesis = BOOTSTRAP_SCRIPT
            .find("seed_membership_genesis()")
            .expect("genesis function must exist");
        let keychain = BOOTSTRAP_SCRIPT[genesis..]
            .find("-s signing_key_passphrase")
            .expect("genesis must provision the keychain descriptor");
        let seed = BOOTSTRAP_SCRIPT[genesis..]
            .find("assignment init-signing-secret")
            .expect("genesis must seed the assignment signing secret");
        assert!(
            keychain < seed,
            "the assignment-signing-secret seed must follow the keychain \
             provisioning inside seed_membership_genesis (keychain at byte \
             {keychain}, seed at byte {seed})"
        );
        // Fail-closed: no allow-failure escape hatch on the seed.
        for softened in [
            "assignment init-signing-secret ||",
            "|| assignment init-signing-secret",
        ] {
            assert!(
                !BOOTSTRAP_SCRIPT.contains(softened),
                "the seed must fail the bootstrap loud, not soften with '{softened}'"
            );
        }
    }

    /// MAC-D13 drift guard (macOS-gated, mirrors
    /// owner_signing_key_path_matches_macos_genesis_driver): the path the
    /// bootstrap script seeds must equal the one the issuance verbs resolve
    /// (ops_e2e::ASSIGNMENT_SIGNING_SECRET_PATH), or distribute_assignments
    /// fails closed with "assignment signing secret missing" at the resolved
    /// path even though genesis seeded a different one.
    #[cfg(target_os = "macos")]
    #[test]
    fn bootstrap_script_assignment_secret_path_matches_issuance_verbs() {
        assert!(
            BOOTSTRAP_SCRIPT.contains(crate::ops_e2e::ASSIGNMENT_SIGNING_SECRET_PATH),
            "bootstrap-seeded secret path must match the issuers' resolved path \
             (ops_e2e::ASSIGNMENT_SIGNING_SECRET_PATH)"
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
            BOOTSTRAP_SCRIPT.contains("secure_remove_file \"${runtime_key}\""),
            "macOS bootstrap must remove the plaintext runtime key from the persistent keys/ dir (no plaintext private key at rest)"
        );
        // Stronger than the `rm -f` this asserted until 2026-07-17 (RSA-0080):
        // removal must go through secure_remove_file, which refuses to scrub
        // through a planted symlink and zeroes the bytes before unlinking. A plain
        // `rm -f` on this path is now a secrets-hygiene gate failure.
        assert!(
            !BOOTSTRAP_SCRIPT.contains("rm -f \"${runtime_key}\""),
            "the runtime key must not be removed with a plain rm -f"
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
                BOOTSTRAP_SCRIPT.contains(flag),
                "macOS bootstrap install invocation must forward {flag} so the bootstrap-time \
                 daemon uses the same lab freshness window"
            );
        }
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
    /// reaches the install-script. Assert against the REAL builder output
    /// (QH-24 extraction) that the derived utun name lands as
    /// `--wg-interface 'utun<N>'` for the lab macOS node.
    #[test]
    fn enforce_daemon_constructs_wg_interface_flag_with_derived_value() {
        let node_id = "macos-client-1";
        let expected_iface = utun_name_for_node_id(node_id);
        let script = build_auto_tunnel_enforce_install_script(
            "client",
            node_id,
            "lab-net",
            &expected_iface,
            "false",
            "",
            None,
        );
        assert!(
            script.contains(&format!("--wg-interface '{expected_iface}'")),
            "enforce_daemon must pass --wg-interface with the derived utun name: {script}"
        );
        assert!(
            script.contains(&format!("--node-id '{node_id}'")),
            "enforce_daemon must pass the node id: {script}"
        );
        // Pin that the derived name is in the legal range, not the
        // install-script default (utun9). For node_id "macos-client-1"
        // the FNV-1a hash must NOT land on 9.
        assert_ne!(
            expected_iface, "utun9",
            "derived name for macos-client-1 must not collide with the install-script default"
        );
    }

    /// QH-24 content pin for the macOS fail-closed enforcement path: the
    /// enforce re-invocation must carry `--auto-tunnel-enforce true`, all
    /// four freshness ceilings, the fail-closed SSH posture, and the C-STUN
    /// detection prelude. A regression that drops any of these silently
    /// weakens the enforced posture (the daemon would start non-enforcing,
    /// or without its traversal/SSH posture) while downstream stages assume
    /// enforcement is live.
    #[test]
    fn auto_tunnel_enforce_install_script_pins_enforce_posture() {
        let script = build_auto_tunnel_enforce_install_script(
            "exit",
            "exit-1",
            "lab-net",
            "utun1234",
            "true",
            "192.168.64.0/24",
            None,
        );

        // The whole point of the enforce path: enforcement ON, explicitly.
        assert!(
            script.contains("--auto-tunnel-enforce true"),
            "enforce must set --auto-tunnel-enforce true: {script}"
        );
        assert!(
            !script.contains("--auto-tunnel-enforce false"),
            "the enforce command must never be able to pass false: {script}"
        );
        // Freshness ceilings: the lab issues bundles once, so production
        // relies on these windows — each must be present with 86400.
        for flag in [
            "--trust-max-age-secs 86400",
            "--auto-tunnel-max-age-secs 86400",
            "--traversal-max-age-secs 86400",
            "--dns-zone-max-age-secs 86400",
        ] {
            assert!(
                script.contains(flag),
                "freshness ceiling `{flag}` must be threaded: {script}"
            );
        }
        // Fail-closed SSH posture.
        assert!(
            script.contains("--fail-closed-ssh-allow 'true'")
                && script.contains("--fail-closed-ssh-allow-cidrs '192.168.64.0/24'"),
            "fail-closed SSH allow flags must be threaded: {script}"
        );
        // Privilege boundary: sudo -n (non-interactive), against the
        // installed-by-the-binary script.
        assert!(
            script.contains("sudo -n /tmp/Install-RustyNetMacosService.sh"),
            "the install script must be re-invoked via sudo -n: {script}"
        );
        // The C-STUN prelude must survive the enforce re-render, or the
        // bootstrap-time --traversal-stun-servers would be silently dropped.
        assert!(
            script.contains("--traversal-stun-servers") && script.contains("$RN_LAB_GW:3478"),
            "STUN detection prelude must be preserved: {script}"
        );
        assert!(
            script.contains("grep -Eq '^[0-9]{1,3}(\\.[0-9]{1,3}){3}$'"),
            "the gateway must be IPv4-regex-guarded: {script}"
        );
        // Role and interface are threaded.
        assert!(script.contains("--node-role 'exit'"), "{script}");
        assert!(script.contains("--wg-interface 'utun1234'"), "{script}");
    }

    /// --lab-stun-servers: the enforce script must REPLACE the gateway
    /// detection with the literal validated CSV (cross-NAT runs point at a
    /// real STUN responder, not the same-LAN gateway).
    #[test]
    fn auto_tunnel_enforce_install_script_lab_stun_override_replaces_gateway_detection() {
        let script = build_auto_tunnel_enforce_install_script(
            "client",
            "client-1",
            "lab-net",
            "utun10",
            "false",
            "",
            Some("1.2.3.4:19302,5.6.7.8:3478"),
        );
        assert!(
            script.contains(
                "RN_STUN_FLAG='--traversal-stun-servers' ; RN_STUN_VAL='1.2.3.4:19302,5.6.7.8:3478'"
            ),
            "override must set the STUN flags to the literal CSV: {script}"
        );
        assert!(
            !script.contains("RN_LAB_GW"),
            "override must not run gateway detection: {script}"
        );
        assert!(
            !script.contains("$RN_LAB_GW:3478"),
            "gateway fallback value must be absent under override: {script}"
        );
        assert!(
            script.contains("$RN_STUN_FLAG $RN_STUN_VAL"),
            "the flags must still flow onto the install invocation: {script}"
        );
    }

    /// Single-quote escaping parity: values interpolated into single-quoted
    /// shell args must arrive escaped (`'\''`), or a crafted value could
    /// break out of the quoting. The builder takes pre-escaped values; this
    /// pins that they land verbatim inside the quoted args.
    #[test]
    fn auto_tunnel_enforce_install_script_preserves_shell_escaping() {
        // Values arrive PRE-ESCAPED from the caller (node_id.replace('\'',
        // "'\\''")), so pass the escaped forms here, exactly as enforce_daemon
        // does.
        let script = build_auto_tunnel_enforce_install_script(
            "client",
            r"node'\''x",
            r"net'\''id",
            "utun10",
            "false",
            "",
            None,
        );
        assert!(
            script.contains("--node-id 'node'\\''x'"),
            "escaped node id must round-trip through the single quotes: {script}"
        );
        assert!(
            script.contains("--network-id 'net'\\''id'"),
            "escaped network id must round-trip: {script}"
        );
        // Empty allow-list renders as an empty quoted arg, not a bare flag.
        assert!(
            script.contains("--fail-closed-ssh-allow 'false'")
                && script.contains("--fail-closed-ssh-allow-cidrs ''"),
            "the disabled SSH-allow posture must render exactly: {script}"
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
        let env = build_bootstrap_env("macos-client-1", &NodeRole::Client, &ctx).expect("env");
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

    /// MAC-D8 regression test: the macOS bootstrap must provision the
    /// membership signing credential-workspace parent alongside its sibling
    /// STATE_ROOT dirs. Without it, `stage_membership_signing_passphrase`
    /// fails closed with "credential workspace parent missing or unreadable"
    /// and the whole macOS exit cell never gets past `membership_init`.
    ///
    /// Custody matches the Linux systemd install adapter
    /// (`ops_install_systemd.rs`, /var/lib/rustynet/credentials-workspace):
    /// root:rustynetd 0700. Ops verbs run as root and create per-invocation
    /// 0700 leaves via mkdir(2); the daemon never opens this parent on macOS.
    #[test]
    fn bootstrap_provisions_credentials_workspace_root_rustynetd_0700() {
        assert!(
            BOOTSTRAP_SCRIPT.contains(
                "install -d -m 0700 -o root      -g rustynetd \"${STATE_ROOT}/credentials-workspace\""
            ),
            "setup_directories must create credentials-workspace as 0700 root:rustynetd \
             (Linux install-adapter parity)"
        );
        // Negative: a rustynetd-owned workspace parent would let the daemon
        // write into the parent, diverging from the Linux fence where only
        // root ops verbs provision per-invocation leaves.
        assert!(
            !BOOTSTRAP_SCRIPT
                .contains("install -d -m 0700 -o rustynetd -g rustynetd \"${STATE_ROOT}/credentials-workspace\"")
                && !BOOTSTRAP_SCRIPT
                    .contains("install -d -m 0755 -o rustynetd -g rustynetd \"${STATE_ROOT}/credentials-workspace\""),
            "credentials-workspace must stay root-owned 0700, not rustynetd-owned"
        );
    }

    fn live_status_transcript(node_id: &str) -> String {
        // Shape of a real `rustynet status` reply, followed by the marker the
        // in-guest probe loop echoes on exit 0.
        // `parse_status_field` splits on whitespace and matches `key=value`.
        format!("node_id={node_id} role=client peers=2\ndaemon-live\n")
    }

    #[test]
    fn a_refusing_socket_is_not_live() {
        // THE regression this replaced. On macos-utm-1 the dead predecessor's
        // socket inode survived a restart-in-place, `test -S` passed, and
        // dns_failclosed_validation then hit ECONNREFUSED 2 s before the
        // successor bound. The transcript of that state must read NOT live.
        let refused = "error [transient_failure (70)]: daemon unreachable: connect \
             /private/var/run/rustynet/rustynetd.sock failed: Connection refused (os error 61)\n\
             daemon-unreachable\n";
        assert!(!daemon_probe_reports_live(refused));
    }

    #[test]
    fn the_old_existence_token_alone_is_not_live() {
        // Guards against reverting to an existence check by any route: the old
        // probe's success token proves only that an inode is a socket.
        assert!(!daemon_probe_reports_live("socket-ready\n"));
    }

    #[test]
    fn answering_without_an_identity_is_not_live() {
        // The daemon can accept a connection while still initialising and reply
        // without a node_id. The identity challenge that gates every role
        // validator would reject that moments later, so the gate must too.
        assert!(!daemon_probe_reports_live(
            "role=client peers=0\ndaemon-live\n"
        ));
    }

    #[test]
    fn an_identity_without_the_marker_is_not_live() {
        // A node_id scraped from anywhere other than a successful status call
        // (a cached file, a log line) must not satisfy the gate on its own.
        // NOTE the `=` form. With `node_id: ...` this passed for the WRONG
        // reason -- the parser found no identity at all -- so it proved nothing
        // about the marker being required.
        assert!(!daemon_probe_reports_live("node_id=macos-client-1\n"));
    }

    #[test]
    fn a_daemon_that_answers_with_its_identity_is_live() {
        assert!(daemon_probe_reports_live(&live_status_transcript(
            "macos-client-1"
        )));
    }

    #[test]
    fn the_readiness_probe_queries_the_daemon_rather_than_stat_ing_a_path() {
        // Pin the mechanism, not just the verdict: the probe must invoke
        // `rustynet status` against the control socket. A future edit that
        // reverts to `test -S` -- which a dead predecessor's socket satisfies
        // permanently, because rustynetd does not unlink on shutdown -- must
        // break here.
        let probe = macos_daemon_readiness_probe();
        assert!(
            probe.contains(MACOS_RUSTYNET_PATH) && probe.contains("status"),
            "probe must query the daemon: {probe}"
        );
        assert!(
            probe.contains(MACOS_DAEMON_SOCKET),
            "probe must target the control socket: {probe}"
        );
        assert!(
            !probe.contains("test -S"),
            "probe must not fall back to an existence check: {probe}"
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

    /// QH-40: the two plists this script renders carry the two halves of ONE
    /// timeout setting, and they must stay coherent.
    ///
    /// The helper plist's `--timeout-ms` is the SERVER budget; the daemon
    /// plist's `--privileged-helper-timeout-ms` is the CLIENT read wait on the
    /// other end of the same socket. The script used to hardcode 30000 on the
    /// helper and pass NOTHING on the daemon, so the deployed daemon read at
    /// the 2000 ms default against a helper serving at 30000 ms — a 15x
    /// asymmetry in which any privileged command slower than 2 s failed
    /// daemon-side while the helper was still serving it (measured on
    /// macos-utm-1, MacOsHelperShutdownOrderingDesign_2026-08-27.md §8.2).
    ///
    /// This test pins the rendered shape: one configurable server value, a
    /// client value DERIVED from it, both flags actually emitted, and the
    /// fail-closed guards that reject an incoherent or unreachable pair.
    #[test]
    fn install_service_script_renders_coherent_privileged_helper_timeout_pair() {
        // The literal 30000 must be gone — it is the defect.
        assert!(
            !INSTALL_SERVICE_SCRIPT.contains("<string>30000</string>"),
            "the helper plist must not hardcode a 30000 ms timeout: it is 6x launchd's \
             measured 5 s exit ceiling and 15x the daemon's client default"
        );

        // Helper plist renders the server value from the variable.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<string>${PRIVILEGED_HELPER_TIMEOUT_MS}</string>"),
            "the helper plist must render --timeout-ms from PRIVILEGED_HELPER_TIMEOUT_MS"
        );
        // Daemon plist renders the derived client value, and actually passes
        // the flag — its absence is what deployed the mismatch.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("<string>--privileged-helper-timeout-ms</string>"),
            "the daemon plist must pass --privileged-helper-timeout-ms; omitting it \
             silently falls back to the client default regardless of the helper's value"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT
                .contains("<string>${DAEMON_PRIVILEGED_HELPER_TIMEOUT_MS}</string>"),
            "the daemon plist must render the DERIVED client timeout, not the server one"
        );

        // The client value is derived, not independently declared.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains(
                "DAEMON_PRIVILEGED_HELPER_TIMEOUT_MS=$((PRIVILEGED_HELPER_TIMEOUT_MS + \
                 PRIVILEGED_HELPER_CLIENT_TIMEOUT_MARGIN_MS))"
            ),
            "the daemon client timeout must be derived from the helper server timeout \
             plus the shared margin, so the two cannot drift apart"
        );

        // Fail-closed guards: ordering and the launchd ceiling.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("is shorter than the helper server timeout"),
            "the script must reject a client timeout below the server timeout"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains("exceeds launchd's measured"),
            "the script must reject a client timeout above launchd's exit-timeout ceiling"
        );

        // The constants must match the Rust source of truth they are keyed to.
        assert!(
            INSTALL_SERVICE_SCRIPT.contains(&format!(
                "PRIVILEGED_HELPER_TIMEOUT_MS=\"${{RUSTYNET_PRIVILEGED_HELPER_TIMEOUT_MS:-{}}}\"",
                rustynetd::privileged_helper::DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS
            )),
            "the script's helper-timeout default must equal \
             DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains(&format!(
                "PRIVILEGED_HELPER_CLIENT_TIMEOUT_MARGIN_MS={}",
                rustynetd::privileged_helper::PRIVILEGED_HELPER_CLIENT_TIMEOUT_MARGIN_MS
            )),
            "the script's client margin must equal \
             PRIVILEGED_HELPER_CLIENT_TIMEOUT_MARGIN_MS"
        );
        assert!(
            INSTALL_SERVICE_SCRIPT.contains(&format!(
                "MACOS_LAUNCHD_EXIT_TIMEOUT_MS={}",
                rustynetd::privileged_helper::MACOS_LAUNCHD_EXIT_TIMEOUT_MS
            )),
            "the script's launchd ceiling must equal MACOS_LAUNCHD_EXIT_TIMEOUT_MS"
        );

        // And the rendered pair must actually satisfy the invariant at the
        // script's own defaults.
        let server_ms = rustynetd::privileged_helper::DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS;
        let client_ms =
            rustynetd::privileged_helper::privileged_helper_client_timeout_ms(server_ms);
        rustynetd::privileged_helper::validate_privileged_helper_timeout_pair(server_ms, client_ms)
            .expect("the script's default pair must satisfy the client >= server invariant");
        rustynetd::privileged_helper::validate_macos_privileged_helper_shutdown_budget(client_ms)
            .expect("the script's default pair must fit under the launchd kill ceiling");
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
            "rn_bootstrap_windows.ps1 must wait for Status = Running"
        );
    }

    #[test]
    fn workdir_probe_and_assignment_read_render_argv_through_the_validated_seam() {
        let workdir_args = vec![
            ValidatedArg::cli_token("test").expect("token"),
            ValidatedArg::cli_token("-d").expect("token"),
            ValidatedArg::path("/Users/lab/Rustynet").expect("path"),
        ];
        let workdir_script =
            ssh::RemoteCommand::from_args("macos workdir probe", &workdir_args).expect("render");
        assert_eq!(workdir_script.as_str(), "'test' '-d' '/Users/lab/Rustynet'");

        let assignment_pub = format!("{MACOS_STATE_ROOT}/trust/assignment.pub");
        let assignment_args = vec![
            ValidatedArg::cli_token("sudo").expect("token"),
            ValidatedArg::cli_token("-n").expect("token"),
            ValidatedArg::cli_token("cat").expect("token"),
            ValidatedArg::path(&assignment_pub).expect("path"),
        ];
        let assignment_script =
            ssh::RemoteCommand::from_args("macos assignment pubkey read", &assignment_args)
                .expect("render");
        assert_eq!(
            assignment_script.as_str(),
            format!("'sudo' '-n' 'cat' '{assignment_pub}'")
        );
    }

    #[test]
    fn workdir_probe_rejects_an_out_of_shape_workdir_at_the_seam() {
        // The path class is a SHAPE check (absolute, no traversal segment, no
        // control characters); shell metacharacters inside a path are inert
        // because every token is single-quoted at render. What the class must
        // refuse before any command exists: a relative path, a traversal
        // segment, and a control character.
        assert!(ValidatedArg::path("Users/lab").is_err());
        assert!(ValidatedArg::path("/Users/../etc").is_err());
        assert!(ValidatedArg::path("/Users/lab\nrm -rf /").is_err());
        let quoted = ValidatedArg::path("/Users/lab; rm -rf /").expect("shape-valid path");
        assert_eq!(quoted.quoted(), "'/Users/lab; rm -rf /'");
    }

    // ── S2b: helper-liveness restore before the daemon restart ──────────────

    /// Shared recorder for the driver tests: each closure appends its step name
    /// so the tests can assert exactly which remote effects ran, and in order.
    #[derive(Clone, Default)]
    struct StepRecorder(std::rc::Rc<std::cell::RefCell<Vec<&'static str>>>);

    impl StepRecorder {
        fn record(&self, step: &'static str) {
            self.0.borrow_mut().push(step);
        }
        fn steps(&self) -> Vec<&'static str> {
            self.0.borrow().clone()
        }
    }

    /// Helper job present with a live socket ⇒ probe-gated no-op: no restore,
    /// and the daemon stop/start steps are the ONLY follow-ups. (No daemon
    /// restart may ever be skipped silently, and no helper restore may ever
    /// run needlessly.)
    #[test]
    fn restart_helper_present_means_no_action() {
        let rec = StepRecorder::default();
        let (rec_probe, rec_socket, rec_restore, rec_stop, rec_start) = (
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
        );
        let step = drive_restart_with_helper_liveness(
            &mut || {
                rec_probe.record("probe");
                HelperJobPresence::PresentAlive
            },
            &mut || {
                rec_socket.record("socket");
                true
            },
            &mut || {
                rec_restore.record("restore");
                Ok(1)
            },
            &mut || {
                rec_stop.record("stop");
                Ok(())
            },
            &mut || {
                rec_start.record("start");
                Ok(())
            },
        )
        .expect("present helper must proceed");
        assert_eq!(step, HelperLivenessStep::HelperPresent);
        assert_eq!(
            rec.steps(),
            vec!["probe", "socket", "stop", "start"],
            "present live helper: socket checked, no restore, straight to the daemon restart"
        );
    }

    /// Helper job absent ⇒ restore runs BEFORE the daemon restart, and the
    /// step reports what it did (bootout + bootstrap + bounded socket wait)
    /// under the `JobAbsent` reason. A dead job never consults the socket
    /// probe: the restore path is entered directly.
    #[test]
    fn restart_restores_absent_helper_before_daemon_restart() {
        let rec = StepRecorder::default();
        let (rec_probe, rec_socket, rec_restore, rec_stop, rec_start) = (
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
        );
        let step = drive_restart_with_helper_liveness(
            &mut || {
                rec_probe.record("probe");
                HelperJobPresence::Absent
            },
            &mut || {
                rec_socket.record("socket");
                true
            },
            &mut || {
                rec_restore.record("restore");
                Ok(4)
            },
            &mut || {
                rec_stop.record("stop");
                Ok(())
            },
            &mut || {
                rec_start.record("start");
                Ok(())
            },
        )
        .expect("restorable helper must proceed");
        assert_eq!(
            step,
            HelperLivenessStep::HelperRestored {
                socket_probes: 4,
                reason: HelperRestoreReason::JobAbsent,
            }
        );
        assert_eq!(
            rec.steps(),
            vec!["probe", "restore", "stop", "start"],
            "absent helper: bootout + bootstrap + socket wait strictly before the daemon \
             restart, and the socket probe is never consulted"
        );
    }

    /// Present-but-dead (loaded, no live `pid = ` line) ⇒ demoted to the
    /// restore path with the `PresentButDead` reason (review §1's exact
    /// hole: a bare `is_ok()` probe used to sail straight through).
    #[test]
    fn restart_demotes_present_dead_helper_to_the_restore_path() {
        let rec = StepRecorder::default();
        let (rec_probe, rec_socket, rec_restore, rec_stop, rec_start) = (
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
        );
        let step = drive_restart_with_helper_liveness(
            &mut || {
                rec_probe.record("probe");
                HelperJobPresence::PresentDead
            },
            &mut || {
                rec_socket.record("socket");
                panic!("a dead job must not consult the socket probe");
            },
            &mut || {
                rec_restore.record("restore");
                Ok(2)
            },
            &mut || {
                rec_stop.record("stop");
                Ok(())
            },
            &mut || {
                rec_start.record("start");
                Ok(())
            },
        )
        .expect("restorable helper must proceed");
        assert_eq!(
            step,
            HelperLivenessStep::HelperRestored {
                socket_probes: 2,
                reason: HelperRestoreReason::PresentButDead,
            }
        );
        assert_eq!(
            rec.steps(),
            vec!["probe", "restore", "stop", "start"],
            "present-but-dead helper: restore before the daemon restart"
        );
    }

    /// A live job whose socket is gone is ALSO demoted to the restore path
    /// (`PresentButDead`): the daemon's shutdown rollback dials the socket,
    /// so a live pid alone is not good enough to skip the restore.
    #[test]
    fn restart_demotes_present_alive_helper_without_socket() {
        let rec = StepRecorder::default();
        let (rec_probe, rec_socket, rec_restore, rec_stop, rec_start) = (
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
        );
        let step = drive_restart_with_helper_liveness(
            &mut || {
                rec_probe.record("probe");
                HelperJobPresence::PresentAlive
            },
            &mut || {
                rec_socket.record("socket");
                false
            },
            &mut || {
                rec_restore.record("restore");
                Ok(1)
            },
            &mut || {
                rec_stop.record("stop");
                Ok(())
            },
            &mut || {
                rec_start.record("start");
                Ok(())
            },
        )
        .expect("restorable helper must proceed");
        assert_eq!(
            step,
            HelperLivenessStep::HelperRestored {
                socket_probes: 1,
                reason: HelperRestoreReason::PresentButDead,
            }
        );
        assert_eq!(
            rec.steps(),
            vec!["probe", "socket", "restore", "stop", "start"],
            "live job, dead socket: restore before the daemon restart"
        );
    }

    /// Restore failure ⇒ the error propagates and the daemon restart commands
    /// are never issued: a restart known to lose its rollback must not run.
    #[test]
    fn restart_refused_when_helper_restore_fails() {
        let rec = StepRecorder::default();
        let (rec_probe, rec_socket, rec_restore, rec_stop, rec_start) = (
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
            rec.clone(),
        );
        let err = drive_restart_with_helper_liveness(
            &mut || {
                rec_probe.record("probe");
                HelperJobPresence::Absent
            },
            &mut || {
                rec_socket.record("socket");
                true
            },
            &mut || {
                rec_restore.record("restore");
                Err(AdapterError::Protocol {
                    message: "helper socket never appeared".to_owned(),
                })
            },
            &mut || {
                rec_stop.record("stop");
                Ok(())
            },
            &mut || {
                rec_start.record("start");
                Ok(())
            },
        )
        .expect_err("a failed restore must fail the restart");
        assert!(err.to_string().contains("helper socket never appeared"));
        assert_eq!(
            rec.steps(),
            vec!["probe", "restore"],
            "no daemon bootout/bootstrap may follow a failed helper restore"
        );
    }

    /// The tri-state classifier (review §1): `launchctl print` stdout with a
    /// live `pid = ` line ⇒ PresentAlive; loaded-but-dead stdout (exit 0, no
    /// pid line) ⇒ PresentDead — NOT absent, NOT alive.
    #[test]
    fn helper_job_stdout_classification_pins_the_pid_predicate() {
        assert_eq!(
            classify_helper_job_stdout(
                "com.rustynet.privileged-helper => {\n\tpid = 4242\n\tstate = running\n}"
            ),
            HelperJobPresence::PresentAlive
        );
        assert_eq!(
            classify_helper_job_stdout(
                "com.rustynet.privileged-helper => {\n\tstate = not running\n}"
            ),
            HelperJobPresence::PresentDead
        );
        assert_eq!(
            classify_helper_job_stdout(""),
            HelperJobPresence::PresentDead
        );
    }

    /// Restore-path ordering pin (review §Tests b): the bootout of any stale
    /// job slot is built BEFORE the bootstrap, so a loaded-but-dead job can
    /// actually be re-bootstrapped (`launchctl bootstrap` of an already-loaded
    /// job fails). The ordered pair makes the order assertable without SSH.
    #[test]
    fn helper_restore_commands_put_bootout_before_bootstrap() {
        let (bootout, bootstrap) = privileged_helper_restore_commands().expect("ok");
        assert_eq!(
            bootout.as_str(),
            "'sudo' '-n' 'launchctl' 'bootout' 'system/com.rustynet.privileged-helper'"
        );
        assert_eq!(
            bootstrap.as_str(),
            "'sudo' '-n' 'launchctl' 'bootstrap' 'system' \
             '/Library/LaunchDaemons/com.rustynet.privileged-helper.plist'"
        );
    }

    /// The three S2b remote commands render through the validated seam as
    /// plain single-quoted argv (rendering pins).
    #[test]
    fn helper_liveness_commands_render_validated_argv() {
        let probe = privileged_helper_job_probe_command().expect("fixed literals validate");
        assert_eq!(
            probe.as_str(),
            "'sudo' '-n' 'launchctl' 'print' 'system/com.rustynet.privileged-helper'"
        );
        let bootstrap = ssh::RemoteCommand::from_args(
            "macos privileged-helper bootstrap",
            &[
                ValidatedArg::cli_token("sudo").expect("token"),
                ValidatedArg::cli_token("-n").expect("token"),
                ValidatedArg::cli_token("launchctl").expect("token"),
                ValidatedArg::cli_token("bootstrap").expect("token"),
                ValidatedArg::cli_token("system").expect("token"),
                ValidatedArg::path(MACOS_PRIVILEGED_HELPER_PLIST).expect("path"),
            ],
        )
        .expect("ok");
        assert_eq!(
            bootstrap.as_str(),
            "'sudo' '-n' 'launchctl' 'bootstrap' 'system' \
             '/Library/LaunchDaemons/com.rustynet.privileged-helper.plist'"
        );
        let socket = ssh::RemoteCommand::from_args(
            "macos privileged-helper socket probe",
            &[
                ValidatedArg::cli_token("sudo").expect("token"),
                ValidatedArg::cli_token("-n").expect("token"),
                ValidatedArg::cli_token("test").expect("token"),
                ValidatedArg::cli_token("-S").expect("token"),
                ValidatedArg::path(MACOS_PRIVILEGED_HELPER_SOCKET).expect("path"),
            ],
        )
        .expect("ok");
        assert_eq!(
            socket.as_str(),
            "'sudo' '-n' 'test' '-S' '/private/var/run/rustynet/rustynetd-privileged.sock'"
        );
    }

    /// M2 site pin: both installer stop regions boot the helper out only
    /// after a bounded daemon-exit poll (`launchctl print … | grep -q 'pid = '`
    /// replaced the bare `sleep 1`), because the daemon's shutdown rollback
    /// dials the helper socket and the helper must outlive the daemon (plan
    /// MacosHelperShutdownOrderingImplementationPlan_2026-09-02 M2,
    /// Install-RustyNetMacosService.sh:604-611 and
    /// Bootstrap-RustyNetMacos.sh clear_residual_state).
    #[test]
    fn install_scripts_stop_the_helper_only_after_the_daemon_exit_wait() {
        for (name, script) in [
            ("Install-RustyNetMacosService.sh", INSTALL_SERVICE_SCRIPT),
            ("Bootstrap-RustyNetMacos.sh", BOOTSTRAP_SCRIPT),
        ] {
            let daemon_bootout = script
                .find("launchctl bootout system/com.rustynet.daemon")
                .unwrap_or_else(|| panic!("{name}: daemon bootout present"));
            let helper_bootout = script
                .find("launchctl bootout system/com.rustynet.privileged-helper")
                .unwrap_or_else(|| panic!("{name}: helper bootout present"));
            assert!(
                daemon_bootout < helper_bootout,
                "{name}: the daemon must be stopped before the helper"
            );
            let between = &script[daemon_bootout..helper_bootout];
            assert!(
                between.contains("grep -q 'pid = '")
                    && between.contains("seq 1 20")
                    && between.contains("sleep 0.5"),
                "{name}: a bounded daemon-exit pid poll must sit between the daemon \
                 bootout and the helper bootout"
            );
        }
    }

    /// Gap A (MacosEnforceRefreshParityPlan_2026-09-02 §3.1): the post-restart
    /// signed-state refresh goes through the validated-argument seam with the
    /// exact argv the C6 role-transition path and `macos_daemon_readiness_probe`
    /// use to reach the daemon control socket in-guest —
    /// `sudo -n env RUSTYNET_DAEMON_SOCKET=… /usr/local/bin/rustynet state
    /// refresh` — never a `format!`-built shell string.
    #[test]
    fn enforce_state_refresh_command_pins_exact_argv() {
        let cmd = macos_state_refresh_command().expect("validated refresh command");
        assert_eq!(
            cmd.as_str(),
            "'sudo' '-n' 'env' \
             'RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock' \
             '/usr/local/bin/rustynet' 'state' 'refresh'",
            "macOS enforce state-refresh argv drifted from the pinned seam contract"
        );
    }

    /// Gap A ordering pin: the refresh is issued ONLY after the socket wait
    /// has succeeded, and a refresh `Err` propagates as the enforce error
    /// (one attempt — no retry that could mask a failing daemon).
    #[test]
    fn enforce_refresh_runs_only_after_socket_wait_and_propagates_refresh_error() {
        // Both driver closures record into one shared log; RefCell lets the
        // two `FnMut` closures each borrow it without aliasing `&mut`.
        let log = std::cell::RefCell::new(Vec::<&'static str>::new());

        // (a) Socket wait fails ⇒ refresh never issued, wait error propagates.
        let err = drive_enforce_post_restart_refresh(
            &mut || {
                log.borrow_mut().push("wait");
                Err(AdapterError::Protocol {
                    message: "socket never came up".to_owned(),
                })
            },
            &mut || {
                log.borrow_mut().push("refresh");
                Ok("refresh ok".to_owned())
            },
        )
        .expect_err("wait failure must propagate");
        assert_eq!(
            *log.borrow(),
            vec!["wait"],
            "refresh must not run after a failed wait"
        );
        assert!(err.to_string().contains("socket never came up"));

        // (b) Wait succeeds ⇒ refresh runs, in that order.
        *log.borrow_mut() = Vec::new();
        let message = drive_enforce_post_restart_refresh(
            &mut || {
                log.borrow_mut().push("wait");
                Ok(())
            },
            &mut || {
                log.borrow_mut().push("refresh");
                Ok("refresh ok".to_owned())
            },
        )
        .expect("refresh must run after a successful wait");
        assert_eq!(*log.borrow(), vec!["wait", "refresh"]);
        assert_eq!(message, "refresh ok");

        // (c) Refresh fails after a good wait ⇒ the refresh error IS the
        // enforce error, not a warning.
        *log.borrow_mut() = Vec::new();
        let err = drive_enforce_post_restart_refresh(
            &mut || {
                log.borrow_mut().push("wait");
                Ok(())
            },
            &mut || {
                log.borrow_mut().push("refresh");
                Err(AdapterError::Protocol {
                    message: "state refresh failed".to_owned(),
                })
            },
        )
        .expect_err("refresh failure must fail the enforce");
        assert_eq!(*log.borrow(), vec!["wait", "refresh"]);
        assert!(err.to_string().contains("state refresh failed"));
    }
}
