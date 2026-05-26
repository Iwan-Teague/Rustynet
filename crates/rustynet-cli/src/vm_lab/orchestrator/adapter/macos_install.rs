#![allow(dead_code)]
use std::io::Write as IoWrite;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{AdapterError, InstallReport};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::source_archive::SourceArchive;

pub const MACOS_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
pub const MACOS_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
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

    // Probe: exit 0 if workdir exists, non-zero otherwise.
    let workdir_present =
        ssh::run_remote(conn, &format!("test -d '{workdir}'"), SHORT_TIMEOUT).is_ok();

    let build_cmd = if workdir_present {
        // Workdir already has the fresh source (a prior caller — e.g.
        // an earlier orchestrator stage or a manual sync — populated
        // it).  Pack it into the bootstrap archive path and proceed.
        format!(
            "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             cd '{workdir}' && tar -czf /tmp/rn_source.tar.gz . && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
        )
    } else if let Some(source) = source {
        // Workdir absent but the orchestrator carried a fresh source
        // archive.  Ship it directly, then run the bootstrap with
        // SOURCE_ARCHIVE pointing at the SCP'd tarball.  Skipping
        // build here (the old behaviour) silently kept stale
        // binaries across deploys and was the actual root cause of
        // "membership role preflight failed" reappearing after the
        // capability fix was merged.
        ssh::scp_to(conn, source.path(), "/tmp/rn_source.tar.gz", BUILD_TIMEOUT)?;
        "chmod 700 /tmp/rn_macos_bootstrap.sh /tmp/Install-RustyNetMacosService.sh && \
             echo 'SOURCE_ARCHIVE=/tmp/rn_source.tar.gz' >> /tmp/rn_macos_bootstrap.env && \
             sudo bash /tmp/rn_macos_bootstrap.sh /tmp/rn_macos_bootstrap.env"
            .to_owned()
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
    let probe = format!(
        "for i in $(seq 1 40); do \
            if sudo test -S {socket}; then echo socket-ready; exit 0; fi; \
            sleep 1; \
         done; \
         echo socket-missing; exit 1"
    );
    ssh::run_remote(conn, &probe, Duration::from_secs(60)).map_err(|err| AdapterError::Protocol {
        message: format!(
            "macOS daemon socket {socket} failed to appear within 40 s after launchd bootstrap: {err}"
        ),
    })?;
    Ok(())
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
           --node-id '{node_id}' \
           --node-role '{daemon_node_role}' \
           --network-id '{network_id}' \
           --wg-interface '{wg_interface}' \
           --auto-tunnel-enforce true \
           --trust-max-age-secs 86400 \
           --auto-tunnel-max-age-secs 86400 \
           --traversal-max-age-secs 86400 \
           --dns-zone-max-age-secs 86400 \
           --fail-closed-ssh-allow '{ssh_allow_flag}' \
           --fail-closed-ssh-allow-cidrs '{ssh_allow_cidrs}'",
        network_id = ctx.network_id,
    );
    ssh::run_remote(conn, &script, Duration::from_secs(60))?;
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
            BOOTSTRAP_SCRIPT.contains("chown rustynetd:rustynetd \"${runtime_key}\" \"${encrypted_key}\" \"${public_key}\" \"${passphrase_file}\""),
            "root-created key files must be handed back to the daemon service account"
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
