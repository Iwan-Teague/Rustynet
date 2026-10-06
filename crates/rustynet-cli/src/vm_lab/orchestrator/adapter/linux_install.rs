#![allow(dead_code)]
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

/// Canonical path of `rustynetd` on Linux targets.
pub const LINUX_RUSTYNETD_PATH: &str = "/usr/local/bin/rustynetd";
/// Canonical path of `rustynet` CLI on Linux targets.
pub const LINUX_RUSTYNET_PATH: &str = "/usr/local/bin/rustynet";
/// Canonical path of the `rustynet-relay` sibling binary on Linux targets.
/// Built + installed by the bootstrap script (alongside rustynetd / rustynet)
/// so a node assigned (or later role-switched to) Relay always has it; the
/// relay *service* is only enabled on Relay nodes by `DeployRelayServiceStage`.
pub const LINUX_RUSTYNET_RELAY_PATH: &str = "/usr/local/bin/rustynet-relay";
/// Canonical systemd service name.
pub const LINUX_SERVICE_NAME: &str = "rustynetd";
/// Daemon UNIX socket path.
pub const LINUX_DAEMON_SOCKET: &str = "/run/rustynet/rustynetd.sock";

const LINUX_DAEMON_READY_PROBE: &str = "for i in $(seq 1 40); do \
       if sudo -n env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock \
          /usr/local/bin/rustynet status >/dev/null 2>&1; then \
         echo daemon-ready; exit 0; \
       fi; \
       sleep 1; \
     done; \
     sudo -n systemctl status rustynetd.service --no-pager || true; \
     echo daemon-not-ready; exit 1";

/// Bootstrap script embedded at compile time from the reviewed copy at
/// `scripts/bootstrap/linux/rn_bootstrap.sh`. The script is the same one
/// the bash orchestrator ships via heredoc; factored here so the Rust
/// adapter can scp + invoke it without shelling out to the bash orchestrator.
static BOOTSTRAP_SCRIPT: &str =
    include_str!("../../../../../../scripts/bootstrap/linux/rn_bootstrap.sh");

/// Scp the `SourceArchive`, the bootstrap env, and the bootstrap script to
/// the remote host. Then run the bootstrap script and wait for the daemon
/// socket to appear. Returns an `InstallReport` on success.
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
        // Install-time: no daemon exists yet to report its id, so the
        // sanctioned bootstrap mint applies (adapter::mint_bootstrap_node_id).
        .unwrap_or_else(|| super::mint_bootstrap_node_id(alias));

    let short_timeout = Duration::from_secs(30);
    // The source archive is tens of MB and, on a cross-LAN topology, crosses
    // two physical networks — 30s (sized for the tiny script/env files) timed
    // it out on the lenovo guests (run livelab-1787835570). Give the bulk
    // transfer its own budget.
    let archive_timeout = Duration::from_secs(300);
    let build_timeout = Duration::from_secs(900); // cargo build can take a while
    let socket_timeout = Duration::from_secs(300);

    // host-cross-binary / --prebuilt-node-binaries: if the orchestrator wrote a
    // prebuilt-binary manifest for this node (host_cross_build increment 3c/4),
    // ship those binaries and tell the bootstrap to install them instead of
    // building. Absent manifest = normal build-on-guest run, unchanged. Shipped
    // FIRST so a failed transfer/verification stops before anything else is
    // copied, and so the (per-install) remote dir can go into the env file.
    let prebuilt_binaries = host_cross_build::read_host_cross_binaries(&ctx.report_dir, alias)
        .map_err(|message| AdapterError::Protocol { message })?;
    let remote = SshPrebuiltRemote {
        conn,
        run_timeout: short_timeout,
        scp_timeout: archive_timeout,
    };
    // `shipped` owns the cleanup guard: it is a NAMED binding so the
    // per-install remote dir is removed when this function returns by ANY path
    // (every `?` below, a failed bootstrap, success) — and the guard exists from
    // the instant the ship succeeds, before anything else can fail.
    let shipped = match &prebuilt_binaries {
        Some(binaries) => {
            // `--prebuilt-node-binaries` records the sha256 of each binary in the
            // run's provenance (read errors if provenance exists but lacks this
            // alias); re-check the copies on the node against it.
            let expected = host_cross_build::read_prebuilt_sha256(&ctx.report_dir, alias)
                .map_err(|message| AdapterError::Protocol { message })?;
            let shipped = ship_and_guard(&remote, alias, binaries, expected.as_ref())?;
            eprintln!(
                "[host-cross] {alias}: shipped {} prebuilt binaries to {}{}",
                binaries.len(),
                shipped.dir,
                if expected.is_some() {
                    " (sha256 verified)"
                } else {
                    ""
                }
            );
            Some(shipped)
        }
        None => None,
    };
    let prebuilt_dir: Option<String> = shipped.as_ref().map(|s| s.dir.clone());

    // Write bootstrap script to a temp file.
    let script_tmp = write_temp_file("rn_bootstrap_", ".sh", BOOTSTRAP_SCRIPT.as_bytes())?;

    // Write env file (append the host-cross flags when shipping prebuilts).
    let mut env_content = build_bootstrap_env(&node_id, &role, ctx)?;
    if let Some(dir) = &prebuilt_dir {
        env_content.push_str(&format!(
            "\nRN_PREBUILT_BINARIES=1\nRN_PREBUILT_DIR={dir}\n"
        ));
    }
    let env_tmp = write_temp_file("rn_bootstrap_env_", ".env", env_content.as_bytes())?;

    // SCP the three artefacts.
    ssh::scp_to(
        conn,
        script_tmp.as_path(),
        "/tmp/rn_bootstrap.sh",
        short_timeout,
    )?;
    ssh::scp_to(
        conn,
        env_tmp.as_path(),
        "/tmp/rn_bootstrap.env",
        short_timeout,
    )?;
    ssh::scp_to(
        conn,
        source.path(),
        "/tmp/rn_source.tar.gz",
        archive_timeout,
    )?;

    // Cleanup temp files (best-effort; ignore errors).
    let _ = std::fs::remove_file(&script_tmp);
    let _ = std::fs::remove_file(&env_tmp);

    // Run bootstrap, streaming stdout+stderr to a per-node log so cargo
    // build progress is visible in real time rather than only on completion.
    let bootstrap_log = ctx
        .report_dir
        .join("logs")
        .join(format!("bootstrap_node_{alias}.log"));
    ssh::run_remote_with_log(
        conn,
        "chmod 700 /tmp/rn_bootstrap.sh && bash /tmp/rn_bootstrap.sh /tmp/rn_bootstrap.env",
        build_timeout,
        &bootstrap_log,
    )?;
    let _ = socket_timeout; // daemon socket is checked in enforce_baseline_runtime / validate_baseline_runtime, not install.

    // Verify binaries are present and the rustynetd group exists.
    // /var/lib/rustynet/keys is `drwx------ root:root` (mode 700) by design
    // so the orchestrator's SSH user cannot stat through it without sudo.
    // Using `sudo -n` keeps the check non-interactive and consistent with
    // the bootstrap script's other privileged steps; passwordless sudo is
    // already a precondition of the bootstrap path.
    let verify_script = format!(
        "test -x {LINUX_RUSTYNETD_PATH} && test -x {LINUX_RUSTYNET_PATH} && \
         test -x {LINUX_RUSTYNET_RELAY_PATH} && \
         sudo -n test -f /var/lib/rustynet/keys/wireguard.pub && \
         getent group rustynetd >/dev/null 2>&1",
    );
    ssh::run_remote(conn, &verify_script, short_timeout)?;

    Ok(InstallReport {
        daemon_path: LINUX_RUSTYNETD_PATH.into(),
        service_name: LINUX_SERVICE_NAME.to_owned(),
    })
}

/// Template for the per-install remote dir the prebuilt binaries are shipped
/// into (`mktemp -d` fills the `X`s).
const PREBUILT_REMOTE_DIR_TEMPLATE: &str = "/tmp/rn_prebuilt.XXXXXXXX";
const PREBUILT_REMOTE_DIR_PREFIX: &str = "/tmp/rn_prebuilt.";

/// The two node operations the prebuilt ship sequence needs, injected so the
/// command ORDER and the fail-closed stops are unit-testable without ssh.
trait PrebuiltRemote {
    fn run(&self, command: &ssh::RemoteCommand) -> Result<String, AdapterError>;
    fn scp(&self, local: &std::path::Path, remote_path: &str) -> Result<(), AdapterError>;
}

struct SshPrebuiltRemote<'a> {
    conn: &'a NodeConnection,
    run_timeout: Duration,
    scp_timeout: Duration,
}

impl PrebuiltRemote for SshPrebuiltRemote<'_> {
    fn run(&self, command: &ssh::RemoteCommand) -> Result<String, AdapterError> {
        ssh::run_remote(self.conn, command.as_str(), self.run_timeout)
    }
    fn scp(&self, local: &std::path::Path, remote_path: &str) -> Result<(), AdapterError> {
        ssh::scp_to(self.conn, local, remote_path, self.scp_timeout)
    }
}

fn remote_command(
    label: &str,
    tokens: &[&str],
    path_args: &[String],
) -> Result<ssh::RemoteCommand, AdapterError> {
    let mut args = Vec::with_capacity(tokens.len() + path_args.len());
    for token in tokens {
        args.push(ValidatedArg::cli_token(token)?);
    }
    for path in path_args {
        args.push(ValidatedArg::path(path)?);
    }
    ssh::RemoteCommand::from_args(label, &args)
}

/// `rm -rf <dir>` for a per-install prebuilt dir; refuses anything that is not
/// under the `/tmp/rn_prebuilt.` prefix.
fn remove_dir_command(dir: &str) -> Result<ssh::RemoteCommand, AdapterError> {
    check_prebuilt_remote_dir(dir)?;
    remote_command("prebuilt dir cleanup", &["rm", "-rf"], &[dir.to_owned()])
}

/// The remote dir is interpolated into the bootstrap env file and later into
/// commands, so accept only `/tmp/rn_prebuilt.` + alphanumerics.
fn check_prebuilt_remote_dir(dir: &str) -> Result<(), AdapterError> {
    let ok = dir
        .strip_prefix(PREBUILT_REMOTE_DIR_PREFIX)
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric()));
    if ok {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!("mktemp returned an unexpected prebuilt dir '{dir}'"),
        })
    }
}

/// Removes the per-install remote dir (best-effort) when dropped, unless
/// disarmed. Held from the moment `mktemp` succeeds until the install function
/// returns, so EVERY exit path — a failed scp or hash check, a failed later
/// copy, a failed bootstrap, success — leaves no copies of the binaries behind
/// on a small node's /tmp. (A failed bootstrap deliberately does not keep the
/// dir for diagnosis: it only holds copies of orchestrator-side files, and the
/// bootstrap log is written locally.)
struct RemoteDirCleanup<'a> {
    remote: &'a dyn PrebuiltRemote,
    dir: String,
    armed: bool,
}

impl<'a> RemoteDirCleanup<'a> {
    fn new(remote: &'a dyn PrebuiltRemote, dir: String) -> Self {
        Self {
            remote,
            dir,
            armed: true,
        }
    }

    /// Hand the dir back without removing it (ownership moves to the caller,
    /// which installs its own guard).
    fn disarm(mut self) -> String {
        self.armed = false;
        std::mem::take(&mut self.dir)
    }
}

impl Drop for RemoteDirCleanup<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Ok(rm) = remove_dir_command(&self.dir)
        {
            if let Err(err) = self.remote.run(&rm) {
                eprintln!(
                    "[host-cross] warning: could not remove {} on the node: {err}",
                    self.dir
                );
            }
        }
    }
}

/// A shipped per-install dir together with the guard that removes it when this
/// value is dropped.
struct ShippedPrebuilt<'a> {
    dir: String,
    _cleanup: RemoteDirCleanup<'a>,
}

/// [`ship_prebuilt_binaries`], then hand the dir over to a guard that lives as
/// long as the returned value (see `install_daemon`).
fn ship_and_guard<'a>(
    remote: &'a dyn PrebuiltRemote,
    alias: &str,
    binaries: &[std::path::PathBuf],
    expected: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<ShippedPrebuilt<'a>, AdapterError> {
    let dir = ship_prebuilt_binaries(remote, alias, binaries, expected)?;
    Ok(ShippedPrebuilt {
        dir: dir.clone(),
        _cleanup: RemoteDirCleanup::new(remote, dir),
    })
}

/// Ship the host-built binaries to a fresh, owner-only per-install dir on the
/// node and return that dir. Sequence (each step fail-closed, in this order):
/// `mktemp -d` (atomic, unpredictable name, mode 700, owned by the ssh user —
/// so another user cannot pre-create or swap the dir) -> `chmod 700` -> scp
/// each binary -> `sha256sum` -> compare with the orchestrator-verified hashes
/// (when `expected` is `Some`) -> `chmod 0555` the binaries. Any failure stops
/// before the chmod 0555 and, because the caller ships before scp'ing the
/// bootstrap env/archive, before the bootstrap runs. A failure after the dir
/// exists removes it again (best-effort) before returning the error.
fn ship_prebuilt_binaries(
    remote: &dyn PrebuiltRemote,
    alias: &str,
    binaries: &[std::path::PathBuf],
    expected: Option<&std::collections::BTreeMap<String, String>>,
) -> Result<String, AdapterError> {
    let mktemp = remote_command(
        "prebuilt dir",
        &["mktemp", "-d"],
        &[PREBUILT_REMOTE_DIR_TEMPLATE.to_owned()],
    )?;
    let dir = remote.run(&mktemp)?.trim().to_owned();
    check_prebuilt_remote_dir(&dir)?;
    // Dropped (=> rm -rf) by any `?` below; disarmed only on success.
    let cleanup = RemoteDirCleanup::new(remote, dir.clone());
    remote.run(&remote_command(
        "prebuilt dir mode",
        &["chmod", "700"],
        &[dir.clone()],
    )?)?;
    let mut shipped: Vec<String> = Vec::with_capacity(binaries.len());
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
        remote.scp(bin.as_path(), &format!("{dir}/{name}"))?;
        shipped.push(name.to_owned());
    }
    let remote_paths: Vec<String> = shipped.iter().map(|n| format!("{dir}/{n}")).collect();
    if let Some(expected) = expected {
        let output = remote.run(&remote_command(
            "prebuilt sha256 check",
            &["sha256sum"],
            &remote_paths,
        )?)?;
        verify_remote_sha256(&output, &dir, expected, &shipped).map_err(|message| {
            AdapterError::Protocol {
                message: format!("{alias}: {message}"),
            }
        })?;
    }
    remote.run(&remote_command(
        "prebuilt binary mode",
        &["chmod", "0555"],
        &remote_paths,
    )?)?;
    Ok(cleanup.disarm())
}

/// Compare `sha256sum <dir>/<name>...` output from the node with the
/// hashes verified on the orchestrator. Fail closed: every shipped binary must
/// have an expected hash AND appear in the output with exactly that hash, so a
/// short or garbled output can never pass.
fn verify_remote_sha256(
    output: &str,
    dir: &str,
    expected: &std::collections::BTreeMap<String, String>,
    shipped: &[String],
) -> Result<(), String> {
    let mut remote: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for line in output.lines().filter(|l| !l.trim().is_empty()) {
        let mut parts = line.split_whitespace();
        let (Some(hash), Some(path), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(format!("unparseable sha256sum output line '{line}'"));
        };
        if let Some(name) = path
            .strip_prefix(dir)
            .and_then(|rest| rest.strip_prefix('/'))
        {
            remote.insert(name, hash);
        }
    }
    for name in shipped {
        let want = expected
            .get(name)
            .ok_or_else(|| format!("no verified sha256 recorded for prebuilt '{name}'"))?;
        let got = remote
            .get(name.as_str())
            .ok_or_else(|| format!("node sha256sum output has no entry for prebuilt '{name}'"))?;
        if !got.eq_ignore_ascii_case(want) {
            return Err(format!(
                "prebuilt '{name}' on the node has sha256 {got}, expected {want} (fail closed)"
            ));
        }
    }
    Ok(())
}

/// Enforce baseline runtime: re-run `install-systemd` with
/// `auto_tunnel_enforce=true` so the daemon applies assignment bundles.
///
/// Called by `EnforceBaselineRuntime` after all verifier keys are in place.
/// This is distinct from `start_daemon` (plain `systemctl start`, a no-op if
/// the daemon is already running) because:
///  * Bootstrap starts the daemon with `auto_tunnel_enforce=false`.
///  * After assignment/traversal/dns-zone bundles are distributed we must
///    restart the daemon with enforcement enabled and a fresh trust token.
///  * `rustynet ops e2e-enforce-host` wraps `ops install-systemd` with the
///    correct env and refreshes trust evidence immediately before restart.
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
    // F2 fail-closed: EnforceBaselineRuntime is transitively downstream of
    // CollectPubkeys, so reaching enforce with no daemon-reported id means a
    // skip/reuse path bypassed collection. Never mint a label-derived
    // identity here — a guessed `--node-id` is exactly the query-under-a-
    // guessed-identity shape the macOS anchor stage refuses (QH-68 class).
    let node_id = ctx
        .node_ids
        .get(alias)
        .cloned()
        .ok_or_else(|| AdapterError::Protocol {
            message: format!(
                "{alias}: no daemon-reported node id recorded (collect_pubkeys must run \
                 first); refusing to mint a '{alias}-bootstrap' identity for enforcement"
            ),
        })?;
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
        .map_err(|message| AdapterError::Protocol { message })?;
    // SSH_ALLOW_CIDRS may contain commas; quote the whole arg.
    // Backslash-escape any single quotes in the cidr string (none expected in practice).
    let ssh_allow_cidrs = ctx.ssh_allow_cidrs.replace('\'', "'\\''");
    // node_id flows from inventory/daemon status into a single-quoted arg below;
    // escape embedded single quotes for parity with ssh_allow_cidrs so a stray
    // quote cannot break out of the quoting (defence-in-depth).
    let node_id = node_id.replace('\'', "'\\''");

    // Detect the SSH user's home directory for the source root that the
    // bootstrap script extracts to (`${HOME}/Rustynet`).
    let home = ssh::run_remote(conn, "echo $HOME", Duration::from_secs(10))?
        .trim()
        .to_owned();
    if home.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine $HOME on remote for e2e-enforce-host".to_owned(),
        });
    }
    let src_dir = format!("{home}/Rustynet");

    // Run e2e-enforce-host as root: re-installs systemd units with
    // auto_tunnel_enforce=true and refreshes trust evidence before restart.
    // Budget: install-systemd rebuild is fast (binaries already present);
    // add 120 s for daemon restart + socket readiness poll.
    //
    // RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400: the assignment bundle is issued
    // by the exit node during DistributeAssignments and may be several minutes
    // old by the time enforce_daemon runs.  The production default (300 s) is
    // correct for nodes with an active assignment-refresh timer, but the lab
    // pipeline distributes a single bundle and doesn't rotate it.  86400 s
    // matches the Windows lab setting and lets the daemon start successfully.
    //
    // RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400: the traversal bundle is issued
    // with a 120-s TTL but the lab pipeline does not refresh it, so the same
    // extended window is needed here.
    //
    // RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400: the dns-zone bundle is distributed
    // once by DistributeDnsZone and is not refreshed.  The default 300-s window
    // causes dns_alarm_state=error once the bundle ages past 5 minutes, which
    // can block traffic validation in longer pipeline runs.
    //
    // --lab-stun-servers override: when configured, the validated numeric CSV
    // REPLACES the gateway-derived default (cross-NAT runs point at a real
    // STUN responder instead of the same-LAN gateway). Each entry already
    // parsed as a SocketAddr at flag-parse time — SocketAddr Display is
    // numeric-only, so rendering it into the script is the typed path (no
    // untrusted interpolation).
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
    let script = build_enforce_script(
        role_str,
        &node_id,
        &src_dir,
        &ssh_allow_cidrs,
        lab_stun_csv.as_deref(),
    );
    ssh::run_remote(conn, &script, Duration::from_secs(120))?;
    Ok(())
}

/// Render the remote `e2e-enforce-host` invocation for [`enforce_daemon`].
///
/// RUSTYNET_TRAVERSAL_STUN_SERVERS (C-STUN, BashOrchestratorRetirementProgram):
/// an empty value disables srflx candidate gathering entirely, so the lab
/// enforce pass threads the guest's default gateway on 3478 (the UTM host as
/// seen from the guest's subnet — a valid ip:port, which is all the daemon's
/// socket-address parser accepts). A live responder there is optional:
/// gathering fails soft on a bounded timeout and same-LAN validation rides
/// host candidates either way. Detected on the guest because each guest's
/// subnet (and therefore gateway) differs; empty detection leaves the env
/// var unset, preserving the pre-C-STUN behaviour. This mirrors the identical
/// threading in rn_bootstrap.sh — the enforce pass rewrites the systemd unit,
/// so without it the bootstrap-time value would be silently dropped here.
///
/// `lab_stun_servers` (--lab-stun-servers): when `Some(csv)`, the numeric
/// ip:port CSV REPLACES the gateway detection entirely — the env var is set
/// to the literal override (each entry validated as a SocketAddr upstream, so
/// the interpolation carries only numeric characters, dots, colons, and
/// commas). `None` preserves the C-STUN gateway detection byte-identically.
fn build_enforce_script(
    role_str: &str,
    node_id: &str,
    src_dir: &str,
    ssh_allow_cidrs: &str,
    lab_stun_servers: Option<&str>,
) -> String {
    let stun_prelude = match lab_stun_servers {
        Some(csv) => format!("RN_STUN_ENV=\"RUSTYNET_TRAVERSAL_STUN_SERVERS={csv}\";"),
        // Plain string literal, NOT a format! template: braces are literal
        // awk syntax here (a `{{` escape would ship a broken awk program).
        None => "RN_LAB_GW=\"$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')\"; \
                 RN_STUN_ENV=''; \
                 if [ -n \"$RN_LAB_GW\" ]; then RN_STUN_ENV=\"RUSTYNET_TRAVERSAL_STUN_SERVERS=$RN_LAB_GW:3478\"; fi;"
            .to_owned(),
    };
    format!(
        "{stun_prelude} \
         sudo -n env \
         PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin \
         RUSTYNET_INSTALL_SOURCE_ROOT={src_dir} \
         RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400 \
         RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400 \
         RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400 \
         $RN_STUN_ENV \
         {LINUX_RUSTYNET_PATH} ops e2e-enforce-host \
         --role {role_str} \
         --node-id '{node_id}' \
         --src-dir '{src_dir}' \
         --ssh-allow-cidrs '{ssh_allow_cidrs}'"
    )
}

/// Install script for the relay verifier public key under the product
/// custody directory.
///
/// `/etc/rustynet` carries product posture `0750 root:rustynetd`
/// (`rustynetd/src/linux_runtime_acls.rs`, enforced by
/// `scripts/e2e/live_lab_common.sh`). The directory creation therefore pins
/// the FULL posture — mode AND owner AND group — so that if this stage is
/// the one to create it (first bring-up, before
/// `distribute_verifier_key` or the live install ever ran), it is born
/// traversable by the `rustynetd` group. A bare `install -d -m 0750` would
/// create it `root:root`, which the daemon's custody evaluation cannot
/// traverse. Only the key FILE is then installed (public key, `0644`).
fn linux_relay_verifier_install_script() -> String {
    "sudo -n sh -c 'install -d -m 0750 -o root -g rustynetd /etc/rustynet && \
     install -m 0644 /tmp/rn-relay-verifier.pub /etc/rustynet/relay-verifier.pub && \
     rm -f /tmp/rn-relay-verifier.pub'"
        .to_owned()
}

/// Deploy the `rustynet-relay` sibling service onto this Relay node so the
/// `relay_validation` stage has a live relay to prove.
///
/// The relay binary is already present at [`LINUX_RUSTYNET_RELAY_PATH`] (built +
/// installed by the bootstrap script while the network was open). This step
/// supplies the two things the unit needs that the baseline install does not:
///
///   1. The relay `--verifier-key`: `rustynet-relay` loads it as raw 32 bytes,
///      and its systemd unit fail-closes (`ExecStartPre`) if the file is absent.
///      We derive it from the assignment authority public key the orchestrator
///      already distributed to this node as `/etc/rustynet/assignment.pub` (hex)
///      — the same control-plane verifier the relay must trust, and a PUBLIC key
///      (never secret), so it is safe to read, decode, and re-place. Decoding to
///      raw bytes happens in Rust (fail-closed on a short / non-hex key); the
///      bytes are shipped via scp + `install` so no data is ever interpolated
///      into a shell string and the guest needs no `xxd`.
///   2. The installed + enabled `rustynet-relay.service`, via the shared
///      `ops install-systemd-relay` helper — the one hardened relay-install path
///      (also used by the role-transition orchestrator). It reads the unit from
///      `scripts/systemd/rustynet-relay.service` relative to the source root the
///      bootstrap extracted to (`$HOME/Rustynet`), so it runs with that cwd.
///
/// Fail-closed throughout: a missing assignment key, a malformed key, or a
/// failed install all surface as `Err`.
pub fn deploy_relay_service(conn: &NodeConnection) -> Result<(), AdapterError> {
    let short_timeout = Duration::from_secs(30);

    // 1. Read the already-distributed assignment authority pubkey (hex). It
    //    lives at /etc/rustynet/assignment.pub (placed by
    //    distribute_verifier_key(Assignment) during DistributeAssignments).
    //    /etc/rustynet is 0750 root:rustynetd, so read it with sudo -n.
    let assignment_hex = ssh::run_remote(
        conn,
        "sudo -n cat /etc/rustynet/assignment.pub",
        short_timeout,
    )?;

    // 2. Decode hex -> raw 32 bytes (fail-closed); the relay --verifier-key
    //    loader requires exactly 32 raw bytes.
    let verifier_bytes = decode_assignment_pubkey_hex(&assignment_hex)
        .map_err(|message| AdapterError::Protocol { message })?;

    // 3. Ship the raw verifier key to the host and install it at the unit's
    //    fail-closed-checked path (mode 0644). scp the bytes (no shell data
    //    interpolation), then install with a constant command.
    let tmp = write_temp_file("rn_relay_verifier_", ".pub", &verifier_bytes)?;
    let ship = ssh::scp_to(
        conn,
        tmp.as_path(),
        "/tmp/rn-relay-verifier.pub",
        short_timeout,
    );
    let _ = std::fs::remove_file(&tmp);
    ship?;
    ssh::run_remote(conn, &linux_relay_verifier_install_script(), short_timeout)?;

    // 4. Drop any /etc/default/rustynet-relay left by a PREVIOUS run before
    //    installing the unit. The unit sources it with
    //    `EnvironmentFile=-/etc/default/rustynet-relay`, so a stale file's
    //    `RUSTYNET_RELAY_BIND` overrides every `Environment=` default in the
    //    freshly installed unit. When a guest's LAN address changes between
    //    runs (routine here: vmnet reassigns addresses on start order), the
    //    relay then binds an address the host no longer holds, dies with
    //    EADDRNOTAVAIL, and crash-loops — observed live in run
    //    `live-lab-linux-relay-fwd9-20260907-172608`, where a file written
    //    2026-09-06 pinned `192.168.64.10:4500` on a guest that had since
    //    moved to 192.168.65.5. That deadlocks the relay track: the HP-3
    //    provisioner which rewrites this file with the live address runs
    //    inside `relay_forwards_frame_validation`, which is gated behind the
    //    `relay_validation` that the stale bind breaks. Removing it restores
    //    the unit's own loopback-only default (the documented posture: an
    //    operator must opt in before the relay serves off-host peers), which
    //    the HP-3 provisioner still widens when it runs.
    let drop_stale_override = ssh::RemoteCommand::from_args(
        "relay stale environment override",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("rm")?,
            ValidatedArg::cli_token("-f")?,
            ValidatedArg::path("/etc/default/rustynet-relay")?,
        ],
    )?;
    ssh::run_remote(conn, drop_stale_override.as_str(), short_timeout)?;

    // 5. Install + enable + start rustynet-relay.service via the shared helper.
    //    It reads scripts/systemd/rustynet-relay.service relative to cwd, so run
    //    from the source root the bootstrap extracted to ($HOME/Rustynet). The
    //    source dir is passed only inside a single-quoted env assignment; the
    //    executed shell body is a compile-time constant.
    let home = ssh::run_remote(conn, "echo $HOME", Duration::from_secs(10))?
        .trim()
        .to_owned();
    if home.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine $HOME on remote for install-systemd-relay".to_owned(),
        });
    }
    let src_dir = format!("{home}/Rustynet");
    let src_dir_esc = src_dir.replace('\'', "'\\''");
    // Absolute CLI path (not bare `rustynet`) so the install never depends on
    // sudo's PATH inside the root `sh -c`. The executed shell body stays a
    // compile-time constant; only the source dir is a (single-quoted) value.
    let install_cmd = format!(
        "sudo -n env RN_SRC='{src_dir_esc}' sh -c 'cd \"$RN_SRC\" && {LINUX_RUSTYNET_PATH} ops install-systemd-relay'"
    );
    ssh::run_remote(conn, &install_cmd, Duration::from_secs(120))?;

    // 6. Fail closed on a unit that installed but did not come up. The helper
    //    exits 0 once systemd accepts the unit, so without this check a relay
    //    that crash-loops (bad bind, missing key, restart-limit hit) is
    //    reported as a clean deploy and the failure only surfaces one stage
    //    later as an unexplained `relay_validation` failure. Report the unit
    //    state with the journal tail so the cause is in this stage's evidence.
    let unit_state_query = ssh::RemoteCommand::from_args(
        "relay unit state",
        &[
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("systemctl")?,
            ValidatedArg::cli_token("is-active")?,
            ValidatedArg::service(RELAY_SERVICE_NAME)?,
        ],
    )?;
    // `systemctl is-active` exits non-zero for an inactive unit, so a dead
    // relay arrives here as `Err` exactly like a transport failure would.
    // Treat any failure as "not active" and let the journal read below explain
    // which it was: a transport fault leaves the journal unavailable too, and
    // that pair is reported verbatim. Never treat an unreadable state as
    // healthy.
    let state = ssh::run_remote(conn, unit_state_query.as_str(), short_timeout)
        .unwrap_or_else(|err| format!("<unit state unavailable: {err}>"));
    if state.trim() != "active" {
        let journal_query = ssh::RemoteCommand::from_args(
            "relay unit journal tail",
            &[
                ValidatedArg::cli_token("sudo")?,
                ValidatedArg::cli_token("-n")?,
                ValidatedArg::cli_token("journalctl")?,
                ValidatedArg::cli_token("-u")?,
                ValidatedArg::service(RELAY_SERVICE_NAME)?,
                ValidatedArg::cli_token("-n")?,
                ValidatedArg::cli_token("12")?,
                ValidatedArg::cli_token("--no-pager")?,
            ],
        )?;
        let journal = ssh::run_remote(conn, journal_query.as_str(), short_timeout)
            .unwrap_or_else(|err| format!("<journal unavailable: {err}>"));
        return Err(AdapterError::Protocol {
            message: format!(
                "rustynet-relay.service is {} after install (expected active); journal tail: {}",
                state.trim(),
                journal.trim()
            ),
        });
    }
    Ok(())
}

/// Service unit the post-install relay health gate inspects. Both the state
/// query and the journal tail are built as validated argv through
/// `RemoteCommand` + `ValidatedArg`, so neither reaches the remote sink as an
/// interpolated string and neither needs a shell.
const RELAY_SERVICE_NAME: &str = "rustynet-relay.service";

/// Start the rustynetd systemd service.
///
/// In the orchestration pipeline, prefer `enforce_daemon` over this function:
/// `enforce_daemon` transitions the daemon from its bootstrap
/// (`auto_tunnel_enforce=false`) to an enforcement-enabled configuration.
/// `start_daemon` starts systemd, then waits until the daemon accepts a real
/// status request. This closes the systemd-active -> socket-accepting race.
pub fn start_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "start")?;
    wait_for_linux_daemon_ready(conn)
}

/// Stop the rustynetd systemd service.
pub fn stop_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "stop")
}

/// Restart the rustynetd systemd service.
pub fn restart_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    run_systemctl(conn, "restart")?;
    wait_for_linux_daemon_ready(conn)
}

/// Stop the service and remove daemon binaries and configuration.
pub fn uninstall_daemon(conn: &NodeConnection) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    // Stop service (best-effort — it may not be running).
    let _ = ssh::run_remote(
        conn,
        "if sudo systemctl is-active rustynetd >/dev/null 2>&1; then sudo systemctl stop rustynetd; fi",
        timeout,
    );
    // Remove WireGuard interface if still present (daemon may not have torn it
    // down, e.g. if the previous run's cleanup stage was skipped).  Best-effort.
    let _ = ssh::run_remote(
        conn,
        "sudo ip link delete rustynet0 2>/dev/null || true",
        Duration::from_secs(10),
    );
    // Tear down the rustynet-relay sibling service first (best-effort — most
    // nodes never had it). Then remove both binaries, both unit files, the
    // relay env file, and all state dirs (incl the relay replay store under
    // /var/lib/rustynet and the relay runtime dir). Leaving a stranded relay
    // unit/binary would let a prior run's relay keep binding :4500 across runs.
    ssh::run_remote(
        conn,
        &format!(
            "sudo systemctl stop rustynet-relay.service 2>/dev/null || true; \
             sudo systemctl disable rustynet-relay.service 2>/dev/null || true; \
             sudo rm -f {LINUX_RUSTYNETD_PATH} {LINUX_RUSTYNET_PATH} {LINUX_RUSTYNET_RELAY_PATH} \
                        /etc/systemd/system/rustynetd.service /etc/systemd/system/rustynet-relay.service \
                        /etc/default/rustynet-relay && \
             sudo systemctl daemon-reload 2>/dev/null || true && \
             sudo rm -rf /etc/rustynet /var/lib/rustynet /run/rustynet /run/rustynet-relay",
        ),
        timeout,
    )?;
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn run_systemctl(conn: &NodeConnection, action: &str) -> Result<(), AdapterError> {
    let timeout = Duration::from_secs(60);
    // QH-01 Step 4c: argv-shaped command rendered through the validated seam
    // (systemctl action ∈ {start, stop, restart} from internal callers).
    let args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("systemctl")?,
        ValidatedArg::cli_token(action)?,
        ValidatedArg::service(LINUX_SERVICE_NAME)?,
    ];
    let script = ssh::RemoteCommand::from_args("linux systemd {action}", &args)?;
    ssh::run_remote(conn, script.as_str(), timeout)?;
    Ok(())
}

fn wait_for_linux_daemon_ready(conn: &NodeConnection) -> Result<(), AdapterError> {
    let output = ssh::run_remote(conn, LINUX_DAEMON_READY_PROBE, Duration::from_secs(60))?;
    if output.contains("daemon-ready") {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!(
                "Linux daemon failed readiness probe at {LINUX_DAEMON_SOCKET}: {}",
                output.trim()
            ),
        })
    }
}

/// Env line telling rn_bootstrap.sh to build the daemon with the
/// `lab-substrate` cargo feature. Emitted ONLY for a vxlan run that actually
/// provisioned the overlay; every other run keeps the env byte-identical to
/// the pre-substrate format (the bootstrap treats the variable as unset).
fn lab_substrate_env_line(
    substrate_record: Option<
        &crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord,
    >,
) -> &'static str {
    match substrate_record {
        Some(record) if record.substrate_id == "vxlan" && record.provisioned => {
            "RN_LAB_SUBSTRATE=1\n"
        }
        _ => "",
    }
}

fn build_bootstrap_env(
    node_id: &str,
    role: &NodeRole,
    ctx: &OrchestrationContext,
) -> Result<String, AdapterError> {
    let role_str = role
        .daemon_node_role_for_platform(&VmGuestPlatform::Linux)
        .map_err(|message| AdapterError::Protocol { message })?;
    let ssh_allow_cidrs = &ctx.ssh_allow_cidrs;
    let network_id = &ctx.network_id;
    // --lab-stun-servers override: rn_bootstrap.sh reads
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
    // --linux-backend pin: rn_bootstrap.sh forwards RUSTYNET_BACKEND to
    // `ops install-systemd`, which otherwise keeps whatever value the guest's
    // /etc/default/rustynetd already carries (guest history), so the line is
    // only emitted when the operator pinned a backend. The value is one of
    // the allow-listed literals from `parse_linux_backend` — the bootstrap's
    // RSA-0068 env-file parser accepts only the allow-listed keys, so nothing
    // else may reach it.
    let linux_backend_line = match ctx.linux_backend.as_deref() {
        Some(mode) if crate::vm_lab::LINUX_BACKEND_MODES.contains(&mode) => {
            format!("RUSTYNET_BACKEND={mode}\n")
        }
        Some(other) => {
            return Err(AdapterError::Protocol {
                message: format!(
                    "refusing to write non-allow-listed RUSTYNET_BACKEND value {other:?} into the bootstrap env"
                ),
            });
        }
        None => String::new(),
    };
    Ok(format!(
        "ROLE={role_str}\nNODE_ID={node_id}\nNETWORK_ID={network_id}\nSSH_ALLOW_CIDRS={ssh_allow_cidrs}\nSOURCE_ARCHIVE=/tmp/rn_source.tar.gz\nRUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS=2\n{lab_stun_line}{linux_backend_line}{}",
        lab_substrate_env_line(ctx.substrate_record.as_ref())
    ))
}

/// Write `content` to a temp file with the given prefix and suffix.
/// Returns the temp file path.
fn write_temp_file(
    prefix: &str,
    suffix: &str,
    content: &[u8],
) -> Result<std::path::PathBuf, AdapterError> {
    // Bootstrap runs per-node in parallel. A PID-only name lets workers
    // overwrite one another's role/node-id env file before SCP, producing a
    // valid build with the wrong identity. `tempfile` creates a collision-free
    // mode-0600 file; persist it only until the caller finishes SCP.
    super::write_secure_temp_file(prefix, suffix, content)
}

#[cfg(test)]
mod relay_deploy_hygiene_tests {
    //! Pins the two properties that made run
    //! `live-lab-linux-relay-fwd9-20260907-172608` unrecoverable: a stale
    //! `/etc/default/rustynet-relay` surviving the deploy, and a deploy that
    //! reports success while the unit crash-loops.
    use super::RELAY_SERVICE_NAME;

    /// The deploy MUST remove the previous run's environment override before
    /// installing the unit. Without this the unit's
    /// `EnvironmentFile=-/etc/default/rustynet-relay` re-applies a bind
    /// address the guest may no longer hold (EADDRNOTAVAIL crash-loop).
    #[test]
    fn deploy_removes_the_stale_relay_environment_override() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("pub fn deploy_relay_service(")
            .expect("relay deploy fn must exist");
        let body = &source[start..];
        let end = body[1..]
            .find("\npub fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains("ValidatedArg::path(\"/etc/default/rustynet-relay\")"),
            "deploy must drop the previous run's env override, as validated argv"
        );
        let removal = body
            .find("ValidatedArg::path(\"/etc/default/rustynet-relay\")")
            .expect("removal present");
        let install = body
            .find("ops install-systemd-relay")
            .expect("install present");
        assert!(
            removal < install,
            "the stale override must be removed BEFORE the unit is installed"
        );
    }

    /// The deploy MUST verify the unit actually came up. A helper that exits 0
    /// once systemd accepts the unit says nothing about whether it stayed up.
    #[test]
    fn deploy_fails_closed_when_the_unit_is_not_active() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("pub fn deploy_relay_service(")
            .expect("relay deploy fn must exist");
        let body = &source[start..];
        let end = body[1..]
            .find("\npub fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len());
        let body = &body[..end];
        assert!(
            body.contains("\"is-active\""),
            "deploy must query the unit state after install"
        );
        assert!(
            body.contains("!= \"active\""),
            "deploy must compare against the exact healthy state token"
        );
        assert!(
            body.contains("AdapterError::Protocol"),
            "a non-active unit must fail the deploy, not warn"
        );
    }

    /// Both post-install queries are built as validated argv, never as an
    /// interpolated string at the remote sink, and both name the same unit.
    /// The shell forms they replaced (`|| true`, `2>&1 | tail`) are gone: an
    /// unreadable state is handled in Rust as "not active" rather than by a
    /// shell that would also mask a transport failure.
    #[test]
    fn both_post_install_queries_are_validated_argv_for_the_same_unit() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("pub fn deploy_relay_service(")
            .expect("relay deploy fn must exist");
        let body = &source[start..];
        let end = body[1..]
            .find("\npub fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len());
        let body = &body[..end];
        assert_eq!(RELAY_SERVICE_NAME, "rustynet-relay.service");
        assert_eq!(
            body.matches("ValidatedArg::service(RELAY_SERVICE_NAME)")
                .count(),
            2,
            "the state query and the journal tail must both name the unit through ValidatedArg"
        );
        assert!(
            body.contains("\"journalctl\""),
            "journal tail must be queried"
        );
        for shell_form in ["|| true", "2>&1", "| tail", "2>/dev/null"] {
            assert!(
                !body.contains(shell_form),
                "post-install queries must not reach the sink through a shell ({shell_form})"
            );
        }
        assert!(
            body.contains("unit state unavailable"),
            "an unreadable unit state must be reported, never read as healthy"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    /// Custody pin: the relay verifier install must create `/etc/rustynet`
    /// (whenever this stage is the one to create it) with the FULL product
    /// posture `0750 root:rustynetd` — a bare `install -d -m 0750` would
    /// create it `root:root`, untraversable by the `rustynetd` group the
    /// daemon's custody evaluation requires. Mutation caught: dropping
    /// `-o root -g rustynetd` from the directory install goes RED here.
    #[test]
    fn relay_verifier_install_uses_the_full_product_custody_posture() {
        let script = linux_relay_verifier_install_script();
        assert!(
            script.contains("install -d -m 0750 -o root -g rustynetd /etc/rustynet"),
            "directory creation must carry mode AND owner AND group: {script}"
        );
        let file_install =
            "install -m 0644 /tmp/rn-relay-verifier.pub /etc/rustynet/relay-verifier.pub";
        assert!(
            script.contains(file_install),
            "only the key FILE is installed, 0644: {script}"
        );
    }

    /// RSA-0068 witness: the env-file argument must never be interpreted as
    /// bash. The old `source "$1"` gave any shell metacharacter in the file
    /// the script's (sudoer) privileges; the strict KEY=VALUE parser
    /// replaces it, over a fixed allowlist of exactly the keys this
    /// orchestrator writes.
    #[test]
    fn bootstrap_script_parses_the_env_file_instead_of_sourcing_it() {
        assert!(
            !BOOTSTRAP_SCRIPT.contains("source \"$1\""),
            "the env-file argument must not be sourced: that is the RSA-0068 root code-exec sink"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("load_bootstrap_env \"$1\""),
            "the env file must go through the strict KEY=VALUE parser"
        );
        for key in [
            "ROLE",
            "NODE_ID",
            "NETWORK_ID",
            "SSH_ALLOW_CIDRS",
            "SOURCE_ARCHIVE",
            "RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS",
            "RUSTYNET_LAB_STUN_SERVERS",
            "RUSTYNET_BACKEND",
            "RN_PREBUILT_BINARIES",
            "RN_PREBUILT_DIR",
        ] {
            assert!(
                BOOTSTRAP_SCRIPT.contains(&format!("\n  {key}\n")),
                "parser allowlist is missing the orchestrator-written key {key}"
            );
        }
    }

    #[cfg(unix)]
    fn write_rsa0068_test_file(name: &str, contents: &[u8], mode: u32) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("{}_{}", name, std::process::id()));
        std::fs::write(&path, contents).expect("write RSA-0068 test file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .expect("chmod RSA-0068 test file");
        path
    }

    /// Well-formed configs must land in the named variables with exactly the
    /// values `source` used to produce, and optional keys must stay UNSET
    /// (not merely empty) when absent. Runs ONLY the extracted allowlist
    /// array + parser under bash — never the bootstrap main flow, which
    /// would install packages on a real guest.
    #[cfg(unix)]
    #[test]
    fn bootstrap_env_parser_assigns_exactly_the_allowlisted_values() {
        use std::process::Command;

        let script_path = write_rsa0068_test_file(
            "rn_bootstrap_rsa0068_extract.sh",
            BOOTSTRAP_SCRIPT.as_bytes(),
            0o700,
        );
        let env_path = write_rsa0068_test_file(
            "rn_rsa0068_good.env",
            concat!(
                "# orchestrator-written config\n",
                "\n",
                "ROLE=admin\n",
                "NODE_ID=exit-node1-abc123\n",
                "NETWORK_ID=test-net\n",
                "SSH_ALLOW_CIDRS=192.168.64.0/24\n",
                "SOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n",
                "RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS=2\n",
                "RUSTYNET_LAB_STUN_SERVERS=10.0.0.1:3478\n",
                "RUSTYNET_BACKEND=userspace\n",
                "RN_PREBUILT_BINARIES=1\n",
                "RN_PREBUILT_DIR=/tmp/rn_prebuilt\n",
            )
            .as_bytes(),
            0o600,
        );
        let harness = r#"set -euo pipefail
eval "$(awk '/^RN_BOOTSTRAP_ENV_KEYS=\($/,/^\)$/ {print} /^load_bootstrap_env\(\) \{/,/^\}$/ {print}' "$1")"
load_bootstrap_env "$2"
printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s' \
  "${ROLE-UNSET}" "${NODE_ID-UNSET}" "${NETWORK_ID-UNSET}" "${SSH_ALLOW_CIDRS-UNSET}" \
  "${SOURCE_ARCHIVE-UNSET}" "${RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS-UNSET}" \
  "${RUSTYNET_LAB_STUN_SERVERS-UNSET}" "${RUSTYNET_BACKEND-UNSET}" \
  "${RN_PREBUILT_BINARIES-UNSET}" "${RN_PREBUILT_DIR-UNSET}"
"#;
        let output = Command::new("bash")
            .arg("-c")
            .arg(harness)
            .arg("rn_rsa0068_extract")
            .arg(script_path.as_os_str())
            .arg(env_path.as_os_str())
            .output()
            .expect("run the extracted RSA-0068 parser under bash");
        assert!(
            output.status.success(),
            "a well-formed config must parse: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "admin|exit-node1-abc123|test-net|192.168.64.0/24|/tmp/rn_source.tar.gz|2|10.0.0.1:3478|userspace|1|/tmp/rn_prebuilt",
            "values must land in the named variables exactly as `source` produced them"
        );
        let _ = std::fs::remove_file(&env_path);
        let _ = std::fs::remove_file(&script_path);
    }

    /// Runs the REAL script against hostile or malformed env files. The
    /// parser is the first thing the script does, so every refusal must
    /// happen before any other action — proven by a canary value that would
    /// create a file if the env file were ever interpreted as shell.
    #[cfg(unix)]
    #[test]
    fn bootstrap_env_parser_refuses_hostile_and_malformed_configs_before_any_execution() {
        use std::process::Command;

        let script_path = write_rsa0068_test_file(
            "rn_bootstrap_rsa0068_case.sh",
            BOOTSTRAP_SCRIPT.as_bytes(),
            0o700,
        );
        let canary = std::env::temp_dir().join(format!("rn_rsa0068_canary_{}", std::process::id()));
        let good = "ROLE=admin\n\
                    NODE_ID=exit-node1-abc123\n\
                    NETWORK_ID=test-net\n\
                    SSH_ALLOW_CIDRS=192.168.64.0/24\n\
                    SOURCE_ARCHIVE=/tmp/rn_source.tar.gz\n";
        // (case name, env-file contents, env-file mode)
        let cases: Vec<(&str, String, u32)> = vec![
            ("unknown key", format!("{good}EXTRA_KEY=1\n"), 0o600),
            (
                "duplicate key",
                "ROLE=admin\nROLE=client\nNODE_ID=n\nNETWORK_ID=x\nSSH_ALLOW_CIDRS=y\nSOURCE_ARCHIVE=z\n"
                    .to_string(),
                0o600,
            ),
            (
                "command substitution",
                format!(
                    "ROLE=admin\nNODE_ID=n\nNETWORK_ID=x\nSSH_ALLOW_CIDRS=y\nSOURCE_ARCHIVE=$(touch {})\n",
                    canary.display()
                ),
                0o600,
            ),
            (
                "backtick",
                format!(
                    "ROLE=admin\nNODE_ID=n\nNETWORK_ID=x\nSSH_ALLOW_CIDRS=y\nSOURCE_ARCHIVE=`touch {}`\n",
                    canary.display()
                ),
                0o600,
            ),
            ("line without equals", format!("{good}JUSTTEXT\n"), 0o600),
            ("group-writable file", good.to_string(), 0o664),
            ("world-writable file", good.to_string(), 0o666),
            (
                "missing required key",
                "ROLE=admin\nNODE_ID=n\nNETWORK_ID=x\nSSH_ALLOW_CIDRS=y\n".to_string(),
                0o600,
            ),
        ];
        for (name, env_body, mode) in cases {
            let env_path =
                write_rsa0068_test_file("rn_rsa0068_case.env", env_body.as_bytes(), mode);
            let _ = std::fs::remove_file(&canary);
            let output = Command::new("bash")
                .arg(script_path.as_os_str())
                .arg(env_path.as_os_str())
                .output()
                .expect("run rn_bootstrap.sh under bash");
            assert!(
                !output.status.success(),
                "case {name} must exit non-zero, got {:?}",
                output.status.code()
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("refusing"),
                "case {name} must be refused by the parser, not fail later: {stderr}"
            );
            assert!(
                !canary.exists(),
                "case {name} executed the env file: the canary file was created"
            );
            let _ = std::fs::remove_file(&env_path);
        }
        let _ = std::fs::remove_file(&canary);
        let _ = std::fs::remove_file(&script_path);
    }

    #[test]
    fn bootstrap_env_includes_role_and_node_id() {
        use std::collections::HashMap;
        let assignments = vec![NodeRoleAssignment {
            alias: "node1".to_owned(),
            role: NodeRole::Exit,
        }];
        let ctx = OrchestrationContext {
            assignments,
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "test-net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: "10.0.0.0/8".to_owned(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        let env = build_bootstrap_env("exit-node1-abc123", &NodeRole::Exit, &ctx).expect("env");
        assert!(
            env.contains("ROLE=admin"),
            "exit node must map to admin role: {env}"
        );
        assert!(
            env.contains("NODE_ID=exit-node1-abc123"),
            "must contain NODE_ID: {env}"
        );
        assert!(
            env.contains("NETWORK_ID=test-net"),
            "must contain NETWORK_ID: {env}"
        );
        assert!(
            env.contains("RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS=2"),
            "Rust-native lab bootstrap should reach offline fallback quickly on no-egress guests: {env}"
        );
        assert!(
            !env.contains("RUSTYNET_LAB_STUN_SERVERS="),
            "unset --lab-stun-servers must leave the env byte-identical: {env}"
        );
    }

    #[test]
    fn bootstrap_env_threads_lab_stun_servers_when_configured() {
        use std::collections::HashMap;
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: vec![
                "1.2.3.4:19302".parse().expect("socket addr"),
                "5.6.7.8:3478".parse().expect("socket addr"),
            ],
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        let env = build_bootstrap_env("id1", &NodeRole::Client, &ctx).expect("env");
        assert!(
            env.contains("RUSTYNET_LAB_STUN_SERVERS=1.2.3.4:19302,5.6.7.8:3478\n"),
            "configured --lab-stun-servers must override the gateway default as a CSV line: {env}"
        );
        assert!(
            !env.contains("RUSTYNET_BACKEND"),
            "no --linux-backend pin must leave the backend to the install's existing-value logic: {env}"
        );
    }

    #[test]
    fn bootstrap_env_threads_the_linux_backend_pin_and_refuses_anything_else() {
        use std::collections::HashMap;
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: Some("linux-wireguard-userspace-shared".to_owned()),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        let env = build_bootstrap_env("id1", &NodeRole::Client, &ctx).expect("env");
        assert!(
            env.ends_with("RUSTYNET_BACKEND=linux-wireguard-userspace-shared\n"),
            "pinned --linux-backend must reach the guest as RUSTYNET_BACKEND: {env}"
        );

        // Defense in depth below the CLI parser: a value that is not one of
        // the allow-listed literals never reaches a sourced env file.
        ctx.linux_backend = Some("linux-wireguard\nRUSTYNET_NODE_ROLE=admin".to_owned());
        let err = build_bootstrap_env("id1", &NodeRole::Client, &ctx).expect_err("must refuse");
        assert!(
            err.to_string()
                .contains("non-allow-listed RUSTYNET_BACKEND"),
            "{err}"
        );
    }

    #[test]
    fn parallel_temp_files_are_unique_and_keep_each_workers_content() {
        let payloads = [b"exit-node".as_slice(), b"client-a", b"client-b"];
        let paths = crate::vm_lab::orchestrator::parallel::bounded_parallel_map(
            &payloads,
            payloads.len(),
            |payload| write_temp_file("rn_parallel_test_", ".env", payload).unwrap(),
        );

        let unique: std::collections::HashSet<_> = paths.iter().collect();
        assert_eq!(unique.len(), payloads.len());
        for (path, expected) in paths.iter().zip(payloads) {
            assert_eq!(std::fs::read(path).unwrap(), expected);
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn bootstrap_env_non_exit_roles_map_to_client() {
        use std::collections::HashMap;
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        for role in [
            NodeRole::Client,
            NodeRole::Entry,
            NodeRole::Aux,
            NodeRole::Extra,
        ] {
            let env = build_bootstrap_env("id1", &role, &ctx).expect("env");
            assert!(
                env.contains("ROLE=client"),
                "non-exit role {role:?} must map to client: {env}"
            );
        }
    }

    #[test]
    fn bootstrap_script_is_non_empty() {
        assert!(
            !BOOTSTRAP_SCRIPT.is_empty(),
            "embedded bootstrap script must not be empty"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("rn_bootstrap.sh"),
            "embedded script must contain its own name"
        );
    }

    /// Regression: the Linux lab bootstrap must relax the freshness window
    /// (86400 s) for the auto-tunnel, traversal and DNS-zone bundles at
    /// bootstrap time, the same way the macOS Bootstrap-RustyNetMacos.sh and
    /// the Windows installer already do. The bootstrap installs the daemon via
    /// `rustynet ops e2e-bootstrap-host`, which forwards these env vars into
    /// `ops install-systemd`; without them a freshly bootstrapped Linux node
    /// runs the strict 300 s/120 s production window and can be stranded
    /// fail-closed if the later `e2e-enforce-host` pass is interrupted (the
    /// daemon ages a bundle past 300 s, wedges in restrict_permanent, and the
    /// enforce restart cannot cleanly cycle the socket). The systemd unit's
    /// 300 s/120 s production default is unchanged; this only sets the LAB
    /// window via the bootstrap env passthrough.
    #[test]
    fn bootstrap_script_relaxes_lab_freshness_window_for_all_bundles() {
        for env_assignment in [
            "RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400",
            "RUSTYNET_TRAVERSAL_MAX_AGE_SECS=86400",
            "RUSTYNET_DNS_ZONE_MAX_AGE_SECS=86400",
        ] {
            assert!(
                BOOTSTRAP_SCRIPT.contains(env_assignment),
                "linux bootstrap must forward {env_assignment} on the e2e-bootstrap-host \
                 invocation so the bootstrap-time daemon uses the relaxed lab freshness \
                 window instead of the strict 300 s/120 s production default"
            );
        }
        // The relaxed env must be on the e2e-bootstrap-host invocation itself
        // (not some unrelated command), so e2e-bootstrap-host forwards it into
        // install-systemd.
        assert!(
            BOOTSTRAP_SCRIPT.contains("rustynet ops e2e-bootstrap-host"),
            "bootstrap must install the daemon via e2e-bootstrap-host"
        );
    }

    /// C-STUN (BashOrchestratorRetirementProgram): both Linux install passes
    /// must thread a non-empty RUSTYNET_TRAVERSAL_STUN_SERVERS into the daemon
    /// install, because an empty value disables srflx candidate gathering and
    /// the enforce pass rewrites the unit (dropping any bootstrap-time value).
    #[test]
    fn bootstrap_script_threads_lab_stun_servers() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("RUSTYNET_TRAVERSAL_STUN_SERVERS="),
            "linux bootstrap must forward a lab STUN endpoint so srflx candidate \
             gathering is exercised in lab deployments"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("\"${stun_env[@]}\""),
            "the stun env must be forwarded on the e2e-bootstrap-host invocation"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("RUSTYNET_LAB_STUN_SERVERS"),
            "the bootstrap env override hook must exist"
        );
    }

    #[test]
    fn enforce_script_threads_lab_stun_servers() {
        let script = build_enforce_script(
            "client",
            "node-1",
            "/home/lab/Rustynet",
            "192.168.64.0/24",
            None,
        );
        assert!(
            script.contains("RUSTYNET_TRAVERSAL_STUN_SERVERS=$RN_LAB_GW:3478"),
            "enforce must thread the guest-gateway STUN endpoint: {script}"
        );
        assert!(
            script.contains("$RN_STUN_ENV"),
            "the stun env word must be on the sudo env invocation: {script}"
        );
        assert!(
            script.contains("ops e2e-enforce-host"),
            "must still invoke e2e-enforce-host: {script}"
        );
    }

    /// --lab-stun-servers: the enforce script must REPLACE the gateway
    /// detection with the literal validated CSV (cross-NAT runs point at a
    /// real STUN responder, not the same-LAN gateway).
    #[test]
    fn enforce_script_lab_stun_servers_override_replaces_gateway_detection() {
        let script = build_enforce_script(
            "client",
            "node-1",
            "/home/lab/Rustynet",
            "192.168.64.0/24",
            Some("1.2.3.4:19302,5.6.7.8:3478"),
        );
        assert!(
            script.contains(
                "RN_STUN_ENV=\"RUSTYNET_TRAVERSAL_STUN_SERVERS=1.2.3.4:19302,5.6.7.8:3478\""
            ),
            "override must set the env var to the literal CSV: {script}"
        );
        assert!(
            !script.contains("RN_LAB_GW"),
            "override must not run gateway detection: {script}"
        );
        assert!(
            !script.contains(":3478\"; fi"),
            "gateway fallback must be absent under override: {script}"
        );
    }

    #[test]
    fn bootstrap_script_builds_and_installs_the_relay_binary() {
        // The relay runtime deploy stage assumes the bootstrap built + installed
        // rustynet-relay (the deploy stage only places the verifier key + unit).
        assert!(
            BOOTSTRAP_SCRIPT.contains("-p rustynet-relay --features daemon"),
            "bootstrap must build the rustynet-relay binary"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains(
                "install -m 0755 \"${rn_bin_src}/rustynet-relay\" /usr/local/bin/rustynet-relay"
            ),
            "bootstrap must install rustynet-relay to /usr/local/bin (from the selected \
             source dir: target/release for a guest build, /tmp/rn_prebuilt for host-cross)"
        );
    }

    #[test]
    fn bootstrap_script_builds_only_the_installed_cli_binary() {
        // `cargo build -p rustynet-cli` builds every bin target in that package.
        // The lab installs only target/release/rustynet-cli, so building helper
        // bins on every node is dead work and made no-egress bootstrap much slower.
        assert!(
            BOOTSTRAP_SCRIPT.contains("-p rustynet-cli --features vm-lab --bin rustynet-cli"),
            "bootstrap must compile only the installed rustynet-cli binary, \
             with the vm-lab feature so guests serve the `ops e2e-*` \
             lab-protocol commands (RNQ-17 gates them out of default builds)"
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("-p rustynetd -p rustynet-cli"),
            "bootstrap must not build the whole rustynet-cli package bin set"
        );
    }

    #[test]
    fn bootstrap_uses_absolute_installed_cli_under_sudo_secure_path() {
        assert!(BOOTSTRAP_SCRIPT.contains("/usr/local/bin/rustynet ops e2e-bootstrap-host"));
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin")
        );
        assert!(
            !BOOTSTRAP_SCRIPT.contains("\n  rustynet ops e2e-bootstrap-host"),
            "Rocky sudo secure_path may exclude /usr/local/bin"
        );
    }

    #[test]
    fn bootstrap_repins_regular_fail_closed_resolver_immediately_before_daemon_start() {
        assert!(BOOTSTRAP_SCRIPT.contains("pin_regular_resolv_conf()"));
        assert!(BOOTSTRAP_SCRIPT.contains("pin_regular_resolv_conf 1.1.1.1 8.8.8.8"));
        let protected_pin = BOOTSTRAP_SCRIPT
            .find("pin_regular_resolv_conf 127.0.0.1")
            .expect("protected resolver pin");
        let daemon_start = BOOTSTRAP_SCRIPT
            .find("/usr/local/bin/rustynet ops e2e-bootstrap-host")
            .expect("daemon bootstrap invocation");
        assert!(
            protected_pin < daemon_start,
            "regular loopback resolver must be pinned before rustynetd starts"
        );
        assert!(
            BOOTSTRAP_SCRIPT[protected_pin..daemon_start]
                .contains("failed to pin /etc/resolv.conf as a regular file")
                || BOOTSTRAP_SCRIPT.contains("[[ -L /etc/resolv.conf || ! -f /etc/resolv.conf ]]"),
            "bootstrap must fail closed if distro DNS management recreates a symlink"
        );
    }

    #[test]
    fn bootstrap_network_diagnostics_timeout_getent_before_offline_fallback() {
        // No-egress UTM guests can leave getent blocked indefinitely. Diagnostics
        // must be bounded so the script reaches the cargo --offline fallback.
        assert!(
            BOOTSTRAP_SCRIPT.contains("timeout 10 getent ahosts"),
            "bootstrap DNS diagnostics must not hang before offline cargo fallback"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("RUSTYNET_BOOTSTRAP_REGISTRY_ATTEMPTS:-8"),
            "bootstrap registry probe count should remain configurable"
        );
    }

    #[test]
    fn bootstrap_prerequisites_support_fedora_ca_and_llvm_layout() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("/etc/pki/tls/certs/ca-bundle.crt"),
            "Fedora/RHEL CA bundle must satisfy prerequisite validation"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("sqlite-devel clang llvm llvm-devel nftables"),
            "Fedora/RHEL install must include llvm-devel, which provides llvm-config"
        );
        assert!(BOOTSTRAP_SCRIPT.contains("wireguard-tools tar gzip tcpdump iputils"));
        assert!(BOOTSTRAP_SCRIPT.contains("tcpdump iputils-ping"));
        assert!(BOOTSTRAP_SCRIPT.contains("gzip tcpdump ping"));
        assert!(BOOTSTRAP_SCRIPT.contains("install_rustup_hardened"));
        assert!(BOOTSTRAP_SCRIPT.contains("${HOME}/.cargo/bin:/usr/local/sbin"));
        assert!(BOOTSTRAP_SCRIPT.contains("rustup-init.sha256"));
        assert!(BOOTSTRAP_SCRIPT.contains("sha256sum -c rustup-init.sha256"));
        assert!(
            !BOOTSTRAP_SCRIPT.contains("wireguard-tools rustup"),
            "Rocky repositories do not provide a rustup RPM; rustup must use the checksum-verified installer"
        );
    }

    /// b30 (live 2026-09-27, rocky-utm-1 / Rocky Linux 10 aarch64): the EL
    /// base repositories do not carry libfaketime (it is EPEL-only, and EPEL
    /// is deliberately NOT enabled per ADR-027), and dnf refuses the WHOLE
    /// transaction when one name is unresolvable ("Error: Unable to find a
    /// match: libfaketime"). So libfaketime must not ride the core dnf
    /// transaction; it stays required on the apt side (Debian/Ubuntu carry
    /// it) and required on Fedora via the strict post-install verification.
    /// Witness: the pre-fix script's core dnf block ends in
    /// `iproute libfaketime`, so every assertion here fails against it.
    #[test]
    fn bootstrap_splits_libfaketime_out_of_the_core_dnf_transaction() {
        fn dnf_core_transaction() -> String {
            let start = BOOTSTRAP_SCRIPT
                .find("run_root_timed 1800 dnf install -y")
                .expect("core dnf transaction must exist");
            let rest = &BOOTSTRAP_SCRIPT[start..];
            let mut block = String::new();
            for line in rest.lines().skip(1) {
                block.push_str(line);
                block.push('\n');
                if !line.trim_end().ends_with('\\') {
                    break;
                }
            }
            block
        }
        let block = dnf_core_transaction();
        assert!(
            !block.contains("libfaketime"),
            "libfaketime must not ride the core dnf transaction (EL base repos lack it; one unresolved name fails the whole transaction): {block}"
        );
        assert!(
            block.contains("iproute iproute-tc"),
            "tc ships in the separate iproute-tc package on Fedora/EL, not in iproute (live 2026-09-27, fedora-utm-1 / Fedora 44: prerequisite verification failed on the missing tc command after every listed package installed): {block}"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("iproute2 libfaketime"),
            "libfaketime stays REQUIRED on the Debian/Ubuntu apt side where the package exists"
        );
    }

    /// b30: on EL a missing libfaketime must be reported LOUDLY and treated
    /// as OPTIONAL (so an EL guest does not re-enter install_prereqs on
    /// every run), while staying required everywhere else. The discriminator
    /// is the is_el_linux helper; the WARN must name the chaos clock-attack
    /// stage as the only consumer.
    #[test]
    fn bootstrap_treats_libfaketime_as_optional_only_on_el_with_loud_warn() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("is_el_linux() {"),
            "an EL discriminator must exist for the dnf-family split"
        );
        let fn_start = BOOTSTRAP_SCRIPT
            .find("build_bootstrap_prereqs_present() {")
            .expect("prereq function must exist");
        let tail = &BOOTSTRAP_SCRIPT[fn_start..];
        let fn_len = tail
            .find("\n}")
            .expect("prereq function must close at column 0");
        let body = &tail[..fn_len];
        assert!(
            body.contains("is_el_linux"),
            "build_bootstrap_prereqs_present must branch on is_el_linux for the optional-on-EL treatment: {body}"
        );
        assert!(
            body.contains("[bootstrap] WARN: libfaketime"),
            "a missing libfaketime on EL must be reported loudly: {body}"
        );
        assert!(
            body.contains("chaos clock-attack"),
            "the WARN must name the chaos clock-attack stage as the only consumer: {body}"
        );
    }

    /// Behavioural witness: run the REAL extracted is_el_linux under bash and
    /// check the EL/Fedora/Debian classification end to end. On the pre-fix
    /// script the function does not exist, the awk extraction is empty, and
    /// the harness fails — this witness cannot pass against the old
    /// behaviour.
    #[cfg(unix)]
    #[test]
    fn bootstrap_el_detection_function_classifies_el_fedora_and_debian() {
        use std::process::Command;

        let script_path = write_rsa0068_test_file(
            "rn_bootstrap_b30_el_detect.sh",
            BOOTSTRAP_SCRIPT.as_bytes(),
            0o700,
        );
        let harness = r#"set -euo pipefail
eval "$(awk '/^is_el_linux\(\) \{/,/^\}$/ {print}' "$1")"
for spec in \
  'rocky:rhel centos fedora:EL' \
  'rhel:fedora:EL' \
  'almalinux:rhel centos:EL' \
  'centos:rhel fedora:EL' \
  'ol::EL' \
  'fedora::NOT-EL' \
  'fedora:rhel centos:NOT-EL' \
  'ubuntu:debian:NOT-EL' \
  '::NOT-EL'; do
  id="${spec%%:*}"
  rest="${spec#*:}"
  like="${rest%%:*}"
  expected="${rest##*:}"
  if is_el_linux "$id" "$like"; then got=EL; else got=NOT-EL; fi
  if [ "$got" != "$expected" ]; then
    echo "is_el_linux(id=$id, like=$like) = $got, expected $expected" >&2
    exit 1
  fi
done
echo OK
"#;
        let output = Command::new("bash")
            .arg("-c")
            .arg(harness)
            .arg("rn_bootstrap_b30_extract")
            .arg(script_path.as_os_str())
            .output()
            .expect("run the extracted EL detector under bash");
        assert!(
            output.status.success(),
            "is_el_linux must classify EL, Fedora and Debian correctly: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_file(&script_path);
    }

    /// Collects a top-level shell function's text from the embedded bootstrap
    /// script, starting at the byte offset of its `name() {` header, through
    /// the closing `}` at column 0 (the script's functions are column-0
    /// delimited; every inner block is indented).
    fn bootstrap_function_block(start: usize) -> String {
        let rest = &BOOTSTRAP_SCRIPT[start..];
        let mut block = String::new();
        for line in rest.lines() {
            block.push_str(line);
            block.push('\n');
            if line == "}" {
                break;
            }
        }
        block
    }

    /// rz1-r2 (live 2026-10-06, linux-x86-client-1): unattended-upgrades held
    /// the dpkg frontend lock and `run_apt_install_hardened` had NO package
    /// manager wait (the update path already had one), so its three install
    /// attempts burned seconds apart and the run died. The install path must
    /// wait before every attempt, with a pattern covering the unattended-
    /// upgrade python parent (`/usr/bin/python3 /usr/sbin/unattended-upgrade`)
    /// that holds the lock between phases, and a bounded wait (300 x 2s).
    #[test]
    fn bootstrap_apt_install_waits_for_the_package_manager_before_installing() {
        let start = BOOTSTRAP_SCRIPT
            .find("run_apt_install_hardened() {")
            .expect("run_apt_install_hardened must exist in the embedded bootstrap script");
        let block = bootstrap_function_block(start);
        assert!(
            block.contains(
                "wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg|unattended-upgr' 'apt/dpkg' 300"
            ),
            "the apt install path must wait for the package manager before each attempt, covering \
             the unattended-upgrade python parent, with a bounded wait (rz1-r2: pid 3515 held the \
             dpkg lock ~2h while three installs burned seconds apart): {block}"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains(
                "wait_for_package_manager_idle 'apt-get|/usr/lib/apt/methods/|dpkg|unattended-upgr' 'apt/dpkg'"
            ),
            "the update path's wait pattern must cover unattended-upgr too"
        );
    }

    /// The dnf path already waited, but on `'dnf|rpm'` — packagekitd (the
    /// GNOME Software backend) holds the same rpm/dnf lock and is invisible
    /// to that pattern. Same gap class as the apt install path.
    #[test]
    fn bootstrap_dnf_wait_pattern_covers_packagekitd() {
        assert!(
            BOOTSTRAP_SCRIPT
                .contains("wait_for_package_manager_idle 'dnf|rpm|packagekitd' 'dnf/rpm'"),
            "the dnf path's idle-wait pattern must cover packagekitd: {}",
            BOOTSTRAP_SCRIPT
                .lines()
                .filter(|line| line.contains("wait_for_package_manager_idle"))
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    /// rz1-r2: on the lock error the script ran `repair_bootstrap_dns_state`
    /// and then two screens of `emit_bootstrap_network_diagnostics` (healthy
    /// DNS!) and mislabelled the failure. Lock errors must be classified,
    /// get lock diagnostics (who holds the lock), and NEVER trigger DNS
    /// repair or network diagnostics — on both apt paths.
    #[test]
    fn bootstrap_apt_lock_failures_get_lock_diagnostics_never_dns_repair() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("apt_attempt_failed_on_package_lock() {"),
            "a lock-error classifier must exist in the embedded bootstrap script"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("emit_bootstrap_package_lock_diagnostics() {"),
            "lock diagnostics (who holds the lock) must exist in the embedded bootstrap script"
        );
        let install_start = BOOTSTRAP_SCRIPT
            .find("run_apt_install_hardened() {")
            .expect("run_apt_install_hardened must exist");
        let install_block = bootstrap_function_block(install_start);
        let update_start = BOOTSTRAP_SCRIPT
            .find("run_apt_update_hardened() {")
            .expect("run_apt_update_hardened must exist");
        let update_block = bootstrap_function_block(update_start);
        for (label, block) in [("install", &install_block), ("update", &update_block)] {
            assert!(
                block.contains("apt_attempt_failed_on_package_lock"),
                "the apt {label} path must classify lock failures per attempt: {block}"
            );
            assert!(
                block.contains("emit_bootstrap_package_lock_diagnostics"),
                "the apt {label} path must emit lock diagnostics on a lock failure: {block}"
            );
            assert!(
                block.contains("NOT repairing DNS"),
                "the apt {label} path must say explicitly that DNS is NOT being repaired on the lock path: {block}"
            );
            let final_lock = block
                .find("lock stayed held by another process")
                .unwrap_or_else(|| {
                    panic!("the apt {label} path must fail loudly on a persistent lock: {block}")
                });
            let tail = &block[final_lock..];
            let return_at = tail
                .find("return 1")
                .unwrap_or_else(|| panic!("the apt {label} lock path must return 1: {tail}"));
            assert!(
                !tail[..return_at].contains("emit_bootstrap_network_diagnostics"),
                "the apt {label} lock-final path must return WITHOUT network diagnostics: {}",
                &tail[..return_at]
            );
            assert!(
                !tail[..return_at].contains("repair_bootstrap_dns_state"),
                "the apt {label} lock-final path must return WITHOUT DNS repair: {}",
                &tail[..return_at]
            );
            assert!(
                !tail[..return_at].contains("return 0"),
                "the apt {label} lock path must not return success before its failure return: {}",
                &tail[..return_at]
            );
        }
        assert!(
            install_block.contains("emit_bootstrap_network_diagnostics \"deb.debian.org\""),
            "the non-lock install failure keeps its network diagnostics (existing behaviour)"
        );
        // Exactly ONE DNS-repair call site per apt block: the non-lock retry
        // branch. A second one on the lock branch is the rz1-r2 misdiagnosis.
        for (label, block) in [("install", &install_block), ("update", &update_block)] {
            assert_eq!(
                block.matches("repair_bootstrap_dns_state").count(),
                1,
                "the apt {label} block must call repair_bootstrap_dns_state exactly once (the non-lock branch only): {block}"
            );
        }
    }

    /// Behavioural witness: run the REAL extracted lock classifier under bash
    /// against the two E: shapes apt-get emitted on rz1-r2 and against a
    /// genuine fetch failure. On the pre-fix script the function does not
    /// exist, the awk extraction is empty, and the lock log misclassifies.
    #[cfg(unix)]
    #[test]
    fn bootstrap_apt_lock_error_classifier_recognises_lock_shapes_under_bash() {
        use std::process::Command;

        let script_path = write_rsa0068_test_file(
            "rn_bootstrap_b126_lock_classifier.sh",
            BOOTSTRAP_SCRIPT.as_bytes(),
            0o700,
        );
        let lock_log_path = write_rsa0068_test_file(
            "rn_bootstrap_b126_lock.log",
            concat!(
                "Reading package lists...\n",
                "E: Could not get lock /var/lib/dpkg/lock-frontend. It is held by process 3515 (unattended-upgr)\n",
                "E: Unable to acquire the dpkg frontend lock /var/lib/dpkg/lock-frontend, are you root?\n",
            )
            .as_bytes(),
            0o600,
        );
        let net_log_path = write_rsa0068_test_file(
            "rn_bootstrap_b126_net.log",
            concat!(
                "Err:1 http://deb.debian.org/debian bookworm InRelease\n",
                "W: Failed to fetch http://deb.debian.org/debian bookworm InRelease: Temporary failure resolving 'deb.debian.org'\n",
                "E: Some index files failed to download.\n",
            )
            .as_bytes(),
            0o600,
        );
        let harness = r#"set -euo pipefail
eval "$(awk '/^apt_attempt_failed_on_package_lock\(\) \{/,/^\}$/ {print}' "$1")"
if apt_attempt_failed_on_package_lock "$2"; then echo LOCK; else echo OTHER; fi
"#;
        let output = Command::new("bash")
            .arg("-c")
            .arg(harness)
            .arg("rn_bootstrap_b126_classifier_extract")
            .arg(script_path.as_os_str())
            .arg(lock_log_path.as_os_str())
            .output()
            .expect("run the extracted lock classifier under bash");
        assert!(
            output.status.success(),
            "classifier must run under bash: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "LOCK",
            "the dpkg-lock E: shapes must classify as a lock failure: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new("bash")
            .arg("-c")
            .arg(harness)
            .arg("rn_bootstrap_b126_classifier_extract")
            .arg(script_path.as_os_str())
            .arg(net_log_path.as_os_str())
            .output()
            .expect("run the extracted lock classifier under bash");
        assert!(
            output.status.success(),
            "classifier must run under bash: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "OTHER",
            "a genuine fetch failure must stay on the DNS-repair path: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_file(&script_path);
        let _ = std::fs::remove_file(&lock_log_path);
        let _ = std::fs::remove_file(&net_log_path);
    }

    /// Behavioural witness for the bounded wait: with a fake unattended-upgr
    /// holder running, the extracted `wait_for_package_manager_idle` must
    /// fail (exit 1, holder named on stderr) within the caller's bound
    /// (`timeout 15`); the pre-fix helper ignores the max-attempts argument
    /// and loops 60x2s, so it cannot answer inside 15s. With no holder it
    /// must return 0 immediately.
    ///
    /// Linux-only: the bootstrap script runs on Linux guests and names the
    /// holder with `pgrep -af`, where `-a` prints the command line. On macOS
    /// `pgrep -a` means "include ancestors" and prints bare pids, so the
    /// holder-naming assertion cannot hold there (the macOS landing gate
    /// failed on exactly that); the Linux leg of the landing gates runs it.
    #[cfg(target_os = "linux")]
    #[test]
    fn bootstrap_wait_for_package_manager_idle_bounds_its_wait_and_names_the_holder() {
        use std::process::Command;

        let script_path = write_rsa0068_test_file(
            "rn_bootstrap_b126_wait_idle.sh",
            BOOTSTRAP_SCRIPT.as_bytes(),
            0o700,
        );
        // The driver runs from a FILE, never `bash -c <text>`: with -c the
        // driver's own argv carries the pgrep pattern and pgrep -f would
        // match the driver itself, making every run look busy.
        let driver_path = write_rsa0068_test_file(
            "rn_bootstrap_b126_wait_driver.sh",
            r#"set -u
eval "$(awk '/^wait_for_package_manager_idle\(\) \{/,/^\}$/ {print}' "$1")"
case "$2" in
  busy)
    bash -c 'exec -a rn-b126-fake-unattended-upgr sleep 30' &
    holder=$!
    wait_for_package_manager_idle 'rn-b126-fake-unattended-upgr' 'apt/dpkg' 2
    rc=$?
    kill "$holder" 2>/dev/null || true
    wait "$holder" 2>/dev/null || true
    if [ "$rc" -eq 0 ]; then echo IDLE-UNEXPECTED; else exit "$rc"; fi
    ;;
  idle)
    wait_for_package_manager_idle 'rn-b126-no-such-process-xyz' 'apt/dpkg' 2
    echo IDLE-OK
    ;;
esac
"#
            .as_bytes(),
            0o700,
        );
        let output = Command::new("timeout")
            .arg("15")
            .arg("bash")
            .arg(driver_path.as_os_str())
            .arg(script_path.as_os_str())
            .arg("busy")
            .output()
            .expect("run the extracted idle-wait under bash");
        assert_eq!(
            output.status.code(),
            Some(1),
            "a busy package manager must fail with exit 1 inside the bounded wait \
             (pre-fix helper loops 60x2s and cannot answer inside timeout 15): status={:?} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("remained busy"),
            "the busy failure must say the label remained busy: {stderr}"
        );
        assert!(
            stderr.contains("rn-b126-fake-unattended-upgr"),
            "the busy failure must name the lock holder: {stderr}"
        );
        let output = Command::new("bash")
            .arg(driver_path.as_os_str())
            .arg(script_path.as_os_str())
            .arg("idle")
            .output()
            .expect("run the extracted idle-wait under bash");
        assert!(
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "IDLE-OK",
            "an idle package manager must return 0 immediately: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _ = std::fs::remove_file(&script_path);
        let _ = std::fs::remove_file(&driver_path);
    }

    #[test]
    fn bootstrap_root_timeout_wraps_child_command_not_sudo() {
        // `timeout sudo resolvectl ...` can leave the root child alive after
        // sudo exits. Run timeout under sudo so diagnostics cannot stall the
        // Rust engine before the offline cargo fallback.
        assert!(
            BOOTSTRAP_SCRIPT.contains("sudo -n timeout --kill-after=5"),
            "root command timeout must wrap the child command under sudo"
        );
    }

    #[test]
    fn bootstrap_keeps_firewalld_enabled_and_opens_only_wireguard_udp() {
        assert!(BOOTSTRAP_SCRIPT.contains("configure_lab_wireguard_firewall()"));
        assert!(BOOTSTRAP_SCRIPT.contains("systemctl is-active --quiet firewalld.service"));
        assert!(BOOTSTRAP_SCRIPT.contains("firewall-cmd --permanent --add-port=51820/udp"));
        assert!(BOOTSTRAP_SCRIPT.contains("firewall-cmd --add-port=51820/udp"));
        assert!(!BOOTSTRAP_SCRIPT.contains("systemctl stop firewalld"));
        assert!(!BOOTSTRAP_SCRIPT.contains("systemctl disable firewalld"));
    }

    #[test]
    fn daemon_start_readiness_requires_a_live_control_request() {
        assert!(LINUX_DAEMON_READY_PROBE.contains("for i in $(seq 1 40)"));
        assert!(LINUX_DAEMON_READY_PROBE.contains(LINUX_DAEMON_SOCKET));
        assert!(LINUX_DAEMON_READY_PROBE.contains("/usr/local/bin/rustynet status"));
        assert!(LINUX_DAEMON_READY_PROBE.contains("daemon-not-ready; exit 1"));
    }

    #[test]
    fn run_systemctl_renders_argv_through_the_validated_seam() {
        let args = vec![
            ValidatedArg::cli_token("sudo").expect("token"),
            ValidatedArg::cli_token("systemctl").expect("token"),
            ValidatedArg::cli_token("restart").expect("token"),
            ValidatedArg::service(LINUX_SERVICE_NAME).expect("service"),
        ];
        let script =
            ssh::RemoteCommand::from_args("linux systemd {action}", &args).expect("render");
        assert_eq!(script.as_str(), "'sudo' 'systemctl' 'restart' 'rustynetd'");
    }

    #[test]
    fn run_systemctl_rejects_a_metacharacter_action_at_the_seam() {
        let err = ValidatedArg::cli_token("start; reboot").expect_err("must reject");
        assert!(err.to_string().contains("not safe for shell embedding"));
    }

    fn sha_map(pairs: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    const H1: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const DIR: &str = "/tmp/rn_prebuilt.AbC12345";

    #[test]
    fn remote_sha256_check_accepts_matching_hashes() {
        let expected = sha_map(&[("rustynetd", H1), ("rustynet-cli", H2)]);
        let shipped = vec!["rustynetd".to_owned(), "rustynet-cli".to_owned()];
        let out = format!("{H1}  {DIR}/rustynetd\n{H2}  {DIR}/rustynet-cli\n");
        verify_remote_sha256(&out, DIR, &expected, &shipped).expect("matching hashes verify");
    }

    /// Mutation caught: dropping the comparison, or treating a missing /
    /// short / garbled `sha256sum` output as success.
    #[test]
    fn remote_sha256_check_fails_closed() {
        let expected = sha_map(&[("rustynetd", H1)]);
        let shipped = vec!["rustynetd".to_owned()];
        let check = |out: &str, exp: &std::collections::BTreeMap<String, String>| {
            verify_remote_sha256(out, DIR, exp, &shipped)
        };
        // Wrong hash.
        let err =
            check(&format!("{H2}  {DIR}/rustynetd\n"), &expected).expect_err("mismatch must fail");
        assert!(
            err.contains("rustynetd") && err.contains("expected"),
            "{err}"
        );
        // Empty output (sha256sum produced nothing).
        assert!(check("", &expected).is_err());
        // Output for a different file only.
        assert!(check(&format!("{H1}  {DIR}/rustynet-cli\n"), &expected).is_err());
        // Right hash but in a different directory.
        assert!(check(&format!("{H1}  /tmp/other/rustynetd\n"), &expected).is_err());
        // Garbled line.
        assert!(check("sha256sum: no such file\n", &expected).is_err());
        // A shipped binary with no verified hash on record.
        let err = check(&format!("{H1}  {DIR}/rustynetd\n"), &sha_map(&[]))
            .expect_err("no recorded hash must fail");
        assert!(err.contains("no verified sha256"), "{err}");
    }

    /// Records every remote command / scp in order and answers `mktemp` and
    /// `sha256sum` from canned data, so the ship sequence runs without ssh.
    struct FakeRemote {
        log: std::cell::RefCell<Vec<String>>,
        mktemp_output: String,
        sha256sum_output: Result<String, ()>,
        fail_scp: bool,
        fail_chmod_dir: bool,
    }

    impl FakeRemote {
        fn new(sha256sum_output: Result<String, ()>) -> Self {
            Self {
                log: std::cell::RefCell::new(Vec::new()),
                mktemp_output: format!("{DIR}\n"),
                sha256sum_output,
                fail_scp: false,
                fail_chmod_dir: false,
            }
        }
        fn log(&self) -> Vec<String> {
            self.log.borrow().clone()
        }
    }

    impl PrebuiltRemote for FakeRemote {
        fn run(&self, command: &ssh::RemoteCommand) -> Result<String, AdapterError> {
            let text = command.as_str().replace('\'', "");
            self.log.borrow_mut().push(text.clone());
            if text.starts_with("mktemp") {
                return Ok(self.mktemp_output.clone());
            }
            if self.fail_chmod_dir && text.starts_with("chmod 700") {
                return Err(AdapterError::Protocol {
                    message: "chmod: operation not permitted".to_owned(),
                });
            }
            if text.starts_with("sha256sum") {
                return self
                    .sha256sum_output
                    .clone()
                    .map_err(|()| AdapterError::Protocol {
                        message: "sha256sum: command not found".to_owned(),
                    });
            }
            Ok(String::new())
        }
        fn scp(&self, _local: &std::path::Path, remote_path: &str) -> Result<(), AdapterError> {
            self.log.borrow_mut().push(format!("scp {remote_path}"));
            if self.fail_scp {
                return Err(AdapterError::Protocol {
                    message: "scp: connection lost".to_owned(),
                });
            }
            Ok(())
        }
    }

    fn three_binaries() -> Vec<std::path::PathBuf> {
        ["rustynetd", "rustynet-cli", "rustynet-relay"]
            .iter()
            .map(|n| std::path::PathBuf::from(format!("/host/{n}")))
            .collect()
    }

    fn expected_all() -> std::collections::BTreeMap<String, String> {
        sha_map(&[
            ("rustynetd", H1),
            ("rustynet-cli", H2),
            ("rustynet-relay", H1),
        ])
    }

    fn good_sha_output() -> String {
        format!("{H1}  {DIR}/rustynetd\n{H2}  {DIR}/rustynet-cli\n{H1}  {DIR}/rustynet-relay\n")
    }

    /// The exact command order: a fresh private dir first, locked down BEFORE any
    /// binary lands in it, hashes verified BEFORE the binaries are made
    /// executable-read-only. Mutations caught: removing the dir chmod, the
    /// sha256sum, or reordering the 0555 chmod ahead of the verification.
    #[test]
    fn ship_prebuilt_runs_the_sequence_in_order() {
        let remote = FakeRemote::new(Ok(good_sha_output()));
        let dir = ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect("a matching ship succeeds");
        assert_eq!(dir, DIR);
        assert_eq!(
            remote.log(),
            vec![
                "mktemp -d /tmp/rn_prebuilt.XXXXXXXX".to_owned(),
                format!("chmod 700 {DIR}"),
                format!("scp {DIR}/rustynetd"),
                format!("scp {DIR}/rustynet-cli"),
                format!("scp {DIR}/rustynet-relay"),
                format!("sha256sum {DIR}/rustynetd {DIR}/rustynet-cli {DIR}/rustynet-relay"),
                format!("chmod 0555 {DIR}/rustynetd {DIR}/rustynet-cli {DIR}/rustynet-relay"),
            ]
        );
    }

    /// A hash mismatch stops the ship: Err, and the 0555 chmod never ran (the
    /// caller propagates the Err before the bootstrap is even copied).
    #[test]
    fn ship_prebuilt_stops_on_a_mismatching_sha256sum() {
        let bad = good_sha_output().replace(H2, H1);
        let remote = FakeRemote::new(Ok(bad));
        let err = ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("a mismatch must fail");
        assert!(err.to_string().contains("n1") && err.to_string().contains("rustynet-cli"));
        assert!(
            !remote.log().iter().any(|c| c.starts_with("chmod 0555")),
            "no chmod 0555 after a failed verification: {:?}",
            remote.log()
        );
    }

    #[test]
    fn ship_prebuilt_fails_when_sha256sum_itself_fails() {
        let remote = FakeRemote::new(Err(()));
        let err = ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("a missing sha256sum must fail");
        assert!(err.to_string().contains("sha256sum"));
        assert!(!remote.log().iter().any(|c| c.starts_with("chmod 0555")));
    }

    /// Every failure after the dir exists removes it again, so a failed ship
    /// does not strand copies of the binaries on the node. Mutation caught:
    /// disarming the guard early / dropping the cleanup.
    #[test]
    fn ship_prebuilt_removes_the_remote_dir_on_failure_only() {
        let rm = format!("rm -rf {DIR}");
        // Hash mismatch.
        let remote = FakeRemote::new(Ok(good_sha_output().replace(H2, H1)));
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("mismatch fails");
        assert_eq!(remote.log().last(), Some(&rm), "{:?}", remote.log());
        // scp failure.
        let mut remote = FakeRemote::new(Ok(good_sha_output()));
        remote.fail_scp = true;
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("scp failure fails");
        assert_eq!(remote.log().last(), Some(&rm), "{:?}", remote.log());
        // sha256sum command failure.
        let remote = FakeRemote::new(Err(()));
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("sha256sum failure fails");
        assert_eq!(remote.log().last(), Some(&rm));
        // The dir lock-down step itself failing.
        let mut remote = FakeRemote::new(Ok(good_sha_output()));
        remote.fail_chmod_dir = true;
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect_err("chmod 700 failure fails");
        assert_eq!(remote.log().last(), Some(&rm), "{:?}", remote.log());
        assert!(!remote.log().iter().any(|c| c.starts_with("scp")));
        // Success: the dir is handed back intact (the caller's guard owns it).
        let remote = FakeRemote::new(Ok(good_sha_output()));
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), Some(&expected_all()))
            .expect("ships");
        assert!(!remote.log().iter().any(|c| c.starts_with("rm ")));
    }

    /// What `install_daemon` holds: a successful ship yields a value whose
    /// drop removes the dir (and that does not remove it earlier); a failed
    /// ship yields no value and has already cleaned up. Mutations caught:
    /// returning a disarmed guard, or dropping the guard inside the helper.
    #[test]
    fn ship_and_guard_holds_the_dir_until_dropped() {
        let remote = FakeRemote::new(Ok(good_sha_output()));
        let shipped =
            ship_and_guard(&remote, "n1", &three_binaries(), Some(&expected_all())).expect("ships");
        assert_eq!(shipped.dir, DIR);
        assert!(
            !remote.log().iter().any(|c| c.starts_with("rm ")),
            "the dir must still exist while the install runs"
        );
        drop(shipped);
        assert_eq!(remote.log().last(), Some(&format!("rm -rf {DIR}")));
        let remote = FakeRemote::new(Ok(good_sha_output().replace(H1, H2)));
        assert!(ship_and_guard(&remote, "n1", &three_binaries(), Some(&expected_all())).is_err());
        assert_eq!(remote.log().last(), Some(&format!("rm -rf {DIR}")));
    }

    #[test]
    fn remote_dir_cleanup_guard_removes_on_drop_unless_disarmed() {
        let remote = FakeRemote::new(Ok(String::new()));
        drop(RemoteDirCleanup::new(&remote, DIR.to_owned()));
        assert_eq!(remote.log(), vec![format!("rm -rf {DIR}")]);
        let remote = FakeRemote::new(Ok(String::new()));
        let dir = RemoteDirCleanup::new(&remote, DIR.to_owned()).disarm();
        assert_eq!(dir, DIR);
        assert!(remote.log().is_empty());
        // A path outside the per-install prefix is never removed.
        let remote = FakeRemote::new(Ok(String::new()));
        drop(RemoteDirCleanup::new(&remote, "/tmp".to_owned()));
        assert!(remote.log().is_empty());
    }

    /// Without recorded hashes (plain host-cross-binary) there is nothing to
    /// compare, so no sha256sum is run — but the dir is still private + fresh.
    #[test]
    fn ship_prebuilt_without_expected_hashes_skips_only_the_verification() {
        let remote = FakeRemote::new(Err(()));
        ship_prebuilt_binaries(&remote, "n1", &three_binaries(), None).expect("ships");
        let log = remote.log();
        assert!(!log.iter().any(|c| c.starts_with("sha256sum")));
        assert!(log[0].starts_with("mktemp -d") && log[1] == format!("chmod 700 {DIR}"));
    }

    /// The dir name comes back from the node and lands in the bootstrap env
    /// file, so anything but `/tmp/rn_prebuilt.<alnum>` is refused.
    #[test]
    fn ship_prebuilt_rejects_an_unexpected_mktemp_result() {
        for bad in [
            "/tmp/other.abc",
            "/tmp/rn_prebuilt.",
            "/tmp/rn_prebuilt.a/b",
            "/tmp/rn_prebuilt.a$b",
            "/tmp/rn_prebuilt.a b",
            "",
        ] {
            let mut remote = FakeRemote::new(Ok(good_sha_output()));
            remote.mktemp_output = bad.to_owned();
            assert!(
                ship_prebuilt_binaries(&remote, "n1", &three_binaries(), None).is_err(),
                "{bad}"
            );
            assert_eq!(remote.log().len(), 1, "nothing runs after a bad dir: {bad}");
        }
    }

    /// Pin: install_daemon ships (and so verifies) BEFORE it copies the
    /// bootstrap env/archive or runs the bootstrap, and points the bootstrap at
    /// the per-install dir rather than a fixed /tmp path. Mutation caught:
    /// dropping the verification arm at runtime is caught by the behavioural
    /// tests above; this pins the call site's placement and wiring.
    #[test]
    fn install_daemon_ships_prebuilts_before_bootstrap_and_uses_the_private_dir() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("pub fn install_daemon(")
            .expect("install_daemon must exist");
        let body = &source[start..];
        let end = body[1..]
            .find("\npub fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len());
        let body = &body[..end];
        let ship = body.find("ship_and_guard(").expect("ship call");
        let read_sums = body.find("read_prebuilt_sha256(").expect("hash read");
        let env_scp = body.find("\"/tmp/rn_bootstrap.env\"").expect("env scp");
        let bootstrap = body
            .find("bash /tmp/rn_bootstrap.sh")
            .expect("bootstrap run");
        assert!(read_sums < ship && ship < env_scp && env_scp < bootstrap);
        // The cleanup guard is created by ship_and_guard and held in a NAMED
        // binding (`shipped`) across every later step, in scope until return.
        assert!(
            body.contains("let shipped = match &prebuilt_binaries {")
                && body.contains("ship_and_guard(&remote, alias, binaries, expected.as_ref())?")
                && body.contains("Some(shipped)"),
            "install_daemon must keep the guard-owning value alive"
        );
        // The dir is read out BY REFERENCE: consuming `shipped` would drop the
        // guard (and rm -rf the dir) before the bootstrap runs.
        assert!(
            body.contains("shipped.as_ref().map(|s| s.dir.clone())"),
            "the guard-owning value must outlive the env/bootstrap steps"
        );
        assert!(
            body.contains("RN_PREBUILT_DIR={dir}")
                && !body.contains("RN_PREBUILT_DIR=/tmp/rn_prebuilt"),
            "the env must carry the per-install dir"
        );
    }
}

#[cfg(test)]
mod daemon_launch_flag_parity_tests {
    //! N4 flag-parity (NodeEngineAdapterParityManifest 2026-09-09 F3): the
    //! Linux daemon's launch flags live in the systemd unit the bootstrap
    //! installs, so that unit's ExecStart must carry every
    //! [`REQUIRED_DAEMON_LAUNCH_FLAGS`] entry — a dropped `--node-role`
    //! silently defaults the daemon to admin (the Windows N4 failure class).

    use super::BOOTSTRAP_SCRIPT;
    use super::lab_substrate_env_line;

    /// The exact unit `ops install-systemd` renders to
    /// /etc/systemd/system/rustynetd.service during bootstrap.
    static LINUX_DAEMON_UNIT: &str =
        include_str!("../../../../../../scripts/systemd/rustynetd.service");

    /// Mutation: drop `--node-role ${RUSTYNET_NODE_ROLE}` from the unit's
    /// ExecStart — this test must fail.
    #[test]
    fn linux_daemon_args_include_every_required_launch_flag() {
        let exec_start = LINUX_DAEMON_UNIT
            .lines()
            .find(|line| line.trim_start().starts_with("ExecStart="))
            .expect("rustynetd.service must declare an ExecStart line");
        for flag in crate::vm_lab::orchestrator::adapter::node_adapter::REQUIRED_DAEMON_LAUNCH_FLAGS
        {
            assert!(
                exec_start.contains(&format!("{flag} ${{")),
                "Linux daemon ExecStart is missing required launch flag {flag}"
            );
        }
    }

    /// The bootstrap env file is the only carrier for ROLE/NODE_ID into the
    /// unit's `--node-role`/`--node-id` values, so the two halves must stay
    /// wired: build_bootstrap_env must keep emitting ROLE= and NODE_ID= and
    /// the unit must keep consuming them. Mutation: rename ROLE= in
    /// build_bootstrap_env — this test must fail.
    #[test]
    fn bootstrap_env_identity_keys_feed_the_unit_identity_flags() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("fn build_bootstrap_env(")
            .expect("build_bootstrap_env must exist");
        let body = &source[start..];
        assert!(
            body.contains("ROLE={role_str}") && body.contains("NODE_ID={node_id}"),
            "bootstrap env must keep emitting ROLE= and NODE_ID= for the unit"
        );
        assert!(
            LINUX_DAEMON_UNIT.contains("--node-role ${RUSTYNET_NODE_ROLE}"),
            "unit must consume the node role env the bootstrap env provides"
        );
    }

    /// Only a vxlan run that provisioned the overlay asks the bootstrap to
    /// build the daemon with `lab-substrate`; every other substrate state
    /// (no record, different substrate, not provisioned) keeps the env
    /// byte-identical to the pre-substrate format.
    #[test]
    fn lab_substrate_env_line_is_emitted_only_for_provisioned_vxlan() {
        use crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord;
        let record = |substrate_id: &str, provisioned: bool| SubstrateRecord {
            substrate_id: substrate_id.to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned,
            participants: vec![],
        };
        assert_eq!(
            lab_substrate_env_line(Some(&record("vxlan", true))),
            "RN_LAB_SUBSTRATE=1\n"
        );
        for record in [
            None,
            Some(record("vxlan", false)),
            Some(record("netns", true)),
        ] {
            assert_eq!(
                lab_substrate_env_line(record.as_ref()),
                "",
                "non-vxlan or unprovisioned substrate must not enable the lab build feature"
            );
        }
    }

    /// Source pin: build_bootstrap_env must thread the substrate line into the
    /// env content (mutation caught: dropping the lab_substrate_env_line call
    /// would strand vxlan runs on daemons without the lab-substrate feature).
    #[test]
    fn bootstrap_env_threads_the_lab_substrate_line() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("linux_install.rs"))
            .expect("linux_install.rs implementation slice must parse");
        let start = source
            .find("fn build_bootstrap_env(")
            .expect("build_bootstrap_env must exist");
        let body = &source[start..];
        assert!(
            body.contains("lab_substrate_env_line(ctx.substrate_record.as_ref())"),
            "bootstrap env must forward the vxlan lab-substrate request to rn_bootstrap.sh"
        );
    }

    /// Source pin (script side): rn_bootstrap.sh must (a) allowlist
    /// RN_LAB_SUBSTRATE in the strict env parser and (b) apply the feature
    /// flag to BOTH daemon build paths (registry + offline fallback) without
    /// touching the cli/relay feature sets.
    #[test]
    fn bootstrap_script_gates_the_daemon_lab_substrate_feature() {
        assert!(
            BOOTSTRAP_SCRIPT.contains("\n  RN_LAB_SUBSTRATE\n"),
            "env parser allowlist must accept RN_LAB_SUBSTRATE"
        );
        assert!(
            BOOTSTRAP_SCRIPT.contains("rn_daemon_features=\"--features lab-substrate\""),
            "bootstrap must map RN_LAB_SUBSTRATE=1 to --features lab-substrate"
        );
        let build_lines = BOOTSTRAP_SCRIPT
            .lines()
            .filter(|line| line.contains("-p rustynetd "))
            .count();
        assert!(
            build_lines >= 2,
            "both the registry and the offline daemon build must exist: {build_lines}"
        );
        for line in BOOTSTRAP_SCRIPT
            .lines()
            .filter(|l| l.contains("-p rustynetd "))
        {
            assert!(
                line.contains("$rn_daemon_features"),
                "daemon build must honour the lab-substrate gate: {line}"
            );
        }
        assert_eq!(
            BOOTSTRAP_SCRIPT
                .lines()
                .filter(|line| line.contains("rn_daemon_features"))
                .count(),
            4,
            "gate init + condition + exactly two build sites expected"
        );
    }

    /// F2 pin: `enforce_daemon` must refuse to mint a label-derived
    /// `{alias}-bootstrap` identity when the context carries no
    /// daemon-reported node id. Mutation caught: restoring the
    /// `unwrap_or_else(|| format!("{alias}-bootstrap"))` fallback flips this
    /// test red (the call proceeds toward SSH instead of erroring).
    #[test]
    fn enforce_daemon_refuses_to_mint_node_id_when_context_has_none() {
        use super::{NodeConnection, OrchestrationContext, enforce_daemon};
        use crate::vm_lab::orchestrator::error::AdapterError;
        use std::collections::HashMap;
        let conn = NodeConnection::Ssh {
            host: "linux-refuses-mint".to_owned(),
            port: 22,
            user: None,
            identity_file: std::path::PathBuf::from("/tmp/id"),
            known_hosts: std::path::PathBuf::from("/tmp/known_hosts"),
            ssh_password: None,
        };
        let ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: "/tmp".into(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        let err = enforce_daemon(&conn, "debian-9", &ctx)
            .expect_err("enforce without a daemon-reported id must fail closed");
        let AdapterError::Protocol { message } = err else {
            panic!("expected Protocol error, got: {err:?}");
        };
        assert!(
            message.contains("collect_pubkeys must run first"),
            "error must name the prerequisite: {message}"
        );
        assert!(
            message.contains("-bootstrap"),
            "error must name the refused mint: {message}"
        );
    }

    /// F2 positive control: the mint survives at INSTALL time only, behind
    /// the named helper — the one sanctioned `-bootstrap` site on this path.
    #[test]
    fn install_daemon_still_mints_the_bootstrap_id_through_the_named_helper() {
        assert_eq!(
            crate::vm_lab::orchestrator::adapter::mint_bootstrap_node_id("debian-1"),
            "debian-1-bootstrap"
        );
    }
}
