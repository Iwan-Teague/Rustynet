#![allow(dead_code)]
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_install::{MACOS_KEYS_DIR, MACOS_STATE_ROOT};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};

const SHORT_TIMEOUT: Duration = Duration::from_secs(30);
const MEDIUM_TIMEOUT: Duration = Duration::from_secs(120);

/// Stop every RustyNet launchd surface that can own the daemon binary or keep
/// stale role state alive across lab runs. The plain daemon profile is not the
/// only process owner: macOS anchor deploys `com.rustynet.anchor`, which runs
/// `/usr/local/bin/rustynetd` too, and relay/privileged-helper profiles can
/// preserve sockets, pf anchors, or state contention. Use both service labels
/// and plist paths because `launchctl bootout` behavior differs depending on
/// whether the job was bootstrapped by label or file path. Then TERM/KILL as a
/// backstop and wait on the real processes, not launchd state.
const MACOS_LAUNCHD_STOP_COMMAND: &str = "sudo -n launchctl bootout system/com.rustynet.daemon 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.daemon.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.privileged-helper.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.anchor 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.anchor.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.relay 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.relay.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.exit 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.exit.plist 2>/dev/null || true; \
     sudo -n pkill -TERM -x rustynetd 2>/dev/null || true; \
     sudo -n pkill -TERM -f '/usr/local/bin/rustynetd.*privileged-helper' 2>/dev/null || true; \
     sudo -n pkill -TERM -x rustynet-relay 2>/dev/null || true; \
     for _ in $(seq 1 60); do \
         if pgrep -x rustynetd >/dev/null 2>&1 || pgrep -x rustynet-relay >/dev/null 2>&1; then \
             sleep 0.5; \
         else \
             break; \
         fi; \
     done; \
     sudo -n launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.anchor 2>/dev/null || true; \
     sudo -n pkill -KILL -x rustynetd 2>/dev/null || true; \
     sudo -n pkill -KILL -f '/usr/local/bin/rustynetd.*privileged-helper' 2>/dev/null || true; \
     sudo -n pkill -KILL -x rustynet-relay 2>/dev/null || true; \
     for _ in $(seq 1 20); do \
         if pgrep -x rustynetd >/dev/null 2>&1 || pgrep -x rustynet-relay >/dev/null 2>&1; then \
             sleep 0.5; \
         else \
             break; \
         fi; \
     done";

/// Tear down any residual RustyNet `pf` killswitch / exit-NAT anchor a crashed or
/// torn-down daemon left loaded, then any leftover mesh `utun` interface. This is
/// the macOS analogue of the Linux `LINUX_NFT_KILLSWITCH_RESET_COMMAND` +
/// `LINUX_INTERFACE_RESET_COMMAND`: a default-deny killswitch anchor still loaded
/// starves the next bootstrap's egress, and a `utun` still carrying the mesh CIDR
/// collides with the next bring-up.
///
/// Three RustyNet pf anchor families can be left behind (all confirmed against
/// the daemon's own constants):
///
/// - `com.apple/rustynet_g<N>` — the generation-rotated killswitch/filter anchor
///   (`macos_exit_killswitch_precedence::MACOS_RUSTYNET_ANCHOR_PREFIX`),
/// - `com.rustynet/nat` — the regular-exit NAT anchor
///   (`macos_exit_nat_lifecycle::DEFAULT_MACOS_EXIT_PF_ANCHOR`),
/// - `com.rustynet/blind_exit` — the blind-exit filter anchor
///   (`macos_blind_exit::DEFAULT_MACOS_BLIND_EXIT_PF_ANCHOR`).
///
/// Anchors are ENUMERATED from `pfctl -s Anchors` and matched on the substring
/// `rustynet` (covers every family, including an unanticipated future
/// generation), then flushed with `pfctl -a <anchor> -F all` — never a fixed
/// name, so an unexpected anchor cannot be left loaded. `-F all` only flushes
/// that anchor's own rules/state; it does not touch the base ruleset.
///
/// The mesh interface on macOS is a node-id-derived `utun<N>` (index 10–4095,
/// NOT a fixed `rustynet0`; see `macos_install::utun_name_for_node_id`), so it
/// cannot be matched by a `rustynet*` name prefix the way Linux links are.
/// Instead a leftover mesh interface is identified by the RustyNet CGNAT mesh
/// address it carries (`100.64.0.0/10`, RFC 6598): any `utun` with an
/// `inet 100.64..100.127` address is a stale RustyNet device and is removed with
/// `ifconfig <utun> destroy`. A bare `utun` without a mesh address is left alone
/// (iCloud Private Relay / corporate VPNs also use `utun`). Best-effort and
/// idempotent at every privileged step; runs AFTER the daemon is stopped so
/// nothing re-creates the anchor or device mid-delete.
const MACOS_RESET_COMMAND: &str = "rn_anchors=$(sudo -n pfctl -s Anchors 2>/dev/null \
         | sed 's/^[[:space:]]*//' | grep -i rustynet || true); \
     for a in $rn_anchors; do sudo -n pfctl -a \"$a\" -F all 2>/dev/null || true; done; \
     for dev in $(ifconfig -l 2>/dev/null | tr ' ' '\\n' | grep '^utun'); do \
         if ifconfig \"$dev\" 2>/dev/null | grep -Eq 'inet 100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'; then \
             sudo -n ifconfig \"$dev\" destroy 2>/dev/null || true; \
         fi; \
     done";

/// Comprehensive post-cleanup verification probe used by [`assert_node_clean`],
/// the macOS analogue of `linux_traffic::LINUX_NODE_CLEAN_PROBE`. Emits exactly
/// three space-separated tokens on a single line that
/// [`parse_macos_node_clean_probe`] interprets:
///   `pf=<names|->`    active leftover RustyNet pf anchor names, or `-` if none
///   `daemon=<up|down>` whether a `rustynetd` process is still running
///   `iface=<names|->`  leftover mesh `utun` interface names (a `utun` carrying a
///                      `100.64.0.0/10` mesh address), or `-` if none
///
/// A node is clean only when all three are benign (`pf=-`, `daemon=down`,
/// `iface=-`). `pfctl -s Anchors` can retain an empty parent anchor name after
/// rules/state are flushed, so the pf dimension reports only anchors that still
/// carry rules, NAT rules, or state. Each sub-probe tolerates the relevant tool
/// being absent and is read-only (mutates nothing), so it is safe to run
/// repeatedly.
const MACOS_NODE_CLEAN_PROBE: &str = "rn_pf=''; \
     for a in $(sudo -n pfctl -s Anchors 2>/dev/null \
         | sed 's/^[[:space:]]*//' | grep -i rustynet || true); do \
         if sudo -n pfctl -a \"$a\" -sr 2>/dev/null | grep -q . \
             || sudo -n pfctl -a \"$a\" -sn 2>/dev/null | grep -q . \
             || sudo -n pfctl -a \"$a\" -ss 2>/dev/null | grep -q .; then \
             rn_pf=\"${rn_pf}${a},\"; \
         fi; \
     done; \
     rn_daemon=$(pgrep -x rustynetd >/dev/null 2>&1 && echo up || echo down); \
     rn_iface=$(for dev in $(ifconfig -l 2>/dev/null | tr ' ' '\\n' | grep '^utun'); do \
             if ifconfig \"$dev\" 2>/dev/null \
                 | grep -Eq 'inet 100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\.'; then \
                 printf '%s,' \"$dev\"; \
             fi; \
         done); \
     printf 'pf=%s daemon=%s iface=%s\\n' \
         \"${rn_pf:--}\" \"$rn_daemon\" \"${rn_iface:--}\"";

/// Pure parser for [`MACOS_NODE_CLEAN_PROBE`] output, the macOS analogue of
/// `linux_traffic::parse_node_clean_probe`. Returns `Ok(())` when the node is
/// verifiably clean (no leftover RustyNet pf anchor, no running `rustynetd`, no
/// leftover mesh `utun`) and a descriptive `node still dirty: …` error listing
/// every dirty dimension otherwise.
///
/// Fail closed: any token that is missing, malformed, or does not explicitly
/// assert the benign value is treated as dirty. A truncated or garbled probe
/// (e.g. SSH noise prepended) therefore fails the assertion rather than passing
/// a node whose true state is unknown.
fn parse_macos_node_clean_probe(raw: &str) -> Result<(), AdapterError> {
    // The probe prints a single result line; tolerate leading log/banner lines
    // by scanning for the line that carries the three expected tokens.
    let line = raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .rev()
        .find(|l| l.contains("pf=") && l.contains("daemon=") && l.contains("iface="));
    let Some(line) = line else {
        return Err(AdapterError::Protocol {
            message: format!(
                "node still dirty: clean-probe output unrecognised (fail closed): {:?}",
                raw.trim()
            ),
        });
    };

    let mut pf: Option<&str> = None;
    let mut daemon: Option<&str> = None;
    let mut iface: Option<&str> = None;
    for tok in line.split_whitespace() {
        if let Some(v) = tok.strip_prefix("pf=") {
            pf = Some(v);
        } else if let Some(v) = tok.strip_prefix("daemon=") {
            daemon = Some(v);
        } else if let Some(v) = tok.strip_prefix("iface=") {
            iface = Some(v);
        }
    }

    // `-` (or empty) is the benign "nothing leftover" sentinel; any other value
    // is a comma-joined list of leftover resource names. Strip a trailing comma
    // the `tr '\n' ','` / `printf '%s,'` join leaves on a non-empty list.
    let clean_list = |v: Option<&str>| -> Option<String> {
        match v {
            None => None, // token absent → unknown → treat as dirty below
            Some(s) => {
                let s = s.trim().trim_end_matches(',');
                if s.is_empty() || s == "-" {
                    Some(String::new())
                } else {
                    Some(s.to_owned())
                }
            }
        }
    };

    let mut dirty: Vec<String> = Vec::new();
    match clean_list(pf) {
        Some(s) if s.is_empty() => {}
        Some(s) => dirty.push(format!("pf anchor(s): {s}")),
        None => dirty.push("pf-anchor status unknown (probe token missing)".to_owned()),
    }
    match daemon {
        Some("down") => {}
        Some("up") => dirty.push("rustynetd still running".to_owned()),
        _ => dirty.push("daemon status unknown (probe token missing)".to_owned()),
    }
    match clean_list(iface) {
        Some(s) if s.is_empty() => {}
        Some(s) => dirty.push(format!("mesh utun interface(s): {s}")),
        None => dirty.push("interface status unknown (probe token missing)".to_owned()),
    }

    if dirty.is_empty() {
        Ok(())
    } else {
        Err(AdapterError::Protocol {
            message: format!("node still dirty after cleanup: {}", dirty.join("; ")),
        })
    }
}

/// Read the `WireGuard` public key from the macOS state root.
/// Returns the base64-encoded key decoded to hex.
/// The keys directory is mode 700 owned by rustynetd, so the SSH user needs
/// sudo to traverse it. Try sudo first, fall back to direct access.
pub fn collect_wireguard_public_key(conn: &NodeConnection) -> Result<String, AdapterError> {
    let pub_key_path = format!("{MACOS_KEYS_DIR}/wireguard.pub");
    let output = ssh::run_remote(
        conn,
        &format!(
            "if sudo -n true >/dev/null 2>&1; then \
                 sudo -n cat '{pub_key_path}'; \
             else \
                 cat '{pub_key_path}' 2>/dev/null || echo ''; \
             fi"
        ),
        SHORT_TIMEOUT,
    )?;
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(AdapterError::Protocol {
            message: format!(
                "WireGuard public key not found at {pub_key_path}; \
                 has the daemon been bootstrapped?"
            ),
        });
    }
    decode_wireguard_pubkey_to_hex(trimmed).map_err(|err| AdapterError::Protocol { message: err })
}

/// Read the local `node_id` from the running daemon via `rustynet status`.
/// Falls back to extracting `--node-id` from the launchd plist if the
/// `rustynet` CLI binary is absent (e.g. a SKIP_BUILD bootstrap that only
/// installed `rustynetd`).
pub fn collect_node_id(conn: &NodeConnection) -> Result<String, AdapterError> {
    // Read node_id from the launchd plist (--node-id) FIRST — it is the
    // authoritative value the daemon was configured with and needs no IPC
    // socket. `rustynet status` queries the daemon socket, which is unreliable
    // at bootstrap (enforce=false): the reconcile loop fail-closes on the
    // not-yet-distributed membership ("membership snapshot is missing") and
    // escalates to restrict_permanent within max_reconcile_failures, tearing
    // the socket down before collect_pubkeys runs (observed live: collect_pubkeys
    // "node_id: daemon unreachable: …rustynetd.sock: Connection refused"). The
    // restrict_permanent state is transient — the enforce_baseline_runtime
    // restart clears it once membership is distributed — so node_id collection
    // must not depend on the socket. Fall back to `rustynet status` only if the
    // plist read yields nothing.
    let output = ssh::run_remote(
        conn,
        "nid=$(sudo -n /usr/libexec/PlistBuddy \
                 -c 'Print :ProgramArguments' \
                 /Library/LaunchDaemons/com.rustynet.daemon.plist 2>/dev/null \
               | awk '/--node-id/{getline; gsub(/^[[:space:]]+|[[:space:]]+$/, \"\"); print}'); \
         if test -n \"$nid\"; then \
             echo \"$nid\"; \
         elif test -x /usr/local/bin/rustynet; then \
             sudo -n env \
               RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock \
               /usr/local/bin/rustynet status 2>&1; \
         fi",
        SHORT_TIMEOUT,
    )?;
    // Try to parse as `rustynet status` output first (contains `node_id=<value>`).
    if let Some(nid) = ssh::parse_status_node_id(&output) {
        return Ok(nid);
    }
    // Plist fallback: awk emits the raw node-id value on a single line.
    let trimmed = output.trim().to_owned();
    if trimmed.is_empty() {
        return Err(AdapterError::Protocol {
            message: "could not determine node_id: rustynet CLI absent and plist fallback \
                      returned empty (plist may not exist yet)"
                .to_owned(),
        });
    }
    Ok(trimmed)
}

/// Ping `peer_mesh_ip` 3 times. Returns `Reachable` on success.
/// On failure, captures the full ping stdout/stderr so the stage log
/// carries diagnostic detail instead of a bare "ping to X failed".
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    let script = format!("ping -c 3 -W 1000 '{peer_mesh_ip}' 2>&1");
    match ssh::run_remote(conn, &script, Duration::from_secs(30)) {
        Ok(_stdout) => Ok(TrafficTestResult::Reachable),
        Err(AdapterError::Command { stderr, .. }) => Ok(TrafficTestResult::Error(format!(
            "ping to {peer_mesh_ip} failed: {}",
            stderr.trim()
        ))),
        Err(other) => Err(other),
    }
}

/// Negative ACL test: confirm `denied_ip` is blocked.
pub fn probe_denied_peer(
    conn: &NodeConnection,
    denied_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(denied_ip)?;
    let output = ssh::run_remote(
        conn,
        &format!("ping -c 1 -W 5000 '{denied_ip}' >/dev/null 2>&1 && echo ok || echo fail"),
        Duration::from_secs(15),
    )?;
    if output.trim() == "ok" {
        Ok(TrafficTestResult::Reachable) // reached denied target = security failure
    } else {
        Ok(TrafficTestResult::Blocked) // blocked as expected
    }
}

/// Collect active `WireGuard` tunnels via `wg show`.
pub fn collect_active_tunnels(conn: &NodeConnection) -> Result<TunnelsList, AdapterError> {
    let output = ssh::run_remote(
        conn,
        "wg show 2>/dev/null || echo 'wg-not-installed'",
        SHORT_TIMEOUT,
    )?;
    let tunnels: Vec<String> = output
        .lines()
        .filter(|l| !l.is_empty())
        .map(std::string::ToString::to_string)
        .collect();
    Ok(TunnelsList { tunnels })
}

/// Collect diagnostic artifacts from the macOS host to `dst`.
/// Key material paths (`keys/*`, `*.priv`) MUST NOT appear in the archive.
pub fn collect_artifacts(conn: &NodeConnection, dst: &Path) -> Result<(), AdapterError> {
    let remote_tmp = "/tmp/rn_diag_artifacts.tar.gz";

    let diag_cmd = format!(
        "tar -czf '{remote_tmp}' \
         --exclude='{MACOS_STATE_ROOT}/keys' \
         --exclude='*.priv' \
         --exclude='*.key' \
         --exclude='*.pem' \
         '{MACOS_STATE_ROOT}' /usr/local/var/log/rustynet 2>/dev/null || \
         tar -czf '{remote_tmp}' --files-from /dev/null"
    );
    ssh::run_remote(conn, &diag_cmd, MEDIUM_TIMEOUT)?;

    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local artifact destination dir failed: {err}"),
        })?;
    }
    ssh::scp_from(conn, remote_tmp, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let _ = ssh::run_remote(conn, &format!("rm -f '{remote_tmp}'"), SHORT_TIMEOUT);

    verify_no_key_material_tarball(dst)?;

    Ok(())
}

/// Remove runtime state files, leaving the installation intact.
pub fn cleanup_runtime_state(conn: &NodeConnection) -> Result<(), AdapterError> {
    // Stop launchd/process surfaces first (best-effort). Wait until no
    // rustynetd/rustynet-relay process remains BEFORE pf/interface reset:
    // a live role daemon can re-load the killswitch anchor or re-create the
    // utun after a single flush pass, tripping assert_node_clean.
    let _ = ssh::run_remote(conn, MACOS_LAUNCHD_STOP_COMMAND, Duration::from_secs(90));

    // Flush every leftover RustyNet pf killswitch / exit-NAT anchor and tear down
    // any residual mesh `utun` interface the daemon left behind. Runs AFTER the
    // daemon-stop wait so nothing re-creates the anchor/device mid-delete. Without
    // this a prior run's default-deny killswitch anchor starves the next
    // bootstrap's egress (cargo registry downloads), and a stale utun still
    // carrying the mesh CIDR collides with the fresh bring-up. Best-effort and
    // idempotent — a clean node is a no-op.
    let _ = ssh::run_remote(conn, MACOS_RESET_COMMAND, Duration::from_secs(30));

    // Remove runtime state but keep WG keys and the installation. This now
    // includes the seed trust evidence (`rustynetd.trust`) and its anti-replay
    // watermark: the macOS bootstrap's `seed_trust_evidence` skips when
    // `rustynetd.trust` already exists, so without removing it on a rebuild the
    // node reuses the *previous* run's seed. That seed goes stale past the
    // daemon's `--trust-max-age-secs` (24h) and fails startup trust-preflight
    // ("trust evidence is stale"), which surfaces only as a bootstrap
    // socket-never-appeared hang. Purging it forces a fresh, current-dated seed
    // on every rebuild — the orchestrator's distribute_* stages then layer the
    // real signed trust/membership over it — matching the clean-slate intent of
    // `--rebuild-nodes`. The watermark is cleared too so the fresh seed is not
    // rejected as a rollback/replay.
    // Also purge the daemon runtime state file (`rustynetd.state`). It persists
    // operational state — including `selected_exit_node` — across restarts.
    // Without removing it on a rebuild the daemon reloads a STALE
    // `selected_exit_node` from an earlier topology (observed live: a May-31
    // `selected_exit_node=exit-1` survived a clean rebuild), and the reconcile
    // loop fails closed — "selected exit node is not active: exit-1" — because
    // that node is absent from the freshly distributed membership, escalating to
    // restrict_permanent and tearing the mesh IP down. Purging it forces the
    // daemon to re-derive its exit selection from the current signed
    // auto-tunnel bundle. It carries no anti-replay watermark (those are the
    // separate `*.watermark` files cleared above), so removal is safe.
    ssh::run_remote(
        conn,
        &format!(
            "sudo rm -f \
             '{MACOS_STATE_ROOT}/membership/membership.snapshot' \
             '{MACOS_STATE_ROOT}/membership/membership.log' \
             '{MACOS_STATE_ROOT}/membership/membership.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.trust' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.trust.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.assignment' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.assignment.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.traversal' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.traversal.watermark' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.dns-zone' \
             '{MACOS_STATE_ROOT}/trust/rustynetd.dns-zone.watermark' \
             '{MACOS_STATE_ROOT}/rustynetd.state' \
             '{MACOS_STATE_ROOT}/keys/wireguard.key' \
             2>/dev/null || true"
        ),
        SHORT_TIMEOUT,
    )?;
    Ok(())
}

/// After cleanup, assert the node is verifiably clean across all three
/// dimensions that break the next bootstrap, the macOS analogue of
/// `linux_traffic::assert_node_clean`: no leftover RustyNet `pf` killswitch /
/// exit-NAT anchor (a default-deny anchor starves egress), no running
/// `rustynetd` (a live daemon re-loads the anchor and owns the interface), and
/// no leftover mesh `utun` interface (a stale device carrying the mesh CIDR
/// collides with the fresh bring-up). Fails loudly so a reset that did not take
/// is caught here, not as a cargo DNS timeout five stages later.
pub fn assert_node_clean(conn: &NodeConnection) -> Result<(), AdapterError> {
    let raw = ssh::run_remote(conn, MACOS_NODE_CLEAN_PROBE, SHORT_TIMEOUT)?;
    parse_macos_node_clean_probe(&raw)
}

/// Best-effort: the macOS daemon's own fail-closed/startup reason, read from
/// `<state-root>/logs/rustynetd.log`, so an enforce failure reports the cause
/// rather than just the downstream symptom.
pub fn collect_daemon_failure_reason(
    conn: &NodeConnection,
) -> Result<Option<String>, AdapterError> {
    let tail = ssh::run_remote(
        conn,
        &format!("sudo -n tail -n 200 '{MACOS_STATE_ROOT}/logs/rustynetd.log' 2>/dev/null || true"),
        SHORT_TIMEOUT,
    )?;
    Ok(crate::vm_lab::orchestrator::adapter::node_adapter::extract_daemon_failure_reason(&tail))
}

/// Verify SSH connectivity by running a no-op command.
pub fn check_ssh_reachable(conn: &NodeConnection) -> Result<(), AdapterError> {
    ssh::run_remote(conn, "echo reachable", Duration::from_secs(10))?;
    Ok(())
}

/// Collect the `WireGuard` mesh IP from the running daemon interface or status.
pub fn collect_mesh_ip(conn: &NodeConnection) -> Result<String, AdapterError> {
    // Prefer the daemon's own status: it reports the mesh IP for the specific
    // node-assigned utun device. A bare `ifconfig | grep utun` can pick the
    // first inet among ANY utun interface (iCloud Private Relay, a corporate
    // VPN, etc.), which on a real Mac may not be the rustynet interface.
    // Query status (sudo + socket env, matching collect_node_id) first and
    // only fall back to the interface scan if status is unavailable.
    let status = ssh::run_remote(
        conn,
        "sudo -n env RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock \
         /usr/local/bin/rustynet status 2>/dev/null || echo ''",
        SHORT_TIMEOUT,
    )?;
    if let Some(ip) = ssh::parse_status_field(&status, "mesh_ip")
        .or_else(|| ssh::parse_status_field(&status, "wg_ip"))
    {
        return Ok(ip);
    }

    let ip = ssh::run_remote(
        conn,
        "ifconfig 2>/dev/null \
         | grep -A 5 'rustynet\\|utun' \
         | grep 'inet ' \
         | awk '{print $2}' | head -1 || echo ''",
        SHORT_TIMEOUT,
    )?;
    let ip = ip.trim().to_owned();
    if !ip.is_empty() {
        return Ok(ip);
    }
    Err(AdapterError::Protocol {
        message: "mesh IP not found via rustynet status or ifconfig".to_owned(),
    })
}

/// Issue signed bundles on this exit node and SCP the results to `local_out_dir`.
pub fn issue_bundles_to_dir(
    conn: &NodeConnection,
    rustynet_path: &str,
    kind: &crate::vm_lab::orchestrator::error::BundleKind,
    env_content: &str,
    local_out_dir: &std::path::Path,
) -> Result<(), AdapterError> {
    use std::io::Write as IoWrite;
    let pid = std::process::id();
    let remote_env = format!("/tmp/rn_issue_env_{pid}.env");
    let remote_issue_dir = format!("/tmp/rn_issue_{pid}");

    let issue_subcmd = match kind {
        crate::vm_lab::orchestrator::error::BundleKind::Assignment => {
            "e2e-issue-assignment-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Traversal => {
            "e2e-issue-traversal-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::DnsZone => {
            "e2e-issue-dns-zone-bundles-from-env"
        }
        crate::vm_lab::orchestrator::error::BundleKind::Membership => {
            return Err(AdapterError::Protocol {
                message: "Membership bundles are issued via init_membership_snapshot".to_owned(),
            });
        }
    };

    let mut env_tmp = std::env::temp_dir();
    env_tmp.push(format!("rn_issue_env_{pid}.env"));
    {
        let mut f = std::fs::File::create(&env_tmp).map_err(|e| AdapterError::Io {
            message: format!("create env tmp: {e}"),
        })?;
        f.write_all(env_content.as_bytes())
            .map_err(|e| AdapterError::Io {
                message: format!("write env tmp: {e}"),
            })?;
    }
    ssh::scp_to(conn, &env_tmp, &remote_env, MEDIUM_TIMEOUT)?;
    let _ = std::fs::remove_file(&env_tmp);

    ssh::run_remote(
        conn,
        &format!("mkdir -p '{remote_issue_dir}'"),
        SHORT_TIMEOUT,
    )?;

    let safe_rustynet = rustynet_path.replace('\'', "'\"'\"'");
    ssh::run_remote(
        conn,
        &format!(
            "env RUSTYNET_NODE_ROLE=admin sudo \
             '{safe_rustynet}' ops {issue_subcmd} \
             --env-file '{remote_env}' --issue-dir '{remote_issue_dir}'"
        ),
        MEDIUM_TIMEOUT,
    )?;

    let listing = ssh::run_remote(
        conn,
        &format!("ls -1 '{remote_issue_dir}' 2>/dev/null"),
        SHORT_TIMEOUT,
    )?;

    std::fs::create_dir_all(local_out_dir).map_err(|e| AdapterError::Io {
        message: format!("create local out dir: {e}"),
    })?;

    for filename in listing.lines().map(str::trim).filter(|s| !s.is_empty()) {
        let remote_path = format!("{remote_issue_dir}/{filename}");
        let local_path = local_out_dir.join(filename);
        ssh::scp_from(conn, &remote_path, &local_path, MEDIUM_TIMEOUT)?;
    }

    let _ = ssh::run_remote(
        conn,
        &format!("rm -f '{remote_env}' && rm -rf '{remote_issue_dir}'"),
        SHORT_TIMEOUT,
    );

    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

fn validate_ip_arg(ip: &str) -> Result<(), AdapterError> {
    let addr = ip.parse::<IpAddr>().map_err(|err| AdapterError::Protocol {
        message: format!("IP argument {ip:?} is not a parseable IP address: {err}"),
    })?;
    if addr.is_unspecified() {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be unspecified"),
        });
    }
    if addr.is_multicast() {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be multicast"),
        });
    }
    if matches!(addr, IpAddr::V4(v4) if v4 == Ipv4Addr::BROADCAST) {
        return Err(AdapterError::Protocol {
            message: format!("IP argument {ip:?} must not be IPv4 broadcast"),
        });
    }
    Ok(())
}

fn decode_wireguard_pubkey_to_hex(value: &str) -> Result<String, String> {
    let decoded = base64_decode_simple(value.as_bytes())
        .map_err(|err| format!("base64 decode of WireGuard public key failed: {err}"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "expected 32-byte WireGuard public key, got {} bytes",
            decoded.len()
        ));
    }
    let mut out = String::with_capacity(64);
    for byte in decoded {
        out.push_str(&format!("{byte:02x}"));
    }
    Ok(out)
}

fn base64_decode_simple(encoded: &[u8]) -> Result<Vec<u8>, String> {
    let filtered: Vec<u8> = encoded
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if filtered.is_empty() {
        return Err("empty base64 input".to_owned());
    }
    let mut table = [255u8; 256];
    for (i, ch) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*ch as usize] = i as u8;
    }
    table[b'=' as usize] = 64;

    let mut output = Vec::with_capacity((filtered.len() * 3) / 4);
    let mut i = 0;
    while i + 3 < filtered.len() {
        let a = table[filtered[i] as usize];
        let b = table[filtered[i + 1] as usize];
        let c = table[filtered[i + 2] as usize];
        let d = table[filtered[i + 3] as usize];
        if a == 255 || b == 255 {
            return Err(format!("invalid base64 character at position {i}"));
        }
        output.push((a << 2) | (b >> 4));
        if c != 64 {
            output.push(((b & 0xf) << 4) | (c >> 2));
        }
        if d != 64 {
            output.push(((c & 0x3) << 6) | d);
        }
        i += 4;
    }
    Ok(output)
}

/// Assert that the collected artifact tarball at `path` contains no key material.
fn verify_no_key_material_tarball(path: &Path) -> Result<(), AdapterError> {
    use std::process::Command;
    let output = Command::new("tar")
        .args(["-tzf"])
        .arg(path.as_os_str())
        .output()
        .map_err(|err| AdapterError::Io {
            message: format!("list tar contents failed: {err}"),
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AdapterError::Io {
            message: format!(
                "list tar contents failed with status {}: {}",
                output.status,
                stderr.trim()
            ),
        });
    }
    let listing = String::from_utf8_lossy(&output.stdout);
    for entry in listing.lines() {
        let lower = entry.to_lowercase();
        if lower.contains("/keys/")
            || lower.ends_with(".priv")
            || lower.ends_with(".pem")
            || lower.ends_with(".key")
        {
            return Err(AdapterError::KeyExclusionViolation {
                path: entry.to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_node_clean_probe_covers_pf_daemon_and_interface() {
        let p = MACOS_NODE_CLEAN_PROBE;
        // pf dimension: leftover RustyNet anchors enumerated from pfctl -s Anchors.
        assert!(p.contains("pfctl -s Anchors"));
        assert!(p.contains("grep -i rustynet"));
        // daemon dimension: a still-running rustynetd (same process name as Linux).
        assert!(p.contains("pgrep -x rustynetd"));
        // interface dimension: a utun carrying a 100.64.0.0/10 mesh address.
        assert!(p.contains("^utun"));
        assert!(p.contains("inet 100"));
        // Emits the three structured tokens the parser keys on.
        assert!(p.contains("pf=%s daemon=%s iface=%s"));
    }

    #[test]
    fn macos_reset_command_flushes_anchors_and_destroys_mesh_utun() {
        let cmd = MACOS_RESET_COMMAND;
        // Enumerates RustyNet pf anchors (not a fixed name) and flushes each.
        assert!(cmd.contains("pfctl -s Anchors"));
        assert!(cmd.contains("grep -i rustynet"));
        assert!(cmd.contains("pfctl -a") && cmd.contains("-F all"));
        // Enumerates utun devices and destroys only those carrying a mesh address.
        assert!(cmd.contains("ifconfig -l"));
        assert!(cmd.contains("inet 100"));
        assert!(cmd.contains("ifconfig") && cmd.contains("destroy"));
        // Best-effort at every privileged step.
        assert!(cmd.contains("|| true"));
        // Captures the anchor list into a variable first, then iterates with a
        // `for` loop — same anti-stdin-drain shape as the Linux resets.
        assert!(cmd.contains("rn_anchors=$("));
        assert!(cmd.contains("for a in $rn_anchors"));
        assert!(
            !cmd.contains("while read"),
            "reset must not pipe into `while read` (inner sudo drains the pipe)"
        );
    }

    #[test]
    fn macos_launchd_stop_command_unloads_all_rustynet_role_profiles() {
        let cmd = MACOS_LAUNCHD_STOP_COMMAND;
        for label in [
            "com.rustynet.daemon",
            "com.rustynet.privileged-helper",
            "com.rustynet.anchor",
            "com.rustynet.relay",
            "com.rustynet.exit",
        ] {
            assert!(
                cmd.contains(label),
                "cleanup must unload stale launchd profile {label}"
            );
        }
        assert!(cmd.contains("launchctl bootout system/com.rustynet.anchor"));
        assert!(
            cmd.contains(
                "launchctl bootout system /Library/LaunchDaemons/com.rustynet.anchor.plist"
            )
        );
        assert!(cmd.contains("pkill -TERM -x rustynetd"));
        assert!(cmd.contains("pkill -TERM -f '/usr/local/bin/rustynetd.*privileged-helper'"));
        assert!(cmd.contains("pkill -KILL -x rustynetd"));
        assert!(cmd.contains("pkill -KILL -f '/usr/local/bin/rustynetd.*privileged-helper'"));
        assert!(cmd.contains("pgrep -x rustynetd"));
        assert!(cmd.contains("pkill -TERM -x rustynet-relay"));
    }

    #[test]
    fn parse_macos_node_clean_probe_accepts_fully_clean_node() {
        assert!(parse_macos_node_clean_probe("pf=- daemon=down iface=-\n").is_ok());
        // Empty-string sentinels (shell var expanded to nothing) are also benign.
        assert!(parse_macos_node_clean_probe("pf= daemon=down iface=").is_ok());
        // Tolerates a leading banner/log line before the result line.
        assert!(parse_macos_node_clean_probe("Warning: blah\npf=- daemon=down iface=-").is_ok());
    }

    #[test]
    fn parse_macos_node_clean_probe_reports_leftover_pf_anchor() {
        let err = parse_macos_node_clean_probe("pf=com.apple/rustynet_g1, daemon=down iface=-")
            .expect_err("leftover pf anchor must fail");
        let msg = err.to_string();
        assert!(msg.contains("node still dirty"));
        assert!(msg.contains("com.apple/rustynet_g1"));
        // The exit-NAT anchor family is also surfaced.
        let err2 = parse_macos_node_clean_probe("pf=com.rustynet/nat, daemon=down iface=-")
            .expect_err("leftover exit-nat anchor must fail");
        assert!(err2.to_string().contains("com.rustynet/nat"));
    }

    #[test]
    fn parse_macos_node_clean_probe_reports_running_daemon() {
        let err = parse_macos_node_clean_probe("pf=- daemon=up iface=-")
            .expect_err("running daemon must fail");
        assert!(err.to_string().contains("rustynetd still running"));
    }

    #[test]
    fn parse_macos_node_clean_probe_reports_leftover_interface() {
        let err = parse_macos_node_clean_probe("pf=- daemon=down iface=utun12,")
            .expect_err("leftover mesh utun must fail");
        let msg = err.to_string();
        assert!(msg.contains("utun"));
        assert!(msg.contains("utun12"));
    }

    #[test]
    fn parse_macos_node_clean_probe_aggregates_multiple_dirty_dimensions() {
        let err =
            parse_macos_node_clean_probe("pf=com.rustynet/blind_exit, daemon=up iface=utun4095,")
                .expect_err("multi-dirty must fail");
        let msg = err.to_string();
        assert!(msg.contains("com.rustynet/blind_exit"));
        assert!(msg.contains("rustynetd still running"));
        assert!(msg.contains("utun4095"));
    }

    #[test]
    fn parse_macos_node_clean_probe_fails_closed_on_unrecognised_output() {
        // No result line at all → unknown state → fail closed, never pass.
        assert!(parse_macos_node_clean_probe("").is_err());
        assert!(parse_macos_node_clean_probe("ssh: connect timed out").is_err());
        // Result line missing a token (e.g. daemon=) → that dimension is unknown
        // → fail closed rather than assume clean.
        let err = parse_macos_node_clean_probe("pf=- iface=-")
            .expect_err("missing daemon token must fail closed");
        assert!(err.to_string().contains("unrecognised") || err.to_string().contains("unknown"));
    }

    #[test]
    fn validate_ip_arg_accepts_valid_ipv4() {
        assert!(validate_ip_arg("10.0.0.1").is_ok());
        assert!(validate_ip_arg("192.168.1.100").is_ok());
    }

    #[test]
    fn validate_ip_arg_accepts_ipv6() {
        assert!(validate_ip_arg("fd00::1").is_ok());
    }

    #[test]
    fn validate_ip_arg_rejects_injection() {
        assert!(validate_ip_arg("10.0.0.1; rm -rf /").is_err());
        assert!(validate_ip_arg("$(whoami)").is_err());
    }

    #[test]
    fn validate_ip_arg_rejects_cidr_and_dns_names() {
        assert!(validate_ip_arg("10.0.0.1/24").is_err());
        assert!(validate_ip_arg("peer-a.local").is_err());
    }

    #[test]
    fn validate_ip_arg_rejects_unsafe_special_addresses() {
        assert!(validate_ip_arg("0.0.0.0").is_err());
        assert!(validate_ip_arg("::").is_err());
        assert!(validate_ip_arg("224.0.0.1").is_err());
        assert!(validate_ip_arg("ff02::1").is_err());
        assert!(validate_ip_arg("255.255.255.255").is_err());
    }

    #[test]
    fn base64_decode_wireguard_key_roundtrip() {
        let encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let hex = decode_wireguard_pubkey_to_hex(encoded).unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn base64_decode_rejects_wrong_length() {
        let encoded = "aGVsbG8="; // "hello" = 5 bytes
        let result = decode_wireguard_pubkey_to_hex(encoded);
        assert!(result.is_err(), "must reject non-32-byte key");
        assert!(result.unwrap_err().contains("32-byte"));
    }

    #[test]
    fn verify_no_key_material_tarball_fails_closed_on_unreadable_archive() {
        let path = std::env::temp_dir().join(format!(
            "rustynet-macos-invalid-artifact-{}.tar.gz",
            std::process::id()
        ));
        std::fs::write(&path, b"not a tarball").expect("write invalid tarball");
        let result = verify_no_key_material_tarball(&path);
        let _ = std::fs::remove_file(&path);
        assert!(
            result.is_err(),
            "unreadable artifact tarball must fail closed"
        );
    }
}
