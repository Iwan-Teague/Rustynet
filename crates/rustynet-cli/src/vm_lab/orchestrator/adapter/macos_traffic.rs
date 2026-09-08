#![allow(dead_code)]
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::Duration;

use crate::vm_lab::orchestrator::adapter::macos_install::{MACOS_KEYS_DIR, MACOS_STATE_ROOT};
use crate::vm_lab::orchestrator::adapter::ssh;
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::connection::NodeConnection;
use crate::vm_lab::orchestrator::error::{AdapterError, TrafficTestResult, TunnelsList};
use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence;

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
///
/// `launchctl disable` on the daemon label is load-bearing and is NOT redundant
/// with the `bootout` above it. `bootout` unloads the job now; it does nothing
/// about later boots. Teardown deliberately deletes the signed trust artifacts
/// (see [`cleanup_runtime_state`]) while leaving the plist installed, and that
/// plist carries `RunAtLoad` and `KeepAlive`. So without a persistent disable,
/// the next boot of a torn-down guest starts a daemon whose `--trust-evidence`
/// path was purged: it fails closed with `EX_DATAERR`, `KeepAlive` respawns it,
/// and the node crash-loops until someone re-provisions. That was measured on
/// macos-utm-1 at 81 spawns, with `launchctl print-disabled` reporting the label
/// still `enabled` and the trust file gone.
///
/// This is the macOS analogue of the Linux path's
/// `systemctl disable --now "$unit"`, which clears the boot-time symlink and is
/// why no Linux guest has ever shown this failure.
///
/// Ordering (M2, MacosHelperShutdownOrderingImplementationPlan_2026-09-02):
/// the privileged helper is booted out ONLY after the bounded daemon-exit wait
/// completes, and it is the constant's single helper stop. The early
/// back-to-back helper bootout that used to sit beside the daemon bootout is
/// deleted, because the daemon's shutdown rollback dials the helper socket
/// (`launchctl bootout` returns at SIGTERM delivery, not at job exit; the
/// helper dies on launchd's 5 s ceiling while the daemon is still dialing).
/// The `pkill -TERM -f …privileged-helper` fallback sits AFTER the helper
/// bootout: KeepAlive would respawn a SIGTERMed helper whose job is still
/// bootstrapped. The daemon-exit wait predicate is JOB-scoped
/// (`launchctl print system/com.rustynet.daemon 2>/dev/null | grep -q
/// 'pid = '`), not process-scoped: the helper runs `/usr/local/bin/rustynetd`
/// too, so a `pgrep -x rustynetd` poll conflates the helper's pid with the
/// daemon's and can spin through its whole budget without ever observing
/// daemon exit (post-merge review §2). The `pgrep -x` / `pkill -x` lines that
/// remain are TERM/KILL backstops aimed by NAME and carry the same
/// conflation — a TERM to `-x rustynetd` can take the helper down as
/// collateral — which is why every KILL backstop is ordered strictly BEFORE
/// the helper bootout (review §3): the helper dies LAST, after the daemon job
/// is confirmed exited.
///
/// Only the daemon label is disabled, deliberately: it is the ONLY label the
/// bootstrap re-enables (`Install-RustyNetMacosService.sh` runs
/// `launchctl enable system/com.rustynet.daemon`, idempotent by its own note).
/// Disabling anchor/exit/relay/privileged-helper as well would strand them with
/// nothing to turn them back on, converting this fix into a worse bug. The
/// privileged helper also does not read trust state -- it stayed up throughout
/// the observed crash loop -- so it has no reason to be disabled.
const MACOS_LAUNCHD_STOP_COMMAND: &str = "sudo -n launchctl bootout system/com.rustynet.daemon 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.daemon.plist 2>/dev/null || true; \
     sudo -n launchctl disable system/com.rustynet.daemon 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.anchor 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.anchor.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.relay 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.relay.plist 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.exit 2>/dev/null || true; \
     sudo -n launchctl bootout system /Library/LaunchDaemons/com.rustynet.exit.plist 2>/dev/null || true; \
     sudo -n pkill -TERM -x rustynetd 2>/dev/null || true; \
     sudo -n pkill -TERM -x rustynet-relay 2>/dev/null || true; \
     for _ in $(seq 1 20); do \
         if sudo -n launchctl print system/com.rustynet.daemon 2>/dev/null | grep -q 'pid = '; then \
             sleep 0.5; \
         else \
             break; \
         fi; \
     done; \
     sudo -n pkill -KILL -x rustynetd 2>/dev/null || true; \
     sudo -n pkill -KILL -x rustynet-relay 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.anchor 2>/dev/null || true; \
     sudo -n launchctl bootout system/com.rustynet.privileged-helper 2>/dev/null || true; \
     sudo -n pkill -TERM -f '/usr/local/bin/rustynetd.*privileged-helper' 2>/dev/null || true; \
     sudo -n pkill -KILL -f '/usr/local/bin/rustynetd.*privileged-helper' 2>/dev/null || true; \
     for _ in $(seq 1 20); do \
         if sudo -n launchctl print system/com.rustynet.daemon 2>/dev/null | grep -q 'pid = '; then \
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
/// Anchors are ENUMERATED from `pfctl -s Anchors` plus the nested `com.apple`
/// and `com.rustynet` listings (the top-level dump hides sub-anchors) and matched on the substring
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
const MACOS_RESET_COMMAND: &str = "for a in $( { sudo -n pfctl -s Anchors; sudo -n pfctl -a com.apple -s Anchors; sudo -n pfctl -a com.rustynet -s Anchors; } 2>/dev/null \
         | sed 's/^[[:space:]]*//' | grep -i rustynet | sort -u ); do \
         sudo -n pfctl -a \"$a\" -F all 2>/dev/null || true; done; \
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
///   `daemon=<up|down>` whether `rustynetd` or `rustynet-relay` is still running
///   `iface=<names|->`  leftover mesh `utun` interface names (a `utun` carrying a
///                      `100.64.0.0/10` mesh address), or `-` if none
///
/// A node is clean only when all three are benign (`pf=-`, `daemon=down`,
/// `iface=-`). `pfctl -s Anchors` can retain an empty parent anchor name after
/// rules/state are flushed, so the pf dimension reports only anchors that still
/// carry rules or NAT rules. Do not use `pfctl -a <anchor> -ss` here: on macOS
/// an empty parent anchor can still print unrelated global connection state,
/// including the SSH session running the probe, which would make clean nodes
/// fail dirty. Each sub-probe tolerates the relevant tool being absent and is
/// read-only (mutates nothing), so it is safe to run repeatedly.
const MACOS_NODE_CLEAN_PROBE: &str = "rn_pf=''; \
     for a in $( { sudo -n pfctl -s Anchors; sudo -n pfctl -a com.apple -s Anchors; sudo -n pfctl -a com.rustynet -s Anchors; } 2>/dev/null \
         | sed 's/^[[:space:]]*//' | grep -i rustynet | sort -u ); do \
         if sudo -n pfctl -a \"$a\" -sr 2>/dev/null | grep -q . \
             || sudo -n pfctl -a \"$a\" -sn 2>/dev/null | grep -q .; then \
             rn_pf=\"${rn_pf}${a},\"; \
         fi; \
     done; \
     rn_daemon=$(if pgrep -x rustynetd >/dev/null 2>&1 \
         || pgrep -x rustynet-relay >/dev/null 2>&1; then echo up; else echo down; fi); \
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
        Some("up") => dirty.push("rustynetd or rustynet-relay still running".to_owned()),
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

/// The live `rustynet status` query, shared by [`query_live_identity`] and
/// [`collect_daemon_status`] so both walk the same proven path: the macOS
/// daemon socket is root-owned under `/private/var/run/rustynet`, so the
/// query pins it by env behind `sudo -n`.
///
/// The trailing `echo now_unix=$(date +%s)` (review F2, 2026-09-07) reports
/// the GUEST clock alongside the status line, so handshake freshness is
/// judged on the clock that wrote `path_latest_live_handshake_unix` instead
/// of the orchestrator host clock. [`query_live_identity`]'s field scan only
/// looks for `node_id=`, so the extra token is inert there.
pub(crate) const DAEMON_STATUS_COMMAND: &str = "sudo -n env \
     RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock \
     /usr/local/bin/rustynet status; echo now_unix=$(date +%s)";

/// Gather a LIVE node-identity for the §4.7 challenge: query the running daemon
/// over its control socket and tag the result `LiveDaemonSocket`. Unlike
/// [`collect_node_id`], this deliberately does NOT prefer the launchd plist —
/// a config-file read proves a file exists, not the live daemon's identity — so
/// it queries `rustynet status` only. At validator time the daemon is up, so a
/// single short-timeout query is correct.
pub fn query_live_identity(conn: &NodeConnection) -> Result<IdentityEvidence, AdapterError> {
    let status = ssh::run_remote(conn, DAEMON_STATUS_COMMAND, SHORT_TIMEOUT)?;
    match ssh::parse_status_node_id(&status) {
        Some(node_id) => Ok(IdentityEvidence::live(node_id)),
        None => Err(AdapterError::Protocol {
            message: format!(
                "live identity challenge: node_id not in rustynet status output: {}",
                &status[..status.len().min(200)]
            ),
        }),
    }
}

/// Fetch the daemon's verbatim `rustynet status` text — the QH-70
/// live-handshake-evidence surface. Same proven command as
/// [`query_live_identity`] (socket env pinned, `sudo -n`), full text returned
/// instead of just the node id. A transport failure is `Err` (fail closed),
/// never an empty string.
pub fn collect_daemon_status(conn: &NodeConnection) -> Result<String, AdapterError> {
    // Local binding + as_str(): a compile-time constant command with zero
    // interpolation, passed through the established seam-lowered call shape.
    let command = DAEMON_STATUS_COMMAND.to_owned();
    ssh::run_remote(conn, command.as_str(), SHORT_TIMEOUT)
}

/// Collect the daemon-reported STUN server-reflexive candidates via
/// `rustynet netcheck`. Mirrors the Linux adapter: the daemon gathers STUN
/// asynchronously at start, so retry every 5 s up to a 60 s deadline; an
/// observed-but-empty gather (`stun_candidates=none`) past the deadline is
/// `Ok(None)` (an ABSENCE the stage classifies against `--lab-stun-servers`),
/// while a persistent transport-level failure propagates as `Err` (fail
/// closed).
pub fn collect_stun_candidates(conn: &NodeConnection) -> Result<Option<Vec<String>>, AdapterError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut last_err: Option<AdapterError>;
    let netcheck = netcheck_command()?;
    loop {
        match ssh::run_remote(conn, netcheck.as_str(), SHORT_TIMEOUT) {
            Ok(netcheck) => match ssh::classify_netcheck_stun_gather(&netcheck) {
                ssh::NetcheckStunGather::Candidates(candidates) => return Ok(Some(candidates)),
                // The daemon can NEVER gather on this backend: fail closed
                // now with its own reason (see the Linux adapter).
                ssh::NetcheckStunGather::Blocked { state, error } => {
                    return Err(AdapterError::Protocol {
                        message: format!(
                            "authoritative STUN gather is impossible on this node: \
                             transport_socket_identity_state={state} \
                             transport_socket_identity_error={error}"
                        ),
                    });
                }
                // Observed but empty — keep polling; clearing last_err marks
                // the gather as observed-empty rather than transport-failed.
                ssh::NetcheckStunGather::Empty => last_err = None,
            },
            Err(e) => last_err = Some(e),
        }
        if std::time::Instant::now() >= deadline {
            return match last_err {
                Some(e) => Err(e),
                None => Ok(None),
            };
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

/// `sudo -n env RUSTYNET_DAEMON_SOCKET=<sock> /usr/local/bin/rustynet netcheck`,
/// argv-shaped through the validated seam (every token is a compile-time
/// constant; the seam is what keeps this off the raw-sink ratchet).
fn netcheck_command() -> Result<ssh::RemoteCommand, AdapterError> {
    let args = [
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("env")?,
        ValidatedArg::cli_token("RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock")?,
        ValidatedArg::path("/usr/local/bin/rustynet")?,
        ValidatedArg::cli_token("netcheck")?,
    ];
    ssh::RemoteCommand::from_args("macos stun candidates netcheck", &args)
}

/// Ping `peer_mesh_ip` 3 times. Returns `Reachable` on success.
/// On failure, captures the full ping stdout/stderr so the stage log
/// carries diagnostic detail instead of a bare "ping to X failed".
pub fn ping_mesh_peer(
    conn: &NodeConnection,
    peer_mesh_ip: &str,
) -> Result<TrafficTestResult, AdapterError> {
    validate_ip_arg(peer_mesh_ip)?;
    // QH-01 Step 4b: argv-shaped script built through the validated seam. The
    // retained `validate_ip_arg` call keeps the stricter IP semantics
    // (unspecified/multicast/broadcast rejection) that `ValidatedArg::ip`'s
    // charset rule alone does not provide; the trailing ` 2>&1` is the fixed
    // trailer `RemoteCommand::from_args_with_stderr_merged` appends.
    let args = [
        ValidatedArg::cli_token("ping")?,
        ValidatedArg::cli_token("-c")?,
        ValidatedArg::cli_token("3")?,
        ValidatedArg::cli_token("-W")?,
        ValidatedArg::cli_token("1000")?,
        ValidatedArg::ip(peer_mesh_ip)?,
    ];
    let script = ssh::RemoteCommand::from_args_with_stderr_merged("macos ping mesh peer", &args)?;
    match ssh::run_remote(conn, script.as_str(), Duration::from_secs(30)) {
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

/// Diagnostic surfaces captured on failure, as `(file-stem, command)` pairs.
/// Every command is read-only and individually best-effort: its output (or its
/// error text) lands in `<staging>/<file-stem>.txt` inside the diagnostics
/// archive, so a denied `sudo -n` or an absent tool degrades ONE file instead
/// of emptying the whole archive. Mirrors the collectors the blocker doc
/// (MacosCrossNetworkTrafficBlocker_2026-09-03) asks for at failure time.
///
/// `launchctl print` output is piped through a sed range that drops each
/// service's `environment = { ... }` dictionary: launchctl prints the full
/// per-job environment and program arguments, and any secret env var set by a
/// plist would otherwise land verbatim in the archive — the tar excludes are
/// name-based and `verify_no_key_material_tarball` never reads member
/// CONTENT, so redaction at the source is the only barrier.
pub fn macos_diagnostic_collectors() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "launchctl_daemon",
            "sudo -n launchctl print system/com.rustynet.daemon \
             | sed '/[[:space:]]environment = {/,/^[[:space:]]*}/d'",
        ),
        (
            "launchctl_anchor",
            "sudo -n launchctl print system/com.rustynet.anchor \
             | sed '/[[:space:]]environment = {/,/^[[:space:]]*}/d'",
        ),
        (
            "launchctl_relay",
            "sudo -n launchctl print system/com.rustynet.relay \
             | sed '/[[:space:]]environment = {/,/^[[:space:]]*}/d'",
        ),
        (
            "launchctl_exit",
            "sudo -n launchctl print system/com.rustynet.exit \
             | sed '/[[:space:]]environment = {/,/^[[:space:]]*}/d'",
        ),
        (
            "launchctl_privileged_helper",
            "sudo -n launchctl print system/com.rustynet.privileged-helper \
             | sed '/[[:space:]]environment = {/,/^[[:space:]]*}/d'",
        ),
        ("pf_anchors", "sudo -n pfctl -s Anchors"),
        (
            "pf_anchor_rules",
            "for a in $( { sudo -n pfctl -s Anchors; sudo -n pfctl -a com.apple -s Anchors; \
             sudo -n pfctl -a com.rustynet -s Anchors; } 2>/dev/null \
             | sed 's/^[[:space:]]*//' | grep -i rustynet | sort -u ); do \
             echo \"== anchor $a\"; sudo -n pfctl -a \"$a\" -s rules 2>/dev/null; done",
        ),
        // Literal rather than format!(&const): a unit test pins this to
        // MACOS_RUSTYNET_PATH so the two cannot drift apart silently.
        ("daemon_status", "/usr/local/bin/rustynet status"),
        ("routes", "netstat -rn"),
        ("dns", "scutil --dns"),
        (
            "daemon_log",
            "if [ -d /usr/local/var/log/rustynet ]; then \
             ls -la /usr/local/var/log/rustynet; \
             tail -n 200 /usr/local/var/log/rustynet/* 2>/dev/null; \
             else echo 'no rustynet log dir at /usr/local/var/log/rustynet'; fi",
        ),
    ]
}

/// Build the remote sh script that stages every diagnostic collector and tars
/// the staging dir (plus `[ -d ]`-guarded state/log roots) into `remote_tar`.
/// Split out from [`collect_artifacts`] so the unit tests can pin its shape.
///
/// Fail-loud contract (run 130201 lesson): the OLD script tared two fixed
/// paths and, when either was missing, fell back to `tar --files-from
/// /dev/null` — a VALID EMPTY archive that sailed through the key-material
/// verification as "success". The new script always stages collector output
/// first (so the archive always has members), and ends with an in-script
/// assertion: zero non-directory members → `exit 42`, which `run_remote`
/// surfaces as `AdapterError::Command`. A second, LOCAL assertion
/// ([`assert_tarball_non_empty`]) re-checks the downloaded copy.
fn build_diag_archive_script(remote_tar: &str) -> String {
    let mut script = String::from(
        "staging=/tmp/rn_diag_capture; rm -rf \"$staging\" 2>/dev/null; \
         mkdir -p \"$staging\"",
    );
    for (name, cmd) in macos_diagnostic_collectors() {
        // Per-collector watchdog (macOS ships no `timeout`): background the
        // collector, kill it after 8s, and wait. Diagnostics run precisely
        // because the node is broken — e.g. `rustynet status` against a
        // wedged daemon blocks on its socket — and without this a single
        // hung collector burns the whole script's MEDIUM_TIMEOUT and loses
        // every other collector's output. 8 s keeps the worst case (every
        // collector hung) inside MEDIUM_TIMEOUT, which 20 s did not.
        script.push_str(&format!(
            "; ( {{ {cmd}; }} & p=$!; \
               ( sleep 8; kill $p ) >/dev/null 2>&1 & wait $p ) \
              > \"$staging/{name}.txt\" 2>&1"
        ));
    }
    // The archive path list is kept in the positional parameters ("$@"), not
    // in an unquoted string variable: the guest runs this under zsh, which
    // does not word-split an unquoted parameter expansion, so `$files` would
    // reach tar as ONE path and the archive would always come back empty.
    script.push_str(&format!(
        "; set -- \"$staging\"; \
         [ -d '{MACOS_STATE_ROOT}' ] && set -- \"$@\" '{MACOS_STATE_ROOT}'; \
         [ -d /usr/local/var/log/rustynet ] && set -- \"$@\" /usr/local/var/log/rustynet; \
         tar -czf '{remote_tar}' \
         --exclude='{MACOS_STATE_ROOT}/keys' \
         --exclude='{MACOS_KEYS_DIR}' \
         --exclude='*.priv' \
         --exclude='*.key' \
         --exclude='*.pem' \
         \"$@\"; \
         members=$(tar -tzf '{remote_tar}' 2>/dev/null | grep -vc '/$'); \
         [ \"$members\" -gt 0 ] || exit 42"
    ));
    script
}

/// Local fail-loud assertion: the downloaded diagnostics archive must contain
/// at least one non-directory member. Belt-and-braces behind the in-script
/// `exit 42` guard in [`build_diag_archive_script`].
fn assert_tarball_non_empty(path: &Path) -> Result<(), AdapterError> {
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
    let non_dir = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|l| !l.is_empty() && !l.ends_with('/'))
        .count();
    if non_dir == 0 {
        return Err(AdapterError::Protocol {
            message: format!(
                "macOS diagnostics archive {} is empty (0 non-directory members); \
                 collectors staged nothing — failing loud instead of shipping an \
                 empty artifact",
                path.display()
            ),
        });
    }
    Ok(())
}

/// Collect diagnostic artifacts from the macOS host to `dst`.
/// Key material paths (`keys/*`, `*.priv`) MUST NOT appear in the archive.
/// Fails loud when the archive would be empty (see [`build_diag_archive_script`]).
pub fn collect_artifacts(conn: &NodeConnection, dst: &Path) -> Result<(), AdapterError> {
    let remote_tmp = "/tmp/rn_diag_artifacts.tar.gz";

    // Built up front so the fail-loud error paths below can best-effort
    // clean the remote archive instead of orphaning it in /tmp.
    // QH-01 Step 4b: through the validated seam so the path is validated
    // and shell-quoted before any command string exists.
    let rm_args = [
        ValidatedArg::cli_token("rm")?,
        ValidatedArg::cli_token("-f")?,
        ValidatedArg::path(remote_tmp)?,
    ];
    let rm_cmd = ssh::RemoteCommand::from_args("macos remove diagnostic archive", &rm_args)?;

    let diag_cmd = build_diag_archive_script(remote_tmp);
    let diag_result = ssh::run_remote(conn, &diag_cmd, MEDIUM_TIMEOUT).map_err(|err| match err {
        AdapterError::Command {
            exit_code: Some(42),
            ..
        } => AdapterError::Protocol {
            message: "macOS diagnostics archive is empty: staged collectors and \
                              state/log roots produced 0 members"
                .to_owned(),
        },
        other => other,
    });
    if diag_result.is_err() {
        // The `?` below would skip the normal cleanup, leaving the (possibly
        // 0-member) tarball behind in the remote /tmp.
        let _ = ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT);
    }
    diag_result?;

    if let Some(parent) = dst.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(|err| AdapterError::Io {
            message: format!("create local artifact destination dir failed: {err}"),
        })?;
    }
    ssh::scp_from(conn, remote_tmp, dst, Duration::from_secs(120))?;

    // Remove temp archive from remote (best-effort).
    let _ = ssh::run_remote(conn, rm_cmd.as_str(), SHORT_TIMEOUT);

    verify_no_key_material_tarball(dst)?;
    assert_tarball_non_empty(dst)?;

    Ok(())
}

/// Strict `com.rustynet/*` pf-anchor name check (charset-validated, no regex dep):
/// `^com\.rustynet/[A-Za-z0-9_.-]+$`. Anything else (including the killswitch
/// family `com.apple/rustynet_g<N>` and shell metacharacters) is rejected so a
/// crafted anchor name can never reach an exec argv.
pub fn is_rustynet_pf_anchor(name: &str) -> bool {
    match name.strip_prefix("com.rustynet/") {
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        }
        None => false,
    }
}

/// True when the top-level `pfctl -s Anchors` listing names the `com.rustynet`
/// parent, i.e. when its sub-anchors must be enumerated separately.
pub fn needs_nested_rustynet_listing(top_level: &[String]) -> bool {
    top_level.iter().any(|name| name == "com.rustynet")
}

/// Parse `pfctl -s Anchors` output into a list of anchor names: one per line,
/// surrounding whitespace trimmed, empty lines dropped.
pub fn parse_pfctl_anchor_list(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Build the argv-only flush command for one `com.rustynet/*` anchor. Fails
/// closed (never builds a command) for a name that does not pass
/// [`is_rustynet_pf_anchor`].
pub fn build_anchor_flush_args(anchor: &str) -> Result<Vec<ValidatedArg>, AdapterError> {
    if !is_rustynet_pf_anchor(anchor) {
        return Err(AdapterError::Protocol {
            message: format!("refusing to flush pf anchor with invalid name: {anchor:?}"),
        });
    }
    Ok(vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("pfctl")?,
        ValidatedArg::cli_token("-a")?,
        ValidatedArg::cli_token(anchor)?,
        ValidatedArg::cli_token("-F")?,
        ValidatedArg::cli_token("all")?,
    ])
}

/// Enumerate pf anchors over SSH, then flush every strictly-named
/// `com.rustynet/*` anchor through an argv-only `pfctl -a <anchor> -F all`
/// (Rust-side name validation; no shell interpolation of remote output).
/// Complements — does not replace — the broader shell `MACOS_RESET_COMMAND`
/// pass, which also covers the `com.apple/rustynet_g<N>` killswitch family
/// the strict prefix deliberately excludes.
///
/// Returns `(found, flushed)` — the count of strict `com.rustynet/*` anchors
/// observed and the count successfully flushed. If ANY observed anchor fails
/// to flush, returns `Err` naming the failures: a surviving default-deny
/// anchor (e.g. blind_exit's `block drop out quick all`) is a live security
/// residue, and a bare count cannot distinguish "nothing to flush" from
/// "flush denied" — callers must not be able to mistake the two
/// (glm-5.3 review of 229ba864). Enumeration failure propagates unchanged
/// (`run_remote` errors on any nonzero exit, so a `sudo -n` denial during
/// the listing cannot be parsed as an empty anchor list).
pub fn flush_rustynet_pf_anchors_argv(
    conn: &NodeConnection,
) -> Result<(usize, usize), AdapterError> {
    let list_args = vec![
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::cli_token("-n")?,
        ValidatedArg::cli_token("pfctl")?,
        ValidatedArg::cli_token("-s")?,
        ValidatedArg::cli_token("Anchors")?,
    ];
    let list_cmd = ssh::RemoteCommand::from_args("macos list pf anchors", &list_args)?;
    let output = ssh::run_remote(conn, list_cmd.as_str(), SHORT_TIMEOUT)?;
    let mut names = parse_pfctl_anchor_list(&output);
    // `pfctl -s Anchors` prints TOP-LEVEL anchors only (`com.apple`,
    // `com.rustynet`); the strict family lives one level down
    // (`com.rustynet/blind_exit`, `com.rustynet/nat`), so enumerate the
    // parent's sub-anchors whenever the parent is present. A listed parent
    // whose sub-anchor listing cannot be read is UNVERIFIABLE — propagate the
    // error rather than report "nothing to flush" (mirrors rustynetd's
    // `read_pf_dns_block_floor`).
    if needs_nested_rustynet_listing(&names) {
        let nested_args = vec![
            ValidatedArg::cli_token("sudo")?,
            ValidatedArg::cli_token("-n")?,
            ValidatedArg::cli_token("pfctl")?,
            ValidatedArg::cli_token("-a")?,
            ValidatedArg::cli_token("com.rustynet")?,
            ValidatedArg::cli_token("-s")?,
            ValidatedArg::cli_token("Anchors")?,
        ];
        let nested_cmd = ssh::RemoteCommand::from_args(
            "macos list nested com.rustynet pf anchors",
            &nested_args,
        )?;
        let nested = ssh::run_remote(conn, nested_cmd.as_str(), SHORT_TIMEOUT)?;
        names.extend(parse_pfctl_anchor_list(&nested));
    }
    names.sort();
    names.dedup();

    let mut found = 0usize;
    let mut flushed = 0usize;
    let mut failures = Vec::new();
    for anchor in names {
        if !is_rustynet_pf_anchor(&anchor) {
            continue;
        }
        found += 1;
        let flush_cmd = match ssh::RemoteCommand::from_args(
            "macos flush rustynet pf anchor",
            &build_anchor_flush_args(&anchor)?,
        ) {
            Ok(cmd) => cmd,
            Err(e) => {
                failures.push(format!("{anchor}: {e}"));
                continue;
            }
        };
        match ssh::run_remote(conn, flush_cmd.as_str(), SHORT_TIMEOUT) {
            Ok(_) => flushed += 1,
            Err(e) => failures.push(format!("{anchor}: {e}")),
        }
    }
    if !failures.is_empty() {
        return Err(AdapterError::Protocol {
            message: format!(
                "com.rustynet/* pf anchor flush left {} of {} anchor(s) in place \
                 (default-deny anchors keep blocking after uninstall): {}",
                failures.len(),
                found,
                failures.join("; ")
            ),
        });
    }
    Ok((found, flushed))
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

    // Second, argv-only pass over the strict com.rustynet/* family with
    // Rust-side name validation: unlike the shell pass above (whose errors
    // are swallowed by `|| true`), a `sudo -n` denial, an unreadable
    // sub-anchor listing or a surviving anchor here FAILS the cleanup. A
    // guest still carrying blind_exit's `block drop out quick all` is not
    // clean, and this is the path the engine's cleanup stages actually run
    // (`uninstall_daemon` has no stage caller), so the error must propagate.
    flush_rustynet_pf_anchors_argv(conn)?;

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
    // Also purge the two durable sibling markers of the state file: the QH-40
    // shutdown-residue marker (`rustynetd.state.shutdown-residue.json`) and
    // the DNS fail-closed backup
    // (`rustynetd.state.networksetup-dns.failclosed.bak`,
    // MacosDnsBackupRebootSurvivalPlan_2026-09-02 §4 step 5). Cleanup stops
    // the daemon mid-protection without teardown, so SC loopback residue
    // persists by design; a surviving durable backup would make the next
    // run's startup guard auto-restore the previous run's baseline — or, on
    // service-set drift, refuse to start and fail `bootstrap_hosts`. Removal
    // keeps every run on a clean slate (the apply re-captures the operator's
    // DNS fresh).
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
             '{MACOS_STATE_ROOT}/rustynetd.state.shutdown-residue.json' \
             '{MACOS_STATE_ROOT}/rustynetd.state.networksetup-dns.failclosed.bak' \
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

    // QH-01 Step 4b: argv-shaped script built through the validated seam; the
    // issue dir is path-validated and shell-quoted before any command exists.
    let mkdir_args = [
        ValidatedArg::cli_token("mkdir")?,
        ValidatedArg::cli_token("-p")?,
        ValidatedArg::path(&remote_issue_dir)?,
    ];
    let mkdir_cmd = ssh::RemoteCommand::from_args("macos create issue dir", &mkdir_args)?;
    ssh::run_remote(conn, mkdir_cmd.as_str(), SHORT_TIMEOUT)?;

    // QH-01 Step 4b: the previous `safe_rustynet` manual quote-escape is
    // replaced by `ValidatedArg::path` + `RemoteCommand::from_args`, which
    // validates then shell-quotes every argument.
    let issue_args = [
        ValidatedArg::cli_token("env")?,
        ValidatedArg::cli_token("RUSTYNET_NODE_ROLE=admin")?,
        ValidatedArg::cli_token("sudo")?,
        ValidatedArg::path(rustynet_path)?,
        ValidatedArg::cli_token("ops")?,
        ValidatedArg::cli_token(issue_subcmd)?,
        ValidatedArg::cli_token("--env-file")?,
        ValidatedArg::path(&remote_env)?,
        ValidatedArg::cli_token("--issue-dir")?,
        ValidatedArg::path(&remote_issue_dir)?,
    ];
    let issue_cmd = ssh::RemoteCommand::from_args("macos issue bundles", &issue_args)?;
    ssh::run_remote(conn, issue_cmd.as_str(), MEDIUM_TIMEOUT)?;

    // rustynet creates the issue dir as root:root 0700; make it and its
    // files readable by the SSH user so the listing and scp_from below work.
    ssh::run_remote(
        conn,
        &format!(
            "sudo -n chmod 755 '{remote_issue_dir}' && \
             sudo -n chmod 644 '{remote_issue_dir}'/*"
        ),
        SHORT_TIMEOUT,
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
    use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNET_PATH;

    /// Tests-first item 7 of MacosDnsBackupRebootSurvivalPlan_2026-09-02
    /// (review A4): the macOS cleanup's explicit rm batch must include the
    /// DURABLE sibling markers of the state file — the QH-40
    /// shutdown-residue marker and the DNS fail-closed backup derived at
    /// `<state>.networksetup-dns.failclosed.bak` — otherwise cleanup stops
    /// the daemon mid-protection (SC loopback residue persists) and the next
    /// run's startup guard auto-restores the previous run's baseline, or
    /// refuses to start on service-set drift and fails `bootstrap_hosts`.
    /// Source-pinned because exercising `cleanup_runtime_state` behaviorally
    /// requires a live SSH node connection; the batch is a single-quoted
    /// literal list (no interpolated values), so presence of the literal is
    /// the contract.
    #[test]
    fn cleanup_rm_batch_includes_durable_state_sibling_markers() {
        let source = crate::vm_lab::implementation_source_slice(include_str!("macos_traffic.rs"))
            .expect("macos_traffic.rs implementation slice must parse");
        let fn_at = source
            .find("pub fn cleanup_runtime_state(")
            .expect("cleanup_runtime_state must exist");
        let body = &source[fn_at..];
        let body = &body[..body[1..]
            .find("\npub fn ")
            .map(|offset| offset + 1)
            .unwrap_or(body.len())];
        let rm_batch_at = body
            .find("sudo rm -f")
            .expect("cleanup must run its rm batch");
        let batch = &body[rm_batch_at..];
        assert!(
            batch.contains("rustynetd.state.shutdown-residue.json"),
            "cleanup must remove the QH-40 shutdown-residue marker"
        );
        assert!(
            batch.contains("rustynetd.state.networksetup-dns.failclosed.bak"),
            "cleanup must remove the durable DNS fail-closed backup"
        );
    }

    #[test]
    fn macos_node_clean_probe_covers_pf_daemon_and_interface() {
        let p = MACOS_NODE_CLEAN_PROBE;
        // pf dimension: leftover RustyNet anchors enumerated from pfctl -s Anchors.
        assert!(p.contains("pfctl -s Anchors"));
        assert!(p.contains("grep -i rustynet"));
        assert!(
            !p.contains("-ss"),
            "state listing on an empty parent anchor can include unrelated global state"
        );
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
        // Iterates a `for` loop over a command substitution — same
        // anti-stdin-drain shape as the Linux resets — and NOT over an
        // unquoted variable, which zsh (the guest login shell) does not
        // word-split. The substitution unions the nested `com.apple` and
        // `com.rustynet` listings because `pfctl -s Anchors` hides sub-anchors
        // (QH-73 merge-time correction, live-proven on macos-utm-1 2026-09-07).
        assert!(cmd.contains("for a in $( {"));
        assert!(cmd.contains("pfctl -a com.rustynet -s Anchors"));
        assert!(cmd.contains("pfctl -a com.apple -s Anchors"));
        assert!(cmd.contains("sort -u"));
        assert!(!cmd.contains("$rn_anchors"));
        assert!(
            !cmd.contains("while read"),
            "reset must not pipe into `while read` (inner sudo drains the pipe)"
        );
    }

    /// Teardown must persistently disable the daemon, and disable NOTHING else.
    ///
    /// Both halves are failure modes that have bitten. Too little: `bootout`
    /// alone leaves `RunAtLoad`/`KeepAlive` armed against trust artifacts this
    /// same teardown deletes, so the guest crash-loops on `EX_DATAERR` at its
    /// next boot -- measured at 81 spawns on macos-utm-1. Too much: only
    /// `system/com.rustynet.daemon` is ever re-enabled (by
    /// `Install-RustyNetMacosService.sh`), so disabling any other label strands
    /// it permanently with nothing to turn it back on.
    #[test]
    fn macos_teardown_disables_the_daemon_and_only_the_daemon() {
        let cmd = MACOS_LAUNCHD_STOP_COMMAND;
        assert!(
            cmd.contains("launchctl disable system/com.rustynet.daemon"),
            "teardown deletes the trust artifacts but leaves the plist installed with \
             RunAtLoad+KeepAlive; without a persistent disable the guest crash-loops \
             on EX_DATAERR at next boot"
        );
        for label in [
            "com.rustynet.privileged-helper",
            "com.rustynet.anchor",
            "com.rustynet.relay",
            "com.rustynet.exit",
        ] {
            assert!(
                !cmd.contains(&format!("launchctl disable system/{label}")),
                "{label} is never re-enabled by the bootstrap, so disabling it here \
                 would strand it permanently; only the daemon label may be disabled"
            );
        }
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
        assert!(cmd.contains("pkill -TERM -x rustynet-relay"));
        assert!(cmd.contains("pkill -KILL -x rustynet-relay"));
        // The daemon-exit polls are JOB-scoped (review §2): the helper runs
        // /usr/local/bin/rustynetd too, so a pgrep -x rustynetd poll cannot
        // tell the daemon from the helper.
        assert!(cmd.contains("launchctl print system/com.rustynet.daemon"));
        assert!(cmd.contains("grep -q 'pid = '"));
        assert!(
            !cmd.contains("pgrep"),
            "the daemon-exit wait is job-scoped, not pgrep-polled"
        );
    }

    /// M2 ordering pin (tests-first #8, plan
    /// MacosHelperShutdownOrderingImplementationPlan_2026-09-02): NO helper
    /// bootout and NO helper pkill may appear before the bounded daemon-exit
    /// wait. The daemon's shutdown rollback dials the helper socket, so a
    /// helper stop delivered before the daemon has exited deterministically
    /// loses the rollback (launchd SIGKILLs the helper 5 s after SIGTERM
    /// while the daemon is still dialing). The post-wait bootout must be the
    /// ONLY helper bootout, and the TERM fallback pkill must sit AFTER it
    /// (KeepAlive would respawn a SIGTERMed helper whose job is still
    /// bootstrapped).
    #[test]
    fn macos_launchd_stop_command_has_no_early_helper_bootout() {
        let cmd = MACOS_LAUNCHD_STOP_COMMAND;
        let wait_at = cmd
            .find("for _ in $(seq 1 20)")
            .expect("daemon-exit wait present");
        let before_wait = &cmd[..wait_at];
        assert!(
            !before_wait.contains("privileged-helper"),
            "no helper bootout or helper pkill may precede the daemon-exit wait; found \
             an early helper stop, which is the M2 completion-order defect"
        );
        let post_wait = &cmd[wait_at..];
        let bootout_at = cmd
            .find("launchctl bootout system/com.rustynet.privileged-helper")
            .expect("the post-wait helper bootout must exist");
        assert!(
            bootout_at >= wait_at
                && post_wait.contains("launchctl bootout system/com.rustynet.privileged-helper"),
            "the post-wait bootout must be the single helper stop"
        );
        assert_eq!(
            cmd.matches("launchctl bootout system/com.rustynet.privileged-helper")
                .count(),
            1,
            "exactly one helper bootout may exist, and only after the daemon-exit wait"
        );
        let term_helper_at = cmd
            .find("pkill -TERM -f '/usr/local/bin/rustynetd.*privileged-helper'")
            .expect("the TERM helper fallback pkill must exist");
        assert!(
            term_helper_at > bootout_at,
            "the TERM helper pkill must come after the helper bootout: KeepAlive would \
             respawn a SIGTERMed helper whose job is still bootstrapped"
        );
    }

    /// Post-merge review §3 ordering pin: the KILL backstops aimed at the
    /// daemon's process name (`pkill -KILL -x rustynetd` /
    /// `rustynet-relay`) may kill the helper as collateral (same binary
    /// path), so they must run BEFORE the helper bootout — the helper dies
    /// LAST, and its KILL fallback after its bootout.
    #[test]
    fn macos_launchd_stop_command_kills_the_daemon_before_booting_the_helper_out() {
        let cmd = MACOS_LAUNCHD_STOP_COMMAND;
        let kill_daemon_at = cmd
            .rfind("pkill -KILL -x rustynetd")
            .expect("the KILL daemon backstop must exist");
        let kill_relay_at = cmd
            .rfind("pkill -KILL -x rustynet-relay")
            .expect("the KILL relay backstop must exist");
        let bootout_at = cmd
            .find("launchctl bootout system/com.rustynet.privileged-helper")
            .expect("the helper bootout must exist");
        assert!(
            kill_daemon_at < bootout_at,
            "pkill -KILL -x rustynetd must precede the helper bootout: the KILL is \
             name-aimed and the helper runs the same binary, so a late KILL would \
             take the freshly-verified helper down (review §3)"
        );
        assert!(
            kill_relay_at < bootout_at,
            "pkill -KILL -x rustynet-relay must precede the helper bootout (review §3)"
        );
        let kill_helper_at = cmd
            .find("pkill -KILL -f '/usr/local/bin/rustynetd.*privileged-helper'")
            .expect("the KILL helper fallback must exist");
        assert!(
            kill_helper_at > bootout_at,
            "the helper KILL fallback stays after the helper bootout — the helper dies last"
        );
    }

    /// Post-merge review §2 predicate pin: both daemon-exit polls are
    /// job-scoped (`launchctl print system/com.rustynet.daemon | grep -q
    /// 'pid = '` — absence of the pid line ⇒ exited), bounded at 20 × 0.5 s.
    #[test]
    fn macos_launchd_stop_command_waits_on_the_daemon_job_not_the_process_name() {
        let cmd = MACOS_LAUNCHD_STOP_COMMAND;
        let polls = cmd
            .matches("launchctl print system/com.rustynet.daemon")
            .count();
        assert_eq!(
            polls, 2,
            "both the post-TERM and post-KILL waits are job-scoped"
        );
        for segment in cmd.split("for _ in $(seq 1 20); do ").skip(1) {
            let poll = segment
                .split("done")
                .next()
                .expect("wait loop body present");
            assert!(
                poll.contains("launchctl print system/com.rustynet.daemon")
                    && poll.contains("grep -q 'pid = '"),
                "every daemon-exit wait polls the launchd job's pid line, not pgrep"
            );
        }
        assert_eq!(
            cmd.matches("seq 1 20").count(),
            2,
            "each wait is bounded at 20 polls; 20 × 0.5 s = 10 s, above launchd's 5 s \
             SIGKILL ceiling"
        );
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
        assert!(
            err.to_string()
                .contains("rustynetd or rustynet-relay still running")
        );
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
        assert!(msg.contains("rustynetd or rustynet-relay still running"));
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

    // ── QH-01 Step 4b: seam-rendered argv-shaped sites ────────────────────────

    #[test]
    fn ping_mesh_peer_renders_the_ping_argv_with_stderr_merged() {
        let ip_arg = ValidatedArg::ip("100.64.0.7").expect("representative mesh ip");
        let args = [
            ValidatedArg::cli_token("ping").expect("token"),
            ValidatedArg::cli_token("-c").expect("token"),
            ValidatedArg::cli_token("3").expect("token"),
            ValidatedArg::cli_token("-W").expect("token"),
            ValidatedArg::cli_token("1000").expect("token"),
            ip_arg,
        ];
        let cmd = ssh::RemoteCommand::from_args_with_stderr_merged("macos ping mesh peer", &args)
            .expect("all validated");
        assert_eq!(
            cmd.as_str(),
            "'ping' '-c' '3' '-W' '1000' '100.64.0.7' 2>&1"
        );
    }

    #[test]
    fn diagnostic_archive_cleanup_renders_rm_f_with_a_validated_path() {
        let args = [
            ValidatedArg::cli_token("rm").expect("token"),
            ValidatedArg::cli_token("-f").expect("token"),
            ValidatedArg::path("/tmp/rn_diag_artifacts.tar.gz").expect("path"),
        ];
        let cmd =
            ssh::RemoteCommand::from_args("macos remove diagnostic archive", &args).expect("ok");
        assert_eq!(cmd.as_str(), "'rm' '-f' '/tmp/rn_diag_artifacts.tar.gz'");
    }

    #[test]
    fn issue_bundles_renders_the_env_sudo_invocation_argv() {
        let args = [
            ValidatedArg::cli_token("env").expect("token"),
            ValidatedArg::cli_token("RUSTYNET_NODE_ROLE=admin").expect("token"),
            ValidatedArg::cli_token("sudo").expect("token"),
            ValidatedArg::path("/usr/local/bin/rustynet").expect("path"),
            ValidatedArg::cli_token("ops").expect("token"),
            ValidatedArg::cli_token("e2e-issue-assignment-bundles-from-env").expect("token"),
            ValidatedArg::cli_token("--env-file").expect("token"),
            ValidatedArg::path("/tmp/rn_issue_env_4242.env").expect("path"),
            ValidatedArg::cli_token("--issue-dir").expect("token"),
            ValidatedArg::path("/tmp/rn_issue_4242").expect("path"),
        ];
        let cmd = ssh::RemoteCommand::from_args("macos issue bundles", &args).expect("ok");
        assert_eq!(
            cmd.as_str(),
            "'env' 'RUSTYNET_NODE_ROLE=admin' 'sudo' '/usr/local/bin/rustynet' 'ops' \
             'e2e-issue-assignment-bundles-from-env' '--env-file' '/tmp/rn_issue_env_4242.env' \
             '--issue-dir' '/tmp/rn_issue_4242'"
        );
    }

    #[test]
    fn macos_traffic_rejection_refuses_a_metacharacter_token_before_any_command_exists() {
        let err = ValidatedArg::cli_token("e2e-issue-assignment-bundles-from-env; id")
            .expect_err("metacharacter must be rejected at construction");
        assert!(
            err.to_string().contains("CLI token"),
            "unexpected error: {err}"
        );
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

    /// QH-71 / TASK 2: the failure-diagnostics collector list must cover every
    /// surface the blocker doc asks for — launchd state per RustyNet label,
    /// pfctl anchor enumeration + per-anchor rules, daemon status, routes,
    /// DNS, and the daemon log. A collector missing from this list is a
    /// regression that silently narrows what a failure report can explain.
    #[test]
    fn diagnostic_collectors_cover_required_failure_surfaces() {
        let collectors = macos_diagnostic_collectors();
        let joined = collectors
            .iter()
            .map(|(name, cmd)| format!("{name}: {cmd}"))
            .collect::<Vec<_>>()
            .join("\n");
        for label in [
            "com.rustynet.daemon",
            "com.rustynet.anchor",
            "com.rustynet.relay",
            "com.rustynet.exit",
            "com.rustynet.privileged-helper",
        ] {
            assert!(
                joined.contains(&format!("launchctl print system/{label}")),
                "missing launchctl collector for {label}"
            );
        }
        assert!(
            joined.contains("pfctl -s Anchors"),
            "must enumerate anchors"
        );
        assert!(
            joined.contains("pfctl -a \"$a\" -s rules"),
            "must dump per-anchor rules for every rustynet anchor"
        );
        assert!(
            joined.contains("rustynet status"),
            "must capture `rustynet status`"
        );
        // The daemon_status command must invoke the SAME binary the bootstrap
        // installs; pinned so a MACOS_RUSTYNET_PATH change cannot silently
        // desync the collector.
        let daemon_status = collectors
            .iter()
            .find(|(name, _)| *name == "daemon_status")
            .expect("daemon_status collector must exist");
        assert_eq!(daemon_status.1, format!("{MACOS_RUSTYNET_PATH} status"));
        assert!(joined.contains("netstat -rn"), "must capture routes");
        assert!(joined.contains("scutil --dns"), "must capture DNS config");
        assert!(
            joined.contains("/usr/local/var/log/rustynet"),
            "must capture the daemon log dir"
        );
        // Every launchctl collector must redact the service environment
        // dictionary: launchctl print dumps env vars verbatim, the tar
        // excludes are name-based, and no downstream check reads member
        // content — this sed is the only secret barrier.
        for (name, cmd) in &collectors {
            if name.starts_with("launchctl_") {
                assert!(
                    cmd.contains("environment = {"),
                    "collector {name} must redact the environment dict"
                );
            }
        }
    }

    /// QH-71 / TASK 2: the archive script must (a) stage every collector into
    /// the staging dir so the archive ALWAYS has members, (b) keep the key
    /// material excludes, and (c) carry the in-script fail-loud assertion
    /// (`exit 42` on zero non-directory members) so the run-130201
    /// empty-but-valid-tarball class can never read as success again.
    #[test]
    fn diag_archive_script_stages_collectors_and_fails_loud_when_empty() {
        let script = build_diag_archive_script("/tmp/rn_diag_artifacts.tar.gz");
        for (name, _cmd) in macos_diagnostic_collectors() {
            assert!(
                script.contains(&format!("> \"$staging/{name}.txt\"")),
                "collector {name} not staged"
            );
        }
        // Key material stays excluded (first line of defense; the local
        // verify_no_key_material_tarball pass is the second).
        assert!(script.contains("--exclude='/usr/local/var/rustynet/keys'"));
        assert!(script.contains("--exclude='*.priv'"));
        assert!(script.contains("--exclude='*.key'"));
        assert!(script.contains("--exclude='*.pem'"));
        // Fail-loud: no `--files-from /dev/null` empty-archive fallback may
        // remain, and the member-count assertion must exit non-zero.
        assert!(
            !script.contains("--files-from /dev/null"),
            "the empty-archive fallback was the run-130201 root cause; it must stay gone"
        );
        assert!(
            script.contains("exit 42"),
            "in-script empty-archive assertion missing"
        );
        assert!(
            script.contains("grep -vc '/$'"),
            "member count must ignore directory entries"
        );
        // Per-collector watchdog: a hung collector (e.g. `rustynet status`
        // against a wedged daemon) must not burn the whole script timeout.
        assert!(
            script.contains("sleep 8; kill $p"),
            "each collector must be wrapped in a kill-after-8s watchdog"
        );
        // zsh does not word-split `$files`; the path list must travel in "$@".
        assert!(
            script.contains("set -- \"$staging\"") && script.contains("\"$@\"; "),
            "archive paths must be passed as positional parameters"
        );
        assert!(
            !script.contains("$files"),
            "unquoted $files expansion must stay gone"
        );
    }

    /// QH-71 / TASK 2: local belt-and-braces assertion — a tarball whose only
    /// members are directories must read as empty, and a missing file must
    /// fail closed.
    #[test]
    fn assert_tarball_non_empty_rejects_dir_only_and_missing_archives() {
        // Missing file: fails closed with an Io error.
        let missing = std::env::temp_dir().join(format!(
            "rustynet-macos-absent-artifact-{}.tar.gz",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&missing);
        assert!(assert_tarball_non_empty(&missing).is_err());

        // Dir-only archive: build a REAL tarball whose only member is a
        // directory and assert the function itself rejects it — the earlier
        // inline re-count only pinned a copy of the logic and would have
        // passed even if the function counted directories.
        let dir =
            std::env::temp_dir().join(format!("rustynet-macos-dironly-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("onlydir")).expect("mkdir dir-only fixture");
        let tar_path = dir.join("archive.tar.gz");
        let tar_status = std::process::Command::new("tar")
            .args(["-czf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&dir)
            .arg("onlydir")
            .status()
            .expect("tar fixture");
        assert!(tar_status.success(), "dir-only tar fixture must build");
        assert!(
            assert_tarball_non_empty(&tar_path).is_err(),
            "dir-only archive must read as empty"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
    /// QH-73 merge-time correction: `pfctl -s Anchors` hides sub-anchors, so
    /// every enumeration must also read the nested `com.apple` and
    /// `com.rustynet` listings, and the strict flush must know when to.
    #[test]
    fn pf_anchor_enumerations_read_nested_listings() {
        for (what, snippet) in [
            ("reset", MACOS_RESET_COMMAND),
            ("clean probe", MACOS_NODE_CLEAN_PROBE),
        ] {
            assert!(
                snippet.contains("pfctl -a com.rustynet -s Anchors")
                    && snippet.contains("pfctl -a com.apple -s Anchors"),
                "{what} must enumerate nested anchors"
            );
            assert!(
                !snippet.contains("$rn_anchors"),
                "{what}: zsh does not split $var"
            );
        }
        let rules = macos_diagnostic_collectors()
            .into_iter()
            .find(|(name, _)| *name == "pf_anchor_rules")
            .map(|(_, cmd)| cmd)
            .expect("pf_anchor_rules collector");
        assert!(rules.contains("pfctl -a com.rustynet -s Anchors"));
        assert!(needs_nested_rustynet_listing(&[
            "com.apple".to_owned(),
            "com.rustynet".to_owned()
        ]));
        assert!(!needs_nested_rustynet_listing(&["com.apple".to_owned()]));
        assert!(!needs_nested_rustynet_listing(&[]));
    }

    #[test]
    fn rustynet_pf_anchor_validator_accepts_strict_names() {
        assert!(is_rustynet_pf_anchor("com.rustynet/nat"));
        assert!(is_rustynet_pf_anchor("com.rustynet/blind_exit"));
        assert!(is_rustynet_pf_anchor("com.rustynet/exit_v2"));
    }

    #[test]
    fn rustynet_pf_anchor_validator_rejects_crafted_names() {
        assert!(!is_rustynet_pf_anchor("com.rustynet/x;reboot"));
        assert!(!is_rustynet_pf_anchor("com.rustynet/../../etc"));
        assert!(!is_rustynet_pf_anchor("com.rustynet/"));
        assert!(!is_rustynet_pf_anchor("com.apple/rustynet_g4"));
        assert!(!is_rustynet_pf_anchor("com.rustynet/a b"));
        assert!(!is_rustynet_pf_anchor(";reboot"));
        assert!(!is_rustynet_pf_anchor(""));
    }

    #[test]
    fn pfctl_anchor_list_parser_trims_and_drops_empty_lines() {
        let out = "com.rustynet/nat\n\n  com.rustynet/blind_exit  \ncom.apple/rustynet_g4\n";
        assert_eq!(
            parse_pfctl_anchor_list(out),
            vec![
                "com.rustynet/nat".to_owned(),
                "com.rustynet/blind_exit".to_owned(),
                "com.apple/rustynet_g4".to_owned(),
            ]
        );
        assert!(parse_pfctl_anchor_list("").is_empty());
    }

    #[test]
    fn anchor_flush_args_reject_invalid_and_build_valid() {
        assert!(build_anchor_flush_args("com.rustynet/x;reboot").is_err());
        let args = build_anchor_flush_args("com.rustynet/blind_exit").unwrap();
        let cmd = ssh::RemoteCommand::from_args("macos flush rustynet pf anchor", &args).unwrap();
        assert_eq!(
            cmd.as_str(),
            "'sudo' '-n' 'pfctl' '-a' 'com.rustynet/blind_exit' '-F' 'all'"
        );
    }

    #[test]
    fn uninstall_daemon_flushes_rustynet_pf_anchors() {
        let src = include_str!("macos_install.rs");
        let start = src.find("pub fn uninstall_daemon").unwrap();
        let end = src[start..].find("\n}\n").map(|i| start + i).unwrap();
        let body = &src[start..end];
        assert!(
            body.contains("flush_rustynet_pf_anchors_argv"),
            "uninstall_daemon must flush com.rustynet/* pf anchors"
        );
        // Fail-closed pin (glm-5.3 review of 229ba864): a flush failure must
        // PROPAGATE — a best-effort eprintln would let a surviving
        // default-deny anchor outlive an "uninstalled" machine.
        assert!(
            body.contains("flush_rustynet_pf_anchors_argv(conn)?"),
            "uninstall_daemon must propagate the anchor-flush error"
        );
        assert!(
            !body.contains("if let Err(e) =\n        crate::vm_lab::orchestrator::adapter::macos_traffic::flush_rustynet_pf_anchors_argv"),
            "uninstall_daemon must not swallow the anchor-flush error"
        );
    }

    /// QH-70 dispatch mutation guard: the shared status command MUST pin the
    /// daemon socket by env and MUST invoke `rustynet status`. Dropping either
    /// breaks this test — the discrimination the addendum asks the
    /// MockShellHost argv test to provide, applied to the command string the
    /// adapter actually runs.
    #[test]
    fn daemon_status_command_pins_socket_env_and_status_verb() {
        let cmd = super::DAEMON_STATUS_COMMAND;
        assert!(
            cmd.contains("RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock"),
            "status query must pin the daemon socket: {cmd}"
        );
        assert!(
            cmd.contains("/usr/local/bin/rustynet status"),
            "status query must run the CLI's status verb: {cmd}"
        );
        assert!(
            cmd.contains("sudo -n env"),
            "status query must keep the proven sudo -n env form: {cmd}"
        );
        // Review F2: the query must also report the guest clock so handshake
        // freshness is judged on the node's own clock, not the host's.
        assert!(
            cmd.contains("echo now_unix=$(date +%s)"),
            "status query must emit the guest clock (now_unix) for freshness: {cmd}"
        );
    }
}
